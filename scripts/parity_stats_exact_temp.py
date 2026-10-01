#!/usr/bin/env python3
from pathlib import Path


def rep(path, old, new, n=1):
    p=Path(path); s=p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:180]!r}")
    p.write_text(s.replace(old,new,n))

# Decoder state observable by the dashboard: static single-path bypass or an
# open dynamic SUSPEND window. This is the same predicate as Go bypassSnapshot.
rep("src/fec.rs",
'''    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.lock();
        (inner.recovered, inner.lost)
    }
''',
'''    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.lock();
        (inner.recovered, inner.lost)
    }

    pub fn bypass_snapshot(&self) -> bool {
        if self.static_single.load(Ordering::Acquire) {
            return true;
        }
        let (from, until) = self.fence.window();
        from != 0 && until == 0
    }
''')

# TX-active means the encoder is actually armed, not merely configured. Expose
# the existing encoder state rather than deriving it again from conn count.
rep("src/fec.rs",
'''    pub fn group_size(&self) -> usize {
        self.k
    }
''',
'''    pub fn group_size(&self) -> usize {
        self.k
    }

    #[inline]
    pub fn armed(&self) -> bool {
        self.multipath && self.armed
    }
''')
rep("src/net.rs",
'''    pub fn parity_sent(&self) -> u64 {
        self.parity_sent.load(Ordering::Relaxed)
    }
''',
'''    pub fn parity_sent(&self) -> u64 {
        self.parity_sent.load(Ordering::Relaxed)
    }

    pub fn fec_tx_armed(&self) -> bool {
        if !self.encoder_enabled.load(Ordering::Acquire) {
            return false;
        }
        self.encoder
            .lock()
            .as_ref()
            .map(|enc| enc.armed())
            .unwrap_or(false)
    }
''')

# Client dashboard: use real sender/receiver state rather than configured conn
# count. Holding the decoder lock here is control-plane only.
p=Path("src/client.rs"); s=p.read_text()
old='''"tx_active_sessions": if self.fec_mode && self.live_conns.load(Ordering::Relaxed) >= 2 { 1 } else { 0 }, "rx_bypass_sessions": if self.conns_count == 1 { 1 } else { 0 }'''
new='''"tx_active_sessions": if self.tx_port.fec_tx_armed() { 1 } else { 0 }, "rx_bypass_sessions": if self.fec_dec.lock().as_ref().map(|d| d.bypass_snapshot()).unwrap_or(false) { 1 } else { 0 }'''
if old not in s: raise SystemExit("client exact FEC status marker not found")
p.write_text(s.replace(old,new,1))

# Server-global retired lifetime survives actual session destruction.
rep("src/server.rs",
'''    pub sessions: RwLock<HashMap<String, Arc<ClientSession>>>,
    pub pool: Mutex<IpPool>,
''',
'''    pub sessions: RwLock<HashMap<String, Arc<ClientSession>>>,
    pub fec_recovered_retired: AtomicU64,
    pub fec_lost_retired: AtomicU64,
    pub pool: Mutex<IpPool>,
''')
rep("src/server.rs",
'''        sessions: RwLock::new(HashMap::new()),
        pool: Mutex::new(pool),
''',
'''        sessions: RwLock::new(HashMap::new()),
        fec_recovered_retired: AtomicU64::new(0),
        fec_lost_retired: AtomicU64::new(0),
        pool: Mutex::new(pool),
''')
rep("src/server.rs",
'''        sessions.remove(cid);
        drop(sessions);
''',
'''        // Fold the final decoder epoch into the same process-lifetime domain
        // before removing the session. Decoder rebuilds have already been
        // accumulated into ClientStat, so add current decoder only once here.
        let mut recovered = session.stat.fec_recovered_lifetime.load(Ordering::Relaxed);
        let mut lost = session.stat.fec_lost_lifetime.load(Ordering::Relaxed);
        if let Some(dec) = &session.epoch_state.read().fec_dec {
            let (r, l) = dec.stats();
            recovered = recovered.saturating_add(r);
            lost = lost.saturating_add(l);
        }
        self.fec_recovered_retired.fetch_add(recovered, Ordering::Relaxed);
        self.fec_lost_retired.fetch_add(lost, Ordering::Relaxed);
        sessions.remove(cid);
        drop(sessions);
''')
rep("src/server.rs",
'''        let mut rec = 0u64;
        let mut lost = 0u64;
''',
'''        let mut rec = self.fec_recovered_retired.load(Ordering::Relaxed);
        let mut lost = self.fec_lost_retired.load(Ordering::Relaxed);
''')

p=Path("src/server.rs"); s=p.read_text()
old='''            let conns = s.stat.active_conns.load(Ordering::Relaxed) as u64;
            if s.fec_enc_k > 0 {
                enabled_sessions += 1;
                if conns >= 2 { tx_active_sessions += 1; }
                if conns <= 1 { rx_bypass_sessions += 1; }
            }
            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
'''
new='''            if s.fec_enc_k > 0 {
                enabled_sessions += 1;
                if s.port.fec_tx_armed() {
                    tx_active_sessions += 1;
                }
            }
            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
                if dec.bypass_snapshot() {
                    rx_bypass_sessions += 1;
                }
'''
if old not in s: raise SystemExit("server exact FEC status marker not found")
p.write_text(s.replace(old,new,1))
