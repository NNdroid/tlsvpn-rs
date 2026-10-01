#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:160]!r}")
    p.write_text(s.replace(old, new, 1))

# Public delivery alias so client/server modules can construct actors without
# duplicating the actor's callback shape.
replace_once(
    "src/rx_actor.rs",
    "type RxDelivery = Arc<dyn Fn(Vec<Arc<Vec<u8>>>) + Send + Sync>;",
    "pub type RxDelivery = Arc<dyn Fn(Vec<Arc<Vec<u8>>>) + Send + Sync>;",
)

# Client imports and state.
replace_once(
    "src/client.rs",
    "use crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\n",
    "use crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\nuse crate::rx_actor::RxSessionActor;\n",
)
replace_once(
    "src/client.rs",
    "    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,\n    tap_delivery: TapDelivery,\n    pub fec_dec: Mutex<Option<Arc<FecDecoder>>>,\n    pub dedup: Arc<DeDuplicator>,\n",
    "    // Legacy/direct receive state is retained for the static single-connection fast path.\n    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,\n    tap_delivery: Arc<TapDelivery>,\n    pub fec_dec: Mutex<Option<Arc<FecDecoder>>>,\n    pub dedup: Arc<DeDuplicator>,\n    // Multi-connection sessions transfer RX ownership to this single actor.\n    pub rx_actor: Option<Arc<RxSessionActor>>,\n",
)

# One snapshot helper keeps WebUI/metrics semantics identical across the legacy
# single-connection path and actor-owned multi-connection path.
client = Path("src/client.rs")
s = client.read_text()
marker = "impl TunnelIpSource for Client {\n"
helper = r'''impl Client {
    fn rx_runtime_snapshot(&self) -> (u64, u64, ReorderStats, bool) {
        if let Some(actor) = &self.rx_actor {
            let snap = actor.snapshot();
            return (
                self.fec_recovered_lifetime
                    .load(Ordering::Relaxed)
                    .saturating_add(snap.recovered),
                self.fec_lost_lifetime
                    .load(Ordering::Relaxed)
                    .saturating_add(snap.lost),
                snap.reorder,
                snap.fec_bypass,
            );
        }
        let (active_rec, active_lost, bypass) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| {
                let (r, l) = d.stats();
                (r, l, d.bypass_snapshot())
            })
            .unwrap_or((0, 0, false));
        (
            self.fec_recovered_lifetime
                .load(Ordering::Relaxed)
                .saturating_add(active_rec),
            self.fec_lost_lifetime
                .load(Ordering::Relaxed)
                .saturating_add(active_lost),
            self.reorder_buf.lock().stats(),
            bypass,
        )
    }
}

'''
if marker not in s:
    raise SystemExit("Client TunnelIpSource marker missing")
client.write_text(s.replace(marker, helper + marker, 1))

# Web stats and Prometheus metrics use the actor snapshot when present.
replace_once(
    "src/client.rs",
    '''        let (active_rec, active_lost) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| d.stats())
            .unwrap_or((0, 0));
        let rec = self.fec_recovered_lifetime.load(Ordering::Relaxed).saturating_add(active_rec);
        let lost = self.fec_lost_lifetime.load(Ordering::Relaxed).saturating_add(active_lost);
''',
    '''        let (rec, lost, reorder, rx_bypass) = self.rx_runtime_snapshot();
''',
)
replace_once(
    "src/client.rs",
    "        let reorder = self.reorder_buf.lock().stats();\n        let local = serde_json::json!({\n",
    "        let local = serde_json::json!({\n",
)
replace_once(
    "src/client.rs",
    '''"rx_bypass_sessions": if self.fec_dec.lock().as_ref().map(|d| d.bypass_snapshot()).unwrap_or(false) { 1 } else { 0 }''',
    '''"rx_bypass_sessions": if rx_bypass { 1 } else { 0 }''',
)
# metrics_text has the same legacy counter prelude plus a reorder snapshot.
replace_once(
    "src/client.rs",
    '''        let (active_rec, active_lost) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| d.stats())
            .unwrap_or((0, 0));
        let rec = self.fec_recovered_lifetime.load(Ordering::Relaxed).saturating_add(active_rec);
        let lost = self.fec_lost_lifetime.load(Ordering::Relaxed).saturating_add(active_lost);
        let reorder = self.reorder_buf.lock().stats();
''',
    '''        let (rec, lost, reorder, _rx_bypass) = self.rx_runtime_snapshot();
''',
)

# Construct actor only for multi-connection client sessions. Delivery stays on
# the existing TAP delivery worker so the actor itself never blocks on TAP I/O.
replace_once(
    "src/client.rs",
    '''    let reorder_buf = Arc::new(Mutex::new(ReorderBuffer::new()));
    let tap_delivery = TapDelivery::new(device.clone());
    // 重排 timeout 不再单独起 5ms 轮询线程；物理连接的 mio poll deadline
    // 会合并 session reorder deadline，仅在真实 gap 存在时提前唤醒。
''',
    '''    let reorder_buf = Arc::new(Mutex::new(ReorderBuffer::new()));
    let tap_delivery = Arc::new(TapDelivery::new(device.clone()));
    let rx_actor = if args.conns.max(1) > 1 {
        let delivery = tap_delivery.clone();
        Some(RxSessionActor::new(
            Arc::new(move |batch| delivery.enqueue(batch)),
            None,
        ))
    } else {
        None
    };
    // Multi-connection reorder timeout is actor-owned. The legacy direct path
    // keeps the connection-loop deadline logic for static single-connection RX.
''',
)
replace_once(
    "src/client.rs",
    '''        tap_delivery,
        fec_dec: Mutex::new(None),
        dedup: Arc::new(DeDuplicator::new()),
''',
    '''        tap_delivery,
        fec_dec: Mutex::new(None),
        dedup: Arc::new(DeDuplicator::new()),
        rx_actor,
''',
)

# Replace session negotiation/rekey block with actor-aware ownership. The TX
# epoch logic remains exactly the same; only RX decoder/reorder reset ownership
# changes for conns>1.
p = Path("src/client.rs")
s = p.read_text()
start_marker = "    // 5. 会话级协商（对齐 Go sessionMu 段）\n"
end_marker = "    // 6. 配置接口与策略路由（Linux；对齐 Go setupInterface/setupPolicyRouting）\n"
start = s.index(start_marker)
end = s.index(end_marker, start)
new_block = r'''    // 5. 会话级协商（对齐 Go sessionMu 段）
    let mut use_xor_fec = false;
    let mut is_new_session = false;
    let mut actor_reconfigure = false;
    let mut actor_fec_k = 0usize;
    {
        let mut st = cl.session.lock();
        if cl.fec_mode && st.fec_negotiated == 0 {
            if resp.fec_group >= fec::FEC_MIN_GROUP as i64 {
                st.fec_negotiated = resp.fec_group;
                *cl.fec_status.lock() = format!("xor K={}", resp.fec_group);
                info!(
                    "[Conn {}] XOR FEC negotiated: K={} (overhead 1/{})",
                    conn_index, resp.fec_group, resp.fec_group
                );
            } else {
                *cl.fec_status.lock() = "off".into();
                warn!(
                    "[Conn {}] FEC requested but server negotiated fec_group={}, FEC disabled",
                    conn_index, resp.fec_group
                );
            }
        }
        if cl.fec_mode && st.fec_negotiated > 0 {
            use_xor_fec = true;
            let actor_mode = cl.rx_actor.is_some();
            let rebuild_needed = if actor_mode {
                st.fec_algo != enc_algo || st.fec_salt_key != resp.enc_salt
            } else {
                let dec_guard = cl.fec_dec.lock();
                dec_guard.is_none()
                    || st.fec_algo != enc_algo
                    || st.fec_salt_key != resp.enc_salt
            };
            if rebuild_needed {
                let negotiated = st.fec_negotiated as usize;
                if actor_mode {
                    // The actor folds its previous decoder counters internally
                    // during reconfigure; the shared decoder remains unused.
                    *cl.fec_dec.lock() = None;
                    actor_reconfigure = true;
                } else {
                    if let Some(old) = cl.fec_dec.lock().as_ref() {
                        let (r, l) = old.stats();
                        cl.fec_recovered_lifetime.fetch_add(r, Ordering::Relaxed);
                        cl.fec_lost_lifetime.fetch_add(l, Ordering::Relaxed);
                        old.reset();
                    }
                    let dec = Arc::new(FecDecoder::new(negotiated, fec_rx.clone()));
                    dec.set_static_single_path(true);
                    let reorder = cl.reorder_buf.clone();
                    dec.set_reorder_progress(Arc::new(move || {
                        reorder.lock().expected_seq_snapshot()
                    }));
                    *cl.fec_dec.lock() = Some(dec);
                }
                cl.tx_port.reset_epoch(negotiated, fec_tx.clone());
                st.fec_algo = enc_algo;
                st.fec_salt_key = resp.enc_salt.clone();
            }
            actor_fec_k = st.fec_negotiated as usize;
        }
        if cl.rx_actor.is_none() {
            if let Some(dec) = cl.fec_dec.lock().as_ref() {
                dec.set_static_single_path(true);
            }
        }
        if st.enc_algo != enc_algo {
            st.enc_algo = enc_algo;
            st.ic_tx = ic_tx.clone();
            st.ic_rx = ic_rx.clone();
        }
        is_new_session =
            st.server_session_id != resp.session_id || st.session_epoch != resp.session_epoch;
        if is_new_session {
            st.server_session_id = resp.session_id.clone();
            st.session_epoch = resp.session_epoch;
            if cl.rx_actor.is_some() {
                actor_reconfigure = true;
            }
        }
        st.gw_v4 = resp.gw_v4.clone();
        st.gw_v6 = resp.gw_v6.clone();
        if resp.brutal_groups {
            st.brutal_tx = resp.brutal_total_tx;
            st.brutal_rx = resp.brutal_total_rx;
        }
        st.session_token = resp.session_token.clone();
        st.tls = resp.tls.clone();
        st.peer_info = resp.peer_info.as_ref().map(normalize_peer_info);
        persist_session_state(
            cl,
            &resp.session_id,
            &resp.session_token,
            resp.session_epoch,
        );
        *cl.assigned_v4.lock() = resp.ipv4.split('/').next().unwrap_or("").to_string();
        *cl.assigned_v6.lock() = resp.ipv6.split('/').next().unwrap_or("").to_string();
        cl.enc_algo_display.store(enc_algo, Ordering::Relaxed);

        if is_new_session {
            if !use_xor_fec {
                cl.tx_port.reset_epoch(0, None);
            }
            cl.sequence_rekeying.store(false, Ordering::Release);
            info!(
                "[Conn {}] 🔄 server reset the session; flushing stale local receive buffers...",
                conn_index
            );
        }
    }
    if let Some(actor) = &cl.rx_actor {
        if actor_reconfigure {
            let decoder = if use_xor_fec && actor_fec_k >= fec::FEC_MIN_GROUP {
                Some(FecDecoder::new(actor_fec_k, fec_rx.clone()))
            } else {
                None
            };
            actor.reconfigure(decoder);
        }
    } else if is_new_session {
        cl.reorder_buf.lock().reset();
        cl.dedup.reset();
    }

'''
p.write_text(s[:start] + new_block + s[end:])

# Actor producer is per physical reader and captures the post-handshake epoch.
replace_once(
    "src/client.rs",
    '''    let mut queued_payload_pending = 0u64;

    // Keep one plaintext batch below rustls' bounded outgoing plaintext
''',
    '''    let mut queued_payload_pending = 0u64;
    let mut rx_producer = cl.rx_actor.as_ref().map(|actor| actor.producer());

    // Keep one plaintext batch below rustls' bounded outgoing plaintext
''',
)
replace_once(
    "src/client.rs",
    '''    while !conn_closed && !EXIT.load(Ordering::Relaxed) {
        if cl.tx_port.is_sequence_exhausted() {
''',
    '''    while !conn_closed && !EXIT.load(Ordering::Relaxed) {
        if let Some(producer) = rx_producer.as_ref() {
            if let Some(error) = producer.take_error() {
                close_reason = error;
                break;
            }
        }
        if cl.tx_port.is_sequence_exhausted() {
''',
)
replace_once(
    "src/client.rs",
    '''        let reorder_wait = cl.reorder_buf.lock().next_timeout();
        if let Some(wait) = reorder_wait {
            poll_timeout = poll_timeout.min(wait);
        }
''',
    '''        let reorder_wait = if rx_producer.is_none() {
            cl.reorder_buf.lock().next_timeout()
        } else {
            None
        };
        if let Some(wait) = reorder_wait {
            poll_timeout = poll_timeout.min(wait);
        }
''',
)
replace_once(
    "src/client.rs",
    '''        if reorder_wait.is_some() {
            flush_reorder_to_tap(&cl);
        }
''',
    '''        if rx_producer.is_none() && reorder_wait.is_some() {
            flush_reorder_to_tap(&cl);
        }
''',
)
replace_once(
    "src/client.rs",
    '''        let fec_dec = if use_xor_fec {
            cl.fec_dec.lock().clone()
        } else {
            None
        };
''',
    '''        let fec_dec = if rx_producer.is_none() && use_xor_fec {
            cl.fec_dec.lock().clone()
        } else {
            None
        };
''',
)
# After decrypt/Arc conversion, actor owns control/FEC/dedup/reorder in one place.
replace_once(
    "src/client.rs",
    '''                            let data = Arc::new(data);
                            if seq == 0 {
''',
    '''                            let data = Arc::new(data);
                            if let Some(producer) = rx_producer.as_mut() {
                                if !producer.push(seq, data) {
                                    close_reason = "session RX actor queue closed".into();
                                    conn_closed = true;
                                    break 'socket_read;
                                }
                                continue;
                            }
                            if seq == 0 {
''',
)
# Flush one owned descriptor batch per socket-drain iteration. Legacy path keeps
# the old shared-lock batch helper unchanged.
replace_once(
    "src/client.rs",
    '''        flush_client_rx_batch(
            &cl,
            fec_dec.as_ref(),
            &mut fec_data_batch,
            &mut reorder_input,
        );

        if rx_packets_batch != 0 {
''',
    '''        if let Some(producer) = rx_producer.as_mut() {
            if !producer.flush() {
                close_reason = "session RX actor queue closed".into();
                conn_closed = true;
            }
            if let Some(error) = producer.take_error() {
                close_reason = error;
                conn_closed = true;
            }
        } else {
            flush_client_rx_batch(
                &cl,
                fec_dec.as_ref(),
                &mut fec_data_batch,
                &mut reorder_input,
            );
        }

        if rx_packets_batch != 0 {
''',
)
