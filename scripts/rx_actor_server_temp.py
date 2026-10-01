#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:180]!r}")
    p.write_text(s.replace(old, new, 1))

# Imports and session state.
replace_once(
    "src/server.rs",
    "use crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\n",
    "use crate::peer_info::{local_peer_info, normalize_peer_info, PeerInfo};\nuse crate::rx_actor::{RxProducer, RxSessionActor};\n",
)
replace_once(
    "src/server.rs",
    '''    pub port: Arc<AsyncPort>,
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    pub dedup: Arc<DeDuplicator>,
''',
    '''    pub port: Arc<AsyncPort>,
    // Legacy/direct receive state for static single-connection sessions.
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    pub dedup: Arc<DeDuplicator>,
    // Multi-connection FEC/reorder/gap-timeout ownership lives here.
    pub rx_actor: Option<Arc<RxSessionActor>>,
''',
)
replace_once(
    "src/server.rs",
    '''    ic_rx: Option<Arc<InnerCipher>>,
    session_epoch: u64,
    write_stalled: Option<Instant>,
''',
    '''    ic_rx: Option<Arc<InnerCipher>>,
    session_epoch: u64,
    rx_producer: Option<RxProducer>,
    write_stalled: Option<Instant>,
''',
)

# Unified receive snapshot for WebUI/metrics/session retirement.
p = Path("src/server.rs")
s = p.read_text()
marker = "pub struct SessionEpochState {\n"
helper = r'''impl ClientSession {
    fn rx_runtime_snapshot(&self) -> (u64, u64, ReorderStats, bool) {
        if let Some(actor) = &self.rx_actor {
            let snap = actor.snapshot();
            return (
                self.stat
                    .fec_recovered_lifetime
                    .load(Ordering::Relaxed)
                    .saturating_add(snap.recovered),
                self.stat
                    .fec_lost_lifetime
                    .load(Ordering::Relaxed)
                    .saturating_add(snap.lost),
                snap.reorder,
                snap.fec_bypass,
            );
        }
        let epoch = self.epoch_state.read();
        let (active_recovered, active_lost, bypass) = epoch
            .fec_dec
            .as_ref()
            .map(|dec| {
                let (r, l) = dec.stats();
                (r, l, dec.bypass_snapshot())
            })
            .unwrap_or((0, 0, false));
        (
            self.stat
                .fec_recovered_lifetime
                .load(Ordering::Relaxed)
                .saturating_add(active_recovered),
            self.stat
                .fec_lost_lifetime
                .load(Ordering::Relaxed)
                .saturating_add(active_lost),
            self.reorder_buf.lock().stats(),
            bypass,
        )
    }
}

'''
if marker not in s:
    raise SystemExit("SessionEpochState marker not found")
p.write_text(s.replace(marker, helper + marker, 1))

# Session retirement uses the same lifetime domain for actor and legacy paths.
replace_once(
    "src/server.rs",
    '''        let mut recovered = session.stat.fec_recovered_lifetime.load(Ordering::Relaxed);
        let mut lost = session.stat.fec_lost_lifetime.load(Ordering::Relaxed);
        if let Some(dec) = &session.epoch_state.read().fec_dec {
            let (r, l) = dec.stats();
            recovered = recovered.saturating_add(r);
            lost = lost.saturating_add(l);
        }
        self.fec_recovered_retired.fetch_add(recovered, Ordering::Relaxed);
        self.fec_lost_retired.fetch_add(lost, Ordering::Relaxed);
''',
    '''        let (recovered, lost, _reorder, _bypass) = session.rx_runtime_snapshot();
        self.fec_recovered_retired
            .fetch_add(recovered, Ordering::Relaxed);
        self.fec_lost_retired.fetch_add(lost, Ordering::Relaxed);
''',
)

# Dashboard session aggregation.
replace_once(
    "src/server.rs",
    '''            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
                if dec.bypass_snapshot() {
                    rx_bypass_sessions += 1;
                }
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
            dropped += s.port.dropped();
            let reorder = s.reorder_buf.lock().stats();
''',
    '''            let (session_rec, session_lost, reorder, rx_bypass) =
                s.rx_runtime_snapshot();
            rec = rec.saturating_add(session_rec);
            lost = lost.saturating_add(session_lost);
            if rx_bypass {
                rx_bypass_sessions += 1;
            }
            let epoch = s.epoch_state.read();
            dropped += s.port.dropped();
''',
)
# Metrics aggregation (retains existing process-domain behavior, but sources
# active session RX state from actor when present).
replace_once(
    "src/server.rs",
    '''            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
            dropped += s.port.dropped();
            let reorder = s.reorder_buf.lock().stats();
''',
    '''            let (session_rec, session_lost, reorder, _rx_bypass) =
                s.rx_runtime_snapshot();
            rec = rec.saturating_add(session_rec);
            lost = lost.saturating_add(session_lost);
            dropped += s.port.dropped();
''',
)

# New physical sockets start without an actor producer; successful application
# handshake binds one from the logical session.
replace_once(
    "src/server.rs",
    '''                    ic_rx: None,
                    session_epoch: 0,
                    write_stalled: None,
''',
    '''                    ic_rx: None,
                    session_epoch: 0,
                    rx_producer: None,
                    write_stalled: None,
''',
)

# Worker poll deadline and timeout flush are legacy-only. Actor sessions own
# their gap timer on the actor thread and must not race this worker scan.
replace_once(
    "src/server.rs",
    '''            if let Some(c_sess) = &sess.client_session {
                if let Some(wait) = c_sess.reorder_buf.lock().next_timeout() {
                    poll_timeout = poll_timeout.min(wait);
                }
            }
''',
    '''            if let Some(c_sess) = &sess.client_session {
                if c_sess.rx_actor.is_none() {
                    if let Some(wait) = c_sess.reorder_buf.lock().next_timeout() {
                        poll_timeout = poll_timeout.min(wait);
                    }
                }
            }
''',
)
replace_once(
    "src/server.rs",
    '''            .filter_map(|sess| sess.client_session.clone())
            .filter(|session| seen_reorder.insert(Arc::as_ptr(session) as usize))
''',
    '''            .filter_map(|sess| sess.client_session.clone())
            .filter(|session| session.rx_actor.is_none())
            .filter(|session| seen_reorder.insert(Arc::as_ptr(session) as usize))
''',
)

# Replace epoch rotation with an actor barrier for multi-connection sessions.
p = Path("src/server.rs")
s = p.read_text()
start_marker = "fn rotate_session_epoch(\n"
end_marker = "fn handle_handshake(\n"
start = s.index(start_marker)
end = s.index(end_marker, start)
rotate = r'''fn rotate_session_epoch(
    session: &Arc<ClientSession>,
    core: &Arc<ServerCore>,
    instance_id: &str,
) -> Result<(), String> {
    let mut epoch = session.epoch_state.write();
    let salt_a = new_random_salt();
    let salt_b = new_random_salt();
    let (ic_tx, ic_rx, fec_tx, fec_rx) = if core.encrypt {
        let algo = epoch.enc_algo;
        (
            Some(Arc::new(InnerCipher::for_algo(&core.psk, &salt_b, algo)?)),
            Some(Arc::new(InnerCipher::for_algo(&core.psk, &salt_a, algo)?)),
            Some(Arc::new(InnerCipher::domain_for_algo(
                &core.psk, &salt_b, "fec", algo,
            )?)),
            Some(Arc::new(InnerCipher::domain_for_algo(
                &core.psk, &salt_a, "fec", algo,
            )?)),
        )
    } else {
        (None, None, None, None)
    };

    let actor_fec = if session.rx_actor.is_some() && session.fec_enc_k > 0 {
        Some(FecDecoder::new(session.fec_enc_k as usize, fec_rx.clone()))
    } else {
        None
    };
    let legacy_fec = if session.rx_actor.is_none() && session.fec_enc_k > 0 {
        Some(Arc::new(FecDecoder::new(
            session.fec_enc_k as usize,
            fec_rx,
        )))
    } else {
        None
    };

    if let Some(actor) = &session.rx_actor {
        // Reconfigure is an epoch barrier: old producers are stale after the
        // worker acknowledges it, so queued data cannot cross into new FEC keys.
        actor.reconfigure(actor_fec);
    } else {
        if let Some(old) = &epoch.fec_dec {
            let (r, l) = old.stats();
            session
                .stat
                .fec_recovered_lifetime
                .fetch_add(r, Ordering::Relaxed);
            session
                .stat
                .fec_lost_lifetime
                .fetch_add(l, Ordering::Relaxed);
            old.reset();
        }
        session.reorder_buf.lock().reset();
        session.dedup.reset();
    }

    if session.fec_enc_k > 0 {
        session
            .port
            .reset_epoch(session.fec_enc_k as usize, fec_tx);
    } else {
        session.port.reset_epoch(0, None);
    }
    epoch.instance_id = instance_id.to_string();
    epoch.epoch = epoch.epoch.saturating_add(1);
    epoch.salt_a = salt_a;
    epoch.salt_b = salt_b;
    epoch.ic_tx = ic_tx;
    epoch.ic_rx = ic_rx;
    epoch.fec_dec = legacy_fec;
    session.stat.active_conns.store(0, Ordering::Release);
    Ok(())
}

'''
p.write_text(s[:start] + rotate + s[end:])

# New logical session: shared decoder only for single connection; actor owns the
# decoder and VSwitch delivery for multi-connection sessions.
replace_once(
    "src/server.rs",
    '''            let fec_dec = if fec_enc_k > 0 {
                Some(Arc::new(FecDecoder::new(fec_enc_k as usize, fec_rx)))
            } else {
                None
            };
''',
    '''            let multi_rx = req.brutal_conns > 1;
            let fec_dec = if !multi_rx && fec_enc_k > 0 {
                Some(Arc::new(FecDecoder::new(
                    fec_enc_k as usize,
                    fec_rx.clone(),
                )))
            } else {
                None
            };
''',
)
replace_once(
    "src/server.rs",
    '''            let mac_bin = parse_mac_key(&mac).unwrap_or_default();
            core.vswitch.add_port(client_id.clone(), port.clone());
''',
    '''            let mac_bin = parse_mac_key(&mac).unwrap_or_default();
            let rx_actor = if multi_rx {
                let vswitch = core.vswitch.clone();
                let actor_client_id = client_id.clone();
                let actor_mac = mac_bin;
                let initial_fec = if fec_enc_k > 0 {
                    Some(FecDecoder::new(fec_enc_k as usize, fec_rx))
                } else {
                    None
                };
                Some(RxSessionActor::new(
                    Arc::new(move |batch| {
                        for ordered in batch {
                            if actor_mac != [0u8; 6] {
                                vswitch.process_session_frame(
                                    &actor_client_id,
                                    actor_mac,
                                    ordered,
                                );
                            } else {
                                vswitch.process_frame(&actor_client_id, ordered);
                            }
                        }
                    }),
                    initial_fec,
                ))
            } else {
                None
            };
            core.vswitch.add_port(client_id.clone(), port.clone());
''',
)
replace_once(
    "src/server.rs",
    '''                reorder_buf: Arc::new(Mutex::new(ReorderBuffer::new())),
                dedup: Arc::new(DeDuplicator::new()),
                fec_enc_k,
''',
    '''                reorder_buf: Arc::new(Mutex::new(ReorderBuffer::new())),
                dedup: Arc::new(DeDuplicator::new()),
                rx_actor,
                fec_enc_k,
''',
)

# Shared decoder configuration is single-path only; actor decoder is private to
# its worker and needs no reorder callback/mutex.
replace_once(
    "src/server.rs",
    '''    {
        let epoch = c_sess.epoch_state.read();
        if let Some(dec) = &epoch.fec_dec {
            dec.set_static_single_path(req.brutal_conns == 1);
            let reorder = c_sess.reorder_buf.clone();
            dec.set_reorder_progress(Arc::new(move || reorder.lock().expected_seq_snapshot()));
        }
    }
''',
    '''    if c_sess.rx_actor.is_none() {
        let epoch = c_sess.epoch_state.read();
        if let Some(dec) = &epoch.fec_dec {
            dec.set_static_single_path(true);
            let reorder = c_sess.reorder_buf.clone();
            dec.set_reorder_progress(Arc::new(move || {
                reorder.lock().expected_seq_snapshot()
            }));
        }
    }
''',
)
replace_once(
    "src/server.rs",
    '''    sess.client_session = Some(c_sess.clone());

    // Brutal 速率协商（对齐 Go）。两个方向的预算不能混：server_tx_rate 是
''',
    '''    sess.rx_producer = c_sess.rx_actor.as_ref().map(|actor| actor.producer());
    sess.client_session = Some(c_sess.clone());

    // Brutal 速率协商（对齐 Go）。两个方向的预算不能混：server_tx_rate 是
''',
)

# process_plain_frames: fail a connection if its actor producer reported a
# protocol error, otherwise transfer decrypted frame ownership before any shared
# decoder/reorder access.
replace_once(
    "src/server.rs",
    '''fn process_plain_frames(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    close: &mut bool,
    tarpit: &mut bool,
    reorder_ready: &mut Vec<Arc<Vec<u8>>>,
) {
    // 共享统计按一次 TLS plaintext drain 聚合，降低多 worker 写同一 cache line 的频率。
''',
    '''fn process_plain_frames(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    close: &mut bool,
    tarpit: &mut bool,
    reorder_ready: &mut Vec<Arc<Vec<u8>>>,
) {
    if let Some(producer) = sess.rx_producer.as_ref() {
        if let Some(error) = producer.take_error() {
            debug!("closing session plaintext path: {}", error);
            *close = true;
            return;
        }
    }
    // 共享统计按一次 TLS plaintext drain 聚合，降低多 worker 写同一 cache line 的频率。
''',
)
# Actor handoff is inserted after session epoch validation, before shared decoder
# is loaded.
replace_once(
    "src/server.rs",
    '''                    let fec_dec = epoch.fec_dec.clone();
                    drop(epoch);
                    if batch_session.is_none() {
''',
    '''                    if sess.rx_producer.is_some() {
                        drop(epoch);
                        let data = Arc::new(data);
                        let producer = sess.rx_producer.as_mut().unwrap();
                        if !producer.push(seq, data) {
                            debug!("closing session plaintext path: RX actor queue closed");
                            *close = true;
                            break;
                        }
                        continue;
                    }
                    let fec_dec = epoch.fec_dec.clone();
                    drop(epoch);
                    if batch_session.is_none() {
''',
)
# End-of-drain actor batch flush. Legacy helper is skipped entirely on actor path.
replace_once(
    "src/server.rs",
    '''    if let Some(c_sess) = batch_session.as_ref() {
        flush_server_rx_batch(
            c_sess,
            core,
            batch_fec_dec.as_ref(),
            &mut fec_data_batch,
            &mut reorder_input,
            reorder_ready,
        );
    }

    if rx_packets_batch != 0 {
''',
    '''    if let Some(producer) = sess.rx_producer.as_mut() {
        if !producer.flush() {
            debug!("closing session plaintext path: RX actor queue closed");
            *close = true;
        }
        if let Some(error) = producer.take_error() {
            debug!("closing session plaintext path: {}", error);
            *close = true;
        }
    } else if let Some(c_sess) = batch_session.as_ref() {
        flush_server_rx_batch(
            c_sess,
            core,
            batch_fec_dec.as_ref(),
            &mut fec_data_batch,
            &mut reorder_input,
            reorder_ready,
        );
    }

    if rx_packets_batch != 0 {
''',
)
