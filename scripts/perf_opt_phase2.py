from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:160]!r}")
    p.write_text(text.replace(old, new, 1))


# ---------------------------------------------------------------------------
# P0: FEC decoder batch API + O(1) completed-group dedup.
# Multiple physical connections feed one logical decoder; one mutex acquisition per
# plaintext batch is substantially cheaper than one acquisition per Ethernet frame.
# ---------------------------------------------------------------------------
replace_once(
    "src/fec.rs",
    "const FEC_DONE_CACHE: usize = 64;",
    "const FEC_DONE_CACHE: usize = 256;\nconst FEC_DONE_MASK: usize = FEC_DONE_CACHE - 1;",
)
replace_once(
    "src/fec.rs",
    "    done: Vec<u32>,",
    "    done: [u32; FEC_DONE_CACHE],",
)
replace_once(
    "src/fec.rs",
    "                done: Vec::with_capacity(FEC_DONE_CACHE),",
    "                done: [0; FEC_DONE_CACHE],",
)
replace_once(
    "src/fec.rs",
    "        inner.done.clear();",
    "        inner.done.fill(0);",
)

old_on_data = '''    /// 记录一个已解密的数据帧。out 为恢复帧输出回调（按原 seq 注入重排缓冲）。\n    pub fn on_data(&self, seq: u32, frame: &Arc<Vec<u8>>, out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {\n        if frame.is_empty() || seq == 0 {\n            return;\n        }\n        let start = self.group_start_of(seq);\n        let mut inner = self.inner.lock();\n        if is_done(&inner.done, start) {\n            return;\n        }\n        {\n            let g = entry(&mut inner.groups, start);\n            let bit = seq - start;\n            let mask = 1u64 << bit;\n            if g.got_mask & mask != 0 {\n                return; // 重复到达\n            }\n            g.got_mask |= mask;\n            if frame.len() > g.acc.len() {\n                g.acc.resize(frame.len(), 0);\n            }\n            xor_into(&mut g.acc, frame);\n        }\n        try_recover(&mut inner, start, out);\n    }\n'''
new_on_data = '''    /// 记录一个已解密的数据帧。out 为恢复帧输出回调（按原 seq 注入重排缓冲）。\n    pub fn on_data(&self, seq: u32, frame: &Arc<Vec<u8>>, out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {\n        if frame.is_empty() || seq == 0 {\n            return;\n        }\n        let mut inner = self.inner.lock();\n        self.on_data_locked(&mut inner, seq, frame, out);\n    }\n\n    /// 批量记录同一次 TLS plaintext drain 得到的数据帧。逻辑与 on_data 完全\n    /// 相同，但整批只获取一次 decoder mutex，避免多连接高 PPS 时 cache-line\n    /// ping-pong 和 parking_lot lock/unlock 成为吞吐瓶颈。\n    pub fn on_data_batch(\n        &self,\n        frames: &[(u32, Arc<Vec<u8>>)],\n        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),\n    ) {\n        if frames.is_empty() {\n            return;\n        }\n        let mut inner = self.inner.lock();\n        for (seq, frame) in frames {\n            if *seq == 0 || frame.is_empty() {\n                continue;\n            }\n            self.on_data_locked(&mut inner, *seq, frame, out);\n        }\n    }\n\n    #[inline]\n    fn on_data_locked(\n        &self,\n        inner: &mut FecDecoderInner,\n        seq: u32,\n        frame: &Arc<Vec<u8>>,\n        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),\n    ) {\n        let start = self.group_start_of(seq);\n        if is_done(&inner.done, start, self.k) {\n            return;\n        }\n        {\n            let g = entry(&mut inner.groups, start);\n            let bit = seq - start;\n            let mask = 1u64 << bit;\n            if g.got_mask & mask != 0 {\n                return;\n            }\n            g.got_mask |= mask;\n            if frame.len() > g.acc.len() {\n                g.acc.resize(frame.len(), 0);\n            }\n            xor_into(&mut g.acc, frame);\n        }\n        try_recover(inner, start, self.k, out);\n    }\n'''
replace_once("src/fec.rs", old_on_data, new_on_data)
replace_once(
    "src/fec.rs",
    "        if is_done(&inner.done, start) {",
    "        if is_done(&inner.done, start, self.k) {",
)
replace_once(
    "src/fec.rs",
    "        try_recover(&mut inner, start, out);",
    "        try_recover(&mut inner, start, self.k, out);",
)
replace_once(
    "src/fec.rs",
    '''fn is_done(done: &[u32], start: u32) -> bool {\n    done.contains(&start)\n}\n\nfn mark_done(done: &mut Vec<u32>, start: u32) {\n    done.push(start);\n    if done.len() > FEC_DONE_CACHE {\n        let drop = done.len() - FEC_DONE_CACHE;\n        done.drain(..drop);\n    }\n}\n''',
    '''#[inline]\nfn done_slot(start: u32, k: usize) -> usize {\n    (((start - 1) / k as u32) as usize) & FEC_DONE_MASK\n}\n\n#[inline]\nfn is_done(done: &[u32; FEC_DONE_CACHE], start: u32, k: usize) -> bool {\n    start != 0 && done[done_slot(start, k)] == start\n}\n\n#[inline]\nfn mark_done(done: &mut [u32; FEC_DONE_CACHE], start: u32, k: usize) {\n    if start != 0 {\n        done[done_slot(start, k)] = start;\n    }\n}\n''',
)
replace_once(
    "src/fec.rs",
    "fn try_recover(inner: &mut FecDecoderInner, start: u32, out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {",
    "fn try_recover(\n    inner: &mut FecDecoderInner,\n    start: u32,\n    k: usize,\n    out: &mut dyn FnMut(u32, Arc<Vec<u8>>),\n) {",
)
replace_once(
    "src/fec.rs",
    "        mark_done(&mut inner.done, start);",
    "        mark_done(&mut inner.done, start, k);",
)

# Batch API regression: same recovery semantics as per-frame API across multiple groups.
replace_once(
    "src/fec.rs",
    '''    #[test]\n    fn fec_recovers_single_drop_per_group() {\n''',
    '''    #[test]\n    fn fec_batch_data_matches_single_frame_recovery() {\n        let k = 4;\n        let mut enc = FecEncoder::new(k, None);\n        let dec = FecDecoder::new(k, None);\n        let mut data_batch = Vec::new();\n        let mut parity = Vec::new();\n        for i in 0..8usize {\n            let seq = (i + 1) as u32;\n            let payload = vec![(i as u8) + 1; 256 + i];\n            if i != 2 && i != 6 {\n                data_batch.push((seq, Arc::new(payload.clone())));\n            }\n            if let Some(p) = enc.add(seq, &payload) {\n                parity.push(p);\n            }\n        }\n        let mut recovered = Vec::new();\n        dec.on_data_batch(&data_batch, &mut |seq, frame| {\n            recovered.push((seq, frame.len()));\n        });\n        for p in &parity {\n            dec.on_parity(p, &mut |seq, frame| recovered.push((seq, frame.len())));\n        }\n        for p in parity {\n            release_frame_vec(p);\n        }\n        recovered.sort_unstable();\n        assert_eq!(recovered, vec![(3, 258), (7, 262)]);\n        assert_eq!(dec.stats(), (2, 0));\n    }\n\n    #[test]\n    fn fec_recovers_single_drop_per_group() {\n''',
)

# ---------------------------------------------------------------------------
# P0: client RX batching. Decrypt/dedup still happens immediately; FEC and reorder
# consume batches so one TLS drain does not lock shared session state per frame.
# ---------------------------------------------------------------------------
replace_once(
    "src/client.rs",
    '''        let fec_dec = if use_xor_fec {\n            cl.fec_dec.lock().clone()\n        } else {\n            None\n        };\n\n        if readable {\n''',
    '''        let fec_dec = if use_xor_fec {\n            cl.fec_dec.lock().clone()\n        } else {\n            None\n        };\n        let mut fec_data_batch: Vec<(u32, Arc<Vec<u8>>)> = Vec::with_capacity(64);\n        let mut reorder_input: Vec<(u32, Arc<Vec<u8>>)> = Vec::with_capacity(64);\n\n        if readable {\n''',
)
replace_once(
    "src/client.rs",
    '''                                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                                            deliver_to_tap(&cl, s, f);\n                                        };\n                                        dec.on_parity(&data, &mut sink);\n''',
    '''                                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                                            reorder_input.push((s, f));\n                                        };\n                                        dec.on_parity(&data, &mut sink);\n''',
)
replace_once(
    "src/client.rs",
    '''                            if let Some(dec) = &fec_dec {\n                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                                    deliver_to_tap(&cl, s, f);\n                                };\n                                dec.on_data(seq, &data, &mut sink);\n                            }\n\n                            if !cl.dedup.is_duplicate(seq) {\n                                deliver_to_tap(&cl, seq, data);\n                            } else {\n                                release_shared_frame(data);\n                            }\n''',
    '''                            if fec_dec.is_some() {\n                                fec_data_batch.push((seq, data.clone()));\n                            }\n\n                            if !cl.dedup.is_duplicate(seq) {\n                                reorder_input.push((seq, data));\n                            } else {\n                                release_shared_frame(data);\n                            }\n\n                            if fec_data_batch.len() >= 64 || reorder_input.len() >= 64 {\n                                flush_client_rx_batch(\n                                    &cl,\n                                    fec_dec.as_ref(),\n                                    &mut fec_data_batch,\n                                    &mut reorder_input,\n                                );\n                            }\n''',
)
replace_once(
    "src/client.rs",
    '''        }\n\n        if rx_packets_batch != 0 {\n''',
    '''        }\n\n        flush_client_rx_batch(\n            &cl,\n            fec_dec.as_ref(),\n            &mut fec_data_batch,\n            &mut reorder_input,\n        );\n\n        if rx_packets_batch != 0 {\n''',
)

replace_once(
    "src/client.rs",
    '''/// Inject one data/recovered frame into reorder and hand any newly contiguous\n/// output to the dedicated TAP writer. Enqueue happens under the reorder lock:\n/// this is nonblocking and preserves strict order across physical connections.\nfn deliver_to_tap(cl: &Arc<Client>, seq: u32, frame: Arc<Vec<u8>>) {\n    let mut ready = cl.tap_delivery.acquire();\n    let mut reorder = cl.reorder_buf.lock();\n    reorder.insert_into(seq, frame, &mut ready);\n    if ready.is_empty() {\n        drop(reorder);\n        cl.tap_delivery.recycle(ready);\n    } else {\n        cl.tap_delivery.enqueue(ready);\n    }\n}\n\n''',
    '''/// Flush one plaintext RX batch through FEC and reorder. FEC takes its mutex once\n/// per batch; reorder likewise receives the whole input burst under one lock.\nfn flush_client_rx_batch(\n    cl: &Arc<Client>,\n    fec_dec: Option<&Arc<FecDecoder>>,\n    fec_data: &mut Vec<(u32, Arc<Vec<u8>>)>,\n    reorder_input: &mut Vec<(u32, Arc<Vec<u8>>)>,\n) {\n    if let Some(dec) = fec_dec {\n        if !fec_data.is_empty() {\n            let mut sink = |seq: u32, frame: Arc<Vec<u8>>| {\n                reorder_input.push((seq, frame));\n            };\n            dec.on_data_batch(fec_data, &mut sink);\n        }\n    }\n    fec_data.clear();\n\n    if reorder_input.is_empty() {\n        return;\n    }\n    let mut ready = cl.tap_delivery.acquire();\n    let mut reorder = cl.reorder_buf.lock();\n    for (seq, frame) in reorder_input.drain(..) {\n        reorder.insert_into(seq, frame, &mut ready);\n    }\n    if ready.is_empty() {\n        drop(reorder);\n        cl.tap_delivery.recycle(ready);\n    } else {\n        // Keep enqueue under the reorder lock just like the old per-frame path so\n        // batches from different physical connections cannot overtake each other.\n        cl.tap_delivery.enqueue(ready);\n    }\n}\n\n''',
)

# ---------------------------------------------------------------------------
# P0: server RX batching. process_plain_frames already drains all available rustls
# plaintext; aggregate its FEC and reorder work before entering shared session locks.
# ---------------------------------------------------------------------------
replace_once(
    "src/server.rs",
    '''    let mut rx_bytes_batch = 0u64;\n    let mut rx_packets_batch = 0u64;\n\n    loop {\n''',
    '''    let mut rx_bytes_batch = 0u64;\n    let mut rx_packets_batch = 0u64;\n    let mut batch_session: Option<Arc<ClientSession>> = None;\n    let mut batch_fec_dec: Option<Arc<FecDecoder>> = None;\n    let mut fec_data_batch: Vec<(u32, Arc<Vec<u8>>)> = Vec::with_capacity(64);\n    let mut reorder_input: Vec<(u32, Arc<Vec<u8>>)> = Vec::with_capacity(64);\n\n    loop {\n''',
)
replace_once(
    "src/server.rs",
    '''                    let fec_dec = epoch.fec_dec.clone();\n                    drop(epoch);\n                    let data = Arc::new(data);\n''',
    '''                    let fec_dec = epoch.fec_dec.clone();\n                    drop(epoch);\n                    if batch_session.is_none() {\n                        batch_session = Some(c_sess.clone());\n                    }\n                    if batch_fec_dec.is_none() {\n                        batch_fec_dec = fec_dec.clone();\n                    }\n                    let data = Arc::new(data);\n''',
)
replace_once(
    "src/server.rs",
    '''                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                                    deliver_to_vswitch(&c_sess, core, s, f, reorder_ready);\n                                };\n                                dec.on_parity(&data, &mut sink);\n''',
    '''                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                                    reorder_input.push((s, f));\n                                };\n                                dec.on_parity(&data, &mut sink);\n''',
)
replace_once(
    "src/server.rs",
    '''                    if let Some(dec) = &fec_dec {\n                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {\n                            deliver_to_vswitch(&c_sess, core, s, f, reorder_ready);\n                        };\n                        dec.on_data(seq, &data, &mut sink);\n                    }\n\n                    if !c_sess.dedup.is_duplicate(seq) {\n                        deliver_to_vswitch(&c_sess, core, seq, data, reorder_ready);\n                    } else {\n                        release_shared_frame(data);\n                    }\n''',
    '''                    if fec_dec.is_some() {\n                        fec_data_batch.push((seq, data.clone()));\n                    }\n\n                    if !c_sess.dedup.is_duplicate(seq) {\n                        reorder_input.push((seq, data));\n                    } else {\n                        release_shared_frame(data);\n                    }\n\n                    if fec_data_batch.len() >= 64 || reorder_input.len() >= 64 {\n                        flush_server_rx_batch(\n                            &c_sess,\n                            core,\n                            batch_fec_dec.as_ref(),\n                            &mut fec_data_batch,\n                            &mut reorder_input,\n                            reorder_ready,\n                        );\n                    }\n''',
)
replace_once(
    "src/server.rs",
    '''    if rx_packets_batch != 0 {\n''',
    '''    if let Some(c_sess) = batch_session.as_ref() {\n        flush_server_rx_batch(\n            c_sess,\n            core,\n            batch_fec_dec.as_ref(),\n            &mut fec_data_batch,\n            &mut reorder_input,\n            reorder_ready,\n        );\n    }\n\n    if rx_packets_batch != 0 {\n''',
)
replace_once(
    "src/server.rs",
    '''fn deliver_to_vswitch(\n    c_sess: &Arc<ClientSession>,\n    core: &Arc<ServerCore>,\n    seq: u32,\n    frame: Arc<Vec<u8>>,\n    ready: &mut Vec<Arc<Vec<u8>>>,\n) {\n    ready.clear();\n    c_sess.reorder_buf.lock().insert_into(seq, frame, ready);\n    for ordered in ready.drain(..) {\n        if c_sess.mac_bin != [0u8; 6] {\n            core.vswitch\n                .process_session_frame(&c_sess.stat.client_id, c_sess.mac_bin, ordered);\n        } else {\n            core.vswitch.process_frame(&c_sess.stat.client_id, ordered);\n        }\n    }\n}\n''',
    '''fn flush_server_rx_batch(\n    c_sess: &Arc<ClientSession>,\n    core: &Arc<ServerCore>,\n    fec_dec: Option<&Arc<FecDecoder>>,\n    fec_data: &mut Vec<(u32, Arc<Vec<u8>>)>,\n    reorder_input: &mut Vec<(u32, Arc<Vec<u8>>)>,\n    ready: &mut Vec<Arc<Vec<u8>>>,\n) {\n    if let Some(dec) = fec_dec {\n        if !fec_data.is_empty() {\n            let mut sink = |seq: u32, frame: Arc<Vec<u8>>| {\n                reorder_input.push((seq, frame));\n            };\n            dec.on_data_batch(fec_data, &mut sink);\n        }\n    }\n    fec_data.clear();\n    if reorder_input.is_empty() {\n        return;\n    }\n\n    ready.clear();\n    {\n        let mut reorder = c_sess.reorder_buf.lock();\n        for (seq, frame) in reorder_input.drain(..) {\n            reorder.insert_into(seq, frame, ready);\n        }\n    }\n    for ordered in ready.drain(..) {\n        if c_sess.mac_bin != [0u8; 6] {\n            core.vswitch\n                .process_session_frame(&c_sess.stat.client_id, c_sess.mac_bin, ordered);\n        } else {\n            core.vswitch.process_frame(&c_sess.stat.client_id, ordered);\n        }\n    }\n}\n''',
)

print("Rust dataplane phase 2 batch patch applied")
