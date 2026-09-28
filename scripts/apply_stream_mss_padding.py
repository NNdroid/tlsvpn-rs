from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    n = s.count(old)
    if n != 1:
        raise SystemExit(f"{path}: expected 1 match, got {n}")
    p.write_text(s.replace(old, new, 1))

frame = Path("src/frame.rs")
s = frame.read_text()
anchor = '''pub fn write_stream_frame_with_limit(buf: &mut Vec<u8>, frame: &[u8], record_limit: usize) {\n    buf.clear();\n    append_padded_frame_with_limit(buf, 0, frame, None, record_limit);\n}\n'''
insert = anchor + r'''

pub const STREAM_TLS_BATCH_SOFT_LIMIT: usize = 12 * 1024;
pub const MAX_TLS_PLAINTEXT_RECORD: usize = 16 * 1024;

/// Data-plane aggregation primitive: append one TLSVPN frame with zero
/// per-frame cover padding. The final frame in the TLS plaintext batch receives
/// all cover bytes after multiple frames have naturally packed together.
pub fn append_unpadded_frame(
    buf: &mut Vec<u8>,
    seq: u32,
    data: &[u8],
    ic: Option<&InnerCipher>,
) -> usize {
    let start = buf.len();
    // A positive limit below the 10-byte frame header forces pad=0 while
    // preserving the exact existing framing/encryption implementation.
    append_padded_frame_with_limit(buf, seq, data, ic, 1);
    start
}

pub fn stream_aligned_tls_plaintext_target(n: usize, record_limit: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let mss = record_limit.saturating_add(TLS_RECORD_OVERHEAD_RESERVE);
    let mss = if mss < 256 { FALLBACK_TCP_MSS } else { mss };
    let segs = (n + TLS_RECORD_OVERHEAD_RESERVE + mss - 1) / mss;
    let target = segs
        .saturating_mul(mss)
        .saturating_sub(TLS_RECORD_OVERHEAD_RESERVE);
    if target < n || target > MAX_TLS_PLAINTEXT_RECORD {
        n
    } else {
        target
    }
}

/// Add cover bytes only to the final frame of an aggregated plaintext batch.
/// This aligns the conservative TLS ciphertext budget to N*TCP_MSS while
/// bounding padding to less than one MSS.
pub fn pad_stream_batch_tail(
    buf: &mut Vec<u8>,
    last_frame_start: Option<usize>,
    record_limit: usize,
) -> usize {
    if pad_mode_name() == PAD_MODE_OFF || buf.is_empty() {
        return 0;
    }
    let Some(start) = last_frame_start else { return 0; };
    if start + 10 > buf.len() {
        return 0;
    }
    let target = stream_aligned_tls_plaintext_target(buf.len(), record_limit);
    let pad_len = target.saturating_sub(buf.len());
    if pad_len == 0 || pad_len > u16::MAX as usize {
        return 0;
    }
    let old_pad = BigEndian::read_u16(&buf[start + 4..start + 6]) as usize;
    if old_pad + pad_len > u16::MAX as usize || pad_len >= PADDING_CACHE.len() {
        return 0;
    }
    BigEndian::write_u16(&mut buf[start + 4..start + 6], (old_pad + pad_len) as u16);
    let offset = RNG.with(|rng| rng.borrow_mut().gen_range(0, PADDING_CACHE.len() - pad_len));
    buf.extend_from_slice(&PADDING_CACHE[offset..offset + pad_len]);
    pad_len
}
'''
if s.count(anchor) != 1:
    raise SystemExit("src/frame.rs: write_stream_frame anchor mismatch")
frame.write_text(s.replace(anchor, insert, 1))

old_client = '''    const TLS_WRITE_BATCH_BYTES: usize = 32 * 1024;'''
replace_once("src/client.rs", old_client, '''    const TLS_WRITE_BATCH_BYTES: usize = STREAM_TLS_BATCH_SOFT_LIMIT;''')

old_client_block = '''        let ic_tx_ref = ic_tx.as_deref();\n        send_buf.clear();\n        let mut tx_packets_batch = 0u64;\n        if !tls.wants_write() && (woken || !rx.is_empty()) {\n            if let Some(n) = &backend.notify {\n                // Only clear pending when we are actually going to drain the\n                // backend queue. If TLS is socket-backpressured, leave pending\n                // set and retry from the periodic poll loop once ciphertext drains.\n                n.consume_wake();\n            }\n            while let Ok(f) = rx.try_recv() {\n                let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };\n                append_padded_frame_with_limit(\n                    &mut send_buf,\n                    f.seq,\n                    f.data.as_slice(),\n                    ic_ref,\n                    pad_record_limit,\n                );\n                f.data.release();\n                tx_packets_batch += 1;\n                if send_buf.len() >= TLS_WRITE_BATCH_BYTES {\n                    break;\n                }\n            }\n        }\n'''
new_client_block = '''        let ic_tx_ref = ic_tx.as_deref();\n        send_buf.clear();\n        let mut tx_packets_batch = 0u64;\n        let mut last_frame_start = None;\n        if !tls.wants_write() && (woken || !rx.is_empty()) {\n            if let Some(n) = &backend.notify {\n                // Only clear pending when we are actually going to drain the\n                // backend queue. If TLS is socket-backpressured, leave pending\n                // set and retry from the periodic poll loop once ciphertext drains.\n                n.consume_wake();\n            }\n            while let Ok(f) = rx.try_recv() {\n                let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };\n                last_frame_start = Some(append_unpadded_frame(\n                    &mut send_buf,\n                    f.seq,\n                    f.data.as_slice(),\n                    ic_ref,\n                ));\n                f.data.release();\n                tx_packets_batch += 1;\n                if send_buf.len() >= TLS_WRITE_BATCH_BYTES {\n                    break;\n                }\n            }\n            if tx_packets_batch != 0 {\n                let _ = pad_stream_batch_tail(&mut send_buf, last_frame_start, pad_record_limit);\n            }\n        }\n'''
replace_once("src/client.rs", old_client_block, new_client_block)

old_server_const = '''    const TLS_WRITE_BATCH_BYTES: usize = 32 * 1024;'''
replace_once("src/server.rs", old_server_const, '''    const TLS_WRITE_BATCH_BYTES: usize = STREAM_TLS_BATCH_SOFT_LIMIT;''')
old_server_block = '''    let mut pulled = 0u64;\n    sess.send_buf.clear();\n    while let Ok(f) = sess.rx.try_recv() {\n        let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };\n        append_padded_frame_with_limit(\n            &mut sess.send_buf,\n            f.seq,\n            f.data.as_slice(),\n            ic_ref,\n            sess.pad_record_limit,\n        );\n        f.data.release();\n        pulled += 1;\n        if sess.send_buf.len() >= TLS_WRITE_BATCH_BYTES || pulled >= 2048 {\n            break;\n        }\n    }\n'''
new_server_block = '''    let mut pulled = 0u64;\n    let mut last_frame_start = None;\n    sess.send_buf.clear();\n    while let Ok(f) = sess.rx.try_recv() {\n        let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };\n        last_frame_start = Some(append_unpadded_frame(\n            &mut sess.send_buf,\n            f.seq,\n            f.data.as_slice(),\n            ic_ref,\n        ));\n        f.data.release();\n        pulled += 1;\n        if sess.send_buf.len() >= TLS_WRITE_BATCH_BYTES || pulled >= 2048 {\n            break;\n        }\n    }\n    if pulled != 0 {\n        let _ = pad_stream_batch_tail(\n            &mut sess.send_buf,\n            last_frame_start,\n            sess.pad_record_limit,\n        );\n    }\n'''
replace_once("src/server.rs", old_server_block, new_server_block)

# Add focused tests next to existing frame tests.
frame = Path("src/frame.rs")
s = frame.read_text()
marker = '''    // ---------- 预认证帧长上限（档 E） ----------\n'''
tests = r'''    #[test]
    fn stream_target_aligns_to_mss_budget() {
        assert_eq!(
            stream_aligned_tls_plaintext_target(2000, mss_padding_record_limit(1440)),
            2848
        );
        assert_eq!(
            stream_aligned_tls_plaintext_target(10000, mss_padding_record_limit(1440)),
            10048
        );
    }

    #[test]
    fn stream_padding_only_touches_last_frame() {
        let _g = crate::crypto::PAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = crate::crypto::pad_mode_name();
        let _ = crate::crypto::set_pad_mode("bucket");
        let mut buf = Vec::new();
        let _first = append_unpadded_frame(&mut buf, 1, &vec![0u8; 700], None);
        let last = append_unpadded_frame(&mut buf, 2, &vec![0u8; 700], None);
        assert_eq!(BigEndian::read_u16(&buf[4..6]), 0);
        let before = buf.len();
        let pad = pad_stream_batch_tail(
            &mut buf,
            Some(last),
            mss_padding_record_limit(1440),
        );
        assert!(pad > 0 && buf.len() > before);
        assert_eq!(BigEndian::read_u16(&buf[last + 4..last + 6]) as usize, pad);
        assert_eq!((buf.len() + TLS_RECORD_OVERHEAD_RESERVE) % 1440, 0);
        let _ = crate::crypto::set_pad_mode(&prev);
    }

'''
if s.count(marker) != 1:
    raise SystemExit("src/frame.rs: tests marker mismatch")
frame.write_text(s.replace(marker, tests + marker, 1))
