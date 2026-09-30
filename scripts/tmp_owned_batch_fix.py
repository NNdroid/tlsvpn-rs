#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text, old, new, label):
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected 1 match, got {n}")
    return text.replace(old, new, 1)


def patch_net():
    p = ROOT / "src/net.rs"
    s = p.read_text()
    s = replace_once(
        s,
        "const OWNED_BATCH_MAX_FRAMES: usize = 8;\nconst OWNED_BATCH_MAX_BYTES: u64 = 8 * 1024;\n",
        "const OWNED_BATCH_MAX_FRAMES: usize = 8;\nconst OWNED_BATCH_MAX_BYTES: u64 = 8 * 1024;\n// Conservative framing allowance: 10-byte TLSVPN header + up to a 16-byte\n// inner AEAD tag, rounded up so a batch accepted under the budget cannot push\n// the rustls plaintext buffer past its hard record limit.\nconst OWNED_BATCH_WIRE_OVERHEAD_PER_FRAME: usize = 32;\n",
        "owned batch constants",
    )
    old = '''    #[inline]\n    pub fn try_pop(&self) -> Option<VPNFrameBatch> {\n        let mut inner = self.inner.lock();\n        let batch = inner.batches.pop_front()?;\n        inner.frames = inner.frames.saturating_sub(batch.frames.len());\n        Some(batch)\n    }\n'''
    new = '''    #[inline]\n    pub fn try_pop_fitting(&self, wire_budget: usize) -> Option<VPNFrameBatch> {\n        let mut inner = self.inner.lock();\n        let front = inner.batches.front()?;\n        let estimated_wire = (front.bytes as usize).saturating_add(\n            front\n                .frames\n                .len()\n                .saturating_mul(OWNED_BATCH_WIRE_OVERHEAD_PER_FRAME),\n        );\n        if estimated_wire > wire_budget {\n            return None;\n        }\n        let batch = inner.batches.pop_front()?;\n        inner.frames = inner.frames.saturating_sub(batch.frames.len());\n        Some(batch)\n    }\n'''
    s = replace_once(s, old, new, "budgeted batch pop")
    old = '''pub fn try_recv_backend_batch(\n    backend: Option<&Backend>,\n    legacy_rx: &Receiver<VPNFrame>,\n) -> Option<VPNFrameBatch> {\n    if let Some(queue) = backend.and_then(|b| b.owned_batches.as_deref()) {\n        return queue.try_pop();\n    }\n'''
    new = '''pub fn try_recv_backend_batch(\n    backend: Option<&Backend>,\n    legacy_rx: &Receiver<VPNFrame>,\n    wire_budget: usize,\n) -> Option<VPNFrameBatch> {\n    if let Some(queue) = backend.and_then(|b| b.owned_batches.as_deref()) {\n        return queue.try_pop_fitting(wire_budget);\n    }\n'''
    s = replace_once(s, old, new, "budgeted receive helper")

    marker = '''mod tests {\n    use super::*;\n    use std::sync::atomic::AtomicU32;\n'''
    tests = marker + r'''

    fn owned_test_frame(seq: u32, bytes: usize) -> VPNFrame {
        VPNFrame {
            seq,
            data: FramePayload::Owned(vec![seq as u8; bytes]),
        }
    }

    #[test]
    fn owned_batch_queue_coalesces_and_preserves_accounting() {
        let queue = OwnedBatchQueue::new(16);
        queue.try_push(owned_test_frame(1, 1200), 1200).unwrap();
        queue.try_push(owned_test_frame(2, 1300), 1300).unwrap();
        assert_eq!(queue.len_frames(), 2);

        let batch = queue.try_pop_fitting(4096).expect("batch must fit");
        assert_eq!(batch.frames.len(), 2);
        assert_eq!(batch.bytes, 2500);
        assert_eq!(batch.frames[0].seq, 1);
        assert_eq!(batch.frames[1].seq, 2);
        assert!(queue.is_empty());
    }

    #[test]
    fn owned_batch_queue_keeps_front_when_wire_budget_is_too_small() {
        let queue = OwnedBatchQueue::new(16);
        queue.try_push(owned_test_frame(7, 1400), 1400).unwrap();
        queue.try_push(owned_test_frame(8, 1400), 1400).unwrap();

        assert!(queue.try_pop_fitting(2800).is_none());
        assert_eq!(queue.len_frames(), 2, "failed fit must not consume ownership");

        let batch = queue.try_pop_fitting(4096).expect("larger budget must drain");
        assert_eq!(batch.frames.len(), 2);
        assert_eq!(batch.bytes, 2800);
    }

    #[test]
    fn owned_batch_queue_capacity_remains_frame_based() {
        let queue = OwnedBatchQueue::new(2);
        queue.try_push(owned_test_frame(1, 64), 64).unwrap();
        queue.try_push(owned_test_frame(2, 64), 64).unwrap();
        let rejected = queue
            .try_push(owned_test_frame(3, 64), 64)
            .expect_err("third frame must hit frame capacity");
        assert_eq!(rejected.seq, 3);
        rejected.data.release();
        assert_eq!(queue.len_frames(), 2);
    }
'''
    s = replace_once(s, marker, tests, "owned queue regression tests")
    p.write_text(s)


def budget_expr(buf):
    return f"MAX_TLS_PLAINTEXT_RECORD.saturating_sub(STREAM_PAD_ABSOLUTE_LIMIT).saturating_sub({buf}.len())"


def patch_client():
    p = ROOT / "src/client.rs"
    s = p.read_text()
    s = replace_once(
        s,
        "if !tls.wants_write() && (woken || !rx.is_empty()) {",
        "if !tls.wants_write()\n            && (woken || !backend_tx_is_empty(Some(backend.as_ref()), &rx))\n        {",
        "client backlog gate",
    )
    old = "while let Some(batch) = try_recv_backend_batch(Some(backend.as_ref()), &rx) {"
    new = '''while let Some(batch) = try_recv_backend_batch(
                Some(backend.as_ref()),
                &rx,
                MAX_TLS_PLAINTEXT_RECORD
                    .saturating_sub(STREAM_PAD_ABSOLUTE_LIMIT)
                    .saturating_sub(send_buf.len()),
            ) {'''
    s = replace_once(s, old, new, "client budgeted batch drain")
    p.write_text(s)


def patch_server():
    p = ROOT / "src/server.rs"
    s = p.read_text()
    old = "while let Some(batch) = try_recv_backend_batch(sess.tx_backend.as_deref(), &sess.rx) {"
    new = '''while let Some(batch) = try_recv_backend_batch(
        sess.tx_backend.as_deref(),
        &sess.rx,
        MAX_TLS_PLAINTEXT_RECORD
            .saturating_sub(STREAM_PAD_ABSOLUTE_LIMIT)
            .saturating_sub(sess.send_buf.len()),
    ) {'''
    s = replace_once(s, old, new, "server budgeted batch drain")
    p.write_text(s)


patch_net()
patch_client()
patch_server()
print("owned batch drain fixes applied")
