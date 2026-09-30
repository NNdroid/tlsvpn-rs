#!/usr/bin/env python3
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    n = text.count(old)
    if n != 1:
        raise SystemExit(f"{label}: expected exactly one match, got {n}")
    return text.replace(old, new, 1)


def patch_frame():
    p = ROOT / "src/frame.rs"
    s = p.read_text()
    if "pub struct VPNFrameBatch" in s:
        return
    old = """pub struct VPNFrame {\n    pub seq: u32,\n    pub data: FramePayload,\n}\n"""
    new = old + """

/// Owned backend handoff unit. `bytes` is authoritative payload accounting and
/// is accumulated once while frames enter the batch, so TLS writers do not
/// rescan frame lengths after ownership transfer.
pub struct VPNFrameBatch {
    pub frames: Vec<VPNFrame>,
    pub bytes: u64,
}

impl VPNFrameBatch {
    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            frames: Vec::with_capacity(capacity),
            bytes: 0,
        }
    }

    #[inline]
    pub fn from_frame(frame: VPNFrame, bytes: u64) -> Self {
        let mut batch = Self::with_capacity(8);
        batch.push(frame, bytes);
        batch
    }

    #[inline]
    pub fn push(&mut self, frame: VPNFrame, bytes: u64) {
        self.frames.push(frame);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.frames.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }
}
"""
    s = replace_once(s, old, new, "frame batch type")
    p.write_text(s)


def add_backend_field_to_literals(text: str, value: str = "None") -> str:
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if "Backend {" not in line or "pub struct Backend" in line:
            out.append(line)
            i += 1
            continue
        # Collect a syntactic block by brace depth. Backend literals in this
        # codebase do not contain braces in string literals on field lines.
        block = [line]
        depth = line.count("{") - line.count("}")
        i += 1
        while i < len(lines) and depth > 0:
            block.append(lines[i])
            depth += lines[i].count("{") - lines[i].count("}")
            i += 1
        joined = "".join(block)
        if "ch:" in joined and "owned_batches:" not in joined:
            patched = []
            inserted = False
            for bline in block:
                patched.append(bline)
                stripped = bline.lstrip()
                if not inserted and stripped.startswith("ch:"):
                    indent = bline[: len(bline) - len(stripped)]
                    patched.append(f"{indent}owned_batches: {value},\n")
                    inserted = True
            block = patched
        out.extend(block)
    return "".join(out)


def patch_net():
    p = ROOT / "src/net.rs"
    s = p.read_text()
    s = s.replace(
        "use crossbeam_channel::{Sender, TrySendError};",
        "use crossbeam_channel::{Receiver, Sender, TrySendError};",
        1,
    )
    s = s.replace("use std::collections::HashMap;", "use std::collections::{HashMap, VecDeque};", 1)
    s = s.replace(
        "use crate::frame::{FramePayload, VPNFrame};",
        "use crate::frame::{FramePayload, VPNFrame, VPNFrameBatch};",
        1,
    )

    marker = "pub struct Backend {\n"
    if "pub struct OwnedBatchQueue" not in s:
        queue_code = r'''const OWNED_BATCH_MAX_FRAMES: usize = 8;
const OWNED_BATCH_MAX_BYTES: u64 = 8 * 1024;

struct OwnedBatchQueueInner {
    batches: VecDeque<VPNFrameBatch>,
    frames: usize,
}

/// Bounded ownership queue used by real TLS backends. Producers append a frame
/// to the current tail batch when possible; the TLS writer atomically takes a
/// complete batch. Capacity is still expressed in frames to preserve the old
/// channel backpressure semantics seen by the adaptive scheduler.
pub struct OwnedBatchQueue {
    inner: Mutex<OwnedBatchQueueInner>,
    capacity_frames: usize,
}

impl OwnedBatchQueue {
    pub fn new(capacity_frames: usize) -> Self {
        Self {
            inner: Mutex::new(OwnedBatchQueueInner {
                batches: VecDeque::new(),
                frames: 0,
            }),
            capacity_frames: capacity_frames.max(1),
        }
    }

    #[inline]
    pub fn try_push(&self, frame: VPNFrame, bytes: u64) -> Result<(), VPNFrame> {
        let mut inner = self.inner.lock();
        if inner.frames >= self.capacity_frames {
            return Err(frame);
        }
        let can_append = inner
            .batches
            .back()
            .map(|batch| {
                batch.frames.len() < OWNED_BATCH_MAX_FRAMES
                    && batch.bytes.saturating_add(bytes) <= OWNED_BATCH_MAX_BYTES
            })
            .unwrap_or(false);
        if can_append {
            inner.batches.back_mut().unwrap().push(frame, bytes);
        } else {
            inner.batches.push_back(VPNFrameBatch::from_frame(frame, bytes));
        }
        inner.frames += 1;
        Ok(())
    }

    #[inline]
    pub fn try_pop(&self) -> Option<VPNFrameBatch> {
        let mut inner = self.inner.lock();
        let batch = inner.batches.pop_front()?;
        inner.frames = inner.frames.saturating_sub(batch.frames.len());
        Some(batch)
    }

    #[inline]
    pub fn len_frames(&self) -> usize {
        self.inner.lock().frames
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().frames == 0
    }

    #[inline]
    pub fn capacity_frames(&self) -> usize {
        self.capacity_frames
    }
}

/// Receive one ownership batch from a real backend; legacy/test backends are
/// wrapped as a one-frame batch so cold-path tests keep their existing channel.
#[inline]
pub fn try_recv_backend_batch(
    backend: Option<&Backend>,
    legacy_rx: &Receiver<VPNFrame>,
) -> Option<VPNFrameBatch> {
    if let Some(queue) = backend.and_then(|b| b.owned_batches.as_deref()) {
        return queue.try_pop();
    }
    let frame = legacy_rx.try_recv().ok()?;
    let bytes = frame.data.as_slice().len() as u64;
    Some(VPNFrameBatch::from_frame(frame, bytes))
}

#[inline]
pub fn backend_tx_is_empty(backend: Option<&Backend>, legacy_rx: &Receiver<VPNFrame>) -> bool {
    if let Some(queue) = backend.and_then(|b| b.owned_batches.as_deref()) {
        return queue.is_empty();
    }
    legacy_rx.is_empty()
}

'''
        s = replace_once(s, marker, queue_code + marker, "owned queue insertion")

    old_struct = """pub struct Backend {\n    pub fec_fence_gen: AtomicU64,\n    pub ch: Sender<VPNFrame>,\n"""
    new_struct = """pub struct Backend {\n    pub fec_fence_gen: AtomicU64,\n    pub ch: Sender<VPNFrame>,\n    pub owned_batches: Option<Arc<OwnedBatchQueue>>,\n"""
    if new_struct not in s:
        s = replace_once(s, old_struct, new_struct, "backend owned queue field")

    old_queue = """    fn scheduler_queue_len(&self) -> usize {\n        self.ch.len()\n    }\n    #[inline]\n    fn scheduler_queue_capacity(&self) -> usize {\n        self.ch.capacity().unwrap_or(4096)\n    }\n"""
    new_queue = """    fn scheduler_queue_len(&self) -> usize {\n        self.owned_batches\n            .as_deref()\n            .map(OwnedBatchQueue::len_frames)\n            .unwrap_or_else(|| self.ch.len())\n    }\n    #[inline]\n    fn scheduler_queue_capacity(&self) -> usize {\n        self.owned_batches\n            .as_deref()\n            .map(OwnedBatchQueue::capacity_frames)\n            .unwrap_or_else(|| self.ch.capacity().unwrap_or(4096))\n    }\n"""
    if new_queue not in s:
        s = replace_once(s, old_queue, new_queue, "adaptive queue accounting")

    old_send = """        let bytes = data.as_slice().len() as u64;\n        b.scheduler.add_queued(bytes);\n        match b.ch.try_send(VPNFrame { seq, data }) {\n            Ok(()) => {\n                if let Some(n) = &b.notify {\n                    n.wake();\n                }\n                Ok(())\n            }\n            Err(TrySendError::Full(frame)) | Err(TrySendError::Disconnected(frame)) => {\n                b.scheduler.complete_queued(bytes);\n                Err(frame.data)\n            }\n        }\n"""
    new_send = """        let bytes = data.as_slice().len() as u64;\n        b.scheduler.add_queued(bytes);\n        if let Some(queue) = &b.owned_batches {\n            return match queue.try_push(VPNFrame { seq, data }, bytes) {\n                Ok(()) => {\n                    if let Some(n) = &b.notify {\n                        n.wake();\n                    }\n                    Ok(())\n                }\n                Err(frame) => {\n                    b.scheduler.complete_queued(bytes);\n                    Err(frame.data)\n                }\n            };\n        }\n        match b.ch.try_send(VPNFrame { seq, data }) {\n            Ok(()) => {\n                if let Some(n) = &b.notify {\n                    n.wake();\n                }\n                Ok(())\n            }\n            Err(TrySendError::Full(frame)) | Err(TrySendError::Disconnected(frame)) => {\n                b.scheduler.complete_queued(bytes);\n                Err(frame.data)\n            }\n        }\n"""
    if new_send not in s:
        s = replace_once(s, old_send, new_send, "owned queue enqueue")

    # Keep every test/cold Backend literal compiling; production client/server
    # literals are switched to Some(...) in their own files below.
    s = add_backend_field_to_literals(s, "None")
    p.write_text(s)


def set_prod_backend(path: Path):
    s = path.read_text()
    s = add_backend_field_to_literals(s, "None")
    # Both real connection constructors use bounded(1024) followed by a Backend
    # literal. Convert only the first owned_batches field in that local region.
    pos = s.find("let (tx, rx) = bounded(1024);")
    if pos < 0:
        raise SystemExit(f"{path}: bounded(1024) backend constructor not found")
    field = s.find("owned_batches: None,", pos)
    if field < 0 or field - pos > 1800:
        raise SystemExit(f"{path}: production owned_batches field not found near backend")
    s = s[:field] + "owned_batches: Some(Arc::new(OwnedBatchQueue::new(1024)))," + s[field + len("owned_batches: None,"):]
    path.write_text(s)


def patch_client_writer():
    p = ROOT / "src/client.rs"
    s = p.read_text()
    set_prod_backend(p)
    s = p.read_text()

    s = s.replace(
        "clamp_poll_for_tx_backlog(poll_timeout, !rx.is_empty(), tls.wants_write())",
        "clamp_poll_for_tx_backlog(\n            poll_timeout,\n            !backend_tx_is_empty(Some(backend.as_ref()), &rx),\n            tls.wants_write(),\n        )",
    )

    pattern = re.compile(
        r"(?P<indent>\s*)while let Ok\(f\) = rx\.try_recv\(\) \{\n"
        r"(?P=indent)    let payload_len = f\.data\.as_slice\(\)\.len\(\) as u64;\n"
        r"(?P<body>.*?)"
        r"(?P=indent)    queued_payload_pending = queued_payload_pending\.saturating_add\(payload_len\);\n"
        r"(?P=indent)    tx_packets_batch \+= 1;\n"
        r"(?P=indent)    if send_buf\.len\(\) >= TLS_WRITE_BATCH_BYTES \{\n"
        r"(?P=indent)        break;\n"
        r"(?P=indent)    \}\n"
        r"(?P=indent)\}",
        re.S,
    )
    m = pattern.search(s)
    if not m:
        raise SystemExit("client writer loop pattern not found")
    indent = m.group("indent")
    body = m.group("body")
    # Existing body references `f`; retain it inside the batch frame loop.
    replacement = (
        f"{indent}while let Some(batch) = try_recv_backend_batch(Some(backend.as_ref()), &rx) {{\n"
        f"{indent}    let batch_bytes = batch.bytes;\n"
        f"{indent}    let batch_frames = batch.frames.len() as u64;\n"
        f"{indent}    for f in batch.frames {{\n"
        + "".join(indent + "        " + line if line.strip() else line for line in body.splitlines(keepends=True))
        + f"{indent}    }}\n"
        f"{indent}    queued_payload_pending = queued_payload_pending.saturating_add(batch_bytes);\n"
        f"{indent}    tx_packets_batch += batch_frames;\n"
        f"{indent}    if send_buf.len() >= TLS_WRITE_BATCH_BYTES {{\n"
        f"{indent}        break;\n"
        f"{indent}    }}\n"
        f"{indent}}}"
    )
    s = s[:m.start()] + replacement + s[m.end():]
    p.write_text(s)


def patch_server_writer():
    p = ROOT / "src/server.rs"
    set_prod_backend(p)
    s = p.read_text()

    pattern = re.compile(
        r"(?P<indent>\s*)while let Ok\(f\) = sess\.rx\.try_recv\(\) \{\n"
        r"(?P=indent)    let payload_len = f\.data\.as_slice\(\)\.len\(\) as u64;\n"
        r"(?P<body>.*?)"
        r"(?P=indent)    pulled_payload = pulled_payload\.saturating_add\(payload_len\);\n"
        r"(?P=indent)    pulled \+= 1;\n"
        r"(?P=indent)    if sess\.send_buf\.len\(\) >= TLS_WRITE_BATCH_BYTES \|\| pulled >= 2048 \{\n"
        r"(?P=indent)        break;\n"
        r"(?P=indent)    \}\n"
        r"(?P=indent)\}",
        re.S,
    )
    m = pattern.search(s)
    if not m:
        raise SystemExit("server writer loop pattern not found")
    indent = m.group("indent")
    body = m.group("body")
    replacement = (
        f"{indent}while let Some(batch) = try_recv_backend_batch(sess.tx_backend.as_deref(), &sess.rx) {{\n"
        f"{indent}    let batch_bytes = batch.bytes;\n"
        f"{indent}    let batch_frames = batch.frames.len() as u64;\n"
        f"{indent}    for f in batch.frames {{\n"
        + "".join(indent + "        " + line if line.strip() else line for line in body.splitlines(keepends=True))
        + f"{indent}    }}\n"
        f"{indent}    pulled_payload = pulled_payload.saturating_add(batch_bytes);\n"
        f"{indent}    pulled = pulled.saturating_add(batch_frames);\n"
        f"{indent}    if sess.send_buf.len() >= TLS_WRITE_BATCH_BYTES || pulled >= 2048 {{\n"
        f"{indent}        break;\n"
        f"{indent}    }}\n"
        f"{indent}}}"
    )
    s = s[:m.start()] + replacement + s[m.end():]
    p.write_text(s)


def main():
    patch_frame()
    patch_net()
    patch_client_writer()
    patch_server_writer()
    print("owned batch patch applied")


if __name__ == "__main__":
    main()
