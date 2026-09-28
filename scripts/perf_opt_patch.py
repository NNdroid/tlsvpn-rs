from pathlib import Path


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected exactly one match, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str, min_count: int = 1) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count < min_count:
        raise SystemExit(f"{path}: expected >= {min_count} matches, found {count}: {old[:120]!r}")
    p.write_text(text.replace(old, new))


# ---------------------------------------------------------------------------
# P0: pooled frame reuse without zeroing bytes that are immediately overwritten.
# Keep acquire_frame_vec() zero-initialized for callers that rely on that semantic,
# and add an explicit overwrite-only API for TAP / scanner hot paths.
# ---------------------------------------------------------------------------
replace_once(
    "src/buffer.rs",
    '''#[inline]\npub fn acquire_frame_vec(len: usize) -> Vec<u8> {\n    if len == 0 {\n        return Vec::new();\n    }\n    let Some(idx) = frame_class_index(len) else {\n        return vec![0u8; len];\n    };\n    let class = FRAME_CLASSES[idx];\n    let mut buf = FRAME_POOLS\n        .with(|pools| pools.borrow_mut()[idx].pop())\n        .unwrap_or_else(|| Vec::with_capacity(class));\n    buf.resize(len, 0);\n    buf\n}\n\n#[inline]\npub fn release_frame_vec(mut buf: Vec<u8>) {\n    let Some(idx) = frame_capacity_class(buf.capacity()) else {\n        return;\n    };\n    buf.clear();\n    FRAME_POOLS.with(|pools| {\n        let mut pools = pools.borrow_mut();\n        if pools[idx].len() < FRAME_CLASS_LIMITS[idx] {\n            pools[idx].push(buf);\n        }\n    });\n}\n''',
    '''#[inline]\nfn acquire_frame_vec_recycled(len: usize) -> Vec<u8> {\n    if len == 0 {\n        return Vec::new();\n    }\n    let Some(idx) = frame_class_index(len) else {\n        return Vec::with_capacity(len);\n    };\n    let class = FRAME_CLASSES[idx];\n    FRAME_POOLS\n        .with(|pools| pools.borrow_mut()[idx].pop())\n        .unwrap_or_else(|| Vec::with_capacity(class))\n}\n\n/// Acquire a zero-filled frame buffer. Use this only when the caller needs the\n/// old contents cleared before it starts writing.\n#[inline]\npub fn acquire_frame_vec(len: usize) -> Vec<u8> {\n    let mut buf = acquire_frame_vec_recycled(len);\n    buf.resize(len, 0);\n    buf[..len].fill(0);\n    buf\n}\n\n/// Acquire a frame buffer whose first `len` bytes are intentionally unspecified.\n/// The caller must overwrite every byte it reads before observing the buffer.\n/// This avoids an otherwise redundant memset on TAP reads and TLS frame extraction.\n#[inline]\npub fn acquire_frame_vec_overwrite(len: usize) -> Vec<u8> {\n    let mut buf = acquire_frame_vec_recycled(len);\n    if buf.len() < len {\n        // Only newly exposed bytes need initialization for Vec's safety invariant.\n        // Existing bytes stay untouched because the caller will overwrite them.\n        buf.resize(len, 0);\n    } else {\n        buf.truncate(len);\n    }\n    buf\n}\n\n#[inline]\npub fn release_frame_vec(buf: Vec<u8>) {\n    let Some(idx) = frame_capacity_class(buf.capacity()) else {\n        return;\n    };\n    // Preserve the logical length instead of clear()+resize() on the next hot-path\n    // acquire. Bytes remain initialized and are overwritten before observation.\n    FRAME_POOLS.with(|pools| {\n        let mut pools = pools.borrow_mut();\n        if pools[idx].len() < FRAME_CLASS_LIMITS[idx] {\n            pools[idx].push(buf);\n        }\n    });\n}\n''',
)

replace_all(
    "src/frame.rs",
    "let mut data = acquire_frame_vec(data_len);\n            data.copy_from_slice",
    "let mut data = acquire_frame_vec_overwrite(data_len);\n            data.copy_from_slice",
)
replace_all(
    "src/client.rs",
    "let mut frame = acquire_frame_vec(tap_read_size);\n                match dev.recv(&mut frame)",
    "let mut frame = acquire_frame_vec_overwrite(tap_read_size);\n                match dev.recv(&mut frame)",
)
replace_all(
    "src/server.rs",
    "let mut frame = acquire_frame_vec(tap_read_size);\n            match dev_reader.recv(&mut frame)",
    "let mut frame = acquire_frame_vec_overwrite(tap_read_size);\n            match dev_reader.recv(&mut frame)",
)

# ---------------------------------------------------------------------------
# P0: lock-free fixed-window de-duplication. Reorder remains the correctness gate;
# collisions can only produce a harmless false negative (duplicate passes onward).
# ---------------------------------------------------------------------------
replace_once(
    "src/buffer.rs",
    "use std::sync::Arc;",
    "use std::sync::{atomic::{AtomicU32, Ordering}, Arc};",
)
replace_once(
    "src/buffer.rs",
    '''// 高速固定窗口去重器（用于 FEC 恢复帧与迟到原始帧）。\n//\n// 重排窗口只有 2048，而去重槽位有 4096（2 的幂）。因此窗口内两个合法\n// 不同 seq 不会落到同一槽位；直接保存完整 seq 即可判断重复，不需要\n// HashSet 的 hash/contains/remove/insert 热路径。\nconst DEDUP_WINDOW: usize = 4096;\nconst DEDUP_MASK: usize = DEDUP_WINDOW - 1;\n\npub struct DeDuplicator {\n    slots: [u32; DEDUP_WINDOW],\n}\n\nimpl DeDuplicator {\n    pub fn new() -> Self {\n        Self {\n            slots: [0; DEDUP_WINDOW],\n        }\n    }\n\n    #[inline]\n    pub fn is_duplicate(&mut self, seq: u32) -> bool {\n        if seq == 0 {\n            return false;\n        }\n        let idx = (seq as usize) & DEDUP_MASK;\n        if self.slots[idx] == seq {\n            return true;\n        }\n        self.slots[idx] = seq;\n        false\n    }\n\n    pub fn reset(&mut self) {\n        self.slots.fill(0);\n    }\n}\n''',
    '''// 高速固定窗口去重器（用于 FEC 恢复帧与迟到原始帧）。\n//\n// 多条物理连接会并发调用去重器。每个槽位使用 AtomicU32 后无需在每包热路径\n// 外再套一层 Mutex。窗口碰撞只会让旧 seq 的重复帧漏过这一层，后续 reorder\n// 仍会按真实 seq 丢弃，不会把不同数据误判成重复。\nconst DEDUP_WINDOW: usize = 4096;\nconst DEDUP_MASK: usize = DEDUP_WINDOW - 1;\n\npub struct DeDuplicator {\n    slots: Box<[AtomicU32]>,\n}\n\nimpl DeDuplicator {\n    pub fn new() -> Self {\n        Self {\n            slots: (0..DEDUP_WINDOW)\n                .map(|_| AtomicU32::new(0))\n                .collect::<Vec<_>>()\n                .into_boxed_slice(),\n        }\n    }\n\n    #[inline]\n    pub fn is_duplicate(&self, seq: u32) -> bool {\n        if seq == 0 {\n            return false;\n        }\n        let idx = (seq as usize) & DEDUP_MASK;\n        self.slots[idx].swap(seq, Ordering::Relaxed) == seq\n    }\n\n    pub fn reset(&self) {\n        for slot in self.slots.iter() {\n            slot.store(0, Ordering::Relaxed);\n        }\n    }\n}\n''',
)

for path in ("src/client.rs", "src/server.rs"):
    replace_all(path, "Arc<Mutex<DeDuplicator>>", "Arc<DeDuplicator>")
    replace_all(path, "Arc::new(Mutex::new(DeDuplicator::new()))", "Arc::new(DeDuplicator::new())")
    replace_all(path, ".dedup.lock().reset()", ".dedup.reset()")
replace_all("src/client.rs", "cl.dedup.lock().is_duplicate(seq)", "cl.dedup.is_duplicate(seq)")
replace_all("src/server.rs", "c_sess.dedup.lock().is_duplicate(seq)", "c_sess.dedup.is_duplicate(seq)")

# ---------------------------------------------------------------------------
# P0: skip the FEC encoder mutex entirely when FEC is disabled.
# ---------------------------------------------------------------------------
replace_once(
    "src/net.rs",
    "    encoder: Mutex<Option<FecEncoder>>,\n    dropped: AtomicU64,",
    "    encoder: Mutex<Option<FecEncoder>>,\n    encoder_enabled: AtomicBool,\n    dropped: AtomicU64,",
)
replace_once(
    "src/net.rs",
    "            encoder: Mutex::new(None),\n            dropped: AtomicU64::new(0),",
    "            encoder: Mutex::new(None),\n            encoder_enabled: AtomicBool::new(false),\n            dropped: AtomicU64::new(0),",
)
replace_once(
    "src/net.rs",
    '''    pub fn attach_encoder(&self, k: usize, ic: Option<Arc<InnerCipher>>) {\n        *self.encoder.lock() = Some(FecEncoder::new(k, ic));\n    }\n''',
    '''    pub fn attach_encoder(&self, k: usize, ic: Option<Arc<InnerCipher>>) {\n        *self.encoder.lock() = Some(FecEncoder::new(k, ic));\n        self.encoder_enabled.store(true, Ordering::Release);\n    }\n''',
)
replace_once(
    "src/net.rs",
    '''        *self.encoder.lock() = if k >= crate::fec::FEC_MIN_GROUP {\n            Some(FecEncoder::new(k, ic))\n        } else {\n            None\n        };\n''',
    '''        let enabled = k >= crate::fec::FEC_MIN_GROUP;\n        if !enabled {\n            self.encoder_enabled.store(false, Ordering::Release);\n        }\n        *self.encoder.lock() = if enabled {\n            Some(FecEncoder::new(k, ic))\n        } else {\n            None\n        };\n        if enabled {\n            self.encoder_enabled.store(true, Ordering::Release);\n        }\n''',
)
replace_once(
    "src/net.rs",
    '''        let parity = self\n            .encoder\n            .lock()\n            .as_mut()\n            .and_then(|enc| enc.add(seq, frame.as_slice()));\n''',
    '''        let parity = if self.encoder_enabled.load(Ordering::Relaxed) {\n            self.encoder\n                .lock()\n                .as_mut()\n                .and_then(|enc| enc.add(seq, frame.as_slice()))\n        } else {\n            None\n        };\n''',
)

# ---------------------------------------------------------------------------
# P0/P1: FEC encoder only clears the bytes touched by the current group. A one-off
# jumbo frame must not turn every future 1500-byte group reset into a jumbo memset.
# ---------------------------------------------------------------------------
replace_once(
    "src/fec.rs",
    "    acc: Vec<u8>,\n    ic: Option<Arc<InnerCipher>>,",
    "    acc: Vec<u8>,\n    active_len: usize,\n    ic: Option<Arc<InnerCipher>>,",
)
replace_once(
    "src/fec.rs",
    "            acc: Vec::with_capacity(2048),\n            ic,",
    "            acc: Vec::with_capacity(2048),\n            active_len: 0,\n            ic,",
)
replace_once(
    "src/fec.rs",
    "        xor_into(&mut self.acc, data);",
    "        self.active_len = self.active_len.max(data.len());\n        xor_into(&mut self.acc[..data.len()], data);",
)
replace_once(
    "src/fec.rs",
    '''    fn reset(&mut self) {\n        self.seqs.clear();\n        self.lens.clear();\n        for b in self.acc.iter_mut() {\n            *b = 0;\n        }\n    }\n\n    fn build_parity(&mut self) -> Vec<u8> {\n        let max_len = self.acc.len();\n''',
    '''    fn reset(&mut self) {\n        self.seqs.clear();\n        self.lens.clear();\n        self.acc[..self.active_len].fill(0);\n        self.active_len = 0;\n    }\n\n    fn build_parity(&mut self) -> Vec<u8> {\n        let max_len = self.active_len;\n''',
)
replace_once(
    "src/fec.rs",
    "        buf[off..off + max_len].copy_from_slice(&self.acc);",
    "        buf[off..off + max_len].copy_from_slice(&self.acc[..max_len]);",
)

# Add regression tests around the two P0 changes.
replace_once(
    "src/buffer.rs",
    '''    #[test]\n    fn hot_frame_pool_keeps_common_ethernet_capacity_bounded() {\n''',
    '''    #[test]\n    fn overwrite_pool_reuses_initialized_storage_without_zero_contract() {\n        let mut buf = acquire_frame_vec_overwrite(1500);\n        buf.fill(0x5a);\n        let cap = buf.capacity();\n        release_frame_vec(buf);\n\n        let buf = acquire_frame_vec_overwrite(1500);\n        assert_eq!(buf.len(), 1500);\n        assert_eq!(buf.capacity(), cap);\n        release_frame_vec(buf);\n\n        let zeroed = acquire_frame_vec(1500);\n        assert!(zeroed.iter().all(|b| *b == 0));\n        release_frame_vec(zeroed);\n    }\n\n    #[test]\n    fn atomic_dedup_handles_concurrent_duplicate_checks() {\n        use std::sync::Arc;\n        use std::thread;\n\n        let d = Arc::new(DeDuplicator::new());\n        let mut joins = Vec::new();\n        for _ in 0..8 {\n            let d = d.clone();\n            joins.push(thread::spawn(move || d.is_duplicate(12345)));\n        }\n        let duplicate_count = joins\n            .into_iter()\n            .map(|j| j.join().unwrap())\n            .filter(|dup| *dup)\n            .count();\n        assert_eq!(duplicate_count, 7);\n        d.reset();\n        assert!(!d.is_duplicate(12345));\n    }\n\n    #[test]\n    fn hot_frame_pool_keeps_common_ethernet_capacity_bounded() {\n''',
)

print("dataplane performance patch applied")
