use lazy_static::lazy_static;
use std::cell::RefCell;

use crate::utils::FastRand;
use crate::frame::FramePayload;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HOT_FRAME_CLASS: usize = 2048;
const FRAME_CLASSES: [usize; 7] = [
    2 * 1024,
    4 * 1024,
    8 * 1024,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
];
// Standard-MTU frames stay hottest; jumbo classes are intentionally shallow.
// Worst-case retained capacity is bounded per worker/thread instead of letting
// occasional large tunnel frames fall back to the allocator every time.
const FRAME_CLASS_LIMITS: [usize; 7] = [32, 8, 4, 2, 1, 1, 1];

#[inline]
fn frame_class_index(len: usize) -> Option<usize> {
    match len {
        1..=2048 => Some(0),
        2049..=4096 => Some(1),
        4097..=8192 => Some(2),
        8193..=16384 => Some(3),
        16385..=32768 => Some(4),
        32769..=65536 => Some(5),
        65537..=131072 => Some(6),
        _ => None,
    }
}

#[inline]
fn frame_capacity_class(capacity: usize) -> Option<usize> {
    FRAME_CLASSES.iter().position(|&class| class == capacity)
}

thread_local! {
    static FRAME_POOLS: RefCell<[Vec<Vec<u8>>; FRAME_CLASSES.len()]> =
        RefCell::new(std::array::from_fn(|_| Vec::new()));
}

#[inline]
pub fn acquire_frame_vec(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    let Some(idx) = frame_class_index(len) else {
        return vec![0u8; len];
    };
    let class = FRAME_CLASSES[idx];
    let mut buf = FRAME_POOLS
        .with(|pools| pools.borrow_mut()[idx].pop())
        .unwrap_or_else(|| Vec::with_capacity(class));
    buf.resize(len, 0);
    buf
}

#[inline]
pub fn release_frame_vec(mut buf: Vec<u8>) {
    let Some(idx) = frame_capacity_class(buf.capacity()) else {
        return;
    };
    buf.clear();
    FRAME_POOLS.with(|pools| {
        let mut pools = pools.borrow_mut();
        if pools[idx].len() < FRAME_CLASS_LIMITS[idx] {
            pools[idx].push(buf);
        }
    });
}

#[inline]
pub fn release_shared_frame(frame: Arc<Vec<u8>>) {
    if let Ok(buf) = Arc::try_unwrap(frame) {
        release_frame_vec(buf);
    }
}

lazy_static! {
    pub static ref PADDING_CACHE: Vec<u8> = {
        let mut cache = vec![0u8; 1024 * 1024];
        let mut rng = FastRand::new();
        rng.fill(&mut cache);
        cache
    };
}

// 高速固定窗口去重器（用于 FEC 恢复帧与迟到原始帧）。
//
// 重排窗口只有 2048，而去重槽位有 4096（2 的幂）。因此窗口内两个合法
// 不同 seq 不会落到同一槽位；直接保存完整 seq 即可判断重复，不需要
// HashSet 的 hash/contains/remove/insert 热路径。
const DEDUP_WINDOW: usize = 4096;
const DEDUP_MASK: usize = DEDUP_WINDOW - 1;

pub struct DeDuplicator {
    slots: [u32; DEDUP_WINDOW],
}

impl DeDuplicator {
    pub fn new() -> Self {
        Self {
            slots: [0; DEDUP_WINDOW],
        }
    }

    #[inline]
    pub fn is_duplicate(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        let idx = (seq as usize) & DEDUP_MASK;
        if self.slots[idx] == seq {
            return true;
        }
        self.slots[idx] = seq;
        false
    }

    pub fn reset(&mut self) {
        self.slots.fill(0);
    }
}

const REORDER_INITIAL_WINDOW: u32 = 2048;
const REORDER_MAX_WINDOW: u32 = 65536;
const REORDER_SKIP_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReorderStats {
    pub gap_events: u64,
    pub timeout_flushes: u64,
    pub skipped_frames: u64,
}

/// 乱序重排缓冲区，行为对齐 Go ReorderBuffer：
/// - expectedSeq 初始为 0，由首个到达的包学习（服务端重启后立即重新同步）；
/// - seq==0 的帧（心跳/校验帧等控制类）直接丢弃；
/// - 槽位已被占用时保留先到者（后到者视为冗余丢弃）；
/// - 第一个未来序号到达后超过 50ms 仍未补齐时跳过缺口强制输出。
///
/// 帧以 Arc 共享：重排输出 → 交换机 → 端口 → 多后端广播全程零拷贝。
pub struct ReorderBuffer {
    expected_seq: u32,
    ring: Vec<Option<FramePayload>>,
    seq_slots: Vec<u32>,
    bitmap: Vec<u64>,
    window_mask: u32,
    gap_since: Option<Instant>,
    stats: ReorderStats,
}

impl ReorderBuffer {
    pub fn new() -> Self {
        let size = REORDER_INITIAL_WINDOW as usize;
        let mut ring = Vec::with_capacity(size);
        ring.resize_with(size, || None);
        Self {
            expected_seq: 0,
            ring,
            seq_slots: vec![0; size],
            bitmap: vec![0; size / 64],
            window_mask: REORDER_INITIAL_WINDOW - 1,
            gap_since: None,
            stats: ReorderStats::default(),
        }
    }

    /// 热路径版本：把按序就绪帧追加到调用方复用的 scratch Vec。
    ///
    /// 典型无丢包链路每个输入帧都会立即就绪。旧接口每包构造一个
    /// `Vec<Arc<Vec<u8>>>`，造成纯 allocator churn；由调用方长期复用
    /// scratch 后，顺序流不再为重排输出额外分配。
    pub fn insert_payload_into(
        &mut self,
        seq: u32,
        data: FramePayload,
        ready: &mut Vec<FramePayload>,
    ) {
        if seq == 0 {
            data.release();
            return;
        }

        if self.expected_seq == 0 {
            self.expected_seq = seq;
        }

        // 丢弃太老的包（int32 语义比较，对齐 Go）
        let diff = seq.wrapping_sub(self.expected_seq) as i32;
        if diff < 0 {
            data.release();
            return;
        }

        let distance = diff as u32;
        if distance >= self.ring.len() as u32 {
            if distance >= REORDER_MAX_WINDOW || !self.grow_window(distance + 1) {
                data.release();
                return;
            }
        }

        let idx = (seq & self.window_mask) as usize;
        // 动态扩容后用真实 seq 校验槽位，避免窗口变大时错误碰撞。
        if self.ring[idx].is_some() {
            data.release();
            return;
        }

        self.ring[idx] = Some(data);
        self.seq_slots[idx] = seq;
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);

        if seq == self.expected_seq {
            self.flush_locked_into(ready);
        } else {
            self.refresh_gap(Instant::now());
        }
    }

    /// Arc compatibility wrapper. Hot client/server paths use
    /// insert_payload_into() and keep Owned payloads through reorder.
    pub fn insert_into(
        &mut self,
        seq: u32,
        data: Arc<Vec<u8>>,
        ready: &mut Vec<Arc<Vec<u8>>>,
    ) {
        let mut payload_ready = Vec::new();
        self.insert_payload_into(seq, FramePayload::Shared(data), &mut payload_ready);
        ready.extend(payload_ready.into_iter().map(FramePayload::into_shared));
    }

    /// 兼容包装：测试和非热路径可继续按返回 Vec 的方式使用。
    pub fn insert(&mut self, seq: u32, data: Arc<Vec<u8>>) -> Vec<Arc<Vec<u8>>> {
        let mut ready = Vec::new();
        self.insert_into(seq, data, &mut ready);
        ready
    }

    fn grow_window(&mut self, required_distance: u32) -> bool {
        let old_size = self.ring.len();
        if old_size >= REORDER_MAX_WINDOW as usize {
            return false;
        }

        let mut new_size = old_size;
        while (new_size as u32) < required_distance && new_size < REORDER_MAX_WINDOW as usize {
            new_size <<= 1;
        }
        new_size = new_size.min(REORDER_MAX_WINDOW as usize);
        if (new_size as u32) < required_distance {
            return false;
        }

        let new_mask = (new_size - 1) as u32;
        let mut new_ring = Vec::with_capacity(new_size);
        new_ring.resize_with(new_size, || None);
        let mut new_seq_slots = vec![0u32; new_size];
        let mut new_bitmap = vec![0u64; new_size / 64];

        for idx in 0..old_size {
            let Some(frame) = self.ring[idx].take() else { continue };
            let seq = self.seq_slots[idx];
            let new_idx = (seq & new_mask) as usize;
            new_ring[new_idx] = Some(frame);
            new_seq_slots[new_idx] = seq;
            new_bitmap[new_idx / 64] |= 1u64 << (new_idx % 64);
        }

        self.ring = new_ring;
        self.seq_slots = new_seq_slots;
        self.bitmap = new_bitmap;
        self.window_mask = new_mask;
        true
    }

    fn flush_locked_into(&mut self, ready: &mut Vec<FramePayload>) {
        self.gap_since = None;
        loop {
            let idx = (self.expected_seq & self.window_mask) as usize;
            let Some(frame) = self.ring[idx].take() else { break };
            self.seq_slots[idx] = 0;
            self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
            if !frame.is_empty() {
                ready.push(frame);
            } else {
                frame.release();
            }
            self.expected_seq = self.expected_seq.wrapping_add(1);
        }
        self.refresh_gap(Instant::now());
    }

    fn has_gap(&self) -> bool {
        self.expected_seq != 0
            && self.ring[(self.expected_seq & self.window_mask) as usize].is_none()
            && self.bitmap.iter().any(|word| *word != 0)
    }

    fn refresh_gap(&mut self, now: Instant) {
        if self.has_gap() {
            if self.gap_since.is_none() {
                self.gap_since = Some(now);
                self.stats.gap_events = self.stats.gap_events.saturating_add(1);
            }
        } else {
            self.gap_since = None;
        }
    }

    pub fn reset(&mut self) {
        self.expected_seq = 0;
        for slot in self.ring.iter_mut() {
            if let Some(frame) = slot.take() {
                frame.release();
            }
        }
        self.seq_slots.fill(0);
        self.bitmap.fill(0);
        self.gap_since = None;
    }

    pub fn stats(&self) -> ReorderStats {
        self.stats
    }

    /// 距离当前缺口 deadline 的剩余时间。无缺口时返回 None，调用方可以让
    /// poller 使用自己的常规定时周期而不为空闲会话轮询。
    pub fn next_timeout(&self) -> Option<Duration> {
        self.gap_since.map(|since| REORDER_SKIP_DELAY.saturating_sub(since.elapsed()))
    }

    /// 缺口 deadline 到达后向前寻找第一个已收到的帧，跳过永久缺失序号。
    pub fn flush_payload_timeout_into(&mut self, ready: &mut Vec<FramePayload>) {
        let Some(since) = self.gap_since else { return };
        if since.elapsed() < REORDER_SKIP_DELAY || !self.has_gap() {
            return;
        }
        // 超时才会扫描，O(窗口) 不进入正常数据热路径，并且正确覆盖环形首字
        // 低位（旧位图扫描在 expected 位于字中部时会漏掉该区域）。
        for delta in 1..self.ring.len() as u32 {
            let seq = self.expected_seq.wrapping_add(delta);
            if self.ring[(seq & self.window_mask) as usize].is_some() {
                self.expected_seq = seq;
                self.gap_since = None;
                self.stats.timeout_flushes = self.stats.timeout_flushes.saturating_add(1);
                self.stats.skipped_frames = self.stats.skipped_frames.saturating_add(delta as u64);
                self.flush_locked_into(ready);
                return;
            }
        }
        self.gap_since = None;
    }

    /// Arc compatibility wrapper for tests/non-hot callers.
    pub fn flush_timeout_into(&mut self, ready: &mut Vec<Arc<Vec<u8>>>) {
        let mut payload_ready = Vec::new();
        self.flush_payload_timeout_into(&mut payload_ready);
        ready.extend(payload_ready.into_iter().map(FramePayload::into_shared));
    }

    /// 兼容包装；热路径优先使用 `flush_payload_timeout_into`。
    pub fn flush_timeout(&mut self) -> Vec<Arc<Vec<u8>>> {
        let mut ready = Vec::new();
        self.flush_timeout_into(&mut ready);
        ready
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hot_frame_pool_keeps_common_ethernet_capacity_bounded() {
        let mut buf = acquire_frame_vec(1514);
        assert_eq!(buf.len(), 1514);
        assert_eq!(buf.capacity(), HOT_FRAME_CLASS);
        buf[0] = 0x5a;
        release_frame_vec(buf);

        let buf = acquire_frame_vec(1500);
        assert_eq!(buf.len(), 1500);
        assert_eq!(buf.capacity(), HOT_FRAME_CLASS);
        release_frame_vec(buf);
    }

    #[test]
    fn frame_pool_uses_bounded_size_classes() {
        for &(len, want_cap) in &[
            (1514usize, 2048usize),
            (3000, 4096),
            (9000, 16384),
            (40_000, 65536),
            (100_000, 131072),
        ] {
            let mut buf = acquire_frame_vec(len);
            assert_eq!(buf.len(), len);
            assert_eq!(buf.capacity(), want_cap, "len={len}");
            buf[0] = 0xa5;
            release_frame_vec(buf);

            let buf2 = acquire_frame_vec(len);
            assert_eq!(buf2.capacity(), want_cap, "reacquire len={len}");
            release_frame_vec(buf2);
        }

        let big = acquire_frame_vec(140_000);
        assert_eq!(big.len(), 140_000);
        assert!(big.capacity() >= 140_000);
        release_frame_vec(big);
    }

    #[test]
    fn shared_frame_only_recycles_after_last_owner() {
        let frame = Arc::new(acquire_frame_vec(1400));
        let other = frame.clone();
        release_shared_frame(frame);
        assert_eq!(other.len(), 1400);
        // 最后一个 owner 才能 try_unwrap 并归池。
        release_shared_frame(other);

        let buf = acquire_frame_vec(1400);
        assert_eq!(buf.capacity(), HOT_FRAME_CLASS);
        release_frame_vec(buf);
    }

    #[test]
    fn deduplicator_uses_fixed_sequence_slots() {
        let mut d = DeDuplicator::new();
        assert!(!d.is_duplicate(1));
        assert!(d.is_duplicate(1));

        // 4097 与 1 共槽；进入新窗口后覆盖旧 seq，随后 4097 才被识别为重复。
        assert!(!d.is_duplicate(4097));
        assert!(d.is_duplicate(4097));
        assert!(!d.is_duplicate(1), "过期窗口的旧 seq 不应永久保留");

        d.reset();
        assert!(!d.is_duplicate(4097));
    }

    #[test]
    fn authenticated_replay_sequence_is_delivered_only_once() {
        let mut rb = ReorderBuffer::new();
        let first = rb.insert(42, Arc::new(vec![0x41]));
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].as_slice(), &[0x41]);
        let replay = rb.insert(42, Arc::new(vec![0x42]));
        assert!(replay.is_empty());
    }

    #[test]
    fn idle_time_does_not_pre_age_a_future_gap() {
        let mut rb = ReorderBuffer::new();
        assert_eq!(rb.insert(1, Arc::new(vec![1])).len(), 1);
        std::thread::sleep(Duration::from_millis(70));
        assert!(rb.insert(3, Arc::new(vec![3])).is_empty());
        assert!(rb.flush_timeout().is_empty());
        std::thread::sleep(REORDER_SKIP_DELAY + Duration::from_millis(5));
        let ready = rb.flush_timeout();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].as_slice(), &[3]);
        assert_eq!(rb.stats(), ReorderStats { gap_events: 1, timeout_flushes: 1, skipped_frames: 1 });
    }

    #[test]
    fn reorder_window_grows_for_large_multipath_skew() {
        let mut rb = ReorderBuffer::new();
        assert_eq!(rb.insert(1, Arc::new(vec![1])).len(), 1);

        // 4096 is outside the initial 2048-frame window but well within the
        // adaptive maximum. It must be retained instead of silently dropped.
        assert!(rb.insert(4096, Arc::new(vec![0x5a])).is_empty());
        assert!(rb.ring.len() >= 4096);

        std::thread::sleep(REORDER_SKIP_DELAY + Duration::from_millis(5));
        let ready = rb.flush_timeout();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].as_slice(), &[0x5a]);
        assert_eq!(rb.stats().skipped_frames, 4094);
    }


    #[test]
    fn reorder_growth_uses_smallest_power_of_two_window() {
        let mut rb = ReorderBuffer::new();
        assert_eq!(rb.insert(1, Arc::new(vec![1])).len(), 1);

        // expected=2, seq=4097 -> distance=4095, so 4096 slots are exactly enough.
        assert!(rb.insert(4097, Arc::new(vec![0x5a])).is_empty());
        assert_eq!(
            rb.ring.len(),
            4096,
            "exact power-of-two boundary must not overgrow to 8192"
        );
    }

    #[test]
    fn timeout_scan_wraps_into_lower_bits_of_the_same_bitmap_word() {
        let mut rb = ReorderBuffer::new();
        assert_eq!(rb.insert(100, Arc::new(vec![100])).len(), 1);

        // expected=101（位图 word 1, bit 37），2138 落在同一 word 的 bit 26。
        // 旧扫描只检查首 word 中 expected 之后的高位，环绕一整圈后不会再
        // 检查该 word 的低位，因此这个合法窗口内帧会永久卡住。
        assert!(rb.insert(2138, Arc::new(vec![42])).is_empty());
        std::thread::sleep(REORDER_SKIP_DELAY + Duration::from_millis(5));
        let ready = rb.flush_timeout();
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].as_slice(), &[42]);
        assert_eq!(rb.stats().skipped_frames, 2037);
    }
}
