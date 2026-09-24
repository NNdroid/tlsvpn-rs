use lazy_static::lazy_static;
use crossbeam_queue::ArrayQueue;

use crate::utils::FastRand;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

const HOT_FRAME_CLASS: usize = 2048;
const HOT_FRAME_POOL_ITEMS: usize = 1024;

lazy_static! {
    // 典型 1500B Ethernet + 16B GCM tag/FEC descriptor 都落在 2KB 档。
    // 有界 1024 项，最多保留约 2MiB payload capacity，避免“为了池化而囤内存”。
    static ref HOT_FRAME_POOL: ArrayQueue<Vec<u8>> = ArrayQueue::new(HOT_FRAME_POOL_ITEMS);
}

#[inline]
pub fn acquire_frame_vec(len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }
    if len <= HOT_FRAME_CLASS {
        let mut buf = HOT_FRAME_POOL
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(HOT_FRAME_CLASS));
        buf.resize(len, 0);
        return buf;
    }
    vec![0u8; len]
}

#[inline]
pub fn release_frame_vec(mut buf: Vec<u8>) {
    if buf.capacity() == HOT_FRAME_CLASS {
        buf.clear();
        let _ = HOT_FRAME_POOL.push(buf);
    }
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

// 高速环形去重器 (用于 FEC 过滤)，与 Go DeDuplicator 一致
pub struct DeDuplicator {
    set: HashSet<u32>,
    ring: [u32; 4096],
    idx: usize,
}

impl DeDuplicator {
    pub fn new() -> Self {
        Self {
            set: HashSet::with_capacity(4096),
            ring: [0; 4096],
            idx: 0,
        }
    }
    pub fn is_duplicate(&mut self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        if self.set.contains(&seq) {
            return true;
        }

        let oldest = self.ring[self.idx];
        if oldest != 0 {
            self.set.remove(&oldest);
        }

        self.ring[self.idx] = seq;
        self.set.insert(seq);
        self.idx = (self.idx + 1) % 4096;
        false
    }
    pub fn reset(&mut self) {
        self.set.clear();
        self.ring.fill(0);
        self.idx = 0;
    }
}

const REORDER_WINDOW: u32 = 2048;
const BITMAP_WORDS: usize = (REORDER_WINDOW / 64) as usize;
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
    ring: Vec<Option<Arc<Vec<u8>>>>,
    bitmap: [u64; BITMAP_WORDS],
    gap_since: Option<Instant>,
    stats: ReorderStats,
}

impl ReorderBuffer {
    pub fn new() -> Self {
        let mut ring = Vec::with_capacity(REORDER_WINDOW as usize);
        for _ in 0..REORDER_WINDOW {
            ring.push(None);
        }
        Self {
            expected_seq: 0,
            ring,
            bitmap: [0; BITMAP_WORDS],
            gap_since: None,
            stats: ReorderStats::default(),
        }
    }

    /// 热路径版本：把按序就绪帧追加到调用方复用的 scratch Vec。
    ///
    /// 典型无丢包链路每个输入帧都会立即就绪。旧接口每包构造一个
    /// `Vec<Arc<Vec<u8>>>`，造成纯 allocator churn；由调用方长期复用
    /// scratch 后，顺序流不再为重排输出额外分配。
    pub fn insert_into(
        &mut self,
        seq: u32,
        data: Arc<Vec<u8>>,
        ready: &mut Vec<Arc<Vec<u8>>>,
    ) {
        if seq == 0 {
            return;
        }

        if self.expected_seq == 0 {
            self.expected_seq = seq;
        }

        // 丢弃太老的包（int32 语义比较，对齐 Go）
        let diff = seq.wrapping_sub(self.expected_seq) as i32;
        if diff < 0 || diff as u32 >= REORDER_WINDOW {
            return;
        }

        let idx = (seq % REORDER_WINDOW) as usize;
        // 去重：如果坑里已经有包了，保留先到者，丢弃后到者
        if self.ring[idx].is_some() {
            return;
        }

        self.ring[idx] = Some(data);
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);

        if seq == self.expected_seq {
            self.flush_locked_into(ready);
        } else {
            self.refresh_gap(Instant::now());
        }
    }

    /// 兼容包装：测试和非热路径可继续按返回 Vec 的方式使用。
    pub fn insert(&mut self, seq: u32, data: Arc<Vec<u8>>) -> Vec<Arc<Vec<u8>>> {
        let mut ready = Vec::new();
        self.insert_into(seq, data, &mut ready);
        ready
    }

    fn flush_locked_into(&mut self, ready: &mut Vec<Arc<Vec<u8>>>) {
        self.gap_since = None;
        while let Some(frame) = self.ring[(self.expected_seq % REORDER_WINDOW) as usize].take() {
            let idx = (self.expected_seq % REORDER_WINDOW) as usize;
            self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
            if !frame.is_empty() {
                ready.push(frame);
            }
            self.expected_seq = self.expected_seq.wrapping_add(1);
        }
        self.refresh_gap(Instant::now());
    }

    fn has_gap(&self) -> bool {
        self.expected_seq != 0
            && self.ring[(self.expected_seq % REORDER_WINDOW) as usize].is_none()
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
            *slot = None;
        }
        self.bitmap = [0; BITMAP_WORDS];
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
    pub fn flush_timeout_into(&mut self, ready: &mut Vec<Arc<Vec<u8>>>) {
        let Some(since) = self.gap_since else { return };
        if since.elapsed() < REORDER_SKIP_DELAY || !self.has_gap() {
            return;
        }
        // 超时才会扫描，O(窗口) 不进入正常数据热路径，并且正确覆盖环形首字
        // 低位（旧位图扫描在 expected 位于字中部时会漏掉该区域）。
        for delta in 1..REORDER_WINDOW {
            let seq = self.expected_seq.wrapping_add(delta);
            if self.ring[(seq % REORDER_WINDOW) as usize].is_some() {
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

    /// 兼容包装；热路径优先使用 `flush_timeout_into`。
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
