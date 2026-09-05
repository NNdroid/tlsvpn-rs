use lazy_static::lazy_static;

use crate::utils::FastRand;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// 乱序重排缓冲区，行为对齐 Go ReorderBuffer：
/// - expectedSeq 初始为 0，由首个到达的包学习（服务端重启后立即重新同步）；
/// - seq==0 的帧（心跳/校验帧等控制类）直接丢弃；
/// - 槽位已被占用时保留先到者（后到者视为冗余丢弃）；
/// - 超过 20ms 未推进时跳过缺口强制输出（位图 O(64) 定位缺口）。
///
/// 帧以 Arc 共享：重排输出 → 交换机 → 端口 → 多后端广播全程零拷贝。
pub struct ReorderBuffer {
    expected_seq: u32,
    ring: Vec<Option<Arc<Vec<u8>>>>,
    bitmap: [u64; BITMAP_WORDS],
    last_advance: Instant,
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
            last_advance: Instant::now(),
        }
    }

    /// 将收到的包推入缓冲区，返回按序就绪的帧（所有权转移给调用方）。
    pub fn insert(&mut self, seq: u32, data: Arc<Vec<u8>>) -> Vec<Arc<Vec<u8>>> {
        if seq == 0 {
            // 心跳/校验帧等控制类不进入重排（对齐 Go Insert 的 seq==0 分支）
            return Vec::new();
        }

        if self.expected_seq == 0 {
            self.expected_seq = seq;
        }

        // 丢弃太老的包（int32 语义比较，对齐 Go）
        let diff = seq.wrapping_sub(self.expected_seq) as i32;
        if diff < 0 {
            return Vec::new();
        }

        // 乱序窗口超出限制，防极端情况内存溢出
        if diff as u32 >= REORDER_WINDOW {
            return Vec::new();
        }

        let idx = (seq % REORDER_WINDOW) as usize;
        // 去重：如果坑里已经有包了，保留先到者，丢弃后到者
        if self.ring[idx].is_some() {
            return Vec::new();
        }

        self.ring[idx] = Some(data);
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);

        // 刚好匹配，批量按序输出
        if seq == self.expected_seq {
            return self.flush_locked();
        }
        Vec::new()
    }

    fn flush_locked(&mut self) -> Vec<Arc<Vec<u8>>> {
        let mut ready = Vec::new();
        while let Some(frame) = self.ring[(self.expected_seq % REORDER_WINDOW) as usize].take() {
            let idx = (self.expected_seq % REORDER_WINDOW) as usize;
            self.bitmap[idx / 64] &= !(1u64 << (idx % 64));
            if !frame.is_empty() {
                ready.push(frame);
            }
            self.expected_seq = self.expected_seq.wrapping_add(1);
            self.last_advance = Instant::now();
        }
        ready
    }

    pub fn reset(&mut self) {
        self.expected_seq = 0;
        for slot in self.ring.iter_mut() {
            *slot = None;
        }
        self.bitmap = [0; BITMAP_WORDS];
        self.last_advance = Instant::now();
    }

    /// 后台防死锁巡检（5ms 定时调用）：距上次推进超过 20ms 视为预期包
    /// 彻底丢失，向后找第一个有包的槽位跳过缺口后批量输出。
    pub fn flush_timeout(&mut self) -> Vec<Arc<Vec<u8>>> {
        if self.expected_seq != 0 && self.last_advance.elapsed() > Duration::from_millis(20) {
            let e = (self.expected_seq % REORDER_WINDOW) as usize;
            if self.ring[e].is_none() {
                // 位图从 e 起（环形）找第一个非空槽位：O(窗口/64)
                for word_off in 0..BITMAP_WORDS {
                    let w_idx = (e / 64 + word_off) % BITMAP_WORDS;
                    let mut word = self.bitmap[w_idx];
                    if word_off == 0 {
                        // 首字只看 e 之后的位
                        let shift = (e % 64) + 1;
                        word &= if shift >= 64 {
                            0
                        } else {
                            !((1u64 << shift) - 1)
                        };
                    }
                    if word != 0 {
                        let slot = w_idx * 64 + word.trailing_zeros() as usize;
                        let delta = (slot + REORDER_WINDOW as usize - e) % REORDER_WINDOW as usize;
                        self.expected_seq = self.expected_seq.wrapping_add(delta as u32);
                        return self.flush_locked();
                    }
                }
            }
        }
        Vec::new()
    }
}
