use aes::Aes256;
use crossbeam_queue::ArrayQueue;
use ctr::cipher::KeyIvInit;
use lazy_static::lazy_static;
use sha2::Digest;
use std::collections::HashSet;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::utils::*;

const MAX_FRAME_SIZE: usize = 65536;

lazy_static! {
    pub static ref FRAME_POOL: ArrayQueue<Vec<u8>> = ArrayQueue::new(4096);
    pub static ref PADDING_CACHE: Vec<u8> = {
        let mut cache = vec![0u8; 1024 * 1024];
        let mut rng = FastRand::new();
        rng.fill(&mut cache);
        cache
    };
}

pub fn get_frame() -> Vec<u8> {
    FRAME_POOL
        .pop()
        .unwrap_or_else(|| Vec::with_capacity(MAX_FRAME_SIZE))
}

pub fn put_frame(mut frame: Vec<u8>) {
    if frame.capacity() >= 1500 && frame.capacity() <= MAX_FRAME_SIZE {
        frame.clear();
        let _ = FRAME_POOL.push(frame);
    }
}

// 高速环形去重器 (用于 FEC 过滤)
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

pub struct ReorderBuffer {
    pub next_seq: u32,
    ring: Vec<Option<Vec<u8>>>,
    last_advance: Instant,
}

impl ReorderBuffer {
    pub fn new() -> Self {
        let mut ring = Vec::with_capacity(REORDER_WINDOW as usize);
        for _ in 0..REORDER_WINDOW {
            ring.push(None);
        }
        Self {
            next_seq: 1, // Start with 1, as 0 is control frame
            ring,
            last_advance: Instant::now(),
        }
    }

    pub fn insert(&mut self, seq: u32, data: Vec<u8>) -> Vec<Vec<u8>> {
        if seq == 0 {
            return vec![data];
        }

        let mut ready = Vec::new();
        let diff = seq.wrapping_sub(self.next_seq);

        if diff > 0x80000000 {
            // old packet
            put_frame(data);
            return ready;
        }

        if diff == 0 {
            ready.push(data);
            self.next_seq = self.next_seq.wrapping_add(1);
            if self.next_seq == 0 {
                self.next_seq = 1;
            }

            self.last_advance = Instant::now();

            loop {
                let idx = (self.next_seq % REORDER_WINDOW) as usize;
                if let Some(next_data) = self.ring[idx].take() {
                    ready.push(next_data);
                    self.next_seq = self.next_seq.wrapping_add(1);
                    if self.next_seq == 0 {
                        self.next_seq = 1;
                    }
                    self.last_advance = Instant::now();
                } else {
                    break;
                }
            }
        } else {
            if diff < REORDER_WINDOW {
                let idx = (seq % REORDER_WINDOW) as usize;
                if let Some(old) = self.ring[idx].take() {
                    put_frame(old);
                }
                self.ring[idx] = Some(data);
            } else {
                // Drop it if it's too far in the future
                put_frame(data);
            }

            if self.last_advance.elapsed() > Duration::from_millis(20) {
                let idx = (self.next_seq % REORDER_WINDOW) as usize;
                if self.ring[idx].is_none() {
                    // timeout!
                    let mut found = false;
                    for offset in 1..REORDER_WINDOW {
                        let check_seq = self.next_seq.wrapping_add(offset);
                        if check_seq == 0 {
                            continue;
                        }
                        let c_idx = (check_seq % REORDER_WINDOW) as usize;
                        if self.ring[c_idx].is_some() {
                            self.next_seq = check_seq;
                            found = true;
                            break;
                        }
                    }
                    if found {
                        loop {
                            let c_idx = (self.next_seq % REORDER_WINDOW) as usize;
                            if let Some(next_data) = self.ring[c_idx].take() {
                                ready.push(next_data);
                                self.next_seq = self.next_seq.wrapping_add(1);
                                if self.next_seq == 0 {
                                    self.next_seq = 1;
                                }
                                self.last_advance = Instant::now();
                            } else {
                                break;
                            }
                        }
                    } else {
                        self.last_advance = Instant::now();
                    }
                }
            }
        }
        ready
    }

    pub fn reset(&mut self) {
        self.next_seq = 1;
        for slot in self.ring.iter_mut() {
            if let Some(old) = slot.take() {
                put_frame(old);
            }
        }
        self.last_advance = Instant::now();
    }

    pub fn flush_timeout(&mut self) -> Vec<Vec<u8>> {
        let mut ready = Vec::new();
        if self.last_advance.elapsed() > Duration::from_millis(20) {
            let mut found = false;
            for offset in 0..REORDER_WINDOW {
                let check_seq = self.next_seq.wrapping_add(offset);
                if check_seq == 0 {
                    continue;
                }
                let c_idx = (check_seq % REORDER_WINDOW) as usize;
                if self.ring[c_idx].is_some() {
                    self.next_seq = check_seq;
                    found = true;
                    break;
                }
            }
            if found {
                loop {
                    let c_idx = (self.next_seq % REORDER_WINDOW) as usize;
                    if let Some(next_data) = self.ring[c_idx].take() {
                        ready.push(next_data);
                        self.next_seq = self.next_seq.wrapping_add(1);
                        if self.next_seq == 0 {
                            self.next_seq = 1;
                        }
                        self.last_advance = Instant::now();
                    } else {
                        break;
                    }
                }
            } else {
                self.last_advance = Instant::now();
            }
        }
        ready
    }
}
