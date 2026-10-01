//! Opt-in allocation event counters. No locks, allocation or logging inside hooks.
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct CountingAllocator;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);
pub fn allocation_calls() -> u64 { ALLOCS.load(Ordering::Relaxed) }
pub static COMPACT_BYTES: AtomicU64 = AtomicU64::new(0);
pub static WAKE_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
pub static WAKE_SYSCALLS: AtomicU64 = AtomicU64::new(0);
pub static QUEUE_PEAK: AtomicU64 = AtomicU64::new(0);
static BATCHES: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static QUEUE_US: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];

pub fn popped(frames: usize, elapsed: std::time::Duration) {
    let i = match frames { 0..=1 => 0, 2..=4 => 1, 5..=8 => 2, _ => 3 };
    BATCHES[i].fetch_add(1, Ordering::Relaxed);
    let i = match elapsed.as_micros() { 0..=10 => 0, 11..=100 => 1, 101..=1000 => 2, 1001..=10000 => 3, _ => 4 };
    QUEUE_US[i].fetch_add(1, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = mimalloc::MiMalloc.alloc(layout);
        if !ptr.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = mimalloc::MiMalloc.alloc_zeroed(layout);
        if !ptr.is_null() {
            ALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(layout.size() as u64, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let out = mimalloc::MiMalloc.realloc(ptr, layout, size);
        if !out.is_null() {
            REALLOCS.fetch_add(1, Ordering::Relaxed);
            BYTES.fetch_add(size as u64, Ordering::Relaxed);
        }
        out
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        mimalloc::MiMalloc.dealloc(ptr, layout);
    }
}

pub fn start() {
    if std::env::var_os("TLSVPN_ALLOC_PROFILE").is_none() { return; }
    std::thread::spawn(|| {
      let start = std::time::Instant::now();
      loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        eprintln!("VPN_ALLOC pid={} allocs={} reallocs={} requested_bytes={} elapsed_ns={}",
            std::process::id(), ALLOCS.load(Ordering::Relaxed),
            REALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed), start.elapsed().as_nanos());
        eprintln!("VPN_BATCH pid={} sizes={:?} queue_us={:?} peak_frames={} wakes={}/{} compact_bytes={}",
            std::process::id(), BATCHES.each_ref().map(|n| n.load(Ordering::Relaxed)),
            QUEUE_US.each_ref().map(|n| n.load(Ordering::Relaxed)), QUEUE_PEAK.load(Ordering::Relaxed),
            WAKE_SYSCALLS.load(Ordering::Relaxed), WAKE_ATTEMPTS.load(Ordering::Relaxed),
            COMPACT_BYTES.load(Ordering::Relaxed));
      }
    });
}
