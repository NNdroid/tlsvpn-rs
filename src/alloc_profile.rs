//! Opt-in allocation event counters. No locks, allocation or logging inside hooks.
use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering};

pub struct CountingAllocator;
static ALLOCS: AtomicU64 = AtomicU64::new(0);
static REALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

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
    std::thread::spawn(|| loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
        eprintln!("VPN_ALLOC pid={} allocs={} reallocs={} requested_bytes={}",
            std::process::id(), ALLOCS.load(Ordering::Relaxed),
            REALLOCS.load(Ordering::Relaxed), BYTES.load(Ordering::Relaxed));
    });
}
