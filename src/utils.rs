use aes::Aes256;
use ctr::cipher::KeyIvInit;
use sha2::Digest;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

pub fn ip4_to_u32(ip: &str) -> u32 {
    u32::from_be_bytes(
        Ipv4Addr::from_str(ip)
            .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
            .octets(),
    )
}
pub fn u32_to_ip4(val: u32) -> String {
    Ipv4Addr::from(val).to_string()
}
pub fn ip6_to_u128(ip: &str) -> u128 {
    u128::from_be_bytes(
        Ipv6Addr::from_str(ip)
            .unwrap_or(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
            .octets(),
    )
}
pub fn u128_to_ip6(val: u128) -> String {
    Ipv6Addr::from(val).to_string()
}

pub struct FastRand(u64);
impl FastRand {
    pub fn new() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut state = d.as_nanos() as u64;
        if state == 0 {
            state = 1;
        }
        Self(state)
    }
    pub fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if max <= min {
            return min;
        }
        min + (self.next_u32() as usize % (max - min))
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let r = self.next_u32().to_ne_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&r[..len]);
        }
    }
}
thread_local! {
    pub static RNG: std::cell::RefCell<FastRand> = std::cell::RefCell::new(FastRand::new());
}

pub fn init_logger(level_str: &str) {
    let level = match level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .finish(),
    )
    .ok();
}
