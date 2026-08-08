#[cfg(not(target_os = "linux"))]
pub trait AsRawFd {}
#[cfg(not(target_os = "linux"))]
impl<T> AsRawFd for T {}

use aes::Aes256;
use crossbeam_channel::Sender;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::buffer::*;
use crate::frame::*;
use crate::utils::*;

const H2_403_RESPONSE: &[u8] = &[
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x08, 0x03, b'4', b'0', b'3',
];

pub fn serve_fallback_http<W: Write>(mut writer: W, is_h2: bool) {
    if is_h2 {
        let _ = writer.write_all(H2_403_RESPONSE);
    } else {
        let body = "<html><head><title>403 Forbidden</title></head><body><center><h1>403 Forbidden</h1></center><hr><center>nginx</center></body></html>";
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\n\
             Server: nginx\r\n\
             Content-Type: text/html\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            body.len(),
            body
        );
        let _ = writer.write_all(response.as_bytes());
    }
    let _ = writer.flush();
    // 稍微停顿，让内核有时间把 403 报文推送到对端，而不是触发 RST
    std::thread::sleep(Duration::from_millis(50));
}

// 模拟慢速探测阻力 (焦油坑)，防止主动探测扫描
pub fn camouflage_probe<W: Write>(mut writer: W) {
    let mut junk = vec![0u8; 500];
    loop {
        std::thread::sleep(Duration::from_millis(
            RNG.with(|rng| rng.borrow_mut().gen_range(50, 200)) as u64,
        ));
        let len = RNG.with(|rng| rng.borrow_mut().gen_range(100, 400));
        junk[0] = 0x00;
        junk[1] = len as u8;
        if writer.write_all(&junk[..len + 2]).is_err() {
            break;
        }
        let _ = writer.flush();
    }
}

#[cfg(target_os = "linux")]
pub fn apply_tcp_brutal<S: AsRawFd>(stream: &S, rate_mbps: u64) {
    let fd = stream.as_raw_fd();
    unsafe {
        let algo = b"brutal\0";
        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algo.as_ptr() as *const _,
            7,
        ) != 0
        {
            warn!("Failed to set TCP_CONGESTION=brutal.");
            return;
        }
        let rate_bps = rate_mbps * 1000 * 1000 / 8;
        let mut params = [0u8; 12];
        params[0..8].copy_from_slice(&rate_bps.to_le_bytes());
        params[8..12].copy_from_slice(&20u32.to_le_bytes());

        if libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            23301,
            params.as_ptr() as *const _,
            12,
        ) == 0
        {
            debug!("Applied TCP Brutal limit: {} Mbps", rate_mbps);
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_tcp_brutal<S: AsRawFd>(_stream: &S, rate_mbps: u64) {
    warn!(
        "TCP Brutal requested ({} Mbps) but only supported on Linux.",
        rate_mbps
    );
}

#[cfg(target_os = "linux")]
pub fn apply_tcp_keepalive<S: AsRawFd>(stream: &S) {
    let fd = stream.as_raw_fd();
    unsafe {
        // 开启 SO_KEEPALIVE
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            &optval as *const _ as *const _,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        );

        // 设置 TCP_KEEPIDLE 为 15 秒 (与 Go 保持一致)
        let idle: libc::c_int = 15;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPIDLE,
            &idle as *const _ as *const _,
            std::mem::size_of_val(&idle) as libc::socklen_t,
        );

        // 设置探测间隔 TCP_KEEPINTVL 为 5 秒
        let intvl: libc::c_int = 5;
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPINTVL,
            &intvl as *const _ as *const _,
            std::mem::size_of_val(&intvl) as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_tcp_keepalive<S: AsRawFd>(_stream: &S) {
    // 非 Linux 平台暂不处理或使用其他方案
}

#[cfg(target_os = "linux")]
pub fn get_tcp_rtt<S: AsRawFd>(stream: &S) -> u32 {
    let fd = stream.as_raw_fd();
    let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
    unsafe {
        if libc::getsockopt(
            fd,
            libc::SOL_TCP,
            libc::TCP_INFO,
            &mut info as *mut _ as *mut _,
            &mut len,
        ) == 0
        {
            return info.tcpi_rtt;
        }
    }
    50000
}

#[cfg(not(target_os = "linux"))]
pub fn get_tcp_rtt<S: AsRawFd>(_stream: &S) -> u32 {
    50000
}

pub fn setup_policy_routing(tap_name: &str, fwmark: i32, gw_v4: &str, gw_v6: &str) {
    if fwmark <= 0 {
        return;
    }
    info!(
        "🔀 Configuring Policy Routing for fwmark {} via {}",
        fwmark, tap_name
    );
    Command::new("ip")
        .args([
            "rule",
            "del",
            "fwmark",
            &fwmark.to_string(),
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
    Command::new("ip")
        .args([
            "rule",
            "add",
            "fwmark",
            &fwmark.to_string(),
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
    Command::new("ip")
        .args([
            "route",
            "replace",
            "default",
            "via",
            gw_v4,
            "dev",
            tap_name,
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
    Command::new("ip")
        .args([
            "-6",
            "rule",
            "del",
            "fwmark",
            &fwmark.to_string(),
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
    Command::new("ip")
        .args([
            "-6",
            "rule",
            "add",
            "fwmark",
            &fwmark.to_string(),
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
    Command::new("ip")
        .args([
            "-6",
            "route",
            "replace",
            "default",
            "via",
            gw_v6,
            "dev",
            tap_name,
            "table",
            &fwmark.to_string(),
        ])
        .output()
        .ok();
}

pub struct Backend {
    pub ch: Sender<Vec<VPNFrame>>,
    pub rtt_cache: Arc<AtomicU32>,
}

pub struct AsyncPort {
    pub id: String,
    pub tx_seq: AtomicU32,
    pub fec_mode: bool,
    backends: RwLock<Vec<Arc<Backend>>>,
}

impl AsyncPort {
    pub fn new(id: String, fec_mode: bool) -> Self {
        Self {
            id,
            tx_seq: AtomicU32::new(0),
            fec_mode,
            backends: RwLock::new(Vec::new()),
        }
    }
    pub fn register_backend(&self, backend: Arc<Backend>) {
        self.backends.write().push(backend);
    }
    pub fn unregister_backend(&self, ch_to_remove: &Sender<Vec<VPNFrame>>) {
        self.backends
            .write()
            .retain(|b| !b.ch.same_channel(ch_to_remove));
    }

    pub fn write_frame(&self, frame: Vec<u8>) {
        let backends = self.backends.read();
        if backends.is_empty() {
            put_frame(frame);
            return;
        }

        if self.fec_mode {
            let mut valid_backends = Vec::new();
            for backend in backends.iter() {
                if backend.ch.len() < backend.ch.capacity().unwrap_or(4096) - 100 {
                    valid_backends.push(backend);
                }
            }
            if !valid_backends.is_empty() {
                let mut seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                if seq == 0 {
                    seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                }
                let vpn_frame = VPNFrame { seq, data: frame };
                let batch = vec![vpn_frame];
                for backend in valid_backends {
                    let _ = backend.ch.try_send(batch.clone());
                }
            } else {
                put_frame(frame);
            }
        } else {
            let mut best_backend = None;
            let mut min_score = u32::MAX;

            for b in backends.iter() {
                let q_len = b.ch.len();
                if q_len >= b.ch.capacity().unwrap_or(4096) - 100 {
                    continue;
                }

                let rtt = b.rtt_cache.load(Ordering::Relaxed);
                let penalty = if q_len > 10 {
                    (q_len as u32 - 10) * 1000
                } else {
                    0
                };
                let score = rtt + penalty;

                if score < min_score {
                    min_score = score;
                    best_backend = Some(b);
                }
            }

            if let Some(b) = best_backend.or_else(|| backends.first()) {
                if b.ch.len() < b.ch.capacity().unwrap_or(4096) - 100 {
                    let mut seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    if seq == 0 {
                        seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    }
                    let vpn_frame = VPNFrame { seq, data: frame };
                    let _ = b.ch.try_send(vec![vpn_frame]);
                } else {
                    put_frame(frame);
                }
            } else {
                put_frame(frame);
            }
        }
    }
}

struct MacEntry {
    port_id: String,
    updated_at: Instant,
}

pub struct VSwitch {
    ports: DashMap<String, Arc<AsyncPort>>,
    mac_table: DashMap<[u8; 6], MacEntry>,
}

impl VSwitch {
    pub fn new() -> Arc<Self> {
        let vs = Arc::new(Self {
            ports: DashMap::new(),
            mac_table: DashMap::new(),
        });

        // 垃圾回收协程
        let vs_clone = vs.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(300));
            vs_clone
                .mac_table
                .retain(|_, entry| entry.updated_at.elapsed() < Duration::from_secs(1800));
        });

        vs
    }

    pub fn add_port(&self, id: String, port: Arc<AsyncPort>) {
        self.ports.insert(id, port);
    }

    pub fn remove_port(&self, id: &str) {
        self.ports.remove(id);
        self.mac_table.retain(|_, entry| entry.port_id != id);
    }

    pub fn process_frame(&self, src_port_id: &str, frame: Vec<u8>) {
        if frame.len() < 14 {
            return;
        }
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&frame[6..12]);

        // DashMap 的 entry API 可以避免重复哈希并保证原子性
        self.mac_table
            .entry(src_mac)
            .and_modify(|e| {
                e.port_id = src_port_id.to_string();
                e.updated_at = Instant::now();
            })
            .or_insert_with(|| MacEntry {
                port_id: src_port_id.to_string(),
                updated_at: Instant::now(),
            });

        let mut target_port_id = None;
        if (dst_mac[0] & 1) == 0 {
            if let Some(entry) = self.mac_table.get(&dst_mac) {
                target_port_id = Some(entry.port_id.clone());
            }
        }

        if let Some(target) = target_port_id {
            if target != src_port_id {
                if let Some(port) = self.ports.get(&target) {
                    port.write_frame(frame);
                }
            }
        } else {
            for ref_multi in self.ports.iter() {
                if *ref_multi.key() != src_port_id {
                    ref_multi.value().write_frame(frame.clone());
                }
            }
        }
    }
}
