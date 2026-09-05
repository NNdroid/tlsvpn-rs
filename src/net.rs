use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use mio;
use parking_lot::{Mutex, RwLock};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(target_os = "linux")]
use tracing::debug;
use tracing::{info, warn};

use crate::crypto::*;
use crate::fec::FecEncoder;
use crate::frame::VPNFrame;
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

// 模拟慢速探测阻力 (焦油坑)，防止主动探测扫描。
// 对齐 Go camouflageProbe：先读一次（10s 超时），再循环发送随机垃圾。
pub fn camouflage_probe(mut stream: std::net::TcpStream) {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    let mut junk = vec![0u8; 512];
    loop {
        match std::io::Read::read(&mut stream, &mut junk) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        std::thread::sleep(Duration::from_millis(
            RNG.with(|rng| rng.borrow_mut().gen_range(50, 200)) as u64,
        ));
        let len = RNG.with(|rng| rng.borrow_mut().gen_range(100, 400));
        junk[0] = 0x00;
        junk[1] = len as u8;
        RNG.with(|rng| rng.borrow_mut().fill(&mut junk[2..len + 2]));
        if stream.write_all(&junk[..len + 2]).is_err() {
            break;
        }
        let _ = stream.flush();
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
pub fn apply_socket_buffers<S: AsRawFd>(stream: &S) {
    // 对齐 Go SetReadBuffer/SetWriteBuffer(4MB)
    let fd = stream.as_raw_fd();
    unsafe {
        let buf: libc::c_int = 4 * 1024 * 1024;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &buf as *const _ as *const _,
            std::mem::size_of_val(&buf) as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &buf as *const _ as *const _,
            std::mem::size_of_val(&buf) as libc::socklen_t,
        );
    }
}

#[cfg(not(target_os = "linux"))]
pub fn apply_socket_buffers<S: AsRawFd>(_stream: &S) {}

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

/// 直连拨号前打 SO_MARK（对齐 Go socketMarkControl：mark 影响连接时的
/// 路由查找，必须在 connect 之前设置）。仅 Linux 实现。
#[cfg(target_os = "linux")]
pub fn dial_with_mark(host: &str, port: u16, mark: i32) -> std::io::Result<std::net::TcpStream> {
    use std::net::ToSocketAddrs;
    use std::os::unix::io::FromRawFd;

    if mark <= 0 {
        return std::net::TcpStream::connect((host, port));
    }
    let addrs: Vec<_> = (host, port).to_socket_addrs()?.collect();
    let mut last_err = std::io::Error::new(std::io::ErrorKind::Other, "no addresses");
    for addr in addrs {
        unsafe {
            let fd = libc::socket(
                if addr.is_ipv4() {
                    libc::AF_INET
                } else {
                    libc::AF_INET6
                },
                libc::SOCK_STREAM,
                0,
            );
            if fd < 0 {
                last_err = std::io::Error::last_os_error();
                continue;
            }
            let mark_val: libc::c_int = mark;
            if libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const _ as *const _,
                std::mem::size_of_val(&mark_val) as libc::socklen_t,
            ) != 0
            {
                libc::close(fd);
                last_err = std::io::Error::last_os_error();
                continue;
            }
            let (sa, sa_len) = sockaddr_of(addr);
            if libc::connect(fd, &sa as *const _ as *const _, sa_len) != 0 {
                libc::close(fd);
                last_err = std::io::Error::last_os_error();
                continue;
            }
            return Ok(std::net::TcpStream::from_raw_fd(fd));
        }
    }
    Err(last_err)
}

#[cfg(target_os = "linux")]
fn sockaddr_of(addr: std::net::SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    use std::net::SocketAddr;
    let mut sa: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len;
    match addr {
        SocketAddr::V4(v4) => {
            let sin: *mut libc::sockaddr_in = &mut sa as *mut _ as *mut _;
            unsafe {
                (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                (*sin).sin_port = v4.port().to_be();
                (*sin).sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
            }
            len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        }
        SocketAddr::V6(v6) => {
            let sin6: *mut libc::sockaddr_in6 = &mut sa as *mut _ as *mut _;
            unsafe {
                (*sin6).sin6_family = libc::AF_INET6 as libc::sa_family_t;
                (*sin6).sin6_port = v6.port().to_be();
                (*sin6).sin6_addr.s6_addr = v6.ip().octets();
            }
            len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
        }
    }
    (sa, len)
}

#[cfg(not(target_os = "linux"))]
pub fn dial_with_mark(host: &str, port: u16, _mark: i32) -> std::io::Result<std::net::TcpStream> {
    std::net::TcpStream::connect((host, port))
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

/// 退出时清理策略路由（对齐 Go cleanPolicyRouting）
pub fn clean_policy_routing(tap_name: &str, fwmark: i32, gw_v4: &str, gw_v6: &str) {
    if fwmark <= 0 {
        return;
    }
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
            "route",
            "del",
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
            "route",
            "del",
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

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::process::Command;
#[cfg(not(target_os = "linux"))]
pub trait AsRawFd {}
#[cfg(not(target_os = "linux"))]
impl<T> AsRawFd for T {}

/// 后端就绪通知：端口投递帧成功后唤醒对应 poller（mio Waker 事件驱动），
/// 消除轮询。dirty 队列携带具体 Token，让事件循环精准冲刷对应会话。
pub struct BackendNotify {
    waker: Arc<mio::Waker>,
    dirty: Arc<ArrayQueue<mio::Token>>,
    token: mio::Token,
}

impl BackendNotify {
    pub fn new(
        waker: Arc<mio::Waker>,
        dirty: Arc<ArrayQueue<mio::Token>>,
        token: mio::Token,
    ) -> Self {
        Self {
            waker,
            dirty,
            token,
        }
    }

    #[inline]
    pub fn wake(&self) {
        let _ = self.dirty.push(self.token);
        let _ = self.waker.wake();
    }
}

pub struct Backend {
    pub ch: Sender<VPNFrame>,
    pub rtt_cache: Arc<AtomicU32>,
    pub notify: Option<Arc<BackendNotify>>,
}

/// 异步聚合端口，分发行为对齐 Go AsyncPort.dispatchBatch：
/// - 挂载 XOR FEC 编码器时：数据帧 MinRTT 单路发送，校验帧向所有连接广播；
/// - 传统复制模式（fec_mode）：所有帧向所有连接复制；
/// - 普通模式：MinRTT 单路发送。
pub struct AsyncPort {
    pub id: String,
    tx_seq: AtomicU32,
    fec_mode: bool,
    backends: RwLock<Vec<Arc<Backend>>>,
    encoder: Mutex<Option<FecEncoder>>,
    dropped: AtomicU64,
}

impl AsyncPort {
    pub fn new(id: String, fec_mode: bool) -> Self {
        Self {
            id,
            tx_seq: AtomicU32::new(0),
            fec_mode,
            backends: RwLock::new(Vec::new()),
            encoder: Mutex::new(None),
            dropped: AtomicU64::new(0),
        }
    }

    /// 挂载 XOR FEC 编码器（须在数据流开始前调用一次）
    pub fn attach_encoder(&self, k: usize, ic: Option<Arc<InnerCipher>>) {
        *self.encoder.lock() = Some(FecEncoder::new(k, ic));
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn parity_sent(&self) -> u64 {
        self.encoder
            .lock()
            .as_ref()
            .map(|e| e.parity_sent())
            .unwrap_or(0)
    }

    pub fn register_backend(&self, backend: Arc<Backend>) {
        self.backends.write().push(backend);
    }
    pub fn unregister_backend(&self, ch_to_remove: &Sender<VPNFrame>) {
        self.backends
            .write()
            .retain(|b| !b.ch.same_channel(ch_to_remove));
    }

    fn drop_n(&self, n: u64) {
        if n > 0 {
            self.dropped.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// 以 Arc 共享帧投递给单个后端（零拷贝：引用计数 +1）；队列满时丢弃。
    /// 投递成功即唤醒后端 poller（事件驱动，替代轮询）。
    /// 返回 0（成功）或 1（丢弃），用于丢帧统计。
    fn send_frame_to(&self, b: &Backend, seq: u32, data: &Arc<Vec<u8>>) -> u64 {
        if b.ch
            .try_send(VPNFrame {
                seq,
                data: data.clone(),
            })
            .is_err()
        {
            self.drop_n(1);
            return 1;
        }
        if let Some(n) = &b.notify {
            n.wake();
        }
        0
    }

    /// MinRTT 选路：延迟 + 积压惩罚评分，全部拥塞时回落到首个后端
    fn pick_backend<'a>(&self, backends: &'a [Arc<Backend>]) -> Option<Arc<Backend>> {
        let mut best: Option<&Arc<Backend>> = None;
        let mut min_score = u32::MAX;
        for b in backends {
            let q_len = b.ch.len();
            if q_len >= b.ch.capacity().unwrap_or(4096) - 2 {
                continue;
            }
            let rtt = b.rtt_cache.load(Ordering::Relaxed);
            // 积压超过 10 个包才开始惩罚
            let penalty = if q_len > 10 {
                (q_len as u32 - 10) * 1000
            } else {
                0
            };
            let score = rtt + penalty;
            if score < min_score {
                min_score = score;
                best = Some(b);
            }
        }
        best.or_else(|| backends.first()).cloned()
    }

    pub fn write_frame(&self, frame: Arc<Vec<u8>>) {
        let backends = self.backends.read();
        if backends.is_empty() {
            self.drop_n(1);
            return;
        }

        if self.encoder.lock().is_some() {
            // XOR FEC：数据帧计入编码器（端口级串行，先分配 seq）；
            // 组满生成校验帧广播，数据帧本身按 MinRTT 单路发送。
            let seq = self.next_seq();
            let parity = {
                let mut enc = self.encoder.lock();
                match enc.as_mut().unwrap().add(seq, &frame) {
                    Some(p) => Some(p),
                    None => None,
                }
            };
            if let Some(b) = self.pick_backend(&backends) {
                self.send_frame_to(&b, seq, &frame);
            } else {
                self.drop_n(1);
            }
            if let Some(par) = parity {
                let par = Arc::new(par);
                for b in backends.iter() {
                    self.send_frame_to(b, 0, &par);
                }
            }
            return;
        }

        if self.fec_mode {
            // 传统模式：同一帧复制到所有连接（旧版实现互通用）
            let seq = self.next_seq();
            for b in backends.iter() {
                self.send_frame_to(b, seq, &frame);
            }
            return;
        }

        let seq = self.next_seq();
        if let Some(b) = self.pick_backend(&backends) {
            self.send_frame_to(&b, seq, &frame);
        } else {
            self.drop_n(1);
        }
    }

    fn next_seq(&self) -> u32 {
        let mut seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        if seq == 0 {
            // 0 保留给控制/心跳帧
            seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
        }
        seq
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

    /// MAC 表快照（面板展示，对齐 Go MACSnapshot）
    pub fn mac_snapshot(&self) -> Vec<(String, String, u64)> {
        self.mac_table
            .iter()
            .map(|e| {
                let m = e.key();
                (
                    format!(
                        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                        m[0], m[1], m[2], m[3], m[4], m[5]
                    ),
                    e.value().port_id.clone(),
                    e.value().updated_at.elapsed().as_secs(),
                )
            })
            .collect()
    }

    pub fn process_frame(&self, src_port_id: &str, frame: Arc<Vec<u8>>) {
        if frame.len() < 14 {
            return;
        }
        tracing::trace!(
            "VSWITCH in: src={} len={} ports={}",
            src_port_id,
            frame.len(),
            self.ports.len()
        );
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&frame[6..12]);

        // MAC 学习：仅在端口变化或超过 5 秒时写入（对齐 Go needUpdate，
        // 避免每帧分配 String）
        let need_update = match self.mac_table.get(&src_mac) {
            Some(e) => e.port_id != src_port_id || e.updated_at.elapsed() > Duration::from_secs(5),
            None => true,
        };
        if need_update {
            self.mac_table.insert(
                src_mac,
                MacEntry {
                    port_id: src_port_id.to_string(),
                    updated_at: Instant::now(),
                },
            );
        }

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
        } else if target_port_id.is_none() {
            for ref_multi in self.ports.iter() {
                if *ref_multi.key() != src_port_id {
                    ref_multi.value().write_frame(frame.clone());
                }
            }
        }
    }
}

// AtomicBool 保留给会话保活标记使用
pub type SharedFlag = Arc<AtomicBool>;
