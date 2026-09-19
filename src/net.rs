use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use mio;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
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

/// 本机 TAP 在交换机上的端口名（对齐 Go tapPortID）。网关侧端口，可信：
/// 源 MAC 校验按"未注册端口"放行，洪泛预算豁免
pub const TAP_PORT_ID: &str = "TAP_LOCAL";

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
        if frame.is_empty() {
            // 零长帧不携带数据：不消耗 seq、不参与 FEC 分组
            // （对齐 Go a2701e4：否则接收端按算术分组会把该槽位视为
            // 永久缺失，毒化整组恢复）
            return;
        }
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
    // 源 MAC 归属校验（None = 不过滤）：会话端口只允许声明本会话注册的 MAC。
    // 共享 PSK 的多客户端场景下，恶意客户端可以声明他人的 srcMAC 把受害者的
    // 表项学习到自己的端口，劫持其下行单播流量（学习表翻转攻击）。
    validate_mac: RwLock<Option<Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync>>>,
    spoof_drops: AtomicU64,

    // 广播/未知单播洪泛的每端口令牌桶：恶意客户端可以线速广播，洪泛会被
    // 复制到所有端口放大 N 倍。合法 ARP/mDNS 远低于该预算；超预算的帧直接
    // 丢弃（单播不受影响）。
    flood_mu: Mutex<HashMap<String, FloodBudget>>,
    flood_burst: f64, // 桶容量（突发预算）
    flood_rate_per_sec: f64, // 每秒补充令牌数
    flood_drops: AtomicU64,
    // 豁免洪泛预算的端口（本机 TAP）：网关自己发起的广播不受限
    trusted_port: String,
}

/// 每源端口的洪泛预算（对齐 Go floodBudget）：令牌按时间线性回充
struct FloodBudget {
    tokens: f64,
    last: Instant,
}

impl VSwitch {
    fn with_flood_budgets(burst: f64, rate_per_sec: f64) -> Arc<Self> {
        let vs = Arc::new(Self {
            ports: DashMap::new(),
            mac_table: DashMap::new(),
            validate_mac: RwLock::new(None),
            spoof_drops: AtomicU64::new(0),
            flood_mu: Mutex::new(HashMap::new()),
            // 默认预算覆盖 ~180 Mbps 的纯洪泛流量（1400B 帧）且从不误伤学习
            // 后的单播；线速广播攻击（10 万+ fps）仍被削掉 90% 以上。
            flood_burst: burst,
            flood_rate_per_sec: rate_per_sec,
            flood_drops: AtomicU64::new(0),
            trusted_port: TAP_PORT_ID.to_string(),
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

    /// 默认洪泛预算：突发 8192 帧、每秒回充 16384（对齐 Go NewVSwitch）
    pub fn new() -> Arc<Self> {
        Self::with_flood_budgets(8192.0, 16384.0)
    }

    pub fn add_port(&self, id: String, port: Arc<AsyncPort>) {
        self.ports.insert(id, port);
    }

    pub fn remove_port(&self, id: &str) {
        self.ports.remove(id);
        // 回收洪泛预算槽位，否则长期运行下 map 会随断开的会话无限增长
        self.flood_mu.lock().remove(id);
        self.mac_table.retain(|_, entry| entry.port_id != id);
    }

    /// 注入源 MAC 归属校验回调（对齐 Go validateMAC）。
    ///
    /// 注入方应捕获 `Weak<ServerCore>` 而不是 `Arc`——VSwitch 由 ServerCore
    /// 持有，直接捕获 `Arc` 会构成引用环，进程存活期内两者都无法释放。
    pub fn set_validate_mac(
        &self,
        f: Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync>,
    ) {
        *self.validate_mac.write() = Some(f);
    }

    /// 冒充他人源 MAC 被整帧丢弃的计数（对齐 Go 的
    /// tlsvpn_spoofed_src_dropped_frames_total）
    pub fn spoof_drops(&self) -> u64 {
        self.spoof_drops.load(Ordering::Relaxed)
    }

    /// 超出每端口洪泛预算被丢弃的广播帧计数（对齐 Go 的
    /// tlsvpn_broadcast_dropped_frames_total）
    pub fn flood_drops(&self) -> u64 {
        self.flood_drops.load(Ordering::Relaxed)
    }

    /// 查询某 MAC 当前的表项归属（测试用：确认冒充帧没有改写受害者表项）
    #[cfg(test)]
    fn mac_port(&self, mac: &[u8; 6]) -> Option<String> {
        self.mac_table.get(mac).map(|e| e.port_id.clone())
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
            // 源 MAC 归属校验：端口只能声明自己会话注册的 MAC。冒充帧整帧丢弃
            // （既不学习也不转发——转发等于允许攻击者以受害者身份注入流量）。
            if let Some(f) = self.validate_mac.read().as_ref() {
                if !f(src_port_id, &src_mac) {
                    self.spoof_drops.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(
                        "VSWITCH drop spoofed srcMAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x} from port {}",
                        src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5],
                        src_port_id
                    );
                    return;
                }
            }
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
        } else {
            self.flood(src_port_id, frame);
        }
    }

    /// 洪泛到所有其他端口，但每源端口有独立的广播预算：线速广播会被复制
    /// 到所有端口放大 N 倍，超预算的帧在这里整帧丢弃（单播不受影响——见
    /// process_frame 的分支顺序：只有查不到目标才走到这里）。
    ///
    /// 豁免端口（本机 TAP）不受预算限制：网关自己发起的 ARP/mDNS 不应被
    /// 自己削掉。
    fn flood(&self, exclude_port_id: &str, frame: Arc<Vec<u8>>) {
        if exclude_port_id != self.trusted_port && !self.allow_flood(exclude_port_id) {
            self.flood_drops.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(
                "VSWITCH drop flooded frame over budget from port {}",
                exclude_port_id
            );
            return;
        }
        for ref_multi in self.ports.iter() {
            if *ref_multi.key() != exclude_port_id {
                ref_multi.value().write_frame(frame.clone());
            }
        }
    }

    /// 消耗一个洪泛令牌；令牌按时间线性回充，容量 flood_burst。
    ///
    /// 首次为端口建桶时即消耗一枚——桶满意味着"从此刻起还有 burst 枚预算"，
    /// 若建桶时给满额又直接放行，预算会恒定多出一枚。
    fn allow_flood(&self, src_port_id: &str) -> bool {
        let mut budgets = self.flood_mu.lock();
        let now = Instant::now();
        match budgets.get_mut(src_port_id) {
            None => {
                budgets.insert(
                    src_port_id.to_string(),
                    FloodBudget {
                        tokens: self.flood_burst - 1.0,
                        last: now,
                    },
                );
                true
            }
            Some(b) => {
                let elapsed = now.duration_since(b.last).as_secs_f64();
                if elapsed > 0.0 {
                    b.tokens = (b.tokens + elapsed * self.flood_rate_per_sec)
                        .min(self.flood_burst);
                    b.last = now;
                }
                if b.tokens < 1.0 {
                    return false;
                }
                b.tokens -= 1.0;
                true
            }
        }
    }
}

// AtomicBool 保留给会话保活标记使用
pub type SharedFlag = Arc<AtomicBool>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// 端口后端 + 它的收帧端：测试需要从这一侧把交换机投来的帧取走
    type TestBackend = (
        Arc<Backend>,
        crossbeam_channel::Receiver<VPNFrame>,
    );

    fn make_backend() -> TestBackend {
        let (tx, rx) = crossbeam_channel::bounded(256);
        (
            Arc::new(Backend {
                ch: tx,
                rtt_cache: Arc::new(AtomicU32::new(50000)),
                notify: None,
            }),
            rx,
        )
    }

    /// 从收帧端取走当前所有帧的载荷末字节（测试断言顺序与内容用）
    fn drained_last_byte(
        rx: &crossbeam_channel::Receiver<VPNFrame>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        while let Ok(f) = rx.try_recv() {
            out.push(f.data[f.data.len() - 1]);
        }
        out
    }

    /// 最小合法以太帧（dst 6 + src 6 + ethertype 2 + 载荷）
    fn eth_frame(dst: &[u8; 6], src: &[u8; 6], payload: &[u8]) -> Arc<Vec<u8>> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(dst);
        f.extend_from_slice(src);
        f.extend_from_slice(&0x0800u16.to_be_bytes());
        f.extend_from_slice(payload);
        Arc::new(f)
    }

    /// 与 server.rs 的 src_mac_allowed 同形的回调：注册表里没有条目
    /// （本机 TAP 等非会话端口）或条目是全零 MAC（未上报）时放行。
    fn ownership_callback(
        reg: std::collections::HashMap<String, [u8; 6]>,
    ) -> Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync> {
        Arc::new(move |port_id, mac| {
            match reg.get(port_id) {
                Some(r) if r != &[0u8; 6] => r == mac,
                _ => true,
            }
        })
    }

    #[test]
    fn src_mac_ownership_blocks_impersonation() {
        let vs = VSwitch::new();
        let port_a = Arc::new(AsyncPort::new("A".into(), false));
        let port_b = Arc::new(AsyncPort::new("B".into(), false));
        let (backend_a, rx_a) = make_backend();
        let (backend_b, rx_b) = make_backend();
        port_a.register_backend(backend_a);
        port_b.register_backend(backend_b);
        vs.add_port("A".into(), port_a);
        vs.add_port("B".into(), port_b);

        let mac_a = [0xAA, 0x00, 0x00, 0x00, 0x00, 0x01];
        let mac_b = [0xBB, 0x00, 0x00, 0x00, 0x00, 0x02];
        vs.set_validate_mac(ownership_callback(std::collections::HashMap::from([
            ("A".to_string(), mac_a),
            ("B".to_string(), mac_b),
        ])));

        // 合法路径：两个端口各自声明自己的 MAC，被学习并正常互达
        vs.process_frame("A", eth_frame(&[0, 0, 0, 0, 0, 0], &mac_a, &[0x01]));
        vs.process_frame("B", eth_frame(&[0, 0, 0, 0, 0, 0], &mac_b, &[0x02]));
        assert_eq!(
            vs.mac_port(&mac_a),
            Some("A".to_string()),
            "A 的 MAC 表项必须指向端口 A"
        );
        assert_eq!(vs.mac_port(&mac_b), Some("B".to_string()));
        assert_eq!(
            drained_last_byte(&rx_b),
            vec![0x01],
            "合法帧必须照常投递"
        );
        assert_eq!(
            drained_last_byte(&rx_a),
            vec![0x02],
            "合法帧必须照常投递"
        );
        assert_eq!(vs.spoof_drops(), 0);

        // 冒充：B 声明 A 的 MAC 想抢走 A 的表项 —— 整帧丢弃
        vs.process_frame("B", eth_frame(&[0, 0, 0, 0, 0, 0], &mac_a, &[0xAA]));
        assert_eq!(
            vs.spoof_drops(),
            1,
            "冒充源 MAC 的帧必须被计数"
        );
        assert_eq!(
            vs.mac_port(&mac_a),
            Some("A".to_string()),
            "冒充帧不得改写受害者 MAC 的表项"
        );
        assert_eq!(
            drained_last_byte(&rx_b),
            Vec::<u8>::new(),
            "冒充帧被丢在交换机内，不得再洪泛一次"
        );

        // 表项没被污染：正常单播仍可达 A，攻击者自己的流量不受影响
        vs.process_frame("B", eth_frame(&mac_a, &mac_b, &[0x03]));
        assert_eq!(
            drained_last_byte(&rx_a),
            vec![0x03],
            "单播必须继续按受害者表项投递"
        );

        // 未注册的端口（本机 TAP）声明任意 MAC 放行
        vs.process_frame(TAP_PORT_ID, eth_frame(&mac_a, &[0x42; 6], &[0x04]));
        assert_eq!(
            vs.mac_port(&[0x42; 6]),
            Some(TAP_PORT_ID.to_string()),
            "本机 TAP 端口声明的 MAC 必须放行"
        );
        assert_eq!(drained_last_byte(&rx_a), vec![0x04]);

        // 未上报 MAC 的会话（全零注册值）放行，保持与旧客户端兼容
        let vs2 = VSwitch::new();
        vs2.set_validate_mac(ownership_callback(std::collections::HashMap::from([
            ("C".to_string(), [0u8; 6]),
        ])));
        vs2.process_frame("C", eth_frame(&[0, 0, 0, 0, 0, 0], &[0x07; 6], &[0x05]));
        assert_eq!(
            vs2.mac_port(&[0x07; 6]),
            Some("C".to_string()),
            "空 MAC 会话必须放行"
        );
    }

    #[test]
    fn broadcast_from_exempt_port_is_delivered() {
        // 本机 TAP 端口不在会话注册表里，校验放行：广播照旧洪泛到所有其他端口，
        // 并按正常路径学习（对齐 Go——TAP 侧本来就是多 MAC）。
        let vs = VSwitch::new();
        let (backend_a, rx_a) = make_backend();
        let (backend_b, rx_b) = make_backend();
        let port_a = Arc::new(AsyncPort::new("A".into(), false));
        let port_b = Arc::new(AsyncPort::new("B".into(), false));
        port_a.register_backend(backend_a);
        port_b.register_backend(backend_b);
        vs.add_port("A".into(), port_a);
        vs.add_port("B".into(), port_b);
        vs.set_validate_mac(ownership_callback(std::collections::HashMap::from([
            ("A".to_string(), [0xAA; 6]),
            ("B".to_string(), [0xBB; 6]),
        ])));

        vs.process_frame(
            TAP_PORT_ID,
            eth_frame(&[0xff; 6], &[0xEE; 6], &[0x01]),
        );
        assert_eq!(
            drained_last_byte(&rx_a),
            vec![0x01],
            "广播帧必须投递到所有其他端口"
        );
        assert_eq!(
            drained_last_byte(&rx_b),
            vec![0x01],
            "广播帧必须投递到所有其他端口"
        );
        assert_eq!(
            vs.spoof_drops(),
            0,
            "豁免端口的广播不得计入冒充丢弃"
        );
        assert_eq!(
            vs.mac_port(&[0xEE; 6]),
            Some(TAP_PORT_ID.to_string()),
            "豁免端口按正常路径学习"
        );
    }

    #[test]
    fn illegal_src_mac_broadcast_is_also_dropped() {
        // 校验失败是整帧丢弃，广播也不例外：否则冒充者可以用广播绕过归属校验
        // 把流量注入所有客户端（对齐 Go needUpdate 内的 return）。
        let vs = VSwitch::new();
        let (backend_a, rx_a) = make_backend();
        let port_a = Arc::new(AsyncPort::new("A".into(), false));
        port_a.register_backend(backend_a);
        vs.add_port("A".into(), port_a);
        vs.set_validate_mac(ownership_callback(std::collections::HashMap::from([
            ("A".to_string(), [0xAA; 6]),
        ])));

        vs.process_frame(
            "A",
            eth_frame(&[0xff; 6], &[0xDD; 6], &[0x01]),
        );
        assert_eq!(vs.spoof_drops(), 1, "冒充广播必须被计数");
        assert_eq!(
            drained_last_byte(&rx_a),
            Vec::<u8>::new(),
            "冒充广播必须整帧丢弃"
        );
        assert_eq!(
            vs.mac_port(&[0xDD; 6]),
            None,
            "冒充广播不得进入学习表"
        );
    }

    #[test]
    fn no_callback_keeps_learning_unrestricted() {
        // 未注入回调（对齐 Go validateMAC == nil）时保持原行为：任意端口可学习
        let vs = VSwitch::new();
        let mac = [0xCD; 6];
        let empty = [0u8; 6];
        vs.process_frame("A", eth_frame(&empty, &mac, &[0x01]));
        assert_eq!(vs.mac_port(&mac), Some("A".to_string()));
        vs.process_frame("B", eth_frame(&empty, &mac, &[0x02]));
        assert_eq!(vs.mac_port(&mac), Some("B".to_string()));
        assert_eq!(vs.spoof_drops(), 0);
    }

    // ---------- 广播/洪泛预算（档 G） ----------

    #[test]
    fn flood_budget_consumes_a_token_on_bucket_creation() {
        // 建桶即消耗一枚：满桶意味着"从此刻起还有 burst 枚预算"。若建桶给满额
        // 又直接放行，预算会恒定多出一枚。
        let vs = VSwitch::with_flood_budgets(3.0, 0.0);
        let allowed = (0..6).take_while(|_| vs.allow_flood("A")).count();
        assert_eq!(allowed, 3, "恰好 burst 枚预算");
    }

    #[test]
    fn flood_defaults_match_go() {
        // 默认值必须有真流量意义：突发 8192 帧按 1400B 帧约 9.1MB 缓冲，
        // 回充 16384/秒约等于 180 Mbps 纯洪泛流量
        let vs = VSwitch::new();
        assert_eq!(vs.flood_burst, 8192.0, "对齐 Go NewVSwitch 的 floodBurst");
        assert_eq!(
            vs.flood_rate_per_sec,
            16384.0,
            "对齐 Go NewVSwitch 的 floodRatePerSec"
        );
        assert_eq!(vs.trusted_port, TAP_PORT_ID, "本机 TAP 豁免洪泛预算");

        // 预算内的满量洪泛一帧都不能丢。回充只会增加预算，所以这条断言不会因
        // 时钟漂移误报；反方向（何时开始丢）交给小桶测试验证
        for _ in 0..8192 {
            vs.process_frame(
                "A",
                eth_frame(&[0xff; 6], &[0xDD; 6], &[1]),
            );
        }
        assert_eq!(vs.flood_drops(), 0, "8192 帧洪泛必须全部通过");
    }

    #[test]
    fn flood_budget_refills_and_caps_at_burst() {
        let vs = VSwitch::with_flood_budgets(2.0, 1000.0);
        for _ in 0..4 {
            if !vs.allow_flood("A") {
                break;
            }
        }
        assert!(!vs.allow_flood("A"), "排空后必须拒发");

        // 10ms × 1000 枚/秒 = 10 枚，回充不得越过桶容量
        std::thread::sleep(Duration::from_millis(10));
        let allowed = (0..6).take_while(|_| vs.allow_flood("A")).count();
        assert_eq!(allowed, 2, "回充必须封顶在 burst");
    }

    #[test]
    fn over_budget_broadcast_is_dropped_whole() {
        // 超预算的洪泛帧整帧丢弃：既不学习表项也不投给任何其他端口。
        // 单播不受预算影响——预算只作用于"查不到目标"的洪泛分支。
        let vs = VSwitch::with_flood_budgets(2.0, 0.0);
        let (backend_b, rx_b) = make_backend();
        let port_a = Arc::new(AsyncPort::new("A".into(), false));
        let port_b = Arc::new(AsyncPort::new("B".into(), false));
        port_b.register_backend(backend_b);
        vs.add_port("A".into(), port_a);
        vs.add_port("B".into(), port_b);

        // 单播用的 MAC：首字节 bit0 必须为 0，否则会被当成广播走洪泛分支
        let mac_b = [0xBA, 0x00, 0x00, 0x00, 0x00, 0x01];
        // B 先学习一个 MAC，好让后面的单播断言有目标
        vs.process_frame("B", eth_frame(&[0, 0, 0, 0, 0, 0], &mac_b, &[0x00]));

        for i in [1u8, 2] {
            vs.process_frame("A", eth_frame(&[0xff; 6], &[0xDD; 6], &[i]));
        }
        assert_eq!(vs.flood_drops(), 0, "预算内不得丢帧");

        vs.process_frame("A", eth_frame(&[0xff; 6], &[0xDD; 6], &[0xFF]));
        assert_eq!(vs.flood_drops(), 1, "超预算必须整帧丢弃并计数");

        vs.process_frame("A", eth_frame(&mac_b, &[0xDD; 6], &[0x09]));
        assert_eq!(
            drained_last_byte(&rx_b),
            vec![0x01, 0x02, 0x09],
            "预算内 2 帧 + 超预算广播丢弃 + 单播不受限"
        );
    }

    #[test]
    fn trusted_port_is_exempt_from_flood_budget() {
        // 本机 TAP 豁免洪泛预算：网关自己发起的 ARP/mDNS 不应被自己削掉
        let vs = VSwitch::with_flood_budgets(1.0, 0.0);
        let (backend_b, rx_b) = make_backend();
        let port_b = Arc::new(AsyncPort::new("B".into(), false));
        port_b.register_backend(backend_b);
        vs.add_port("B".into(), port_b);

        for i in 0..10u8 {
            vs.process_frame(
                TAP_PORT_ID,
                eth_frame(&[0xff; 6], &[0xEE; 6], &[i]),
            );
        }
        assert_eq!(
            vs.flood_drops(),
            0,
            "本机 TAP 的洪泛不得计入预算丢弃"
        );
        assert_eq!(
            drained_last_byte(&rx_b).len(),
            10,
            "豁免端口的洪泛必须全部投递"
        );
    }

    #[test]
    fn remove_port_reclaims_flood_budget_slot() {
        // 端口销毁后必须回收预算槽位：否则 map 随断开会话无限增长，重连的端口
        // 还会继承上一个会话用尽的预算
        let vs = VSwitch::with_flood_budgets(1.0, 0.0);
        assert!(vs.allow_flood("A"), "建桶即消耗唯一一枚");
        assert!(!vs.allow_flood("A"), "单枚预算必须被耗尽");

        vs.remove_port("A");
        assert!(
            vs.allow_flood("A"),
            "端口移除后预算必须清零重建，而不是继承耗尽状态"
        );
        assert!(!vs.allow_flood("A"));
    }
}
