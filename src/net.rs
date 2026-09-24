use crossbeam_channel::Sender;
use crossbeam_queue::ArrayQueue;
use dashmap::DashMap;
use mio;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use tracing::{debug, info, warn};

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

pub const MAX_BRUTAL_RATE_MBPS: u64 = 1_000_000;
#[cfg(target_os = "linux")]
const TCP_BRUTAL_PARAMS: i32 = 23301;
#[cfg(target_os = "linux")]
const TCP_BRUTAL_VERSION: i32 = 23302;
#[cfg(any(target_os = "linux", test))]
const BRUTAL_V2_VERSION: u32 = 0x020000;
#[cfg(any(target_os = "linux", test))]
const BRUTAL_CWND_GAIN: u32 = 20;

#[derive(Clone, Debug, Default)]
pub struct BrutalApplyResult {
    pub attempted: bool,
    pub applied: bool,
    pub rule_managed: bool,
    pub version: u32,
    pub rate_bps: u64,
    pub rate_mbps: u64,
    pub cwnd_gain: u32,
    pub group_id: u64,
    pub error: String,
}

#[derive(Debug)]
#[cfg(any(target_os = "linux", test))]
enum BrutalSockError {
    Locked,
    NoVersion,
    Other(String),
}

#[cfg(any(target_os = "linux", test))]
trait BrutalSocketOps {
    fn set_congestion(&mut self, algo: &str) -> Result<(), BrutalSockError>;
    fn get_congestion(&mut self) -> Result<String, BrutalSockError>;
    fn get_version(&mut self) -> Result<u32, BrutalSockError>;
    fn set_params(&mut self, params: &[u8]) -> Result<(), BrutalSockError>;
    fn get_params(&mut self, size: usize) -> Result<Vec<u8>, BrutalSockError>;
}

pub fn split_legacy_brutal_rate(total: u64, conns: usize, index: usize) -> u64 {
    if total == 0 || conns == 0 || index >= conns {
        return 0;
    }
    total / conns as u64 + u64::from((index as u64) < total % conns as u64)
}

pub fn split_legacy_brutal_rate_bps(total_mbps: u64, conns: usize, index: usize) -> u64 {
    if total_mbps == 0 || conns == 0 || index >= conns { return 0; }
    let total_bps = total_mbps * 1_000_000 / 8;
    total_bps / conns as u64 + u64::from((index as u64) < total_bps % conns as u64)
}

pub fn brutal_group_id(domain: &str, identity: &str) -> u64 {
    let mut h = Sha256::new();
    h.update(b"tlsvpn/brutal/");
    h.update(domain.as_bytes());
    h.update([0]);
    h.update(identity.as_bytes());
    let digest = h.finalize();
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&digest[..8]);
    let id = u64::from_le_bytes(raw);
    if id == 0 { 1 } else { id }
}

#[cfg(any(target_os = "linux", test))]
fn encode_brutal_params_bps(rate_bps: u64, gain: u32, group_id: Option<u64>) -> Result<Vec<u8>, String> {
    if rate_bps == 0 || rate_bps > MAX_BRUTAL_RATE_MBPS * 1_000_000 / 8 {
        return Err(format!("TCP Brutal byte rate {} is outside the supported range", rate_bps));
    }
    let mut out = vec![0u8; if group_id.is_some() { 20 } else { 12 }];
    out[..8].copy_from_slice(&rate_bps.to_le_bytes());
    out[8..12].copy_from_slice(&gain.to_le_bytes());
    if let Some(group) = group_id {
        out[12..20].copy_from_slice(&group.to_le_bytes());
    }
    Ok(out)
}

#[cfg(any(target_os = "linux", test))]
fn decode_brutal_params_bps(params: &[u8]) -> Result<(u64, u32, u64), String> {
    if params.len() != 12 && params.len() != 20 {
        return Err(format!("invalid TCP_BRUTAL_PARAMS length {}", params.len()));
    }
    let rate_bps = u64::from_le_bytes(params[..8].try_into().unwrap());
    let gain = u32::from_le_bytes(params[8..12].try_into().unwrap());
    let group = if params.len() == 20 {
        u64::from_le_bytes(params[12..20].try_into().unwrap())
    } else {
        0
    };
    Ok((rate_bps, gain, group))
}

#[cfg(any(target_os = "linux", test))]
fn configure_tcp_brutal<O: BrutalSocketOps>(ops: &mut O, total_rate: u64, legacy_rate_bps: u64, group_id: u64) -> BrutalApplyResult {
    let mut result = BrutalApplyResult { attempted: true, cwnd_gain: BRUTAL_CWND_GAIN, ..Default::default() };
    if total_rate == 0 || total_rate > MAX_BRUTAL_RATE_MBPS {
        result.error = format!("TCP Brutal rate {} Mbps is outside [1, {}]", total_rate, MAX_BRUTAL_RATE_MBPS);
        return result;
    }
    let previous = ops.get_congestion().unwrap_or_default();
    match ops.set_congestion("brutal") {
        Ok(()) => {}
        Err(BrutalSockError::Locked) => {
            if ops.get_congestion().unwrap_or_default() != "brutal" {
                result.error = "TCP_CONGESTION is rule-locked but current algorithm is not brutal".into();
                return result;
            }
            result.rule_managed = true;
        }
        Err(e) => {
            result.error = format!("TCP_CONGESTION=brutal failed: {:?}", e);
            return result;
        }
    }
    let version = match ops.get_version() {
        Ok(v) => v,
        Err(BrutalSockError::NoVersion) => 0,
        Err(e) => {
            if !previous.is_empty() && previous != "brutal" { let _ = ops.set_congestion(&previous); }
            result.error = format!("TCP_BRUTAL_VERSION failed: {:?}", e);
            return result;
        }
    };
    result.version = version;
    let use_group = version >= BRUTAL_V2_VERSION && group_id != 0;
    let rate_bps = if use_group { total_rate * 1_000_000 / 8 } else { legacy_rate_bps };
    if rate_bps == 0 {
        if !previous.is_empty() && previous != "brutal" { let _ = ops.set_congestion(&previous); }
        result.error = "TCP Brutal legacy share is 0 Mbps; connection left unshaped to preserve the total limit".into();
        return result;
    }
    let params = match encode_brutal_params_bps(rate_bps, BRUTAL_CWND_GAIN, if use_group { Some(group_id) } else { None }) {
        Ok(v) => v,
        Err(e) => { result.error = e; return result; }
    };
    match ops.set_params(&params) {
        Ok(()) => {}
        Err(BrutalSockError::Locked) => result.rule_managed = true,
        Err(e) => {
            if !previous.is_empty() && previous != "brutal" { let _ = ops.set_congestion(&previous); }
            result.error = format!("TCP_BRUTAL_PARAMS failed: {:?}", e);
            return result;
        }
    }
    let read_size = if version >= BRUTAL_V2_VERSION { 20 } else { 12 };
    match ops.get_params(read_size).and_then(|p| decode_brutal_params_bps(&p).map_err(BrutalSockError::Other)) {
        Ok(actual) => {
            result.rate_bps = actual.0;
            result.rate_mbps = actual.0 * 8 / 1_000_000;
            result.cwnd_gain = actual.1;
            result.group_id = actual.2;
        }
        Err(BrutalSockError::Locked) if result.rule_managed => {
            // 锁定规则允许内核拒绝 TCP_BRUTAL_PARAMS 读写。算法确实已启用，
            // 但用户请求值不是内核实际值，不能伪装成已读回的限速。
            result.rate_bps = 0;
            result.rate_mbps = 0;
            result.group_id = 0;
            result.error = "TCP Brutal is active under a locked rule; actual rate and group are unavailable".into();
        }
        Err(e) => {
            // 参数已经成功写入；读回失败只影响可观测性，不应把连接降级成未启用。
            result.rate_bps = rate_bps;
            result.rate_mbps = rate_bps * 8 / 1_000_000;
            result.group_id = if use_group { group_id } else { 0 };
            result.error = format!("TCP Brutal applied but parameter readback failed: {:?}", e);
        }
    }
    result.applied = true;
    result
}

#[cfg(target_os = "linux")]
struct LinuxBrutalSocket { fd: i32 }

#[cfg(target_os = "linux")]
fn brutal_errno() -> BrutalSockError {
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() == Some(libc::EPERM) { BrutalSockError::Locked } else { BrutalSockError::Other(e.to_string()) }
}

#[cfg(target_os = "linux")]
impl BrutalSocketOps for LinuxBrutalSocket {
    fn set_congestion(&mut self, algo: &str) -> Result<(), BrutalSockError> {
        let mut value = algo.as_bytes().to_vec();
        value.push(0);
        let rc = unsafe { libc::setsockopt(self.fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, value.as_ptr() as *const _, value.len() as libc::socklen_t) };
        if rc == 0 { Ok(()) } else { Err(brutal_errno()) }
    }
    fn get_congestion(&mut self) -> Result<String, BrutalSockError> {
        let mut value = [0u8; 32];
        let mut len = value.len() as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(self.fd, libc::IPPROTO_TCP, libc::TCP_CONGESTION, value.as_mut_ptr() as *mut _, &mut len) };
        if rc != 0 { return Err(brutal_errno()); }
        let end = value.iter().position(|b| *b == 0).unwrap_or(len as usize);
        Ok(String::from_utf8_lossy(&value[..end]).to_string())
    }
    fn get_version(&mut self) -> Result<u32, BrutalSockError> {
        let mut value = 0u32;
        let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(self.fd, libc::IPPROTO_TCP, TCP_BRUTAL_VERSION, &mut value as *mut _ as *mut _, &mut len) };
        if rc == 0 { return Ok(value); }
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOPROTOOPT) { Err(BrutalSockError::NoVersion) } else { Err(BrutalSockError::Other(e.to_string())) }
    }
    fn set_params(&mut self, params: &[u8]) -> Result<(), BrutalSockError> {
        let rc = unsafe { libc::setsockopt(self.fd, libc::IPPROTO_TCP, TCP_BRUTAL_PARAMS, params.as_ptr() as *const _, params.len() as libc::socklen_t) };
        if rc == 0 { Ok(()) } else { Err(brutal_errno()) }
    }
    fn get_params(&mut self, size: usize) -> Result<Vec<u8>, BrutalSockError> {
        let mut value = vec![0u8; size];
        let mut len = size as libc::socklen_t;
        let rc = unsafe { libc::getsockopt(self.fd, libc::IPPROTO_TCP, TCP_BRUTAL_PARAMS, value.as_mut_ptr() as *mut _, &mut len) };
        if rc != 0 { return Err(brutal_errno()); }
        value.truncate(len as usize);
        Ok(value)
    }
}

#[cfg(target_os = "linux")]
pub fn apply_tcp_brutal<S: AsRawFd>(stream: &S, total_rate: u64, legacy_rate: u64, group_id: u64) -> BrutalApplyResult {
    let mut ops = LinuxBrutalSocket { fd: stream.as_raw_fd() };
    let result = configure_tcp_brutal(&mut ops, total_rate, legacy_rate, group_id);
    if result.applied && result.error.is_empty() {
        debug!("Applied TCP Brutal: {:?}", result);
    } else if result.applied {
        warn!("TCP Brutal is active with limited observability: {}", result.error);
    } else {
        warn!("TCP Brutal not applied: {}", result.error);
    }
    result
}

#[cfg(not(target_os = "linux"))]
pub fn apply_tcp_brutal<S: AsRawFd>(_stream: &S, _total_rate: u64, _legacy_rate: u64, _group_id: u64) -> BrutalApplyResult {
    BrutalApplyResult { attempted: true, error: "TCP Brutal is only supported on Linux".into(), ..Default::default() }
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

/// 策略路由一次安装所需的全部信息；退出清理复用同一个值，避免两处漂移。
///
/// 路由表号恒等于 fwmark：内核按 fwmark 命中规则后查 table，用同一个数字表示两者，
/// 配置里就只有一个需要填的值。
#[derive(Clone, Debug, Default)]
pub struct PolicyRoutingSpec {
    pub mark: i32,
    /// 0 = 交给内核自动分配（iproute2 的保留值）
    pub priority: i64,
    pub tap_name: String,
    /// 空串 = 服务端未下发该族网关，跳过
    pub gw_v4: String,
    pub gw_v6: String,
    /// iproute2 序列化语法，例如 "fd99:10:5:8::/64 dev tap0"
    pub extra_routes: Vec<String>,
    /// 按源地址前缀的规则，与 fwmark 相互独立
    pub source_rules: Vec<SourceRule>,
}

/// 一条按源地址前缀匹配的策略路由规则：`ip rule from <from> table <table>`。
///
/// 它和 fwmark 匹配的东西根本不同：fwmark 走 SO_MARK，只标记本进程自己写的包；
/// 这里匹配包上的源地址，内核转发的流量同样命中。转发包没有任何 socket，
/// SO_MARK 碰不到它，所以"给 socket 打 mark"对转发流量不适用。
///
/// 典型用途是 NPT 网关的回程路由：NPT 把内网地址翻译成公网前缀后，回程包的源
/// 地址就落在该公网前缀里（conntrack 的反向 NAT 在 PREROUTING 完成，早于路由
/// 决策），按源前缀即可把回程精确导向承载该前缀的接口。
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SourceRule {
    /// 源地址前缀；缺掩码按主机路由补全（/32 或 /128）
    pub from: String,
    /// 路由表号，必须显式给出：fwmark 的表号等于 mark 值，这里没有可推导来源
    pub table: u16,
    /// 规则优先级；0 = 交给内核自动分配
    #[serde(default)]
    pub priority: u32,
    /// 该表里除默认路由外的额外路由，语法同 extra_routes
    #[serde(default)]
    pub routes: Vec<String>,
}

impl PolicyRoutingSpec {
    pub fn enabled(&self) -> bool {
        self.mark > 0 || !self.source_rules.is_empty()
    }

    /// 日志/面板展示用：0 显示为 auto
    pub fn priority_label(&self) -> String {
        if self.priority > 0 {
            self.priority.to_string()
        } else {
            "auto".to_string()
        }
    }

    /// fwmark + table 两段的规则参数。删除规则时故意不带 priority：与 Go
    /// removePolicyRules 一致，按 mark+table 定位才不会漏删（优先级被改过之后
    /// 旧值已经不在配置里）。
    fn mark_table_args(&self) -> Vec<String> {
        let m = self.mark.to_string();
        vec!["fwmark".into(), m.clone(), "table".into(), m]
    }
}

/// "ip <family> rule <action> [priority N] fwmark M table M"
fn rule_cmd(spec: &PolicyRoutingSpec, family: &str, action: &str, with_priority: bool) -> Vec<String> {
    let mut cmd = vec![family.to_string(), "rule".into(), action.to_string()];
    if with_priority && spec.priority > 0 {
        cmd.push("priority".into());
        cmd.push(spec.priority.to_string());
    }
    cmd.extend(spec.mark_table_args());
    cmd
}

/// "ip <family> rule <action> [priority N] from <prefix> table <table>"
fn source_rule_cmd(rule: &SourceRule, family: &str, action: &str, with_priority: bool) -> Vec<String> {
    let mut cmd = vec![family.to_string(), "rule".into(), action.to_string()];
    if with_priority && rule.priority > 0 {
        cmd.push("priority".into());
        cmd.push(rule.priority.to_string());
    }
    cmd.push("from".into());
    cmd.push(rule.from.clone());
    cmd.push("table".into());
    cmd.push(rule.table.to_string());
    cmd
}

/// "ip <family> route replace default via <gw> dev <tap> table <table>"
fn default_route_cmd(family: &str, tap: &str, gateway: &str, table: i32) -> Option<Vec<String>> {
    if gateway.is_empty() {
        return None;
    }
    Some(vec![
        family.to_string(),
        "route".into(),
        "replace".into(),
        "default".into(),
        "via".into(),
        gateway.to_string(),
        "dev".into(),
        tap.to_string(),
        "table".into(),
        table.to_string(),
    ])
}

/// "ip route replace <prefix> dev <dev> table <table>"。地址族由前缀自动判定，不写 -4/-6。
fn extra_route_cmd(tap_name: &str, table: i32, raw: &str) -> Result<Vec<String>, String> {
    let (prefix, dev) = parse_route_spec(raw)?;
    let mut cmd = vec!["route".into(), "replace".into(), prefix];
    cmd.push("dev".into());
    cmd.push(if dev.is_empty() { tap_name.to_string() } else { dev });
    cmd.push("table".into());
    cmd.push(table.to_string());
    Ok(cmd)
}

/// "ip <family> route del <prefix> dev <tap> table <table>"
fn route_del_cmd(family: &str, prefix: &str, tap: &str, table: i32) -> Vec<String> {
    vec![
        family.to_string(),
        "route".into(),
        "del".into(),
        prefix.to_string(),
        "dev".into(),
        tap.to_string(),
        "table".into(),
        table.to_string(),
    ]
}

/// 把 "fd99:10:5:8::/64 dev tap0" 这类 iproute2 序列化写法拆成前缀和出接口。
///
/// 只覆盖本项目需要的最小集合：单个前缀 + 至多一个 dev，且 dev 必须紧跟前缀。
/// 多段或带 src/mtu/weight 等选项的写法一律按非法处理——配置期报错永远好过静默配错。
/// 缺掩码的裸地址按主机路由补全（/32 或 /128），与 ip route 的推断一致。
fn parse_route_spec(raw: &str) -> Result<(String, String), String> {
    let fields: Vec<&str> = raw.split_whitespace().collect();
    if fields.is_empty() {
        return Err("entry must not be empty".into());
    }
    // 先校验前缀：写 "dev tap0" 这种漏前缀的串要报"前缀非法"，不是 unsupported option
    let prefix = normalize_prefix(fields[0])?;
    let mut dev = String::new();
    let mut rest = &fields[1..];
    while !rest.is_empty() {
        if rest[0] == "dev" {
            if !dev.is_empty() {
                return Err("duplicate \"dev\" option".into());
            }
            if rest.len() < 2 {
                return Err("\"dev\" requires an interface name".into());
            }
            dev = rest[1].to_string();
            rest = &rest[2..];
            continue;
        }
        return Err(format!("unsupported option {:?}", rest[0]));
    }
    Ok((prefix, dev))
}

/// 带掩码时校验 IP 与掩码位数后原样返回；裸地址补全成主机路由。
fn normalize_prefix(first: &str) -> Result<String, String> {
    let invalid = || format!("invalid prefix {:?}", first);
    if let Some((addr, len_s)) = first.split_once('/') {
        let addr: std::net::IpAddr = addr.parse().map_err(|_| invalid())?;
        let max = if addr.is_ipv4() { 32u32 } else { 128u32 };
        let len: u32 = len_s.parse().map_err(|_| invalid())?;
        if len > max {
            return Err(invalid());
        }
        return Ok(first.to_string());
    }
    let addr: std::net::IpAddr = first.parse().map_err(|_| invalid())?;
    // IPv4-mapped（::ffff:a.b.c.d）按主机路由补 /32，与 Go 侧 net.IP.To4() 一致。
    // segments() 是网络字节序，0xffff 在第 6 段（下标 5）。
    let bits = match &addr {
        std::net::IpAddr::V6(v6) => {
            if v6.segments()[5] == 0xffff { 32 } else { 128 }
        }
        _ => 32,
    };
    Ok(format!("{}/{}", addr, bits))
}

/// 配置加载期就校验 extra_routes，把解析错误挡在隧道握手之前。
pub fn validate_extra_routes(routes: &[String]) -> Result<(), String> {
    for raw in routes {
        parse_route_spec(raw)
            .map_err(|e| format!("client.extra_routes {:?}: {}", raw, e))?;
    }
    Ok(())
}

/// 配置加载期就校验 source_rules。表号保留值 253/254/255 是内核自己的
/// default/main/local 表，写进去等于往内核表里塞东西，必须拒绝。
///
/// from 会就地补全成带掩码的形式（裸地址按主机路由），让后续构造命令不再需要
/// 自己推断地址族。取 &mut 是因为要写回规范化结果，和 Go 侧语义一致。
pub fn validate_source_rules(rules: &mut [SourceRule]) -> Result<(), String> {
    for (i, r) in rules.iter_mut().enumerate() {
        let trimmed = r.from.trim();
        if trimmed.is_empty() {
            return Err(format!("client.source_rules[{}].from: prefix must not be empty", i));
        }
        let Ok((prefix, dev)) = parse_route_spec(trimmed) else {
            return Err(format!("client.source_rules[{}].from: invalid prefix {:?}", i, r.from));
        };
        if !dev.is_empty() {
            return Err(format!(
                "client.source_rules[{}].from: expected a bare prefix, found dev {:?}",
                i, dev
            ));
        }
        r.from = prefix;
        if r.table == 0 || r.table == 253 || r.table == 254 || r.table == 255 {
            return Err(format!(
                "client.source_rules[{}].table {} must be in [1, 65535] and not the reserved 253/254/255",
                i, r.table
            ));
        }
        for raw in &r.routes {
            parse_route_spec(raw)
                .map_err(|e| format!("client.source_rules[{}].routes {:?}: {}", i, raw, e))?;
        }
    }
    Ok(())
}

/// 额外路由的删除命令；解析失败（已在配置加载期拦下）静默跳过。
/// iproute2 命令前缀。前缀里没有冒号就是 IPv4；映射地址（::ffff:a.b.c.d）仍按
/// IPv6 处理，与 `std::net::IpAddr::is_ipv4()` 的判定一致。
fn prefix_family(prefix: &str) -> &'static str {
    if prefix.contains(':') { "-6" } else { "-4" }
}

fn extra_route_del_cmd(tap_name: &str, table: i32, raw: &str) -> Option<Vec<String>> {
    let (prefix, dev) = parse_route_spec(raw).ok()?;
    Some(route_del_cmd(
        prefix_family(&prefix),
        &prefix,
        &if dev.is_empty() { tap_name.to_string() } else { dev },
        table,
    ))
}

/// 为指定表号的两族默认路由生成命令；网关为空表示服务端未下发该族，跳过。
fn default_routes(tap_name: &str, gw_v4: &str, gw_v6: &str, table: i32) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if !gw_v4.is_empty() {
        out.push(default_route_cmd("-4", tap_name, gw_v4, table).expect("gw_v4 非空"));
    }
    if !gw_v6.is_empty() {
        out.push(default_route_cmd("-6", tap_name, gw_v6, table).expect("gw_v6 非空"));
    }
    out
}

/// 安装策略路由需要的命令，分两阶段：
///
/// * `pre` —— 按 mark+table（或 from+table）清掉本进程上次留下的旧规则。
///   幂等操作，失败是常态（第一次安装时根本没有旧规则），不计为错误。
/// * `install` —— 真正生效的规则与路由，必须全部成功，否则整体失败。
///
/// 两类规则独立安装：fwmark 表号等于 mark 值，source_rules 的表号由配置给出。
pub fn policy_routing_cmds(
    spec: &PolicyRoutingSpec,
) -> Result<(Vec<Vec<String>>, Vec<Vec<String>>), String> {
    let (mut pre, mut install) = (Vec::new(), Vec::new());
    if !spec.enabled() {
        return Ok((pre, install));
    }
    if spec.mark > 0 {
        for family in ["-4", "-6"] {
            pre.push(rule_cmd(spec, family, "del", false));
            install.push(rule_cmd(spec, family, "add", true));
        }
        install.extend(default_routes(&spec.tap_name, &spec.gw_v4, &spec.gw_v6, spec.mark));
        for raw in &spec.extra_routes {
            install.push(extra_route_cmd(&spec.tap_name, spec.mark, raw)?);
        }
    }
    for (i, rule) in spec.source_rules.iter().enumerate() {
        // 规则只装到 from 自己的地址族：iproute2 会拒绝 -4 命令里出现 IPv6 前缀。
        // 清理路径同样按前缀判族，两边必须一致，否则会装出一条删不掉的规则。
        let fam = prefix_family(&rule.from);
        let gateway = if fam == "-6" { &spec.gw_v6 } else { &spec.gw_v4 };
        // 缺网关时整条规则命中后查不到默认路由、流量只会落回主表。报出来而不是
        // 静默跳过，否则用户以为配了、实际完全没生效。
        if gateway.is_empty() {
            return Err(format!(
                "client.source_rules[{}].from {} table {}: 服务端未下发 {} 网关",
                i,
                rule.from,
                rule.table,
                if fam == "-6" { "IPv6" } else { "IPv4" }
            ));
        }
        pre.push(source_rule_cmd(rule, fam, "del", false));
        install.push(source_rule_cmd(rule, fam, "add", true));
        if let Some(cmd) = default_route_cmd(fam, &spec.tap_name, gateway, rule.table as i32) {
            install.push(cmd);
        }
        for raw in &rule.routes {
            install.push(extra_route_cmd(&spec.tap_name, rule.table as i32, raw)?);
        }
    }
    Ok((pre, install))
}

/// 退出清理的命令序列。顺序与安装相反：先撤规则（流量立刻回默认表），
/// 再删路由，避免"规则在但表是空的"的中间态把流量黑洞掉。
///
/// extra_routes 已在配置加载期校验过，这里解析失败静默跳过。
pub fn clean_policy_routing_cmds(spec: &PolicyRoutingSpec) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    if !spec.enabled() {
        return out;
    }
    if spec.mark > 0 {
        for family in ["-4", "-6"] {
            out.push(rule_cmd(spec, family, "del", false));
        }
        for raw in &spec.extra_routes {
            if let Some(cmd) = extra_route_del_cmd(&spec.tap_name, spec.mark, raw) {
                out.push(cmd);
            }
        }
        if !spec.gw_v4.is_empty() {
            out.push(route_del_cmd("-4", "default", &spec.tap_name, spec.mark));
        }
        if !spec.gw_v6.is_empty() {
            out.push(route_del_cmd("-6", "default", &spec.tap_name, spec.mark));
        }
    }
    for rule in &spec.source_rules {
        // 只删自己装的那条：安装时规则按 from 的地址族走
        let fam = prefix_family(&rule.from);
        out.push(source_rule_cmd(rule, fam, "del", false));
        for raw in &rule.routes {
            if let Some(cmd) = extra_route_del_cmd(&spec.tap_name, rule.table as i32, raw) {
                out.push(cmd);
            }
        }
        let gateway = if fam == "-6" { &spec.gw_v6 } else { &spec.gw_v4 };
        if !gateway.is_empty() {
            out.push(route_del_cmd(fam, "default", &spec.tap_name, rule.table as i32));
        }
    }
    out
}

/// 执行一条 `ip` 命令。成功返回 true；失败把命令原文和 stderr 记进 errs。
/// 不 panic、不上抛——策略路由的每一步都可能撞 "No such ..."（幂等删除），
/// 全部收集完再由调用方决定要不要报错。
#[cfg(target_os = "linux")]
fn run_ip(args: &[String], errs: &mut Vec<String>) -> bool {
    match Command::new("ip").args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let detail = String::from_utf8_lossy(&o.stderr);
            let detail = if detail.trim().is_empty() {
                String::from_utf8_lossy(&o.stdout).into_owned()
            } else {
                detail.into_owned()
            };
            errs.push(format!("ip {}: {}", args.join(" "), detail.trim()));
            false
        }
        Err(e) => {
            errs.push(format!("ip {}: {}", args.join(" "), e));
            false
        }
    }
}

/// 安装策略路由。路由表号恒等于 fwmark。
///
/// 失败会把 `ip` 的 stderr 原文带上抛，不再静默吞掉——半装状态（有规则没路由、
/// 有路由没规则）比明确报错更糟。
#[cfg(target_os = "linux")]
pub fn setup_policy_routing(spec: &PolicyRoutingSpec) -> Result<(), String> {
    if !spec.enabled() {
        return Ok(());
    }
    // 不等待接口就绪：TAP 是本进程自己建的，晚到的接口下次重拨自会重试
    // （对齐 Go 的 client.setupInterface，两侧都不轮询）。
    let (pre, install) = policy_routing_cmds(spec)?;
    info!(
        "🔀 Configuring Policy Routing (fwmark {} table {} priority {}, {} extra routes; {} source rules)",
        spec.mark,
        spec.mark,
        spec.priority_label(),
        spec.extra_routes.len(),
        spec.source_rules.len()
    );
    let mut errs = Vec::new();
    for cmd in &pre {
        // 幂等删除：目标不存在就是常态，丢弃该步的错误
        let mut discarded = Vec::new();
        run_ip(cmd, &mut discarded);
    }
    for cmd in &install {
        if !run_ip(cmd, &mut errs) {
            warn!("policy routing: {}", errs.last().unwrap_or(&String::new()));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// 非 Linux 没有网络命名空间。这里报错而不是静默返回 Ok——面板需要区分
/// "没配 fwmark" 和 "配了但当前平台无法生效"（对齐 Go tap_other.go）。
#[cfg(not(target_os = "linux"))]
pub fn setup_policy_routing(spec: &PolicyRoutingSpec) -> Result<(), String> {
    if spec.enabled() {
        Err("tunnel interface configuration is only supported on Linux".into())
    } else {
        Ok(())
    }
}

/// 退出时清理策略路由（对齐 Go cleanPolicyRouting：仅告警，不上抛）。
#[cfg(target_os = "linux")]
pub fn clean_policy_routing(spec: &PolicyRoutingSpec) -> Vec<String> {
    if !spec.enabled() {
        return Vec::new();
    }
    let mut errs = Vec::new();
    for cmd in clean_policy_routing_cmds(spec) {
        if !run_ip(&cmd, &mut errs) {
            warn!("policy routing cleanup: {}", errs.last().unwrap_or(&String::new()));
        }
    }
    errs
}

/// 非 Linux：没有规则可清。
#[cfg(not(target_os = "linux"))]
pub fn clean_policy_routing(_spec: &PolicyRoutingSpec) -> Vec<String> {
    Vec::new()
}

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
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
    // 同一 backend 只允许一个未消费的 wake。高吞吐时几十个连续 frame
    // 合并成一次 poll 唤醒，避免每包 eventfd/write syscall。
    pending: AtomicBool,
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
            pending: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn wake(&self) {
        if self
            .pending
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // dirty 队列满时 poller 通常已经被其它 backend 唤醒；即使 token
            // 没排进去，周期巡检仍会 drain。不能在这里阻塞数据面。
            let _ = self.dirty.push(self.token);
            let _ = self.waker.wake();
        }
    }

    /// consumer 在开始 drain 前清 pending。之后若生产者又入队，它会重新
    /// 触发 wake，因此不存在“清标志后新帧被吞掉”的 lost-wakeup 窗口。
    #[inline]
    pub fn consume_wake(&self) {
        self.pending.store(false, Ordering::Release);
    }
}

pub struct Backend {
    pub ch: Sender<VPNFrame>,
    pub rtt_cache: Arc<AtomicU32>,
    pub notify: Option<Arc<BackendNotify>>,
}

/// 异步聚合端口，分发行为对齐 Go AsyncPort.dispatchBatch：
/// - 挂载 XOR FEC 编码器时：数据帧 MinRTT 单路发送，校验帧只发一份并在健康连接间轮转；
/// - 普通模式：MinRTT 单路发送。
pub struct AsyncPort {
    pub id: String,
    tx_seq: AtomicU32,
    backends: RwLock<Vec<Arc<Backend>>>,
    // 后端列表在读锁保护期间索引稳定；用原子索引代替每包
    // Mutex<Weak<Backend>> + upgrade/Arc 比较。
    preferred: AtomicUsize,
    schedule_tick: AtomicU32,
    parity_cursor: AtomicUsize,
    encoder: Mutex<Option<FecEncoder>>,
    dropped: AtomicU64,
    parity_sent: AtomicU64,
    sequence_exhausted: AtomicBool,
}

impl AsyncPort {
    pub fn new(id: String) -> Self {
        Self {
            id,
            tx_seq: AtomicU32::new(0),
            backends: RwLock::new(Vec::new()),
            preferred: AtomicUsize::new(usize::MAX),
            schedule_tick: AtomicU32::new(0),
            parity_cursor: AtomicUsize::new(0),
            encoder: Mutex::new(None),
            dropped: AtomicU64::new(0),
            parity_sent: AtomicU64::new(0),
            sequence_exhausted: AtomicBool::new(false),
        }
    }

    /// 挂载 XOR FEC 编码器（须在数据流开始前调用一次）
    pub fn attach_encoder(&self, k: usize, ic: Option<Arc<InnerCipher>>) {
        *self.encoder.lock() = Some(FecEncoder::new(k, ic));
    }

    pub fn reset_epoch(&self, k: usize, ic: Option<Arc<InnerCipher>>) {
        self.tx_seq.store(0, Ordering::Release);
        self.sequence_exhausted.store(false, Ordering::Release);
        self.parity_cursor.store(0, Ordering::Release);
        *self.encoder.lock() = if k >= crate::fec::FEC_MIN_GROUP {
            Some(FecEncoder::new(k, ic))
        } else {
            None
        };
    }

    pub fn is_sequence_exhausted(&self) -> bool {
        self.sequence_exhausted.load(Ordering::Acquire)
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    pub fn parity_sent(&self) -> u64 {
        self.parity_sent.load(Ordering::Relaxed)
    }

    pub fn register_backend(&self, backend: Arc<Backend>) {
        self.backends.write().push(backend);
    }
    pub fn unregister_backend(&self, ch_to_remove: &Sender<VPNFrame>) {
        self.backends
            .write()
            .retain(|b| !b.ch.same_channel(ch_to_remove));
        // 后端删除会改变 Vec 索引；这是冷路径，直接让下一帧重新评分。
        self.preferred.store(usize::MAX, Ordering::Release);
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

    fn backend_score(b: &Backend) -> Option<u32> {
        let q_len = b.ch.len();
        let capacity = b.ch.capacity().unwrap_or(4096);
        if capacity <= 2 || q_len >= capacity - 2 {
            return None;
        }
        let rtt = b.rtt_cache.load(Ordering::Relaxed);
        let penalty = if q_len > 10 {
            (q_len as u64 - 10) * 1000
        } else {
            0
        };
        Some((rtt as u64 + penalty).min(u32::MAX as u64) as u32)
    }

    /// MinRTT + 积压评分，并为当前路径保留 12.5% RTT（最低 5ms）滞回。
    /// 返回后端索引，避免在每帧路径构造/升级 Weak Arc。
    fn pick_backend_index(&self, backends: &[Arc<Backend>]) -> Option<usize> {
        let mut best_idx = None;
        let mut min_score = u32::MAX;
        for (idx, b) in backends.iter().enumerate() {
            let Some(score) = Self::backend_score(b) else { continue };
            if score < min_score {
                min_score = score;
                best_idx = Some(idx);
            }
        }

        let mut selected = best_idx.or_else(|| (!backends.is_empty()).then_some(0))?;
        let current = self.preferred.load(Ordering::Relaxed);
        if current < backends.len() && current != selected {
            if let Some(current_score) = Self::backend_score(&backends[current]) {
                let hysteresis =
                    5_000u32.max(backends[current].rtt_cache.load(Ordering::Relaxed) / 8);
                if current_score as u64 <= min_score as u64 + hysteresis as u64 {
                    selected = current;
                }
            }
        }
        self.preferred.store(selected, Ordering::Relaxed);
        Some(selected)
    }

    /// 数据帧热路径。路径 RTT/队列不会在相邻几个以太帧之间发生有意义的变化，
    /// 因此正常情况下复用 16 帧当前后端；当前队列接近满时立即重新评分。
    /// 这把 backends 扫描从“每包”降低到约“每 16 包一次”，同时保留快速故障切换。
    fn selected_backend_index(&self, backends: &[Arc<Backend>]) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }
        if backends.len() == 1 {
            self.preferred.store(0, Ordering::Relaxed);
            return Some(0);
        }

        let current = self.preferred.load(Ordering::Relaxed);
        let tick = self.schedule_tick.fetch_add(1, Ordering::Relaxed);
        if (tick & 0x0f) != 0
            && current < backends.len()
            && Self::backend_score(&backends[current]).is_some()
        {
            return Some(current);
        }
        self.pick_backend_index(backends)
    }

    /// parity 只需被会话级 decoder 收到一份。多连接时从轮转游标开始，
    /// 优先选择与当前 data path 不同且队列健康的后端，兼顾路径分散和 1/K 带宽。
    fn parity_backend_index(
        &self,
        backends: &[Arc<Backend>],
        data_idx: Option<usize>,
    ) -> Option<usize> {
        if backends.is_empty() {
            return None;
        }
        let start = self.parity_cursor.fetch_add(1, Ordering::Relaxed) % backends.len();
        if backends.len() > 1 {
            for offset in 0..backends.len() {
                let idx = (start + offset) % backends.len();
                if Some(idx) == data_idx {
                    continue;
                }
                if Self::backend_score(&backends[idx]).is_some() {
                    return Some(idx);
                }
            }
        }
        if let Some(idx) = data_idx {
            if idx < backends.len() && Self::backend_score(&backends[idx]).is_some() {
                return Some(idx);
            }
        }
        for offset in 0..backends.len() {
            let idx = (start + offset) % backends.len();
            if Self::backend_score(&backends[idx]).is_some() {
                return Some(idx);
            }
        }
        Some(start)
    }

    pub fn write_frame(&self, frame: Arc<Vec<u8>>) {
        if frame.is_empty() {
            return;
        }
        let backends = self.backends.read();
        if backends.is_empty() {
            self.drop_n(1);
            return;
        }

        let Some(seq) = self.next_seq() else {
            self.drop_n(1);
            return;
        };

        // FEC encoder 是 session/port 级串行状态；只持锁一次。
        let parity = self
            .encoder
            .lock()
            .as_mut()
            .and_then(|enc| enc.add(seq, &frame));

        let data_idx = self.selected_backend_index(&backends);
        if let Some(idx) = data_idx {
            self.send_frame_to(&backends[idx], seq, &frame);
        } else {
            self.drop_n(1);
        }

        if let Some(par) = parity {
            self.parity_sent.fetch_add(1, Ordering::Relaxed);
            let par = Arc::new(par);
            if let Some(idx) = self.parity_backend_index(&backends, data_idx) {
                self.send_frame_to(&backends[idx], 0, &par);
            } else {
                self.drop_n(1);
            }
        }
    }

    fn next_seq(&self) -> Option<u32> {
        loop {
            let current = self.tx_seq.load(Ordering::Acquire);
            if current == u32::MAX {
                self.sequence_exhausted.store(true, Ordering::Release);
                return None;
            }
            if self
                .tx_seq
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(current + 1);
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
    // 源 MAC 归属校验（None = 不过滤）：会话端口只允许声明本会话注册的 MAC。
    // 共享 PSK 的多客户端场景下，恶意客户端可以声明他人的 srcMAC 把受害者的
    // 表项学习到自己的端口，劫持其下行单播流量（学习表翻转攻击）。
    validate_mac: RwLock<Option<Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync>>>,
    spoof_drops: AtomicU64,

    // 广播/未知单播洪泛的每端口令牌桶：恶意客户端可以线速广播，洪泛会被
    // 复制到所有端口放大 N 倍。合法 ARP/mDNS 远低于该预算；超预算的帧直接
    // 丢弃（单播不受影响）。
    flood_mu: Mutex<HashMap<String, FloodBudget>>,
    flood_burst: f64,        // 桶容量（突发预算）
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
    pub fn set_validate_mac(&self, f: Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync>) {
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
                    b.tokens = (b.tokens + elapsed * self.flood_rate_per_sec).min(self.flood_burst);
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
    type TestBackend = (Arc<Backend>, crossbeam_channel::Receiver<VPNFrame>);

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

    #[test]
    fn async_port_sequence_stops_before_wrap() {
        let port = AsyncPort::new("sequence-test".into());
        port.tx_seq.store(u32::MAX - 1, Ordering::Release);
        assert_eq!(port.next_seq(), Some(u32::MAX));
        assert_eq!(port.next_seq(), None);
        assert_eq!(port.next_seq(), None);
        assert!(port.is_sequence_exhausted());
        port.reset_epoch(0, None);
        assert_eq!(port.next_seq(), Some(1));
        assert!(!port.is_sequence_exhausted());
    }

    #[test]
    fn async_port_keeps_sticky_path_until_backpressure() {
        let port = AsyncPort::new("sticky".into());
        let (tx_a, _rx_a) = crossbeam_channel::bounded(32);
        let (tx_b, _rx_b) = crossbeam_channel::bounded(32);
        let a = Arc::new(Backend {
            ch: tx_a,
            rtt_cache: Arc::new(AtomicU32::new(250_000)),
            notify: None,
        });
        let b = Arc::new(Backend {
            ch: tx_b,
            rtt_cache: Arc::new(AtomicU32::new(240_000)),
            notify: None,
        });
        let backends = vec![a.clone(), b.clone()];
        assert_eq!(port.pick_backend_index(&backends), Some(1));

        a.rtt_cache.store(240_000, Ordering::Relaxed);
        b.rtt_cache.store(255_000, Ordering::Relaxed);
        assert_eq!(
            port.pick_backend_index(&backends),
            Some(1),
            "hysteresis should keep the current path"
        );

        while b.ch.len() < b.ch.capacity().unwrap() - 2 {
            b.ch.try_send(VPNFrame { seq: 0, data: Arc::new(Vec::new()) }).unwrap();
        }
        assert_eq!(
            port.pick_backend_index(&backends),
            Some(0),
            "near-full preferred queue must trigger an immediate switch"
        );
    }

    #[test]
    fn backend_notify_coalesces_until_consumed() {
        let mut poll = mio::Poll::new().unwrap();
        let dirty = Arc::new(ArrayQueue::new(8));
        let waker = Arc::new(mio::Waker::new(poll.registry(), mio::Token(99)).unwrap());
        let notify = BackendNotify::new(waker, dirty.clone(), mio::Token(7));

        notify.wake();
        notify.wake();
        notify.wake();
        assert_eq!(dirty.len(), 1, "multiple producer frames must coalesce to one dirty token");
        assert_eq!(dirty.pop(), Some(mio::Token(7)));

        notify.consume_wake();
        notify.wake();
        assert_eq!(dirty.len(), 1, "consumer re-arm must allow the next batch to wake");
        assert_eq!(dirty.pop(), Some(mio::Token(7)));

        // Keep poll mutable/live so the Waker remains valid for the whole test.
        let mut events = mio::Events::with_capacity(4);
        let _ = poll.poll(&mut events, Some(Duration::from_millis(0)));
    }

    #[test]
    fn parity_counter_survives_epoch_reset() {
        let port = AsyncPort::new("parity".into());
        let (backend, _rx) = make_backend();
        port.register_backend(backend);
        port.reset_epoch(4, None);
        for i in 0..4 {
            port.write_frame(Arc::new(vec![i]));
        }
        assert_eq!(port.parity_sent(), 1);
        port.reset_epoch(4, None);
        for i in 0..4 {
            port.write_frame(Arc::new(vec![i]));
        }
        assert_eq!(port.parity_sent(), 2);
    }

    /// 从收帧端取走当前所有帧的载荷末字节（测试断言顺序与内容用）
    fn drained_last_byte(rx: &crossbeam_channel::Receiver<VPNFrame>) -> Vec<u8> {
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
        Arc::new(move |port_id, mac| match reg.get(port_id) {
            Some(r) if r != &[0u8; 6] => r == mac,
            _ => true,
        })
    }

    #[test]
    fn src_mac_ownership_blocks_impersonation() {
        let vs = VSwitch::new();
        let port_a = Arc::new(AsyncPort::new("A".into()));
        let port_b = Arc::new(AsyncPort::new("B".into()));
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
        assert_eq!(drained_last_byte(&rx_b), vec![0x01], "合法帧必须照常投递");
        assert_eq!(drained_last_byte(&rx_a), vec![0x02], "合法帧必须照常投递");
        assert_eq!(vs.spoof_drops(), 0);

        // 冒充：B 声明 A 的 MAC 想抢走 A 的表项 —— 整帧丢弃
        vs.process_frame("B", eth_frame(&[0, 0, 0, 0, 0, 0], &mac_a, &[0xAA]));
        assert_eq!(vs.spoof_drops(), 1, "冒充源 MAC 的帧必须被计数");
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
        vs2.set_validate_mac(ownership_callback(std::collections::HashMap::from([(
            "C".to_string(),
            [0u8; 6],
        )])));
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
        let port_a = Arc::new(AsyncPort::new("A".into()));
        let port_b = Arc::new(AsyncPort::new("B".into()));
        port_a.register_backend(backend_a);
        port_b.register_backend(backend_b);
        vs.add_port("A".into(), port_a);
        vs.add_port("B".into(), port_b);
        vs.set_validate_mac(ownership_callback(std::collections::HashMap::from([
            ("A".to_string(), [0xAA; 6]),
            ("B".to_string(), [0xBB; 6]),
        ])));

        vs.process_frame(TAP_PORT_ID, eth_frame(&[0xff; 6], &[0xEE; 6], &[0x01]));
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
        assert_eq!(vs.spoof_drops(), 0, "豁免端口的广播不得计入冒充丢弃");
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
        let port_a = Arc::new(AsyncPort::new("A".into()));
        port_a.register_backend(backend_a);
        vs.add_port("A".into(), port_a);
        vs.set_validate_mac(ownership_callback(std::collections::HashMap::from([(
            "A".to_string(),
            [0xAA; 6],
        )])));

        vs.process_frame("A", eth_frame(&[0xff; 6], &[0xDD; 6], &[0x01]));
        assert_eq!(vs.spoof_drops(), 1, "冒充广播必须被计数");
        assert_eq!(
            drained_last_byte(&rx_a),
            Vec::<u8>::new(),
            "冒充广播必须整帧丢弃"
        );
        assert_eq!(vs.mac_port(&[0xDD; 6]), None, "冒充广播不得进入学习表");
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
            vs.flood_rate_per_sec, 16384.0,
            "对齐 Go NewVSwitch 的 floodRatePerSec"
        );
        assert_eq!(vs.trusted_port, TAP_PORT_ID, "本机 TAP 豁免洪泛预算");

        // 预算内的满量洪泛一帧都不能丢。回充只会增加预算，所以这条断言不会因
        // 时钟漂移误报；反方向（何时开始丢）交给小桶测试验证
        for _ in 0..8192 {
            vs.process_frame("A", eth_frame(&[0xff; 6], &[0xDD; 6], &[1]));
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
        let port_a = Arc::new(AsyncPort::new("A".into()));
        let port_b = Arc::new(AsyncPort::new("B".into()));
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
        let port_b = Arc::new(AsyncPort::new("B".into()));
        port_b.register_backend(backend_b);
        vs.add_port("B".into(), port_b);

        for i in 0..10u8 {
            vs.process_frame(TAP_PORT_ID, eth_frame(&[0xff; 6], &[0xEE; 6], &[i]));
        }
        assert_eq!(vs.flood_drops(), 0, "本机 TAP 的洪泛不得计入预算丢弃");
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

    struct FakeBrutalSocket {
        congestion: String,
        version: Result<u32, BrutalSockError>,
        set_algo_locked: bool,
        set_params_locked: bool,
        get_params_locked: bool,
        fail_params: bool,
        params: Vec<u8>,
        algo_calls: Vec<String>,
    }

    impl FakeBrutalSocket {
        fn v2() -> Self {
            Self {
                congestion: "cubic".into(), version: Ok(BRUTAL_V2_VERSION),
                set_algo_locked: false, set_params_locked: false, get_params_locked: false,
                fail_params: false, params: Vec::new(), algo_calls: Vec::new(),
            }
        }
    }

    impl BrutalSocketOps for FakeBrutalSocket {
        fn set_congestion(&mut self, algo: &str) -> Result<(), BrutalSockError> {
            self.algo_calls.push(algo.to_string());
            if self.set_algo_locked && algo == "brutal" { return Err(BrutalSockError::Locked); }
            self.congestion = algo.to_string();
            Ok(())
        }
        fn get_congestion(&mut self) -> Result<String, BrutalSockError> { Ok(self.congestion.clone()) }
        fn get_version(&mut self) -> Result<u32, BrutalSockError> {
            match &self.version {
                Ok(v) => Ok(*v),
                Err(BrutalSockError::NoVersion) => Err(BrutalSockError::NoVersion),
                Err(BrutalSockError::Locked) => Err(BrutalSockError::Locked),
                Err(BrutalSockError::Other(e)) => Err(BrutalSockError::Other(e.clone())),
            }
        }
        fn set_params(&mut self, params: &[u8]) -> Result<(), BrutalSockError> {
            if self.set_params_locked { return Err(BrutalSockError::Locked); }
            if self.fail_params { return Err(BrutalSockError::Other("bad params".into())); }
            self.params = params.to_vec();
            Ok(())
        }
        fn get_params(&mut self, size: usize) -> Result<Vec<u8>, BrutalSockError> {
            if self.get_params_locked { return Err(BrutalSockError::Locked); }
            if self.params.len() == size { Ok(self.params.clone()) } else { Err(BrutalSockError::Other("no params".into())) }
        }
    }

    #[test]
    fn brutal_v2_group_and_v1_fallback_use_correct_abi() {
        let mut v2 = FakeBrutalSocket::v2();
        let legacy_8mbps = 8 * 1_000_000 / 8;
        let got = configure_tcp_brutal(&mut v2, 30, legacy_8mbps, 42);
        assert!(got.applied);
        assert_eq!((got.rate_mbps, got.group_id, v2.params.len()), (30, 42, 20));

        let mut v1 = FakeBrutalSocket::v2();
        v1.version = Err(BrutalSockError::NoVersion);
        let got = configure_tcp_brutal(&mut v1, 30, legacy_8mbps, 42);
        assert!(got.applied);
        assert_eq!((got.rate_mbps, got.group_id, v1.params.len()), (8, 0, 12));
    }

    #[test]
    fn brutal_locked_rule_is_active_and_param_failure_rolls_back() {
        let mut locked = FakeBrutalSocket::v2();
        locked.congestion = "brutal".into();
        locked.set_algo_locked = true;
        locked.set_params_locked = true;
        locked.params = encode_brutal_params_bps(125 * 1_000_000 / 8, 15, Some(7)).unwrap();
        let legacy_8mbps = 8 * 1_000_000 / 8;
        let got = configure_tcp_brutal(&mut locked, 30, legacy_8mbps, 42);
        assert!(got.applied && got.rule_managed);
        assert_eq!((got.rate_mbps, got.cwnd_gain, got.group_id), (125, 15, 7));

        let mut unreadable = FakeBrutalSocket::v2();
        unreadable.congestion = "brutal".into();
        unreadable.set_algo_locked = true;
        unreadable.set_params_locked = true;
        unreadable.get_params_locked = true;
        let got = configure_tcp_brutal(&mut unreadable, 30, legacy_8mbps, 42);
        assert!(got.applied && got.rule_managed);
        assert_eq!((got.rate_bps, got.rate_mbps, got.group_id), (0, 0, 0));
        assert!(got.error.contains("actual rate and group are unavailable"));

        let mut failed = FakeBrutalSocket::v2();
        failed.fail_params = true;
        let got = configure_tcp_brutal(&mut failed, 30, legacy_8mbps, 42);
        assert!(!got.applied);
        assert_eq!(failed.congestion, "cubic");
        assert_eq!(failed.algo_calls, vec!["brutal", "cubic"]);
    }

    #[test]
    fn brutal_legacy_distribution_preserves_total_and_groups_are_domain_separated() {
        for (total, conns) in [(30, 4), (2, 4), (101, 8)] {
            let sum: u64 = (0..conns).map(|i| split_legacy_brutal_rate(total, conns, i)).sum();
            assert_eq!(sum, total);
        }
        assert_eq!(split_legacy_brutal_rate(2, 4, 2), 0);
        let bps_sum: u64 = (0..4).map(|i| split_legacy_brutal_rate_bps(2, 4, i)).sum();
        assert_eq!(bps_sum, 2 * 1_000_000 / 8);
        let client = brutal_group_id("client", "same");
        let server = brutal_group_id("server", "same");
        assert_ne!(client, 0);
        assert_ne!(client, server);
        assert_eq!(client, brutal_group_id("client", "same"));
    }

    fn policy_spec() -> PolicyRoutingSpec {
        PolicyRoutingSpec {
            mark: 0x100,
            priority: 1000,
            tap_name: "tap0".into(),
            gw_v4: "203.0.113.1".into(),
            gw_v6: "fd99:10:5:8::1".into(),
            extra_routes: vec!["fd99:10:5:8::/64".into(), "192.0.2.0/24 dev eth1".into()],
            source_rules: vec![],
        }
    }

    fn policy_spec_with_source_rules() -> PolicyRoutingSpec {
        PolicyRoutingSpec {
            mark: 0,
            priority: 0,
            tap_name: "tap0".into(),
            gw_v4: "203.0.113.1".into(),
            gw_v6: "fd99:10:5:8::1".into(),
            extra_routes: vec![],
            source_rules: vec![SourceRule {
                from: "2001:db8::1/128".into(),
                table: 100,
                priority: 700,
                routes: vec!["fd99:10:5:8::/64 dev tap0".into()],
            }],
        }
    }

    #[test]
    fn parse_route_spec_splits_prefix_and_dev() {
        let ok = [
            ("fd99:10:5:8::/64 dev tap0", ("fd99:10:5:8::/64", "tap0")),
            ("203.0.113.0/24", ("203.0.113.0/24", "")),
            ("203.0.113.7", ("203.0.113.7/32", "")),
            ("fd00::7", ("fd00::7/128", "")),
            ("::ffff:203.0.113.9", ("::ffff:203.0.113.9/32", "")),
            ("\t10.0.0.0/8\tdev\tnet0", ("10.0.0.0/8", "net0")),
        ];
        for (raw, want) in ok {
            assert_eq!(parse_route_spec(raw).unwrap(), (want.0.to_string(), want.1.to_string()), "{raw}");
        }
        let bad = [
            ("", "entry must not be empty"),
            ("dev tap0", "invalid prefix"),
            ("banana", "invalid prefix"),
            ("10.0.0.0/33", "invalid prefix"),
            ("10.0.0.0/", "invalid prefix"),
            ("10.0.0.0/8 dev", "\"dev\" requires an interface name"),
            ("10.0.0.0/8 dev a dev b", "duplicate \"dev\" option"),
            ("10.0.0.0/8 src 10.0.0.1", "unsupported option"),
        ];
        for (raw, msg) in bad {
            let err = parse_route_spec(raw).unwrap_err();
            assert!(err.contains(msg), "{raw:?} -> {err}");
        }
    }

    #[test]
    fn validate_extra_routes_reports_the_offending_entry() {
        assert!(validate_extra_routes(&[]).is_ok());
        assert!(validate_extra_routes(&["10.0.0.0/8 dev tap0".into()]).is_ok());
        let err = validate_extra_routes(&["banana".into()]).unwrap_err();
        assert!(
            err.starts_with("client.extra_routes \"banana\": "),
            "error must name the entry, not just say parsing failed: {err}"
        );
        assert!(err.contains("invalid prefix"));
    }

    #[test]
    fn validate_source_rules_normalizes_prefix_and_rejects_bad_entries() {
        assert!(validate_source_rules(&mut Vec::new()).is_ok());

        // 裸地址就地补全成主机路由，安装逻辑因此不用自己推断地址族
        let mut rules = vec![SourceRule {
            from: "2001:db8::1".into(),
            table: 100,
            routes: vec!["fd99:10:5:8::/64 dev tap0".into()],
            ..SourceRule::default()
        }];
        assert!(validate_source_rules(&mut rules).is_ok());
        assert_eq!(rules[0].from, "2001:db8::1/128");

        for (from, table, priority) in [
            ("2600:70ff:f0a1::/48", 100u16, 1000u32),
            ("203.0.113.0/24", 1u16, 0u32),
            ("203.0.113.7", 65535u16, 0u32),
        ] {
            let mut one = vec![SourceRule { from: from.into(), table, priority, ..SourceRule::default() }];
            let err = validate_source_rules(&mut one);
            assert!(err.is_ok(), "合法条目 {from} table={table} 应通过: {err:?}");
        }

        let bad = [
            (
                SourceRule { from: "".into(), table: 100, ..SourceRule::default() },
                "prefix must not be empty",
            ),
            (
                SourceRule { from: "banana".into(), table: 100, ..SourceRule::default() },
                "invalid prefix",
            ),
            (
                SourceRule { from: "203.0.113.0/33".into(), table: 100, ..SourceRule::default() },
                "invalid prefix",
            ),
            (
                SourceRule {
                    from: "203.0.113.0/8 dev tap0".into(),
                    table: 100,
                    ..SourceRule::default()
                },
                "expected a bare prefix",
            ),
            (
                SourceRule { from: "203.0.113.0/24".into(), table: 0, ..SourceRule::default() },
                "must be in [1, 65535]",
            ),
            (
                SourceRule { from: "203.0.113.0/24".into(), table: 253, ..SourceRule::default() },
                "must be in [1, 65535]",
            ),
            (
                SourceRule { from: "203.0.113.0/24".into(), table: 255, ..SourceRule::default() },
                "must be in [1, 65535]",
            ),
            (
                SourceRule {
                    from: "203.0.113.0/24".into(),
                    table: 100,
                    routes: vec!["banana".into()],
                    ..SourceRule::default()
                },
                "client.source_rules[0].routes",
            ),
        ];
        for (rule, msg) in bad {
            let mut one = vec![rule];
            let err = validate_source_rules(&mut one).unwrap_err();
            assert!(err.contains(msg), "{:?} -> {err}", one[0]);
        }
    }

    #[test]
    fn policy_routing_cmds_scopes_families_and_uses_configured_priority() {
        let (pre, install) = policy_routing_cmds(&policy_spec()).unwrap();
        assert_eq!(
            pre,
            vec![
                vec!["-4", "rule", "del", "fwmark", "256", "table", "256"],
                vec!["-6", "rule", "del", "fwmark", "256", "table", "256"],
            ]
        );
        assert_eq!(
            install,
            vec![
                vec!["-4", "rule", "add", "priority", "1000", "fwmark", "256", "table", "256"],
                vec!["-6", "rule", "add", "priority", "1000", "fwmark", "256", "table", "256"],
                vec![
                    "-4", "route", "replace", "default", "via", "203.0.113.1", "dev", "tap0", "table", "256"
                ],
                vec![
                    "-6", "route", "replace", "default", "via", "fd99:10:5:8::1", "dev", "tap0", "table", "256"
                ],
                vec!["route", "replace", "fd99:10:5:8::/64", "dev", "tap0", "table", "256"],
                vec!["route", "replace", "192.0.2.0/24", "dev", "eth1", "table", "256"],
            ]
        );
        // 删规则的参数里不能出现 priority：优先级被改过之后旧值已不在配置里，
        // 带 priority 会删不到旧规则。
        for cmd in &pre {
            assert!(!cmd.iter().any(|a| a == "priority"), "{cmd:?}");
        }
    }

    #[test]
    fn policy_routing_cmds_omits_unoffered_families_and_priority() {
        let mut s = policy_spec();
        s.priority = 0;
        s.gw_v6 = String::new();
        s.extra_routes.clear();
        let (_, install) = policy_routing_cmds(&s).unwrap();
        assert_eq!(
            install,
            vec![
                vec!["-4", "rule", "add", "fwmark", "256", "table", "256"],
                vec!["-6", "rule", "add", "fwmark", "256", "table", "256"],
                vec![
                    "-4", "route", "replace", "default", "via", "203.0.113.1", "dev", "tap0", "table", "256"
                ],
            ]
        );
    }

    #[test]
    fn policy_routing_cmds_installs_source_rules_without_fwmark() {
        let s = policy_spec_with_source_rules();
        // 只配 source_rules、fwmark 为 0 时策略路由仍要生效（转发流量的唯一手段）
        assert!(s.enabled());
        let (pre, install) = policy_routing_cmds(&s).unwrap();
        assert_eq!(
            pre,
            vec![vec!["-6", "rule", "del", "from", "2001:db8::1/128", "table", "100"]]
        );
        assert_eq!(
            install,
            vec![
                vec!["-6", "rule", "add", "priority", "700", "from", "2001:db8::1/128", "table", "100"],
                vec![
                    "-6", "route", "replace", "default", "via", "fd99:10:5:8::1", "dev", "tap0", "table", "100"
                ],
                vec!["route", "replace", "fd99:10:5:8::/64", "dev", "tap0", "table", "100"],
            ]
        );
        // 规则只能落在 from 自己的地址族：iproute2 会拒绝 -4 命令里出现 IPv6 前缀
        assert!(install.iter().all(|c| c[0] != "-4"), "{install:?}");
        // 表号由配置给出，不能因为 fwmark 为 0 而被顶成 0
        for cmd in &install {
            assert!(!cmd.iter().any(|a| a == "0"), "{cmd:?}");
        }
    }

    #[test]
    fn policy_routing_cmds_uses_the_prefix_family_for_v4_source_rules() {
        let mut s = policy_spec_with_source_rules();
        s.source_rules[0].from = "192.0.2.0/24".into();
        s.source_rules[0].routes = vec!["10.0.0.0/8 dev eth1".into()];
        let (pre, install) = policy_routing_cmds(&s).unwrap();
        assert_eq!(
            pre,
            vec![vec!["-4", "rule", "del", "from", "192.0.2.0/24", "table", "100"]]
        );
        assert_eq!(
            install,
            vec![
                vec!["-4", "rule", "add", "priority", "700", "from", "192.0.2.0/24", "table", "100"],
                vec![
                    "-4", "route", "replace", "default", "via", "203.0.113.1", "dev", "tap0", "table", "100"
                ],
                vec!["route", "replace", "10.0.0.0/8", "dev", "eth1", "table", "100"],
            ]
        );
        assert!(install.iter().all(|c| c[0] != "-6"), "{install:?}");
    }

    #[test]
    fn policy_routing_cmds_rejects_source_rule_without_a_matching_gateway() {
        // 服务端没下发 IPv6 网关时，v6 的 from 规则命中后表里查不到默认路由，
        // 流量只会落回主表。报出来而不是静默跳过：否则整条规则失效而用户毫无察觉。
        let mut s = policy_spec_with_source_rules();
        s.gw_v6 = String::new();
        let err = policy_routing_cmds(&s).unwrap_err();
        assert!(err.contains("未下发 IPv6 网关"), "{err}");
    }

    #[test]
    fn policy_routing_cmds_keeps_source_rule_priority_optional() {
        let mut s = policy_spec_with_source_rules();
        s.source_rules[0].priority = 0;
        let (_, install) = policy_routing_cmds(&s).unwrap();
        let rule_adds: Vec<&Vec<String>> = install.iter().filter(|c| c[1] == "rule").collect();
        assert_eq!(rule_adds.len(), 1);
        // 0 是"交给内核分配"的保留值，不能下发给 ip route
        for cmd in rule_adds {
            assert!(!cmd.iter().any(|a| a == "priority"), "{cmd:?}");
        }
    }

    #[test]
    fn policy_routing_cmds_keeps_mark_and_source_tables_separate() {
        let mut s = policy_spec_with_source_rules();
        s.mark = 0x100;
        s.priority = 1000;
        let (pre, install) = policy_routing_cmds(&s).unwrap();
        let fwmark_rules: Vec<&Vec<String>> =
            install.iter().filter(|c| c.iter().any(|a| a == "fwmark")).collect();
        let from_rules: Vec<&Vec<String>> =
            install.iter().filter(|c| c.iter().any(|a| a == "from")).collect();
        assert_eq!(fwmark_rules.len(), 2);
        assert_eq!(from_rules.len(), 1);
        // 两套规则各自落到自己的表，不能串
        for cmd in fwmark_rules {
            assert!(cmd.iter().any(|a| a == "256"), "{cmd:?}");
            assert!(!cmd.iter().any(|a| a == "100"), "{cmd:?}");
        }
        for cmd in from_rules {
            assert!(cmd.iter().any(|a| a == "100"), "{cmd:?}");
            assert!(!cmd.iter().any(|a| a == "256"), "{cmd:?}");
        }
        // 两类的幂等删除都在场：fwmark 两个地址族各一条，source rule 只按自己的族一条
        assert_eq!(pre.len(), 3);
    }

    #[test]
    fn policy_routing_cmds_rejects_bad_extra_route() {
        let mut s = policy_spec();
        s.extra_routes = vec!["banana".into()];
        let err = policy_routing_cmds(&s).unwrap_err();
        assert!(err.contains("invalid prefix"), "{err}");
    }

    #[test]
    fn clean_policy_routing_cmds_removes_rules_before_routes() {
        let out = clean_policy_routing_cmds(&policy_spec());
        assert_eq!(
            out,
            vec![
                vec!["-4", "rule", "del", "fwmark", "256", "table", "256"],
                vec!["-6", "rule", "del", "fwmark", "256", "table", "256"],
                vec!["-6", "route", "del", "fd99:10:5:8::/64", "dev", "tap0", "table", "256"],
                vec!["-4", "route", "del", "192.0.2.0/24", "dev", "eth1", "table", "256"],
                vec!["-4", "route", "del", "default", "dev", "tap0", "table", "256"],
                vec!["-6", "route", "del", "default", "dev", "tap0", "table", "256"],
            ]
        );
    }

    #[test]
    fn clean_policy_routing_cmds_removes_source_rules() {
        let out = clean_policy_routing_cmds(&policy_spec_with_source_rules());
        assert_eq!(
            out,
            vec![
                vec!["-6", "rule", "del", "from", "2001:db8::1/128", "table", "100"],
                vec!["-6", "route", "del", "fd99:10:5:8::/64", "dev", "tap0", "table", "100"],
                vec!["-6", "route", "del", "default", "dev", "tap0", "table", "100"],
            ]
        );
    }

    #[test]
    fn policy_routing_is_a_noop_when_fwmark_is_zero() {
        let s = PolicyRoutingSpec { mark: 0, ..policy_spec() };
        assert!(!s.enabled());
        assert_eq!(policy_routing_cmds(&s).unwrap(), (Vec::new(), Vec::new()));
        assert!(clean_policy_routing_cmds(&s).is_empty());
        assert_eq!(PolicyRoutingSpec::default().priority_label(), "auto");
        assert_eq!(policy_spec().priority_label(), "1000");
    }
}
