use base64ct::{Base64, Encoding};
use parking_lot::Mutex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server as HttpServer};
use tracing::{info, warn, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// ======================= 握手协议结构（与 Go frame.go 契约一致） =======================
//
// 黄金向量锁定的字段名集合：
//   req : client_id, psk, mac, ipv4, ipv6, padding,
//         brutal_groups, brutal_total_tx, brutal_total_rx, brutal_conns, brutal_conn_index,
//         fec, fec_group, encrypt, enc_algo
//   resp: success, message, session_id, client_id, ipv4, ipv6, gw_v4, gw_v6,
//         padding, brutal_groups, brutal_total_tx, brutal_total_rx,
//         fec, fec_group, encrypt, enc_algo, enc_salt, enc_salt2
// 除 client_id/psk（req）与 success/message/client_id/ipv4/ipv6（resp）外
// 全部对齐 Go 的 omitempty：零值不出现在线路上。

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct HandshakeReq {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub protocol_version: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_instance: String,
    pub client_id: String,
    pub psk: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub brutal_groups: bool,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_total_tx: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_total_rx: u64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub brutal_conns: i64,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub brutal_conn_index: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fec: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub fec_group: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub enc_algo: i64,
    // 客户端回带上一次收到的会话令牌（hex）。protocol v2 固定要求
    // 新进程接管既有会话时携带正确令牌；首次接入时为空串。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_token: String,
}

pub const TLS_CLIENT_HELLO_FINGERPRINT_KIND: &str = "tls-clienthello-v1";

/// 服务端实际观测到的 ClientHello 与最终协商摘要。它不是 JA3/JA4：rustls 与
/// Go 标准库都不暴露完整原始扩展顺序，因此这里只哈希两端都能可靠取得的有序
/// 特征。响应仅在应用层 PSK 验证成功后返回，且不包含随机数、票据、证书正文或密钥。
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default, PartialEq, Eq)]
pub struct TLSHandshakeInfo {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint_kind: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fingerprint_sha256: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub version_id: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub cipher_suite_id: u16,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cipher_suite: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub alpn: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sni: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_cipher_suites: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_signature_schemes: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_groups: Vec<u16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub offered_alpn: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct HandshakeResp {
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub protocol_version: i64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub session_epoch: u64,
    pub success: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gw_v4: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gw_v6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub brutal_groups: bool,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_total_tx: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_total_rx: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fec: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub fec_group: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub enc_algo: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enc_salt: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enc_salt2: String,
    // 本次会话的重连接入令牌（hex）；protocol v2 固定下发，
    // 客户端须在下一次同一 client_id 的握手里回带。
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_token: String,
    // 新客户端把缺失视为旧服务端；旧客户端由 serde 默认忽略未知字段，支持滚动升级。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<TLSHandshakeInfo>,
}

pub fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
pub fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
pub fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
pub fn is_false(v: &bool) -> bool {
    !*v
}

pub fn is_tls_grease(v: u16) -> bool {
    (v >> 8) as u8 == v as u8 && (v as u8 & 0x0f) == 0x0a
}

pub fn normalize_tls_u16(values: &[u16]) -> Vec<u16> {
    values.iter().copied().filter(|v| !is_tls_grease(*v)).collect()
}

/// 规范字节串：kind + NUL；cipher/signature/group 各为 u16 大端项数和有序项；
/// ALPN 为 u16 项数及每项的 u16 字节长度和原始字节。SNI 不进摘要，避免仅因
/// 伪装域名变化就把同一种客户端实现误判成另一种指纹。
pub fn tls_client_hello_fingerprint(
    ciphers: &[u16],
    signatures: &[u16],
    groups: &[u16],
    alpn: &[String],
) -> String {
    let alpn_bytes: Vec<Vec<u8>> = alpn.iter().map(|v| v.as_bytes().to_vec()).collect();
    tls_client_hello_fingerprint_bytes(ciphers, signatures, groups, &alpn_bytes)
}

pub fn tls_client_hello_fingerprint_bytes(
    ciphers: &[u16],
    signatures: &[u16],
    groups: &[u16],
    alpn: &[Vec<u8>],
) -> String {
    let mut canonical = Vec::with_capacity(256);
    canonical.extend_from_slice(TLS_CLIENT_HELLO_FINGERPRINT_KIND.as_bytes());
    canonical.push(0);
    let mut write_u16_list = |values: &[u16]| {
        let normalized = normalize_tls_u16(values);
        let count = normalized.len().min(u16::MAX as usize);
        canonical.extend_from_slice(&(count as u16).to_be_bytes());
        for value in normalized.into_iter().take(count) {
            canonical.extend_from_slice(&value.to_be_bytes());
        }
    };
    write_u16_list(ciphers);
    write_u16_list(signatures);
    write_u16_list(groups);
    let count = alpn.len().min(u16::MAX as usize);
    canonical.extend_from_slice(&(count as u16).to_be_bytes());
    for bytes in alpn.iter().take(count) {
        let len = bytes.len().min(u16::MAX as usize);
        canonical.extend_from_slice(&(len as u16).to_be_bytes());
        canonical.extend_from_slice(&bytes[..len]);
    }
    hex::encode(Sha256::digest(&canonical))
}

pub fn normalize_tls_sni(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn tls_version_name(version: u16) -> String {
    match version {
        0x0303 => "TLS 1.2".into(),
        0x0304 => "TLS 1.3".into(),
        0 => String::new(),
        other => format!("0x{other:04x}"),
    }
}

pub fn tls_cipher_suite_name(suite: u16) -> String {
    match suite {
        0x1301 => "TLS_AES_128_GCM_SHA256".into(),
        0x1302 => "TLS_AES_256_GCM_SHA384".into(),
        0x1303 => "TLS_CHACHA20_POLY1305_SHA256".into(),
        0xc02b => "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256".into(),
        0xc02c => "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384".into(),
        0xc02f => "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".into(),
        0xc030 => "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384".into(),
        0xcca8 => "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0xcca9 => "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256".into(),
        0 => String::new(),
        other => format!("0x{other:04x}"),
    }
}

// ======================= 运行时统计（面板/指标用） =======================

#[derive(Debug)]
pub struct ClientStat {
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub mac: String,
    pub active_conns: std::sync::atomic::AtomicU32,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub force_disconnect: std::sync::atomic::AtomicBool,
    pub disconnect_version: AtomicU64,
    pub fec_mode: Mutex<String>,
    pub enc_algo: std::sync::atomic::AtomicI64,
    pub created_at: Instant,
}

impl ClientStat {
    pub fn new(id: String, ipv4: String, ipv6: String, mac: String) -> Self {
        Self {
            client_id: id,
            ipv4,
            ipv6,
            mac,
            active_conns: std::sync::atomic::AtomicU32::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            force_disconnect: std::sync::atomic::AtomicBool::new(false),
            disconnect_version: AtomicU64::new(0),
            fec_mode: Mutex::new("off".into()),
            enc_algo: std::sync::atomic::AtomicI64::new(0),
            created_at: Instant::now(),
        }
    }
}

pub type StatRegistry =
    Arc<parking_lot::RwLock<std::collections::HashMap<String, Arc<ClientStat>>>>;

/// 封禁表：clientID → 封禁到期 unix 毫秒（0=永久），对齐 Go Server.banned
pub struct BanList {
    inner: Mutex<std::collections::HashMap<String, i64>>,
}

impl BanList {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn ban(&self, client_id: &str, ttl_minutes: i64) -> bool {
        if client_id.is_empty() {
            return false;
        }
        let exp = if ttl_minutes <= 0 {
            0
        } else {
            now_unix_ms() + ttl_minutes * 60 * 1000
        };
        self.inner.lock().insert(client_id.to_string(), exp);
        true
    }

    pub fn unban(&self, client_id: &str) {
        self.inner.lock().remove(client_id);
    }

    pub fn is_banned(&self, client_id: &str) -> bool {
        if client_id.is_empty() {
            return false;
        }
        let mut map = self.inner.lock();
        match map.get(client_id) {
            None => false,
            Some(&exp) => {
                if exp > 0 && now_unix_ms() >= exp {
                    map.remove(client_id);
                    false
                } else {
                    true
                }
            }
        }
    }

    /// 返回 clientID → 剩余秒（0=永久），自动清理过期项
    pub fn snapshot(&self) -> std::collections::HashMap<String, i64> {
        let mut map = self.inner.lock();
        let now = now_unix_ms();
        map.retain(|_, exp| *exp == 0 || *exp > now);
        map.iter()
            .map(|(k, exp)| (k.clone(), if *exp == 0 { 0 } else { (*exp - now) / 1000 }))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl Default for BanList {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ======================= 日志环形缓冲 + 运行时级别 =======================

pub struct LogLine {
    pub seq: u64,
    pub level: String,
    pub time: String,
    pub msg: String,
}

lazy_static::lazy_static! {
    static ref LOG_RING: Mutex<LogRing> = Mutex::new(LogRing::new(500));
    pub static ref LOG_LEVEL_HANDLE: std::sync::OnceLock<tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>> = std::sync::OnceLock::new();
    static ref LOG_LEVEL_NAME: Mutex<String> = Mutex::new("info".into());
}

struct LogRing {
    seq: u64,
    lines: Vec<LogLine>,
    cap: usize,
}

impl LogRing {
    fn new(cap: usize) -> Self {
        Self {
            seq: 0,
            lines: Vec::new(),
            cap,
        }
    }
    fn add(&mut self, level: &str, msg: &str) {
        self.seq += 1;
        self.lines.push(LogLine {
            seq: self.seq,
            level: level.to_string(),
            time: wall_clock_hms(),
            msg: msg.to_string(),
        });
        if self.lines.len() > self.cap {
            let drop = self.lines.len() - self.cap;
            self.lines.drain(..drop);
        }
    }
    fn snapshot(&self, after: u64) -> Vec<&LogLine> {
        self.lines.iter().filter(|l| l.seq > after).collect()
    }
}

// 当地时间不可用时以 UTC 呈现（仅面板展示用途）
fn wall_clock_hms() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86400;
    let ms = now.subsec_millis();
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        ms
    )
}

struct LogRingLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogRingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let level = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        LOG_RING.lock().add(level, &visitor.0);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

/// 初始化日志系统：终端输出 + 环形缓冲 + 可热更级别
pub fn init_logging(level: &str) {
    let filter = EnvFilter::new(level);
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    let _ = LOG_LEVEL_HANDLE.set(handle);
    *LOG_LEVEL_NAME.lock() = level.to_lowercase();

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(LogRingLayer)
        .init();
}

pub fn current_log_level_name() -> String {
    LOG_LEVEL_NAME.lock().clone()
}

pub fn set_runtime_log_level(level: &str) -> Result<(), String> {
    let level = level.trim();
    if matches!(
        level.to_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        if let Some(h) = LOG_LEVEL_HANDLE.get() {
            h.modify(|f| *f = EnvFilter::new(level))
                .map_err(|e| e.to_string())?;
        }
        *LOG_LEVEL_NAME.lock() = level.to_lowercase();
        Ok(())
    } else {
        Err(format!("invalid log level {:?}", level))
    }
}

pub fn log_ring_snapshot(after: u64) -> Vec<serde_json::Value> {
    let ring = LOG_RING.lock();
    ring.snapshot(after)
        .into_iter()
        .map(|l| {
            json!({
                "seq": l.seq,
                "level": l.level,
                "time": l.time,
                "msg": l.msg,
            })
        })
        .collect()
}

// ======================= 进程级指标辅助 =======================

pub fn thread_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Threads:") {
                    return rest.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// 进程 RSS（MB）。heap_alloc_mb 以 RSS 近似呈现（Rust 无 Go 式堆统计）。
pub fn rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = s.split_whitespace().nth(1) {
                if let Ok(pages) = pages.parse::<u64>() {
                    return pages as f64 * 4096.0 / 1024.0 / 1024.0;
                }
            }
        }
        0.0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0.0
    }
}

// ======================= 面板"运行状态"页的数据源 =======================

/// 生效配置与宿主信息的扁平快照。main 在启动时构建一次：Rust 版没有配置热更，
/// 配置只在启动时读一遍，所以这里不需要锁。每次 /api/stats 都并入同一份拷贝，
/// 让面板的"状态"页能直接展示当前实际生效的开关，而不是让运维去翻配置文件。
#[derive(Debug, Clone, Default)]
pub struct RuntimeCtx {
    pub cfg: serde_json::Value,
    pub system: serde_json::Value,
}

impl RuntimeCtx {
    /// 从最终生效的 Args 拍快照。只放"开关现在是开还是关"这类信息，
    /// PSK 等凭据不进入面板：浏览器缓存一份可保存的凭据没有意义还多一个泄露面。
    pub fn from_args(args: &crate::Args, cfg_path: &str) -> Self {
        let pad_actual = crate::crypto::pad_mode_name();
        let web_https = !args.web_cert.is_empty() && !args.web_key.is_empty();
        let mut cfg = serde_json::json!({
                "mode": args.mode,
                "encrypt": args.encrypt,
                "enc_algo": args.enc_algo,
                "min_enc": args.min_enc,
                "pad_mode": pad_actual,
                "brutal": args.brutal,
                "brutal_up": args.brutal_up,
                "brutal_down": args.brutal_down,
                "socks5": !args.socks5.is_empty(),
                "fec": args.fec,
                "fec_group": args.fec_group,
                "log_level": args.loglevel,
                "up": !args.up.is_empty(),
                "down": !args.down.is_empty(),
                "conns": args.conns,
                "workers": args.workers,
                "mtu": args.mtu,
                "tap": args.tap,
                "mac": args.mac,
                "addr": args.addr,
                "web_addr": args.web,
                "web_auth": !args.web_auth.is_empty(),
                "web_bind": args.web_bind,
                "web_https": web_https,
                "encrypt_psk": true,
                "max_sessions": args.max_sessions,
                "v4_cidr": args.v4cidr,
                "v6_cidr": args.v6cidr,
                "req_v4": args.req_v4,
                "req_v6": args.req_v6,
                "sni": args.sni,
                "insecure": args.insecure,
                "cert_sha256": args.cert_sha256,
                "interface_manager": args.interface_manager,
                "fwmark": args.fwmark,
                "fwmark_priority": args.fwmark_priority,
                // 表号永远等于 fwmark 值，这不是巧合而是约定：显式列出来，
                // 免得用户拿错表号去查 ip route
                "fwmark_table": args.fwmark,
                "extra_routes": args.extra_routes,
                "source_rules": args.source_rules,
                "encrypt_present": args.encrypt_present,
            });
        // FEC 分组策略是服务端专属配置。客户端模式下这两个值是协议边界默认，
        // 显示出来会被误读成客户端策略，因此只在服务端模式下发。
        if args.mode == "server" {
            cfg["fec_group_min"] = serde_json::json!(args.fec_group_min);
            cfg["fec_group_max"] = serde_json::json!(args.fec_group_max);
        }
        Self {
            cfg,
            system: system_info(cfg_path),
        }
    }
}

fn read_proc_trim(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// 宿主平台与进程信息。Hostname 失败时留空（容器场景常见）。
pub fn system_info(cfg_path: &str) -> serde_json::Value {
    let cpu = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    serde_json::json!({
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "num_cpu": cpu,
        "host": host_name(),
        "cfg_path": cfg_path.to_string(),
    })
}

/// TCP Brutal 的内核侧状态。
///
/// 主机名。Windows 上没有 HOSTNAME，只有 COMPUTERNAME；两个环境变量都没设时再读
/// /etc/hostname 兜底。面板的"系统与进程"页靠它区分同一台机器上跑的多个进程，读不到
/// 就留空让前端显示 "-"，而不是让运维以为是另一台机器。
fn host_name() -> String {
    for var in ["COMPUTERNAME", "HOSTNAME"] {
        if let Ok(h) = std::env::var(var) {
            if !h.is_empty() {
                return h;
            }
        }
    }
    if let Ok(s) = std::fs::read_to_string("/etc/hostname") {
        let t = s.trim();
        if !t.is_empty() {
            return t.to_owned();
        }
    }
    String::new()
}

/// 支持性按"可用拥塞控制列表里有没有 brutal"判定，而不是按当前值：当前是
/// cubic 并不代表模块没装，把两者混在一起就无法区分"没装模块"与"装了没启用"。
/// 非 Linux（或 /proc 缺失）返回 supported=false 加明确原因。
pub fn brutal_system_status() -> serde_json::Value {
    let current = {
        let s = read_proc_trim("/proc/sys/net/ipv4/tcp_congestion_control");
        if s.is_empty() {
            String::new()
        } else {
            s
        }
    };
    let avail_raw = read_proc_trim("/proc/sys/net/ipv4/tcp_available_congestion_control");
    let available: Vec<String> = if avail_raw.is_empty() {
        Vec::new()
    } else {
        avail_raw
            .split_whitespace()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    };
    let supported = available.iter().any(|s| s == "brutal");
    let mut error = String::new();
    if current.is_empty() && avail_raw.is_empty() {
        error = "not Linux: TCP Brutal needs a Linux kernel with tcp pacing".to_string();
    } else if !supported {
        error = format!(
            "kernel exposes no 'brutal' congestion controller (current={}, available={})",
            if current.is_empty() { "-" } else { &current },
            if avail_raw.is_empty() { "-" } else { &avail_raw }
        );
    }
    serde_json::json!({
        "supported": supported,
        "kernel_current": current,
        "kernel_available": available,
        "error": error,
    })
}

/// 把内层加密强度下限的运行时取值（rank）翻译成配置页显示用的字符串。
/// 只有一种算法（GCM），所以 rank>0 一律是 "gcm"，0 是未设下限。
pub fn min_enc_label(rank: i64) -> &'static str {
    if rank > 0 { "gcm" } else { "" }
}

// ======================= 面板（与 Go dashboardHTML 同源） =======================

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tlsvpn Dashboard</title>
<style>
/* 深色为默认；浅色由 data-theme="light" 覆盖。JS 只负责切这一个属性，
   画布里的网格/曲线颜色再读 CSS 变量，避免两处各存一份色值 */
:root{--bg:#121212;--panel:#1e1e1e;--panel2:#242424;--border:#333;--text:#e0e0e0;
--muted:#999;--accent:#bb86fc;--up:#03dac6;--warn:#e1c94e;--err:#ff7597;
--code-bg:#0d0d0d;--ok-bg:#1b3a2f;--ok-fg:#4ee1a0;--dup-bg:#3a341b;--dup-fg:#e1c94e;
--off-bg:#333;--off-fg:#888;--field:#2a2a2a;--field-bd:#444;--field-fg:#ddd}
:root[data-theme="light"]{--bg:#f4f6f9;--panel:#ffffff;--panel2:#eef1f5;--border:#dde1e7;
--text:#1c1e21;--muted:#5f6469;--accent:#7c4dff;--up:#00897b;--warn:#9a6a00;--err:#c62839;
--code-bg:#f0f2f5;--ok-bg:#e2f5eb;--ok-fg:#157347;--dup-bg:#fcf3d0;--dup-fg:#8a6100;
--off-bg:#e3e6ea;--off-fg:#5f6469;--field:#ffffff;--field-bd:#c9ced6;--field-fg:#1c1e21}
body { font-family:'Segoe UI',Tahoma,sans-serif; background:var(--bg); color:var(--text); margin:0; padding:20px; transition:background .2s,color .2s; }
.wrap { max-width:1320px; margin:0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.card { background:var(--panel); border:1px solid var(--border); border-radius:8px; padding:14px 18px; box-shadow:0 4px 6px rgba(0,0,0,.12); margin-bottom:14px; }
.card.wide { grid-column:1/-1; }
.errbar { background:var(--panel2); border:1px solid var(--err); border-left:4px solid var(--err); border-radius:8px; padding:9px 13px; margin-bottom:14px; color:var(--err); font-family:ui-monospace,Consolas,monospace; font-size:12.5px; line-height:1.6; word-break:break-all; }
.errbar small { color:var(--muted); display:block; font-family:'Segoe UI',Tahoma,sans-serif; font-size:.85em; }
h1 { color:var(--accent); margin:0 0 12px; font-size:1.35em; }
h1 small { color:var(--muted); font-weight:normal; font-size:.55em; margin-left:8px; }
h2 { margin:0 0 10px; color:var(--accent); font-size:1.02em; }
.topbar { display:flex; justify-content:space-between; align-items:flex-start; gap:12px; flex-wrap:wrap; }
.theme-ctl { display:flex; align-items:center; gap:6px; font-size:.84em; color:var(--muted); padding-top:6px; }
.theme-ctl select { background:var(--field); color:var(--field-fg); border:1px solid var(--field-bd); border-radius:4px; padding:4px 8px; font-size:1em; }
.kpi { font-size:1.5em; font-weight:bold; color:var(--up); }
.sub { color:var(--muted); font-size:.84em; margin-top:3px; }
table { width:100%; border-collapse:collapse; margin-top:8px; }
th,td { padding:7px 9px; text-align:left; border-bottom:1px solid var(--border); font-size:.88em; white-space:nowrap; }
th { background:var(--panel2); color:var(--muted); }
table.kv { margin-top:4px; }
table.kv td { border-bottom:1px solid var(--border); white-space:normal; }
table.kv td.k { color:var(--muted); width:42%; font-size:.84em; }
table.kv td.v { font-size:.86em; overflow-wrap:anywhere; }
.speed { color:var(--up); font-weight:bold; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:.78em; font-weight:600; }
.b-on { background:var(--ok-bg); color:var(--ok-fg); } .b-dup { background:var(--dup-bg); color:var(--dup-fg); } .b-off { background:var(--off-bg); color:var(--off-fg); }
.btn { padding:3px 10px; background:#cf6679; color:white; border:none; border-radius:4px; cursor:pointer; font-size:.82em; margin-right:4px; }
.btn:hover { background:#ff7597; }
.btn.blue { background:#3d5a80; } .btn.blue:hover { background:#5b84b1; }
.btn.gray { background:var(--off-bg); color:var(--text); } .btn.gray:hover { background:var(--field-bd); }
#chart { width:100%; height:170px; display:block; }
.legend { font-size:.8em; color:var(--muted); margin-top:6px; }
.legend span { margin-right:14px; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:4px; }
.note { font-size:.8em; color:var(--muted); margin-top:8px; }
.note.bad { color:var(--warn); }
#logbox { background:var(--code-bg); border:1px solid var(--border); border-radius:6px; padding:10px; height:220px; overflow-y:auto; font:12px/1.5 Consolas,monospace; }
#logbox .lv-WARN { color:var(--warn); } #logbox .lv-ERROR,#logbox .lv-PANIC { color:var(--err); } #logbox .lv-DEBUG { color:var(--muted); }
.logbar { display:flex; gap:8px; align-items:center; margin-top:8px; flex-wrap:wrap; }
.logbar select,.logbar input { background:var(--field); color:var(--field-fg); border:1px solid var(--field-bd); border-radius:4px; padding:4px 8px; font-size:.85em; }
.logbar input { width:110px; }
.tabs { display:flex; gap:6px; margin-bottom:10px; flex-wrap:wrap; }
.tabs button { background:var(--field); color:var(--muted); border:none; border-radius:4px 4px 0 0; padding:6px 14px; cursor:pointer; font-size:.88em; }
.tabs button.on { background:var(--accent); color:var(--bg); font-weight:600; }
.pane { display:none; } .pane.on { display:block; }
footer { text-align:center; color:var(--muted); font-size:.78em; margin-top:16px; }
@media (max-width:640px){ th,td{padding:5px;} .hide-sm{display:none;} }
</style>
</head>
<body>
<div class="wrap">
<div class="topbar">
<h1>🚀 tlsvpn <span id="mode">…</span><small id="meta"></small></h1>
<label class="theme-ctl">主题
<select id="theme">
  <option value="system">跟随系统</option>
  <option value="light">浅色</option>
  <option value="dark">深色</option>
</select>
</label>
</div>
<div class="errbar" id="errbar" style="display:none"><span id="errbar-msg"></span>
<small>下一轮成功会自动消失；若反复出现，刷新页面（Ctrl+F5）重试，服务端重启后带凭据的旧地址栏也要重新输入一次</small></div>
<div class="grid">
  <div class="card"><div class="sub">活跃客户端/设备</div><div class="kpi" id="active-clients">0</div><div class="sub" id="conns-sub">TCP 连接: -</div></div>
  <div class="card"><div class="sub">总发送</div><div class="kpi" id="total-tx">0 B</div><div class="sub">↑ <span id="total-tx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">总接收</div><div class="kpi" id="total-rx">0 B</div><div class="sub">↓ <span id="total-rx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">运行时长</div><div class="kpi" id="uptime">-</div><div class="sub">版本 <span id="ver">-</span> · GC <a href="#" onclick="doAction('gc');return false;" style="color:#5b84b1">立即回收</a></div></div>
  <div class="card"><div class="sub">FEC 恢复 / 确认丢失</div><div class="kpi" id="fec-kpi">-</div><div class="sub">校验帧 <span id="parity">-</span> · 丢帧(队列) <span id="dropped">-</span> · 重排跳过 <span id="reorder-skipped">-</span></div></div>
  <div class="card"><div class="sub">进程内存</div><div class="kpi" id="mem">-</div><div class="sub">线程数: <span id="goroutines">-</span></div></div>
  <div class="card" id="ippool-card" style="display:none"><div class="sub">IPv4 地址池</div><div class="kpi" id="ippool-kpi">-</div><div class="sub">IPv6 已分配: <span id="v6used">-</span></div></div>
</div>
<div class="card wide"><h2>吞吐趋势 <span style="font-size:.7em;color:#888">(近 120 秒)</span></h2>
  <canvas id="chart" width="1160" height="170"></canvas>
  <div class="legend"><span><i class="dot" style="background:#03dac6"></i>上行</span><span><i class="dot" style="background:#bb86fc"></i>下行</span></div></div>

<div class="card wide">
  <div class="tabs">
    <button class="on" data-pane="status" onclick="showPane(this)">运行状态</button>
    <button data-pane="clients" onclick="showPane(this)">客户端</button>
    <button data-pane="conns" onclick="showPane(this)">连接明细</button>
    <button data-pane="macs" id="macs-tab" onclick="showPane(this)">MAC 表</button>
    <button data-pane="bans" id="bans-tab" onclick="showPane(this)">封禁</button>
    <button data-pane="logs" onclick="showPane(this)">日志</button>
  </div>

  <div class="pane on" id="pane-status">
    <div class="grid">
      <div class="card"><h2>会话协商结果</h2><table class="kv"><tbody id="st-neg"></tbody></table></div>
      <div class="card"><h2>TCP Brutal</h2><table class="kv"><tbody id="st-brut"></tbody></table>
        <div id="st-brut-note" class="note"></div></div>
    </div>
    <div class="grid">
      <div class="card"><h2>生效配置</h2><div style="overflow-x:auto"><table class="kv"><tbody id="st-cfg"></tbody></table></div></div>
      <div class="card"><h2>系统与进程</h2><table class="kv"><tbody id="st-sys"></tbody></table></div>
    </div>
  </div>

  <div class="pane" id="pane-clients">
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ID</th><th>IPv4</th><th class="hide-sm">IPv6</th><th class="hide-sm">MAC</th><th>TCP</th><th>TX (发)</th><th>RX (收)</th><th>↑ 速率</th><th>↓ 速率</th><th class="hide-sm">FEC</th><th class="hide-sm">FEC 分组</th><th class="hide-sm">加密</th><th class="hide-sm">会话</th><th class="hide-sm">代际</th><th class="hide-sm">Brutal 上/下</th><th class="hide-sm">在线</th><th>操作</th></tr></thead>
      <tbody id="clients-body"></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-conns"><div style="overflow-x:auto"><table>
    <thead><tr><th>#</th><th>目标</th><th>对端</th><th>状态</th><th>RTT</th><th>TX</th><th>RX</th><th class="hide-sm">重试</th><th class="hide-sm">在线</th><th class="hide-sm">FEC</th><th class="hide-sm">加密</th><th class="hide-sm">Brutal</th><th class="hide-sm">最近错误</th><th>操作</th></tr></thead>
    <tbody id="conns-body"><tr><td colspan="14" style="color:var(--muted)">仅客户端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-macs"><div style="overflow-x:auto"><table>
    <thead><tr><th>MAC</th><th>端口</th><th>最近活跃</th></tr></thead>
    <tbody id="macs-body"><tr><td colspan="3" style="color:var(--muted)">仅服务端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-bans">
    <div class="logbar"><input id="ban-id" placeholder="ClientID（可短前缀）"><input id="ban-min" placeholder="分钟（留空=永久）" style="width:150px">
    <button class="btn blue" onclick="addBan()">封禁</button><button class="btn gray" onclick="loadBans()">刷新</button></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ClientID</th><th>剩余</th><th>操作</th></tr></thead>
      <tbody id="bans-body"><tr><td colspan="3" style="color:var(--muted)">仅服务端模式提供</td></tr></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-logs">
    <div id="logbox"></div>
    <div class="logbar">
      <label style="font-size:.85em;color:var(--muted)">级别
        <select id="loglevel" onchange="setLogLevel(this.value)">
          <option value="debug">debug</option><option value="info">info</option>
          <option value="warn">warn</option><option value="error">error</option>
        </select>
      </label>
      <label style="font-size:.85em;color:var(--muted)"><input type="checkbox" id="autoscroll" checked> 自动滚动</label>
      <button class="btn gray" onclick="logSeq=0;document.getElementById('logbox').innerHTML=''">清屏</button>
    </div>
  </div>
</div>
<footer>tlsvpn dashboard · 数据每 2 秒刷新 · <span id="tls-flag"></span></footer>
</div>
<script>
// ---------- 错误可见化（必须最先注册：脚本自身出错也要能写进面板） ----------
// 之前 fetch 抛错只进 console，面板永远停在"…"骨架上，只看到一片空白，
// 分不清是网络不通、认证失败还是脚本自己挂了。现在把最后一次失败显示在顶部，
// 下一轮成功自动消失；累计超过 300 次就静默，别让面板变成报错日志。
let errCount=0;
function showErr(scope,msg){
  const box=document.getElementById('errbar');if(!box)return;
  const n=++errCount,t=document.getElementById('errbar-msg');
  if(t)t.textContent='⚠ 第 '+n+' 次失败 · '+scope+'：'+(msg||'未知错误');
  box.style.display=n>300?'none':'';
}
function clearErr(){const box=document.getElementById('errbar');if(box)box.style.display='none';}
window.addEventListener('error',ev=>showErr('脚本',ev.message||ev.reason||(ev.error&&ev.error.message)));
window.addEventListener('unhandledrejection',ev=>showErr('异步',ev.reason&&ev.reason.message||String(ev.reason)));

const MAXPTS=60;let prev={},lastT=0;const txHist=[],rxHist=[];
let logSeq=0,logTimer=null;

// ---------- 主题 ----------
// 深色是 CSS 默认；'system' 跟随操作系统的 prefers-color-scheme，切系统主题时
// 面板跟着切，不必手动选。选择持久化到 localStorage。
const THEME_KEY='tlsvpn_theme';
const themeSel=document.getElementById('theme');
const savedTheme=localStorage.getItem(THEME_KEY)||'system';
if(!Array.from(themeSel.options).some(o=>o.value===savedTheme))themeSel.value='system';else themeSel.value=savedTheme;
function isDarkSystem(){return window.matchMedia('(prefers-color-scheme: dark)').matches;}
function applyTheme(){
  const v=themeSel.value;
  const dark=v==='dark'||(v==='system'&&isDarkSystem());
  document.documentElement.dataset.theme=dark?'':'light';
  drawChart();
}
themeSel.addEventListener('change',()=>{localStorage.setItem(THEME_KEY,themeSel.value);applyTheme();});
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change',()=>{
  if(themeSel.value==='system')applyTheme();
});
// 首屏就套上主题，避免第一次轮询画图表前闪一下默认深色
applyTheme();
function cssv(name,fallback){
  const v=getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return v||fallback;
}

function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=['B','KB','MB','GB','TB'],i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'天'+h+'时';if(h>0)return h+'时'+m+'分';if(m>0)return m+'分'+(s%60)+'秒';return s+'秒';}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">关闭</span>';
  return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===2)return '<span class="badge b-on">AES-256-GCM</span>';
  if(a===4)return '<span class="badge b-on">AES-128-GCM</span>';
  return '<span class="badge b-off">明文</span>';}
function onoff(b){return b?'<span class="badge b-on">开启</span>':'<span class="badge b-off">关闭</span>';}
// kvRows 的单元格值按 HTML 原样输出，徽章行需要标签；来自 ip stderr 的报错
// 文本必须先转义，否则一条带 < 的内核消息就能改写面板结构
function esc(s){return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\x22/g,'&quot;').replace(/\x27/g,'&#39;');}
// 空值不占行：面板上留一堆空行只会让人误以为字段缺失是故障
function kvRows(pairs){return pairs.filter(p=>p&&p[1]!==undefined&&p[1]!==null&&p[1]!==''&&p[1]!==false)
  .map(p=>'<tr><td class="k">'+p[0]+'</td><td class="v">'+p[1]+'</td></tr>').join('');}
function showPane(btn){document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');document.getElementById('pane-'+btn.dataset.pane).classList.add('on');
  if(btn.dataset.pane==='logs')startLogPoll();else stopLogPoll();}

function drawChart(){
  const c=document.getElementById('chart'),ctx=c.getContext('2d'),W=c.width,H=c.height;
  ctx.clearRect(0,0,W,H);ctx.strokeStyle=cssv('--border','#2a2a2a');
  for(let i=1;i<4;i++){ctx.beginPath();ctx.moveTo(0,H*i/4);ctx.lineTo(W,H*i/4);ctx.stroke();}
  if(txHist.length<2)return;
  const max=Math.max(...txHist,...rxHist,1);
  const plot=(h,col)=>{ctx.strokeStyle=col;ctx.lineWidth=2;ctx.beginPath();
    h.forEach((v,i)=>{const x=i/(MAXPTS-1)*W,y=H-6-(v/max)*(H-20);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();};
  plot(txHist,cssv('--up','#03dac6'));plot(rxHist,cssv('--accent','#bb86fc'));
  ctx.fillStyle=cssv('--muted','#888');ctx.font='11px sans-serif';ctx.fillText(fmtBytes(max),4,12);
}

// 用带凭据的地址（http://admin:xx@host/ 打开面板）时，Chrome 拒绝构造任何 fetch——
// "Request cannot be constructed from a URL that includes credentials"——于是每一轮轮询都抛
// 同一条 TypeError，面板永远停在初始骨架上，日志里只剩一行重复报错，完全看不出是地址栏
// 里的凭据引起的。换成 Authorization 头 + 去掉 userinfo 的 URL 即可；同域请求带这个头
// 不触发预检，所以不影响未启用认证的情况。
const AUTH_HDR=(location.username||location.password)
  ?{Authorization:'Basic '+btoa(unescape(encodeURIComponent(location.username+':'+location.password)))}
  :{};
// location.origin 按规范不含 userinfo，是构造不带凭据 URL 的可靠基址
function url(path){return location.origin+path;}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},AUTH_HDR,opts.headers||{});return fetch(url(path),opts);}

async function fetchStats(){
  try{
    const res=await fetch(url('/api/stats'),AUTH_HDR);
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>需要认证：请用 <code>-web-auth user:pass</code> 配置的凭据登录。</p></div>';return;}
    const data=await res.json();
    clearErr();
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':'HTTP（建议 -web-cert 启用 HTTPS）';

    let tbody='',tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};tTxS+=sx;tRxS+=sr;
      const sid=id.length>10?id.slice(0,10)+'…':id;
      const bid=c.session_id?(c.session_id.length>10?c.session_id.slice(0,10)+'…':c.session_id):'-';
      // 上=客户端上行（会话里的 brutal_rx），下=服务端下发（会话里的 brutal_tx）。
      // 曾写成 brutal_tx / brutal_rx 却配「上/下」表头，两个方向整个对调。
      const brut=c.brutal_applied
        ?((c.brutal_rx||0)+'↑/'+(c.brutal_tx||0)+'↓')
        :((c.brutal_rx||c.brutal_tx)?'未生效':'-');
      const brutTitle=c.brutal_error||'客户端→服务端（上行）/ 服务端→客户端（下行）(Mbps)';
      tbody+='<tr><td title="'+esc(id)+'">'+esc(sid)+'</td><td>'+esc(c.ipv4||'-')+'</td><td class="hide-sm">'+esc(c.ipv6||'-')+'</td>'+
        '<td class="hide-sm">'+esc(c.mac||'-')+'</td><td>'+c.active_conns+'</td>'+
        '<td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
        '<td class="speed">'+fmtBytes(sx,true)+'</td><td class="speed">'+fmtBytes(sr,true)+'</td>'+
        '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+(c.fec_group||'-')+'</td>'+
        '<td class="hide-sm">'+encBadge(c.enc_algo)+'</td><td class="hide-sm" title="'+esc(bid)+'">'+esc(bid)+'</td>'+
        '<td class="hide-sm">'+(c.session_epoch||'-')+'</td>'+
        '<td class="hide-sm" title="'+esc(brutTitle)+'">'+brut+'</td>'+
        '<td class="hide-sm">'+(c.online_sec?fmtDur(c.online_sec):'-')+'</td>'+
        '<td>'+(data.mode==='server'?'<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>'+
          '<button class="btn blue" onclick="banClient(\''+id+'\',0)">封禁</button>':'-')+'</td></tr>';
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;txHist.push(tTxS);rxHist.push(tRxS);
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();}
    drawChart();

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText='TCP 连接: '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('clients-body').innerHTML=tbody||'<tr><td colspan="17" style="color:var(--muted)">暂无客户端</td></tr>';

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small style="font-size:.6em;color:var(--muted)">/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    document.getElementById('dropped').innerText=data.dropped_frames||0;
    document.getElementById('reorder-skipped').innerText=(data.reorder||{}).skipped_frames||0;
    const m=data.mem||{};
    // 取不到时后端给 0。直接显示 "0.0 MB / 0" 会让运维以为进程几乎不占内存，
    // 真相是没有统计到——留空比给个假的零诚实。
    const rss=m.heap_alloc_mb||0,thr=m.num_goroutine||0;
    document.getElementById('mem').innerHTML=rss>0?(m.heap_alloc_mb).toFixed(1)+'<small style="font-size:.55em;color:var(--muted)"> MB</small>':'—';
    document.getElementById('goroutines').innerText=thr>0?thr:'—';

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small style="font-size:.55em;color:var(--muted)"> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('AES-256-GCM');else if(data.enc_algo===4)meta.push('AES-128-GCM');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    const neg0=data.negotiate||{};if(neg0.protocol_version)meta.push('协议 v'+neg0.protocol_version);
    document.getElementById('meta').innerText=meta.join(' · ');

    renderStatus(data);renderConns(data);renderMacs(data);renderBans(data);
  }catch(e){console.error('获取统计数据失败',e);showErr('统计数据',e&&e.message||e);}
}

function renderStatus(data){
  const s=data.system||{},c=data.cfg||{},g=data.negotiate||{},b=g.brutal||{},tls=g.tls||{},bs=data.brutal_system||{},mem=data.mem||{};
  // 内核态（模块在不在、当前 cc、可用列表）来自 brutal_system：它每轮都算，不依赖有没有会话。
  // 协商对象里的同名字段只在 brutal_system 缺时才兜底，免得一台没有任何客户端的机器
  // 只显示一堆 '-'，看不出 Brutal 到底能不能用。
  const ker={
    kernel_supported:bs.supported!==undefined?bs.supported:b.kernel_supported,
    kernel_current:bs.kernel_current||b.kernel_current,
    kernel_available:(bs.kernel_available&&bs.kernel_available.length)?bs.kernel_available:b.kernel_available,
    error:b.error||bs.error
  };

  document.getElementById('st-sys').innerHTML=kvRows([
    ['运行模式',c.mode||data.mode||'-'],
    ['操作系统',s.os||'-'],
    ['架构',s.arch||'-'],
    ['CPU 核数',s.num_cpu||'-'],
    ['主机名',s.host||'-'],
    ['配置文件',s.cfg_path||'（默认配置）'],
    ['版本',data.version||'-'],
    ['运行时长',fmtDur(data.uptime_sec||0)],
    ['服务端 / 对端地址',c.addr||'-'],
    ['面板地址',c.web_addr||'未启用'],
    ['面板认证',c.web_auth?'已启用':'未启用（建议配置）'],
    ['面板传输',c.web_addr?(c.web_https?'HTTPS':'HTTP'):'-'],
    ['面板绑定方式',c.web_bind||'all'],
    ['日志级别',data.log_level||c.log_level||'-'],
    ['内存 / 线程',(mem.heap_alloc_mb>0?mem.heap_alloc_mb.toFixed(1)+' MB':'-')+' / '+(mem.num_goroutine>0?mem.num_goroutine:'-')],
  ]);

  document.getElementById('st-cfg').innerHTML=kvRows([
    ['内层加密 encrypt',c.encrypt?'开启':'关闭'],
    ['内层算法 enc_algo',c.enc_algo||'-'],
    ['加密下限 min_enc',c.min_enc||'不限'],
    ['混淆填充 pad_mode',c.pad_mode||'-'],
    ['TCP Brutal',c.brutal?'开启':'关闭'],
    ['Brutal 上行 (Mbps)',c.brutal_up||'-'],
    ['Brutal 下行 (Mbps)',c.brutal_down||'-'],
    ['FEC',c.fec?'开启':'关闭'],
    ['FEC 分组',c.fec_group||'-'],
    // 服务端策略区间：对照每个客户端协商到的 K，越界的 FEC 握手会被拒
    ['FEC 分组下限 fec_group_min',typeof c.fec_group_min==='number'?c.fec_group_min:'-'],
    ['FEC 分组上限 fec_group_max',typeof c.fec_group_max==='number'?c.fec_group_max:'-'],
    ['物理连接数 conns',c.conns||'-'],
    ['工作线程 workers',c.workers||'-'],
    ['MTU',c.mtu||'-'],
    ['TAP 接口',c.tap||'-'],
    ['MAC 地址',c.mac||'-'],
    ['SOCKS5 代理',c.socks5?'开启':'关闭'],
    ['会话上限 max_sessions',c.max_sessions||'-'],
    ['IPv4 网段 v4_cidr',c.v4_cidr||'-'],
    ['IPv6 网段 v6_cidr',c.v6_cidr||'-'],
    ['请求 IPv4 req_v4',c.req_v4||'-'],
    ['请求 IPv6 req_v6',c.req_v6||'-'],
    ['SNI 伪装',c.sni||'-'],
    ['服务端证书校验',c.insecure?'已跳过':'开启'],
    ['证书指纹 cert_sha256',c.cert_sha256||'-'],
    ['策略路由 fwmark',c.fwmark||'-'],
    ['规则优先级 fwmark_priority',c.fwmark_priority||'自动'],
    ['路由表号 fwmark_table',c.fwmark_table||'-'],
    ['额外路由 extra_routes',Array.isArray(c.extra_routes)&&c.extra_routes.length?c.extra_routes.join(' ; '):'-'],
    // 元素是对象，直接 join 会变成 [object Object]，转成 JSON 展示
    ['按源前缀路由 source_rules',Array.isArray(c.source_rules)&&c.source_rules.length?c.source_rules.map(x=>JSON.stringify(x)).join(' ; '):'-'],
    ['encrypt 字段是否显式写入',c.encrypt_present===false?'未写（按开启处理）':'已写入'],
  ]);

  document.getElementById('st-neg').innerHTML=kvRows([
    ['协议版本','v'+(g.protocol_version||'-')],
    ['内层加密算法',g.enc_algo===2?'AES-256-GCM':(g.enc_algo?'未知('+g.enc_algo+')':'明文（未启用）')],
    ['加密下限 min_enc',g.min_enc||'不限'],
    ['混淆填充 pad_mode',g.pad_mode||'-'],
    ['FEC',g.fec?'开启':'关闭'],
    ['FEC 分组',g.fec_group||'-'],
    ['会话令牌',g.session_token?'已下发':'未启用'],
    ['会话代际 epoch',g.session_epoch||'-'],
    ['每连接上行预算 (Mbps)',g.tx_rate_mbps||'-'],
    ['每连接下行预算 (Mbps)',g.rx_rate_mbps||'-'],
    ['最近连接 ClientHello 指纹（自定义，非 JA3/JA4）',tls.fingerprint_sha256?'<span class="mono">'+esc(tls.fingerprint_kind+':'+tls.fingerprint_sha256)+'</span>':'-'],
    ['TLS 协商版本',tls.version?'<span class="mono">'+esc(tls.version+' (0x'+Number(tls.version_id||0).toString(16).padStart(4,'0')+')')+'</span>':'-'],
    ['TLS 协商套件',tls.cipher_suite?'<span class="mono">'+esc(tls.cipher_suite+' (0x'+Number(tls.cipher_suite_id||0).toString(16).padStart(4,'0')+')')+'</span>':'-'],
    ['TLS ALPN',tls.alpn?'<span class="mono">'+esc(tls.alpn)+'</span>':'-'],
    ['TLS SNI',tls.sni?'<span class="mono">'+esc(tls.sni)+'</span>':'-'],
    ['ClientHello 特征数',tls.fingerprint_sha256?'<span class="mono">'+(tls.offered_cipher_suites||[]).length+' cipher / '+(tls.offered_signature_schemes||[]).length+' sig / '+(tls.offered_groups||[]).length+' group / '+(tls.offered_alpn||[]).length+' ALPN</span>':'-'],
    ['会话上限',g.max_sessions||'-'],
    ['SOCKS5 代理',g.socks5?'开启（本端不整形）':'-'],
    ['策略路由',
      (typeof g.policy_routing==='boolean')
        ? (g.policy_routing_error
            ? '<span class="badge b-off">'+esc(g.policy_routing_error)+'</span>'
            : '<span class="badge b-on">已生效</span>')
        : '-'],
  ]);

  document.getElementById('st-brut').innerHTML=kvRows([
    ['配置状态',b.enabled?'开启':'关闭'],
    ['内核支持',ker.kernel_supported===true?'支持':(ker.kernel_supported===false?'不支持':'未知')],
    ['内核当前拥塞控制',ker.kernel_current||'-'],
    ['内核可用拥塞控制',(ker.kernel_available&&ker.kernel_available.length)?ker.kernel_available.join(', '):'-'],
    ['内核原因',ker.error],
    ['配置上行 (Mbps)',b.up_mbps||'-'],
    ['配置下行 (Mbps)',b.down_mbps||'-'],
    ['每连接下行预算 (Mbps)',b.max_down_mbps||b.per_conn_rx_mbps||'-'],
    ['每连接上行 (Mbps)',b.max_up_mbps||b.per_conn_tx_mbps||'-'],
    ['已生效连接',b.total_conns?(b.applied_conns+'/'+b.total_conns):'-'],
  ]);

  const note=document.getElementById('st-brut-note');
  let txt='',bad=false;
  if(!b.enabled){txt=ker.kernel_supported===true
      ?'未启用：内核支持 Brutal，配置开启即生效；当前未做任何 TCP 整形。'
      :'未启用：内核未做任何 TCP 整形。';}
  else if(ker.kernel_supported!==true){txt=ker.error||'内核不可用：TCP Brutal 无法生效。';bad=true;}
  else if(b.total_conns>0&&b.applied_conns<b.total_conns){
    txt='内核支持，但仅 '+b.applied_conns+'/'+b.total_conns+' 条连接真正生效。'+(b.socks5?'（走 SOCKS5 代理的连接不整形）':'');bad=true;}
  else if(ker.error){txt='连接已生效，但状态读取受限：'+ker.error;bad=true;}
  else{txt='内核支持且所有连接均已生效。';}
  note.className=bad?'note bad':'note';
  note.textContent=txt;
}

function renderConns(data){
  const list=data.conns||[];
  if(data.mode!=='client'){document.getElementById('conns-body').innerHTML='<tr><td colspan="14" style="color:var(--muted)">仅客户端模式提供</td></tr>';return;}
  const neg=data.negotiate||{},b=neg.brutal||{};
  const brutCell=b.enabled?(b.total_conns?b.applied_conns+'/'+b.total_conns+' 已生效':'未生效'):'关闭';
  document.getElementById('conns-body').innerHTML=list.map(c=>'<tr><td>'+c.index+'</td><td>'+esc(c.target)+'</td><td>'+esc(c.remote||'-')+'</td>'+
    '<td>'+(c.state==='up'?'<span class="badge b-on">up</span>':c.state==='connecting'?'<span class="badge b-dup">connecting</span>':'<span class="badge b-off">'+esc(c.state)+'</span>')+'</td>'+
    '<td>'+(c.rtt_ms>=100000?'-':c.rtt_ms+' ms')+'</td><td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
    '<td class="hide-sm">'+c.retries+'</td><td class="hide-sm">'+(c.age_sec?fmtDur(c.age_sec):'-')+'</td>'+
    '<td class="hide-sm">'+badge(data.fec_mode||'off')+'</td><td class="hide-sm">'+encBadge(neg.enc_algo||0)+'</td>'+
    '<td class="hide-sm" title="'+esc(c.brutal_error||'')+'">'+(c.brutal_applied?'<span class="badge b-on">已生效</span>':(b.enabled?'<span class="badge b-dup">未生效</span>':'<span class="badge b-off">未启用</span>'))+'</td>'+
    '<td class="hide-sm" style="color:var(--err)" title="'+esc(c.last_error||c.brutal_error||'')+'">'+esc((c.last_error||c.brutal_error||'').slice(0,40))+'</td>'+
    '<td><button class="btn gray" onclick="doAction(\'reconnect\')">重连</button></td></tr>').join('')||
    '<tr><td colspan="14" style="color:var(--muted)">无连接</td></tr>';
}
function renderMacs(data){
  const t=document.getElementById('macs-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:var(--muted)">仅服务端模式提供</td></tr>';return;}
  const list=data.mac_table||[];
  t.innerHTML=list.map(e=>'<tr><td>'+esc(e.mac)+'</td><td>'+esc(e.port)+'</td><td>'+e.age_sec+' 秒前</td></tr>').join('')||
    '<tr><td colspan="3" style="color:var(--muted)">尚未学习到 MAC</td></tr>';
}
function renderBans(data){
  const t=document.getElementById('bans-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:var(--muted)">仅服务端模式提供</td></tr>';return;}
  const bans=data.banned||{};
  t.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td title="'+id+'">'+(id.length>18?id.slice(0,18)+'…':id)+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">永久</span>':fmtDur(left))+'</td>'+
    '<td><button class="btn gray" onclick="unban(\''+id+'\')">解封</button></td></tr>').join('')||
    '<tr><td colspan="3" style="color:var(--muted)">无封禁记录</td></tr>';
}

async function kickClient(id){if(!confirm('确定要强制断开该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'kick',client_id:id})});fetchStats();}
async function banClient(id,minutes){if(!confirm('确定封禁该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:minutes})});fetchStats();}
async function addBan(){const id=document.getElementById('ban-id').value.trim();if(!id)return alert('请输入 ClientID');
  const m=parseInt(document.getElementById('ban-min').value,10);await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m})});
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();}
async function unban(id){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unban',client_id:id})});fetchStats();}
async function doAction(action,extra){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({action:action},extra||{}))});fetchStats();}
async function setLogLevel(v){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'loglevel',level:v})});}

function startLogPoll(){
  stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);
}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch(url('/api/logs?after='+logSeq),AUTH_HDR);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    box.innerHTML+=lines.map(l=>'<div class="lv-'+esc(l.level)+'">['+esc(l.time)+'] '+esc(l.level)+' '+esc(l.msg)+'</div>').join('');
    logSeq=lines[lines.length-1].seq;
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){showErr('日志',e&&e.message||e);}
}

setInterval(fetchStats,2000);fetchStats();
</script>
</body>
</html>"##;

// ======================= Web 服务（Basic Auth + CSRF + API） =======================

pub const APP_VERSION: &str = "1.1.0-rs";

/// 模式相关的统计/控制由 server/client 各自实现
pub trait WebStatsProvider: Send + Sync {
    fn stats_json(&self) -> serde_json::Value;
    /// Prometheus 文本格式指标
    fn metrics_text(&self) -> String;
    /// 执行管理动作；返回 Err 时以 400 回应
    fn control(
        &self,
        action: &str,
        client_id: &str,
        level: &str,
        ttl_minutes: i64,
    ) -> Result<(), String>;
}

fn http_header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

fn respond_json(req: tiny_http::Request, body: String, status: u16) {
    let resp = Response::from_string(body)
        .with_status_code(status)
        .with_header(http_header("Content-Type", "application/json"));
    let _ = req.respond(resp);
}

/// 常量时间比较，避免时序侧信道
fn ct_eq(a: &str, b: &str) -> bool {
    let ah = Sha256::digest(a.as_bytes());
    let bh = Sha256::digest(b.as_bytes());
    let mut diff = 0u8;
    for (x, y) in ah.iter().zip(bh.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn check_basic_auth(auth_spec: &str, req: &tiny_http::Request) -> bool {
    if auth_spec.is_empty() {
        return true;
    }
    let header = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = Base64::decode_vec(encoded.trim()) else {
        return false;
    };
    let Ok(cred) = String::from_utf8(decoded) else {
        return false;
    };
    ct_eq(&cred, auth_spec)
}

/// 读 web.cert / web.key 组装 HTTPS 凭据。
///
/// 这里只负责读文件：路径是否可读、cert/key 是否配对由 validate_args 先挡，
/// PEM 内容是否合法由 tiny_http 在建 listener 时报错。
fn load_web_ssl(cert: &str, key: &str) -> Result<tiny_http::SslConfig, String> {
    let certificate = std::fs::read(cert).map_err(|e| format!("web.cert {}: {}", cert, e))?;
    let private_key = std::fs::read(key).map_err(|e| format!("web.key {}: {}", key, e))?;
    Ok(tiny_http::SslConfig {
        certificate,
        private_key,
    })
}

/// 单个 listener 的服务循环：bind `addr` 并处理请求直到线程被放弃。
///
/// `ready` 若在 bind 前给出，bind 结果会在进入 accept 循环前回报
/// （true=成功），供 web.bind=tunnel 的重绑管理器逐个采纳。单监听模式
/// 传 None：失败直接记 error，因为没有下一轮会重试。
fn serve_listener(
    addr: String,
    auth: String,
    cert: String,
    key: String,
    provider: Arc<dyn WebStatsProvider>,
    ctx: Arc<RuntimeCtx>,
    ready: Option<std::sync::mpsc::Sender<bool>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    // web.cert + web.key 同时非空 = 面板走 HTTPS（对齐 Go loadWebTLS：只判
    // 非空，不要求配对之外的额外条件）。两者都是路径，PEM 内容的合法性由
    // tiny_http 在建 listener 时校验，失败会走下面 bind 失败的同一条分支。
    let (server, tls) = if cert.is_empty() || key.is_empty() {
        (HttpServer::http(&addr), false)
    } else {
        match load_web_ssl(&cert, &key) {
            Ok(cfg) => (HttpServer::https(&addr, cfg), true),
            Err(e) => {
                if let Some(tx) = ready {
                    let _ = tx.send(false);
                } else {
                    tracing::error!("Web Dashboard TLS: {}", e);
                }
                return;
            }
        }
    };
    let server = match server {
        Ok(s) => {
            if let Some(tx) = ready {
                let _ = tx.send(true);
            }
            s
        }
        Err(e) => {
            if let Some(tx) = ready {
                let _ = tx.send(false);
            } else {
                tracing::error!("Web Server bind failed on {}: {}", addr, e);
            }
            return;
        }
    };
    info!(
        "🚀 Web Dashboard listening at {}://{}",
        if tls { "https" } else { "http" },
        addr
    );
    // 用 recv_timeout 轮询而不是 incoming_requests()：tiny_http 没有公开的
    // close()，监听端口只在线程退出这个循环、Server 被 drop 时才释放。
    // stop 是关闭监听的唯一途径——rebind 回收旧地址、进程退出都靠它。
    loop {
        let next = match server.recv_timeout(Duration::from_millis(500)) {
            Ok(Some(r)) => Some(r),
            Ok(None) => None,
            Err(_) => break,
        };
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        let Some(mut request) = next else {
            continue;
        };
        let url = request.url().split('?').next().unwrap_or("").to_string();

        // 仪表盘页面与 API 一致地受认证保护
        if !check_basic_auth(&auth, &request) {
            let resp = Response::from_string("Unauthorized")
                .with_status_code(401)
                .with_header(http_header(
                    "WWW-Authenticate",
                    r#"Basic realm="tlsvpn dashboard""#,
                ));
            let _ = request.respond(resp);
            continue;
        }

        match (request.method(), url.as_str()) {
            (&Method::Get, "/") => {
                // no-store：面板 HTML 是编译进二进制的，版本变了旧页面不会自己变。
                // 不换地址栏就看不到新代码，排查时会被误判成"改了没生效"。
                let response = Response::from_string(DASHBOARD_HTML)
                    .with_header(http_header("Content-Type", "text/html; charset=utf-8"))
                    .with_header(http_header("Cache-Control", "no-store"));
                let _ = request.respond(response);
            }
            (&Method::Get, "/api/stats") => {
                // provider 出的是运行时数据；cfg/system 是启动时固定的上下文，
                // 在这里并入，避免把静态字段重复写进 server/client 两处实现。
                let mut stats = provider.stats_json();
                if let Some(obj) = stats.as_object_mut() {
                    obj.insert("cfg".to_string(), ctx.cfg.clone());
                    obj.insert("system".to_string(), ctx.system.clone());
                    obj.insert("brutal_system".to_string(), brutal_system_status());
                }
                respond_json(request, stats.to_string(), 200);
            }
            (&Method::Get, "/api/logs") => {
                let after: u64 = request
                    .url()
                    .split_once('?')
                    .and_then(|(_, q)| {
                        q.split('&')
                            .find_map(|kv| kv.strip_prefix("after=")?.parse().ok())
                    })
                    .unwrap_or(0);
                respond_json(request, json!(log_ring_snapshot(after)).to_string(), 200);
            }
            (&Method::Get, "/metrics") => {
                let resp = Response::from_string(provider.metrics_text())
                    .with_header(http_header("Content-Type", "text/plain; version=0.0.4"));
                let _ = request.respond(resp);
            }
            (&Method::Post, "/api/control") => {
                // 管理动作统一走 CSRF 头防护（对齐 Go csrfGuard）
                let has_csrf = request
                    .headers()
                    .iter()
                    .any(|h| h.field.equiv("X-Requested-With") && h.value.as_str() == "tlsvpn");
                if !has_csrf {
                    let _ = request.respond(
                        Response::from_string("Missing X-Requested-With header (CSRF protection)")
                            .with_status_code(403),
                    );
                    continue;
                }
                const MAX_CONTROL_BODY: usize = 64 * 1024;
                if request.body_length().map_or(true, |n| n > MAX_CONTROL_BODY) {
                    respond_json(
                        request,
                        json!({"error": "body length required and must not exceed 65536 bytes"})
                            .to_string(),
                        413,
                    );
                    continue;
                }
                let mut content = String::new();
                if std::io::Read::read_to_string(
                    &mut request.as_reader().take((MAX_CONTROL_BODY + 1) as u64),
                    &mut content,
                )
                .is_err()
                    || content.len() > MAX_CONTROL_BODY
                {
                    respond_json(request, json!({"error": "invalid body"}).to_string(), 400);
                    continue;
                }
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct ControlReq {
                    action: String,
                    #[serde(default)]
                    client_id: String,
                    #[serde(default)]
                    level: String,
                    #[serde(default)]
                    ttl_minutes: i64,
                }
                let Ok(creq) = serde_json::from_str::<ControlReq>(&content) else {
                    respond_json(request, json!({"error": "bad json"}).to_string(), 400);
                    continue;
                };
                match provider.control(&creq.action, &creq.client_id, &creq.level, creq.ttl_minutes)
                {
                    Ok(()) => respond_json(request, r#"{"status": "ok"}"#.to_string(), 200),
                    Err(e) => respond_json(request, json!({"error": e}).to_string(), 400),
                }
            }
            _ => {
                let _ = request.respond(Response::from_string("Not Found").with_status_code(404));
            }
        }
    }
    // 循环退出 = server 被 drop = 监听端口释放
    info!("Web Dashboard listener on {} closed", addr);
}

/// 隧道 IP 提供者：web.bind=tunnel 时由 server/client 各自实现
pub trait TunnelIpSource: Send + Sync {
    /// 当前应绑定的隧道地址列表（host:port 字符串），为空表示尚不可用
    fn tunnel_addrs(&self, port: u16) -> Vec<String>;
}

/// 从 web.addr 解析端口；非法时回落 8080（对齐 Go webPort）
pub fn web_port(addr: &str) -> u16 {
    match addr.rsplit_once(':') {
        Some((_, p)) => p.parse().unwrap_or(8080),
        None => 8080,
    }
}

/// web.bind=all：直接启动单个 listener（默认行为，不变）。stop 永不置位。
pub fn start_web_server(
    addr: String,
    auth: String,
    cert: String,
    key: String,
    provider: Arc<dyn WebStatsProvider>,
    ctx: Arc<RuntimeCtx>,
) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    std::thread::spawn(move || {
        serve_listener(addr, auth, cert, key, provider, ctx, None, stop)
    });
}

/// 同一地址 30 秒内只上报一次绑定失败，避免隧道 IP 未就绪时每 2 秒刷一条
/// （对齐 Go WebManager 的 onceWarn）。
fn warn_throttled(keys: &mut std::collections::HashMap<String, Instant>, key: &str) -> bool {
    match keys.get(key) {
        Some(t) if t.elapsed() < Duration::from_secs(30) => false,
        _ => {
            keys.insert(key.to_string(), Instant::now());
            true
        }
    }
}

/// web.bind=tunnel：2 秒轮询重绑循环，监听隧道自身 IP。
///
/// 采纳是「逐个成功」而非「全有或全无」（对齐 Go WebManager）：IPv4 与
/// IPv6 各自独立打开，某个地址绑定失败（隧道 IP 未就绪、IPv6 被禁、地址
/// 仍处 tentative）只让该地址缺位并记 warning 等下一轮重试，不会把已经
/// 能用的监听一起丢掉。这一点在 tiny_http 上没有公开 shutdown 的前提下
/// 是硬要求——整批放弃会让已 bind 成功的 socket 永久留在自己手里，下一
/// 轮再撞 EADDRINUSE，结果两个地址都监听不上。
pub fn start_web_server_tunnel(
    bind_port: u16,
    auth: String,
    cert: String,
    key: String,
    provider: Arc<dyn WebStatsProvider>,
    ctx: Arc<RuntimeCtx>,
    source: Arc<dyn TunnelIpSource>,
) {
    std::thread::spawn(move || {
        // 已打开的 listener：(地址, 停止标志, 线程句柄)。关闭靠 stop 标志，
        // tiny_http 没有公开 close()；句柄只用来判断线程是否已退出。
        let mut adopted: Vec<(
            String,
            Arc<std::sync::atomic::AtomicBool>,
            std::thread::JoinHandle<()>,
        )> = Vec::new();
        let mut warn_keys: std::collections::HashMap<String, Instant> =
            std::collections::HashMap::new();
        info!("🚀 Web Dashboard manager started (bind=tunnel)");
        loop {
            let wanted = source.tunnel_addrs(bind_port);

            // 规格已消失的地址：通知其线程退出以释放端口（对齐 Go 删除
            // listener）。wanted 为空 = 隧道 IP 尚未就绪，保留现状等下一轮。
            adopted.retain(|(a, stop, _)| {
                if wanted.is_empty() || wanted.contains(a) {
                    true
                } else {
                    info!(
                        "🔀 Web Dashboard listener on {} removed (tunnel address gone)",
                        a
                    );
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    false
                }
            });

            for a in wanted {
                if adopted.iter().any(|(cur, _, _)| *cur == a) {
                    continue;
                }
                let addr_key = a.clone();
                let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let (tx, rx) = std::sync::mpsc::channel::<bool>();
                let addr = a;
                let auth = auth.clone();
                let listener_cert = cert.clone();
                let listener_key = key.clone();
                let provider = provider.clone();
                let listener_ctx = ctx.clone();
                let stop_task = stop.clone();
                let handle = std::thread::spawn(move || {
                    serve_listener(
                        addr,
                        auth,
                        listener_cert,
                        listener_key,
                        provider,
                        listener_ctx,
                        Some(tx),
                        stop_task,
                    );
                });
                // bind 是同步的，正常情况下立刻有结果。超时时结果未知，
                // 保守地不采纳：真已绑定就让它继续服务，下一轮会因
                // EADDRINUSE 再判失败，不会开出重复监听。
                let bound = rx.recv_timeout(Duration::from_secs(1)).unwrap_or(false);
                if bound {
                    adopted.push((addr_key, stop, handle));
                } else if warn_throttled(&mut warn_keys, &addr_key) {
                    warn!(
                        "Web Dashboard bind failed on {} (other listeners still serving, will retry)",
                        addr_key
                    );
                }
            }

            std::thread::sleep(Duration::from_secs(2));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn tls_client_hello_fingerprint_is_stable_across_grease() {
        let alpn = vec!["h2".to_string(), "http/1.1".to_string()];
        let want = tls_client_hello_fingerprint(
            &[0x1301, 0x1302, 0xc02f],
            &[0x0804, 0x0403],
            &[0x001d, 0x0017],
            &alpn,
        );
        let got = tls_client_hello_fingerprint(
            &[0x0a0a, 0x1301, 0x1302, 0xc02f, 0xfafa],
            &[0x0804, 0x2a2a, 0x0403],
            &[0x1a1a, 0x001d, 0x0017],
            &alpn,
        );
        assert_eq!(got, want);
        assert_eq!(got.len(), 64);
    }

    #[test]
    fn tls_client_hello_fingerprint_keeps_opaque_alpn_bytes() {
        let a = tls_client_hello_fingerprint_bytes(&[0x1301], &[], &[], &[vec![0xff, 0x00]]);
        let b = tls_client_hello_fingerprint_bytes(&[0x1301], &[], &[], &[vec![0xef, 0xbf, 0xbd, 0x00]]);
        assert_ne!(a, b, "opaque ALPN bytes must not collapse through UTF-8 replacement");
    }

    #[test]
    fn handshake_tls_summary_is_optional_and_contains_no_secret_fields() {
        let minimal = serde_json::to_string(&HandshakeResp::default()).unwrap();
        assert!(!minimal.contains("\"tls\""));

        let resp = HandshakeResp {
            tls: Some(TLSHandshakeInfo {
                fingerprint_kind: TLS_CLIENT_HELLO_FINGERPRINT_KIND.into(),
                fingerprint_sha256: "a".repeat(64),
                version_id: 0x0304,
                version: "TLS 1.3".into(),
                cipher_suite_id: 0x1301,
                cipher_suite: "TLS_AES_128_GCM_SHA256".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let encoded = serde_json::to_string(&resp).unwrap();
        for forbidden in [
            "client_random",
            "server_random",
            "session_ticket",
            "private_key",
            "master_secret",
            "certificate_der",
        ] {
            assert!(!encoded.contains(forbidden), "leaked forbidden field {forbidden}");
        }
    }

    #[test]
    fn handshake_tls_rolling_upgrade_is_bidirectionally_compatible() {
        // old writer -> new reader
        let old_wire = r#"{"success":true,"message":"OK","client_id":"c","ipv4":"10.0.0.2/24","ipv6":"fd00::2/80"}"#;
        let current: HandshakeResp = serde_json::from_str(old_wire).unwrap();
        assert!(current.tls.is_none());

        // new writer -> old reader：serde 默认忽略未知字段，旧客户端继续读取核心字段。
        #[derive(serde::Deserialize)]
        struct LegacyHandshakeResp {
            success: bool,
            client_id: String,
        }
        let new_wire = serde_json::to_string(&HandshakeResp {
            success: true,
            message: "OK".into(),
            client_id: "c".into(),
            ipv4: "10.0.0.2/24".into(),
            ipv6: "fd00::2/80".into(),
            tls: Some(TLSHandshakeInfo {
                fingerprint_kind: TLS_CLIENT_HELLO_FINGERPRINT_KIND.into(),
                fingerprint_sha256: "a".repeat(64),
                ..Default::default()
            }),
            ..Default::default()
        })
        .unwrap();
        let legacy: LegacyHandshakeResp = serde_json::from_str(&new_wire).unwrap();
        assert!(legacy.success);
        assert_eq!(legacy.client_id, "c");
    }

    struct StubProvider;
    impl WebStatsProvider for StubProvider {
        fn stats_json(&self) -> serde_json::Value {
            json!({"mode": "test"})
        }
        fn metrics_text(&self) -> String {
            String::new()
        }
        fn control(&self, _a: &str, _c: &str, _l: &str, _t: i64) -> Result<(), String> {
            Ok(())
        }
    }

    struct SwitchSource(Arc<Mutex<Vec<String>>>);
    impl TunnelIpSource for SwitchSource {
        fn tunnel_addrs(&self, _port: u16) -> Vec<String> {
            self.0.lock().clone()
        }
    }

    fn free_port() -> u16 {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    }

    /// 发一个真实 HTTP GET，成功返回响应体
    fn http_get(addr: &str, path: &str) -> Option<String> {
        let mut s = std::net::TcpStream::connect(addr).ok()?;
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, addr
        );
        s.write_all(req.as_bytes()).ok()?;
        let mut out = String::new();
        s.read_to_string(&mut out).ok()?;
        Some(out)
    }

    fn http_raw(addr: &str, request: &str) -> String {
        let mut s = std::net::TcpStream::connect(addr).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(request.as_bytes()).unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    }

    fn wait_http(addr: &str, timeout: Duration) -> bool {
        let start = Instant::now();
        while Instant::now().duration_since(start) < timeout {
            if http_get(addr, "/api/stats").is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    fn wait_closed(addr: &str, timeout: Duration) -> bool {
        let start = Instant::now();
        while Instant::now().duration_since(start) < timeout {
            if std::net::TcpStream::connect(addr).is_err() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }

    /// web.cert / web.key 缺失时必须带标签报错，否则面板线程只会反复重试
    #[test]
    fn load_web_ssl_reports_which_file_is_unreadable() {
        let missing =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/no_such_cert.pem");
        let cert_err = load_web_ssl(missing.to_str().unwrap(), "somekey").unwrap_err();
        assert!(
            cert_err.starts_with("web.cert"),
            "缺 cert 应指认 web.cert，实际: {}",
            cert_err
        );
        // cert 存在但 key 缺失：要报 web.key 而不是 web.cert
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("tlsvpn-wss-{}-c.pem", std::process::id()));
        std::fs::write(&cert_path, b"not a real pem\n").unwrap();
        let key_err = load_web_ssl(
            cert_path.to_str().unwrap(),
            dir.join(format!("tlsvpn-wss-{}-k.pem", std::process::id()))
                .to_str()
                .unwrap(),
        )
        .unwrap_err();
        assert!(
            key_err.starts_with("web.key"),
            "缺 key 应指认 web.key，实际: {}",
            key_err
        );
        let _ = std::fs::remove_file(&cert_path);
    }

    #[test]
    fn warn_throttled_suppresses_repeats_within_window() {
        let mut keys: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        assert!(warn_throttled(&mut keys, "127.0.0.1:1"), "首次应上报");
        assert!(
            !warn_throttled(&mut keys, "127.0.0.1:1"),
            "30 秒内重复失败不应重复上报"
        );
        // 不同地址互不影响
        assert!(warn_throttled(&mut keys, "127.0.0.1:2"));
    }

    #[test]
    fn web_auth_and_control_body_limits_are_enforced() {
        assert!(ct_eq("admin:secret", "admin:secret"));
        assert!(!ct_eq("admin:secret", "admin:secret-longer"));

        let addr = format!("127.0.0.1:{}", free_port());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let stop_task = stop.clone();
        let addr_task = addr.clone();
        let handle = std::thread::spawn(move || {
            serve_listener(
                addr_task,
                "admin:secret".into(),
                String::new(),
                String::new(),
                Arc::new(StubProvider),
                Arc::new(RuntimeCtx::default()),
                Some(tx),
                stop_task,
            );
        });
        assert!(rx.recv_timeout(Duration::from_secs(3)).unwrap_or(false));

        let unauthorized = http_raw(
            &addr,
            &format!(
                "GET /api/stats HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                addr
            ),
        );
        assert!(unauthorized.contains(" 401 "));

        let auth = "Authorization: Basic YWRtaW46c2VjcmV0\r\n";
        let missing_len = http_raw(
            &addr,
            &format!(
                "POST /api/control HTTP/1.1\r\nHost: {}\r\n{}X-Requested-With: tlsvpn\r\nConnection: close\r\n\r\n",
                addr, auth
            ),
        );
        assert!(missing_len.contains(" 413 "));

        let bad = r#"{"action":"gc","unexpected":true}"#;
        let unknown = http_raw(
            &addr,
            &format!(
                "POST /api/control HTTP/1.1\r\nHost: {}\r\n{}X-Requested-With: tlsvpn\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                addr,
                auth,
                bad.len(),
                bad
            ),
        );
        assert!(unknown.contains(" 400 "));

        let oversized = http_raw(
            &addr,
            &format!(
                "POST /api/control HTTP/1.1\r\nHost: {}\r\n{}X-Requested-With: tlsvpn\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n",
                addr, auth
            ),
        );
        assert!(oversized.contains(" 413 "));

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = http_get(&addr, "/api/stats");
        assert!(handle.join().is_ok());
    }

    /// stop 是 tiny_http 监听端口唯一的关闭途径；不退出循环端口就不会释放
    #[test]
    fn serve_listener_stop_releases_the_port() {
        let addr = format!("127.0.0.1:{}", free_port());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let stop_task = stop.clone();
        let addr_task = addr.clone();
        let handle = std::thread::spawn(move || {
            serve_listener(
                addr_task,
                String::new(),
                String::new(),
                String::new(),
                Arc::new(StubProvider),
                Arc::new(RuntimeCtx::default()),
                Some(tx),
                stop_task,
            );
        });
        assert!(
            rx.recv_timeout(Duration::from_secs(3)).unwrap_or(false),
            "bind 应成功"
        );
        assert!(wait_http(&addr, Duration::from_secs(3)), "监听应能响应请求");

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(handle.join().is_ok(), "stop 后线程应正常退出");
        // tiny_http 的 drop 到 OS 真正放端口有几百毫秒的窗口，并行跑测试时
        // 单点检查会撞上去
        assert!(
            wait_closed(&addr, Duration::from_secs(3)),
            "stop 后端口必须已释放"
        );
    }

    /// 回归：采纳必须逐个进行。旧实现「全有或全无」会让一个地址绑不上时
    /// 把已 bind 成功的监听一起丢弃，socket 永远占着自己的端口，下一轮
    /// 两个地址都 EADDRINUSE（用户报告的 8000 端口被自己占用的现象）。
    #[test]
    fn tunnel_manager_adopts_addresses_independently() {
        let a1 = format!("127.0.0.1:{}", free_port());
        let a2 = format!("127.0.0.1:{}", free_port());
        // 占住 a2，模拟隧道 IPv6 地址尚未真正就绪时的绑定失败
        let blocker = std::net::TcpListener::bind(&a2).unwrap();

        let addrs = Arc::new(Mutex::new(vec![a1.clone(), a2.clone()]));
        start_web_server_tunnel(
            0,
            String::new(),
            String::new(),
            String::new(),
            Arc::new(StubProvider),
            Arc::new(RuntimeCtx::default()),
            Arc::new(SwitchSource(addrs.clone())),
        );

        // a1 必须单独被采纳，不能跟着 a2 一起失败
        assert!(
            wait_http(&a1, Duration::from_secs(10)),
            "可绑定的地址必须独立生效"
        );

        // 地址就绪后 a2 也要跟上来
        drop(blocker);
        assert!(
            wait_http(&a2, Duration::from_secs(10)),
            "就绪地址应被补齐监听"
        );

        // 地址从规格里消失：旧监听必须关闭并释放端口，而不是永久泄漏
        *addrs.lock() = vec![a2.clone()];
        assert!(
            wait_closed(&a1, Duration::from_secs(10)),
            "消失的地址应释放端口"
        );
        assert!(
            wait_http(&a2, Duration::from_secs(5)),
            "保留的地址应继续服务"
        );
    }
}
