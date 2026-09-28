use crate::peer_info::PeerInfo;
use crate::web_parity::{atomic_write_json, diff_paths, WebParityState};
use base64ct::{Base64, Encoding};
use parking_lot::{Mutex, RwLock};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Response, Server as HttpServer, StatusCode};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_info: Option<PeerInfo>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_info: Option<PeerInfo>,
}

#[cfg(test)]
mod peer_info_protocol_tests {
    use super::*;

    #[test]
    fn peer_info_is_optional_and_round_trips() {
        let old = r#"{"protocol_version":2,"client_id":"x","psk":"y"}"#;
        let req: HandshakeReq = serde_json::from_str(old).unwrap();
        assert!(req.peer_info.is_none());

        let mut req = req;
        req.peer_info = Some(PeerInfo {
            implementation: "rust".into(),
            hostname: "node-r".into(),
            os: "linux".into(),
            arch: "aarch64".into(),
            version: "v1".into(),
            ..Default::default()
        });
        let encoded = serde_json::to_string(&req).unwrap();
        let round: HandshakeReq = serde_json::from_str(&encoded).unwrap();
        assert_eq!(round.peer_info.unwrap().hostname, "node-r");
    }
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
    values
        .iter()
        .copied()
        .filter(|v| !is_tls_grease(*v))
        .collect()
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
#[derive(Debug)]
pub struct RuntimeCtx {
    pub cfg: RwLock<serde_json::Value>,
    pub system: serde_json::Value,
    pub web: WebParityState,
}

impl Default for RuntimeCtx {
    fn default() -> Self {
        Self {
            cfg: RwLock::new(json!({})),
            system: json!({}),
            web: WebParityState::new(""),
        }
    }
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
            "traffic_days": args.traffic_days,
            "traffic_file": args.traffic_file,
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
            cfg: RwLock::new(cfg),
            system: system_info(cfg_path),
            web: WebParityState::new(cfg_path),
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
            if avail_raw.is_empty() {
                "-"
            } else {
                &avail_raw
            }
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
    if rank > 0 {
        "gcm"
    } else {
        ""
    }
}

// ======================= WebUI 静态资源（与 Go webui/ 同源） =======================

#[path = "webui_assets.rs"]
mod webui_assets;

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

fn basic_auth_credential(req: &tiny_http::Request) -> Option<String> {
    let header = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))?
        .value
        .as_str();
    let encoded = header.strip_prefix("Basic ")?;
    let decoded = Base64::decode_vec(encoded.trim()).ok()?;
    String::from_utf8(decoded).ok()
}

fn cookie_value(req: &tiny_http::Request, name: &str) -> String {
    let Some(raw) = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Cookie"))
        .map(|h| h.value.as_str())
    else {
        return String::new();
    };
    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k == name {
                return v.to_string();
            }
        }
    }
    String::new()
}

fn dashboard_authenticated(ctx: &RuntimeCtx, req: &tiny_http::Request, auth: &str) -> bool {
    if auth.is_empty() {
        return true;
    }
    let token = cookie_value(req, "tlsvpn_session");
    if ctx.web.session_valid(&token, auth) {
        return true;
    }
    basic_auth_credential(req)
        .map(|got| ct_eq(&got, auth))
        .unwrap_or(false)
}

fn dashboard_cookie(token: &str, secure: bool, clear: bool) -> Header {
    let mut value = if clear {
        "tlsvpn_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax".to_string()
    } else {
        format!("tlsvpn_session={token}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax")
    };
    if secure {
        value.push_str("; Secure");
    }
    http_header("Set-Cookie", &value)
}

fn query_u64(url: &str, name: &str) -> u64 {
    url.split_once('?')
        .and_then(|(_, q)| {
            q.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                (k == name).then(|| v.parse::<u64>().ok()).flatten()
            })
        })
        .unwrap_or(0)
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

        // Browser authentication matches the Go dashboard: web.auth remains the
        // credential source, but successful login uses an HttpOnly SameSite cookie.
        // Explicit Basic Auth remains accepted for scripts without emitting a browser
        // WWW-Authenticate challenge.
        let dynamic_auth = ctx.web.current_auth();
        let expected_auth = if dynamic_auth.is_empty() {
            auth.clone()
        } else {
            dynamic_auth
        };
        if !expected_auth.is_empty() {
            match url.as_str() {
                "/api/login" => {
                    if request.method() != &Method::Post {
                        respond_json(
                            request,
                            json!({"error":"method not allowed"}).to_string(),
                            405,
                        );
                        continue;
                    }
                    const MAX_LOGIN: usize = 8 * 1024;
                    if request.body_length().map_or(false, |n| n > MAX_LOGIN) {
                        respond_json(request, json!({"error":"invalid request"}).to_string(), 400);
                        continue;
                    }
                    let mut body = String::new();
                    if request
                        .as_reader()
                        .take((MAX_LOGIN + 1) as u64)
                        .read_to_string(&mut body)
                        .is_err()
                        || body.len() > MAX_LOGIN
                    {
                        respond_json(request, json!({"error":"invalid request"}).to_string(), 400);
                        continue;
                    }
                    #[derive(serde::Deserialize)]
                    #[serde(deny_unknown_fields)]
                    struct LoginReq {
                        username: String,
                        password: String,
                    }
                    let Ok(login) = serde_json::from_str::<LoginReq>(&body) else {
                        respond_json(request, json!({"error":"invalid request"}).to_string(), 400);
                        continue;
                    };
                    if !ct_eq(&(login.username + ":" + &login.password), &expected_auth) {
                        std::thread::sleep(Duration::from_millis(150));
                        respond_json(
                            request,
                            json!({"error":"invalid username or password"}).to_string(),
                            401,
                        );
                        continue;
                    }
                    match ctx.web.create_session(&expected_auth) {
                        Ok(token) => {
                            let resp = Response::from_string(r#"{"status":"ok"}"#)
                                .with_header(http_header("Content-Type", "application/json"))
                                .with_header(http_header("Cache-Control", "no-store"))
                                .with_header(dashboard_cookie(&token, tls, false));
                            let _ = request.respond(resp);
                        }
                        Err(e) => respond_json(request, json!({"error":e}).to_string(), 500),
                    }
                    continue;
                }
                "/api/logout" => {
                    if request.method() != &Method::Post {
                        respond_json(
                            request,
                            json!({"error":"method not allowed"}).to_string(),
                            405,
                        );
                        continue;
                    }
                    ctx.web
                        .revoke_session(&cookie_value(&request, "tlsvpn_session"));
                    let resp = Response::from_string(r#"{"status":"ok"}"#)
                        .with_header(http_header("Content-Type", "application/json"))
                        .with_header(http_header("Cache-Control", "no-store"))
                        .with_header(dashboard_cookie("", tls, true));
                    let _ = request.respond(resp);
                    continue;
                }
                "/api/auth/status" => {
                    let ok = dashboard_authenticated(&ctx, &request, &expected_auth);
                    respond_json(request, json!({"authenticated":ok}).to_string(), 200);
                    continue;
                }
                _ => {}
            }
            let login_asset = matches!(
                url.as_str(),
                "/login" | "/login.html" | "/login.css" | "/login.js"
            );
            if !login_asset && !dashboard_authenticated(&ctx, &request, &expected_auth) {
                if url.starts_with("/api/") || url == "/metrics" {
                    respond_json(request, json!({"error":"unauthorized"}).to_string(), 401);
                } else {
                    let resp = Response::from_string("")
                        .with_status_code(303)
                        .with_header(http_header("Location", "/login"));
                    let _ = request.respond(resp);
                }
                continue;
            }
        }

        if request.method() == &Method::Get {
            if let Some((body, content_type)) = webui_assets::asset(url.as_str()) {
                let response = Response::from_data(body.to_vec())
                    .with_header(http_header("Content-Type", content_type))
                    .with_header(http_header("Cache-Control", "no-store"));
                let _ = request.respond(response);
                continue;
            }
        }

        match (request.method(), url.as_str()) {
            (&Method::Get, "/api/stats") => {
                // provider 出的是运行时数据；cfg/system 是启动时固定的上下文，
                // 在这里并入，避免把静态字段重复写进 server/client 两处实现。
                let mut stats = provider.stats_json();
                ctx.web.observe_stats(&stats);
                if let Some(obj) = stats.as_object_mut() {
                    obj.insert("cfg".to_string(), ctx.cfg.read().clone());
                    let mut system = ctx.system.clone();
                    if let Some(sys) = system.as_object_mut() {
                        sys.insert("needs_restart".to_string(), json!(ctx.web.needs_restart()));
                    }
                    obj.insert("system".to_string(), system);
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
            (&Method::Get, "/api/trend") => {
                respond_json(request, ctx.web.trend_json().to_string(), 200);
            }
            (&Method::Get, "/api/events") => {
                let after = query_u64(request.url(), "after");
                let polling = request
                    .url()
                    .split_once('?')
                    .map(|(_, q)| q.split('&').any(|part| part == "stream=0"))
                    .unwrap_or(false);
                if polling {
                    respond_json(
                        request,
                        json!(ctx.web.events.snapshot(after)).to_string(),
                        200,
                    );
                } else {
                    let stream = ctx.web.events.stream(after);
                    let headers = vec![
                        http_header("Content-Type", "text/event-stream"),
                        http_header("Cache-Control", "no-cache, no-store"),
                        http_header("Connection", "keep-alive"),
                        http_header("X-Accel-Buffering", "no"),
                    ];
                    std::thread::spawn(move || {
                        let response = Response::new(StatusCode(200), headers, stream, None, None);
                        let _ = request.respond(response);
                    });
                }
            }
            (&Method::Get, "/api/config") => {
                let body = serde_json::to_string_pretty(&ctx.web.redacted_config())
                    .unwrap_or_else(|_| "{}".to_string());
                respond_json(request, body, 200);
            }
            (&Method::Post, "/api/config") => {
                const MAX_CONFIG_BODY: usize = 1024 * 1024;
                let mut content = String::new();
                if request
                    .as_reader()
                    .take((MAX_CONFIG_BODY + 1) as u64)
                    .read_to_string(&mut content)
                    .is_err()
                    || content.len() > MAX_CONFIG_BODY
                {
                    respond_json(
                        request,
                        json!({"error":"invalid config body"}).to_string(),
                        400,
                    );
                    continue;
                }
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) else {
                    respond_json(request, json!({"error":"bad json"}).to_string(), 400);
                    continue;
                };
                let merged = ctx.web.merge_preserving_secrets(value);
                match crate::validate_config_value(
                    &merged,
                    ctx.web.config_path().to_string_lossy().as_ref(),
                ) {
                    Ok(_) => match atomic_write_json(ctx.web.config_path(), &merged) {
                        Ok(()) => {
                            ctx.web.replace_config(merged);
                            respond_json(request, r#"{"status":"ok"}"#.to_string(), 200);
                        }
                        Err(e) => respond_json(request, json!({"error":e}).to_string(), 400),
                    },
                    Err(e) => respond_json(request, json!({"error":e}).to_string(), 400),
                }
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
                    #[serde(default)]
                    config: Option<serde_json::Value>,
                }
                let Ok(creq) = serde_json::from_str::<ControlReq>(&content) else {
                    respond_json(request, json!({"error": "bad json"}).to_string(), 400);
                    continue;
                };
                if creq.action == "save" || creq.action == "save_apply" {
                    let Some(candidate) = creq.config else {
                        respond_json(
                            request,
                            json!({"error":"config is required"}).to_string(),
                            400,
                        );
                        continue;
                    };
                    let apply = creq.action == "save_apply";
                    let old = ctx.web.current_config();
                    let merged = ctx.web.merge_preserving_secrets(candidate);
                    let validated = match crate::validate_config_value(
                        &merged,
                        ctx.web.config_path().to_string_lossy().as_ref(),
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            respond_json(request, json!({"error":e}).to_string(), 400);
                            continue;
                        }
                    };
                    if let Err(e) = atomic_write_json(ctx.web.config_path(), &merged) {
                        respond_json(request, json!({"error":e}).to_string(), 400);
                        continue;
                    }
                    let changed = diff_paths(&old, &merged);
                    let mut needs_restart = Vec::new();
                    if apply {
                        for field in &changed {
                            match field.as_str() {
                                "log_level" => {
                                    let _ =
                                        provider.control("loglevel", "", &validated.loglevel, 0);
                                }
                                "pad_mode" => {
                                    let _ =
                                        provider.control("pad_mode", "", &validated.pad_mode, 0);
                                }
                                _ => needs_restart.push(field.clone()),
                            }
                        }
                        if let Some(cfg) = ctx.cfg.write().as_object_mut() {
                            cfg.insert("log_level".into(), json!(validated.loglevel));
                            cfg.insert("pad_mode".into(), json!(crate::crypto::pad_mode_name()));
                            cfg.insert("traffic_days".into(), json!(validated.traffic_days));
                            cfg.insert("traffic_file".into(), json!(validated.traffic_file));
                        }
                    }
                    ctx.web.replace_config(merged);
                    ctx.web.set_needs_restart(needs_restart.clone());
                    ctx.web.events.emit(
                        "config",
                        "info",
                        "",
                        &format!("{} (needs_restart: {:?})", creq.action, needs_restart),
                    );
                    respond_json(
                        request,
                        json!({"status":"ok","needs_restart":needs_restart}).to_string(),
                        200,
                    );
                    continue;
                }
                match provider.control(&creq.action, &creq.client_id, &creq.level, creq.ttl_minutes)
                {
                    Ok(()) => {
                        ctx.web
                            .events
                            .emit("control", "info", &creq.client_id, &creq.action);
                        respond_json(request, r#"{"status": "ok"}"#.to_string(), 200)
                    }
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
    std::thread::spawn(move || serve_listener(addr, auth, cert, key, provider, ctx, None, stop));
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
        let b = tls_client_hello_fingerprint_bytes(
            &[0x1301],
            &[],
            &[],
            &[vec![0xef, 0xbf, 0xbd, 0x00]],
        );
        assert_ne!(
            a, b,
            "opaque ALPN bytes must not collapse through UTF-8 replacement"
        );
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
            assert!(
                !encoded.contains(forbidden),
                "leaked forbidden field {forbidden}"
            );
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
