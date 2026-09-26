use crate::Args;
use crossbeam_channel::{bounded, Receiver, Sender};
use crossbeam_queue::ArrayQueue;
use mio::net::{TcpListener, TcpStream as MioTcpStream};
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, ServerConnection};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::fec::{self, FecDecoder};
use crate::frame::*;
use crate::hooks::{HookEnv, LifecycleHooks};
use crate::net::*;
use crate::tap::{MemTap, TapDevice};
use crate::utils::*;

// ======================= IP 地址池（对齐 Go assignIPsLocked 语义） =======================

pub struct IpPool {
    used_v4: HashSet<String>,
    used_v6: HashSet<String>,
    v4_base: u32,
    v4_mask_bits: u32,
    v6_base: u128,
    v6_mask_bits: u32,
    pub mac_to_ip: HashMap<String, (String, String)>,
}

impl IpPool {
    pub fn new(v4cidr: &str, v6cidr: &str) -> (Self, String, String) {
        let (v4_base, v4_mask_bits) = parse_v4_cidr(v4cidr);
        let (v6_base, v6_mask_bits) = parse_v6_cidr(v6cidr);
        // 对齐 Go getFirstIP：网关 = 网络基址 + 1
        let gw_v4 = u32_to_ip4(v4_base + 1);
        let gw_v6 = u128_to_ip6(v6_base + 1);
        let mut pool = Self {
            used_v4: HashSet::new(),
            used_v6: HashSet::new(),
            v4_base,
            v4_mask_bits,
            v6_base,
            v6_mask_bits,
            mac_to_ip: HashMap::new(),
        };
        pool.used_v4.insert(gw_v4.clone());
        pool.used_v6.insert(gw_v6.clone());
        (pool, gw_v4, gw_v6)
    }

    fn v4_broadcast(&self) -> u32 {
        let host_bits = 32 - self.v4_mask_bits;
        if host_bits >= 32 {
            u32::MAX
        } else {
            self.v4_base | ((1u32 << host_bits) - 1)
        }
    }

    fn v6_broadcast(&self) -> u128 {
        let host_bits = 128 - self.v6_mask_bits;
        if host_bits >= 128 {
            u128::MAX
        } else {
            self.v6_base | ((1u128 << host_bits) - 1)
        }
    }

    /// 请求分配：req 命中（解析成功、在网段内、未被占用）则直接使用；
    /// 否则从基址+1 起扫描，跳过已占用与最后字节为 0/255 的地址。
    /// 对齐 Go assignIPsLocked。返回 "" 表示耗尽。
    fn alloc_v4(&mut self, req: &str) -> String {
        let just_ip = req.split('/').next().unwrap_or("");
        if let Ok(ip) = just_ip.parse::<Ipv4Addr>() {
            let val = u32::from(ip);
            let host_bits = 32 - self.v4_mask_bits;
            let in_net = host_bits >= 32 || (val >> host_bits) == (self.v4_base >> host_bits);
            let s = ip.to_string();
            if in_net && !self.used_v4.contains(&s) {
                self.used_v4.insert(s.clone());
                return s;
            }
        }
        let broadcast = self.v4_broadcast();
        let mut cur = self.v4_base + 1;
        while cur < broadcast {
            let last_byte = cur & 0xFF;
            let s = u32_to_ip4(cur);
            if last_byte != 0 && last_byte != 255 && !self.used_v4.contains(&s) {
                self.used_v4.insert(s.clone());
                return s;
            }
            cur += 1;
        }
        String::new()
    }

    fn alloc_v6(&mut self, req: &str) -> String {
        let just_ip = req.split('/').next().unwrap_or("");
        if let Ok(ip) = just_ip.parse::<Ipv6Addr>() {
            let val = u128::from(ip);
            let host_bits = 128 - self.v6_mask_bits;
            let in_net = host_bits >= 128 || (val >> host_bits) == (self.v6_base >> host_bits);
            let s = ip.to_string();
            if in_net && !self.used_v6.contains(&s) {
                self.used_v6.insert(s.clone());
                return s;
            }
        }
        let broadcast = self.v6_broadcast();
        let mut cur = self.v6_base + 1;
        while cur < broadcast {
            let last_byte = (cur & 0xFF) as u8;
            let s = u128_to_ip6(cur);
            if last_byte != 0 && last_byte != 255 && !self.used_v6.contains(&s) {
                self.used_v6.insert(s.clone());
                return s;
            }
            cur += 1;
        }
        String::new()
    }

    /// 会话销毁时回收地址与 MAC 绑定（对齐 Go destroyTimer 内的 delete）
    fn release(&mut self, mac: &str, v4: &str, v6: &str) {
        self.used_v4.remove(v4);
        self.used_v6.remove(v6);
        let matches = self.mac_to_ip.get(mac).map(|b| b.0 == v4).unwrap_or(false);
        if matches {
            // 仅当绑定仍指向本会话地址时清除（期间 MAC 可能已重新绑定）
            self.mac_to_ip.remove(mac);
        }
    }

    pub fn status(&self) -> (usize, usize, usize) {
        // 对齐 Go ipNetHostCount：超大网段封顶 65536，扣除网络号/广播
        let host_bits = 32 - self.v4_mask_bits;
        let total = if host_bits >= 16 {
            1 << 16
        } else {
            let c = 1usize << host_bits;
            if c > 2 {
                c - 2
            } else {
                c
            }
        };
        (self.used_v4.len(), total, self.used_v6.len())
    }
}

fn parse_v4_cidr(cidr: &str) -> (u32, u32) {
    let mut it = cidr.splitn(2, '/');
    let base = it.next().unwrap_or("10.0.0.0");
    let bits: u32 = it.next().unwrap_or("24").parse().unwrap_or(24);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits.min(32))
    };
    (ip4_to_u32(base) & mask, bits.min(32))
}

fn parse_v6_cidr(cidr: &str) -> (u128, u32) {
    let mut it = cidr.splitn(2, '/');
    let base = it.next().unwrap_or("fd00::");
    let bits: u32 = it.next().unwrap_or("64").parse().unwrap_or(64);
    let mask = if bits == 0 {
        0
    } else if bits >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - bits)
    };
    (ip6_to_u128(base) & mask, bits.min(128))
}

// ======================= 会话 =======================

/// 客户端逻辑会话（跨物理连接共享），对齐 Go ClientSession
pub struct ClientSession {
    pub session_id: String,
    pub stat: Arc<ClientStat>,
    pub port: Arc<AsyncPort>,
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    pub dedup: Arc<Mutex<DeDuplicator>>,
    pub fec_enc_k: i64,
    pub mac: String,
    // 握手 MAC 的二进制形式（建会话时解析一次）。全零表示未上报/为空，
    // 归属校验对此放行（见 src_mac_allowed）
    pub mac_bin: [u8; 6],
    pub ipv4: String,
    pub ipv6: String,
    pub epoch_state: RwLock<SessionEpochState>,
    pub destroy_deadline: Mutex<Option<(Instant, u64)>>,
    pub created_at: Instant,
    // 本会话实际生效的 TCP Brutal 整形速率（Mbps），0 = 未启用或被对端压低到 0。
    // 记录的是协商结果而不是配置值：客户端可以申请更低的预算，面板按实际值显示。
    pub brutal_tx: AtomicU64,
    pub brutal_rx: AtomicU64,
    // 物理连接级计数；不能让后建立的一条失败连接覆盖此前成功连接的状态。
    pub brutal_applied_conns: AtomicU64,
    pub brutal_error: Mutex<String>,
}

pub struct SessionEpochState {
    pub instance_id: String,
    pub epoch: u64,
    pub resume_token: String,
    // 两阶段 rollover：先在响应中持续下发，客户端回带后才提升为 current。
    pub pending_resume_token: String,
    pub enc_algo: i64,
    pub salt_a: [u8; ENC_SALT_SIZE],
    pub salt_b: [u8; ENC_SALT_SIZE],
    pub ic_tx: Option<Arc<InnerCipher>>,
    pub ic_rx: Option<Arc<InnerCipher>>,
    pub fec_dec: Option<Arc<FecDecoder>>,
}

struct MioSession {
    socket: MioTcpStream,
    remote_ip: String,
    tls: ServerConnection,
    tls_observed: Arc<Mutex<Option<TLSHandshakeInfo>>>,
    scanner: FrameScanner,
    rx: Receiver<VPNFrame>,
    handshake_done: bool,
    sniffed: bool,
    sniffed_inner: bool,
    client_session: Option<Arc<ClientSession>>,
    tx_backend: Option<Arc<Backend>>,
    last_keepalive: Instant,
    last_rx: Instant,
    rtt_timer: Instant,
    send_buf: Vec<u8>,
    ic_rx: Option<Arc<InnerCipher>>,
    session_epoch: u64,
    write_stalled: Option<Instant>,
    brutal_applied: bool,
}

#[derive(Debug)]
struct ObservingCertResolver {
    inner: Arc<dyn ResolvesServerCert>,
    observed: Arc<Mutex<Option<TLSHandshakeInfo>>>,
}

impl ResolvesServerCert for ObservingCertResolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let info = {
            let offered_cipher_suites = normalize_tls_u16(
                &hello.cipher_suites().iter().map(|v| u16::from(*v)).collect::<Vec<_>>(),
            );
            let offered_signature_schemes = normalize_tls_u16(
                &hello.signature_schemes().iter().map(|v| u16::from(*v)).collect::<Vec<_>>(),
            );
            let offered_groups = normalize_tls_u16(
                &hello
                    .named_groups()
                    .unwrap_or_default()
                    .iter()
                    .map(|v| u16::from(*v))
                    .collect::<Vec<_>>(),
            );
            let offered_alpn_bytes: Vec<Vec<u8>> = hello
                .alpn()
                .map(|protocols| protocols.map(|p| p.to_vec()).collect())
                .unwrap_or_default();
            let offered_alpn: Vec<String> = offered_alpn_bytes
                .iter()
                .map(|p| match std::str::from_utf8(p) {
                    Ok(value) => value.to_owned(),
                    Err(_) => format!("hex:{}", hex::encode(p)),
                })
                .collect();
            let fingerprint_sha256 = tls_client_hello_fingerprint_bytes(
                &offered_cipher_suites,
                &offered_signature_schemes,
                &offered_groups,
                &offered_alpn_bytes,
            );
            TLSHandshakeInfo {
                fingerprint_kind: TLS_CLIENT_HELLO_FINGERPRINT_KIND.into(),
                fingerprint_sha256,
                sni: normalize_tls_sni(hello.server_name().unwrap_or("")),
                offered_cipher_suites,
                offered_signature_schemes,
                offered_groups,
                offered_alpn,
                ..Default::default()
            }
        };
        *self.observed.lock() = Some(info);
        self.inner.resolve(hello)
    }

    fn only_raw_public_keys(&self) -> bool {
        self.inner.only_raw_public_keys()
    }
}

fn observed_tls_handshake(sess: &MioSession) -> Option<TLSHandshakeInfo> {
    let mut info = sess.tls_observed.lock().clone().unwrap_or_default();
    let version = sess.tls.protocol_version().map(u16::from).unwrap_or(0);
    let cipher_suite = sess
        .tls
        .negotiated_cipher_suite()
        .map(|suite| u16::from(suite.suite()))
        .unwrap_or(0);
    if version == 0 && cipher_suite == 0 && info.fingerprint_sha256.is_empty() {
        return None;
    }
    info.version_id = version;
    info.version = tls_version_name(version);
    info.cipher_suite_id = cipher_suite;
    info.cipher_suite = tls_cipher_suite_name(cipher_suite);
    info.alpn = sess
        .tls
        .alpn_protocol()
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    if info.sni.is_empty() {
        info.sni = normalize_tls_sni(sess.tls.server_name().unwrap_or(""));
    }
    Some(info)
}

/// 源 MAC 归属校验判定（对齐 Go validateSrcMAC）：会话端口只允许声明本会话
/// 注册的 MAC，防止持密者声明他人 MAC 把受害者表项翻转到自己端口上劫持其
/// 下行单播流量（学习表翻转攻击）。
///
/// `registered` 为 None（本机 TAP 等非会话端口）或全零（未上报 MAC 的会话）
/// 时无法核对，放行以保持兼容。
fn src_mac_allowed(registered: Option<&[u8; 6]>, mac: &[u8; 6]) -> bool {
    match registered {
        Some(r) if *r != [0u8; 6] => r == mac,
        _ => true,
    }
}

// ======================= 服务端共享状态（面板/控制用） =======================

/// 归一会话上限：0 = 默认 1024（对齐 Go applyDefaults）。配置文件路径在
/// load_config_file 已归一；这里兜住绕过它的调用方。
fn response_enc_salts(
    enc_algo: i64,
    salt_a: &[u8; ENC_SALT_SIZE],
    salt_b: &[u8; ENC_SALT_SIZE],
) -> (String, String) {
    if !is_gcm_algo(enc_algo) {
        return (String::new(), String::new());
    }
    (hex::encode(salt_a), hex::encode(salt_b))
}

fn normalize_max_sessions(n: i32) -> i32 {
    if n == 0 {
        1024
    } else {
        n
    }
}

pub struct ServerCore {
    pub psk: String,
    pub psk_hash: String,
    pub encrypt: bool,
    pub enc_algo: i64,
    pub brutal: bool,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub vswitch: Arc<VSwitch>,
    pub sessions: RwLock<HashMap<String, Arc<ClientSession>>>,
    pub pool: Mutex<IpPool>,
    pub banned: BanList,
    pub registry: StatRegistry,
    pub started_at: Instant,
    pub gw_v4: String,
    pub gw_v6: String,
    pub v4_mask_bits: u32,
    pub v6_mask_bits: u32,
    // 内层加密强度下限（ENC_RANK_* 值，0 = 不限）
    pub min_enc: i64,
    // 并发会话上限（对齐 Go maxSessions；构造时已把 0 归一为 1024）
    pub max_sessions: i32,
    // 服务端接受的对端 FEC 分组大小 K 的区间（默认协议边界 [2,64]，不额外限制）。
    // 越界的 FEC 请求拒连，不夹取：对端要的是自己的编码参数，静默改成别的 K
    // 会让它多付 N/K 冗余开销而不自知（见 handle_handshake 的拒连闸）。
    pub fec_group_min: i64,
    pub fec_group_max: i64,
    // 多 worker 共用的会话回收节流，避免每次断线创建一个睡眠 OS 线程。
    pub last_session_reap_ms: AtomicU64,
}

impl ServerCore {
    fn ipv4_cidr(&self, ip: &str) -> String {
        format!("{}/{}", ip, self.v4_mask_bits)
    }
    fn ipv6_cidr(&self, ip: &str) -> String {
        format!("{}/{}", ip, self.v6_mask_bits)
    }

    /// 会话销毁：移除注册表/交换机端口/统计/IP（对齐 Go destroyTimer）
    fn destroy_session(&self, session: &Arc<ClientSession>) {
        let cid = &session.stat.client_id;
        let mut sessions = self.sessions.write();
        let Some(current) = sessions.get(cid) else {
            return;
        };
        if !Arc::ptr_eq(current, session) {
            return;
        }
        sessions.remove(cid);
        drop(sessions);
        self.vswitch.remove_port(cid);
        self.registry.write().remove(cid);
        self.pool
            .lock()
            .release(&session.mac, &session.ipv4, &session.ipv6);
        info!(
            "[{}] 💀 session timed out and was destroyed, releasing its IPs and memory",
            cid
        );
    }
}

impl TunnelIpSource for ServerCore {
    fn tunnel_addrs(&self, port: u16) -> Vec<String> {
        let mut out = Vec::new();
        if Ipv4Addr::from_str(&self.gw_v4).is_ok() {
            out.push(format!("{}:{}", self.gw_v4, port));
        }
        let v6 = self
            .gw_v6
            .trim_matches(|c| c == '[' || c == ']')
            .to_string();
        if Ipv6Addr::from_str(&v6).is_ok() {
            out.push(format!("[{}]:{}", v6, port));
        }
        out
    }
}

impl WebStatsProvider for ServerCore {
    fn stats_json(&self) -> serde_json::Value {
        let sessions = self.sessions.read();
        let mut clients = serde_json::Map::new();
        let mut rec = 0u64;
        let mut lost = 0u64;
        let mut parity = 0u64;
        let mut dropped = 0u64;
        let mut reorder_gap = 0u64;
        let mut reorder_flushes = 0u64;
        let mut reorder_skipped = 0u64;
        for (id, s) in sessions.iter() {
            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
            parity += s.port.parity_sent();
            dropped += s.port.dropped();
            let reorder = s.reorder_buf.lock().stats();
            reorder_gap += reorder.gap_events;
            reorder_flushes += reorder.timeout_flushes;
            reorder_skipped += reorder.skipped_frames;
            clients.insert(
                id.clone(),
                serde_json::json!({
                    "ipv4": s.ipv4, "ipv6": s.ipv6, "mac": s.mac,
                    "session_id": s.session_id,
                    "session_epoch": epoch.epoch,
                    "session_encrypt": is_gcm_algo(epoch.enc_algo),
                    "active_conns": s.stat.active_conns.load(Ordering::Relaxed),
                    "tx_bytes": s.stat.tx_bytes.load(Ordering::Relaxed),
                    "rx_bytes": s.stat.rx_bytes.load(Ordering::Relaxed),
                    "tx_packets": s.stat.tx_packets.load(Ordering::Relaxed),
                    "rx_packets": s.stat.rx_packets.load(Ordering::Relaxed),
                    "fec": s.stat.fec_mode.lock().clone(),
                    "fec_group": s.fec_enc_k,
                    "enc_algo": s.stat.enc_algo.load(Ordering::Relaxed),
                    "brutal_tx": s.brutal_tx.load(Ordering::Relaxed),
                    "brutal_rx": s.brutal_rx.load(Ordering::Relaxed),
                    "brutal_applied": s.brutal_applied_conns.load(Ordering::Relaxed) > 0,
                    "brutal_applied_conns": s.brutal_applied_conns.load(Ordering::Relaxed),
                    "brutal_error": s.brutal_error.lock().clone(),
                    "reorder": {"gap_events": reorder.gap_events, "timeout_flushes": reorder.timeout_flushes, "skipped_frames": reorder.skipped_frames},
                    "online_sec": s.created_at.elapsed().as_secs(),
                    "uptime_sec": s.created_at.elapsed().as_secs(),
                }),
            );
        }
        let (v4_used, v4_total, v6_used) = self.pool.lock().status();
        let banned = self.banned.snapshot();
        let macs: Vec<serde_json::Value> = self
            .vswitch
            .mac_snapshot()
            .into_iter()
            .map(|(mac, port, age)| serde_json::json!({"mac": mac, "port": port, "age_sec": age}))
            .collect();
        // 协商结果：服务端不消费单一会话，这里给"本端配置意图 + 内核实测状态"，
        // 逐会话的真实取值在 clients 表里（brutal_tx/brutal_rx/enc_algo/fec_group）。
        let brut = brutal_system_status();
        // applied 只统计 setsockopt 真的成功过的会话，不是"配置了就算生效"
        let applied: usize = sessions.values()
            .map(|s| s.brutal_applied_conns.load(Ordering::Relaxed) as usize)
            .sum();
        let mut brutal_errors = Vec::<String>::new();
        for session in sessions.values() {
            let error = session.brutal_error.lock();
            if !error.is_empty() && !brutal_errors.contains(&error) {
                brutal_errors.push(error.clone());
            }
        }
        let brutal_error = if brutal_errors.is_empty() {
            brut["error"].as_str().unwrap_or("").to_string()
        } else {
            brutal_errors.join("; ")
        };
        let total_conns: usize = sessions.values()
            .map(|s| s.stat.active_conns.load(Ordering::Relaxed).max(0) as usize)
            .sum();
        let mut min_up = u64::MAX;
        let mut max_up = 0u64;
        let mut min_down = u64::MAX;
        let mut max_down = 0u64;
        for s in sessions.values() {
            let n = s.stat.active_conns.load(Ordering::Relaxed).max(1) as usize;
            let up = s.brutal_rx.load(Ordering::Relaxed);
            let down = s.brutal_tx.load(Ordering::Relaxed);
            min_up = min_up.min(split_legacy_brutal_rate(up, n, n - 1));
            max_up = max_up.max(split_legacy_brutal_rate(up, n, 0));
            min_down = min_down.min(split_legacy_brutal_rate(down, n, n - 1));
            max_down = max_down.max(split_legacy_brutal_rate(down, n, 0));
        }
        if sessions.is_empty() { min_up = 0; min_down = 0; }
        let negotiate = serde_json::json!({
            "protocol_version": 2,
            "fec": true,
            "fec_group": 4,
            "enc_algo": if self.encrypt { self.enc_algo } else { ENC_ALGO_NONE },
            "pad_mode": pad_mode_name(),
            "min_enc": min_enc_label(self.min_enc),
            "session_token": true,
            "max_sessions": self.max_sessions,

            "brutal": {
                "enabled": self.brutal,
                "up_mbps": self.brutal_up,
                "down_mbps": self.brutal_down,
                "kernel_supported": brut["supported"].as_bool().unwrap_or(false),
                "kernel_current": brut["kernel_current"].as_str().unwrap_or(""),
                "kernel_available": brut["kernel_available"].clone(),
                "applied_conns": applied,
                "total_conns": total_conns,
                "min_up_mbps": min_up,
                "max_up_mbps": max_up,
                "min_down_mbps": min_down,
                "max_down_mbps": max_down,
                "error": brutal_error,
            }
        });
        serde_json::json!({
            "mode": "server",
            "version": APP_VERSION,
            "uptime_sec": self.started_at.elapsed().as_secs(),
            "active_clients": sessions.len(),
            "clients": clients,
            "global_tx_bytes": 0,
            "global_rx_bytes": 0,
            "log_level": current_log_level_name(),
            "pad_mode": pad_mode_name(),
            "dropped_frames": dropped,
            "fec": {"enabled": true, "parity_tx": parity, "recovered": rec, "lost": lost},
            "reorder": {"gap_events": reorder_gap, "timeout_flushes": reorder_flushes, "skipped_frames": reorder_skipped},
            "mem": {"heap_alloc_mb": rss_mb(), "sys_mb": rss_mb(), "num_goroutine": thread_count()},
            "ip_pool": {"v4_used": v4_used, "v4_total": v4_total, "v6_used": v6_used},
            "banned": banned,
            "mac_table": macs,
            "negotiate": negotiate,
        })
    }

    fn metrics_text(&self) -> String {
        let sessions = self.sessions.read();
        let (mut tx, mut rx, mut pk) = (0u64, 0u64, 0u64);
        let (mut rec, mut lost) = (0u64, 0u64);
        let (mut dropped, mut reorder_gap, mut reorder_flushes, mut reorder_skipped) = (0u64, 0u64, 0u64, 0u64);
        for s in sessions.values() {
            tx += s.stat.tx_bytes.load(Ordering::Relaxed);
            rx += s.stat.rx_bytes.load(Ordering::Relaxed);
            pk += s.stat.tx_packets.load(Ordering::Relaxed)
                + s.stat.rx_packets.load(Ordering::Relaxed);
            let epoch = s.epoch_state.read();
            if let Some(dec) = &epoch.fec_dec {
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
            dropped += s.port.dropped();
            let reorder = s.reorder_buf.lock().stats();
            reorder_gap += reorder.gap_events;
            reorder_flushes += reorder.timeout_flushes;
            reorder_skipped += reorder.skipped_frames;
        }
        let (v4_used, v4_total, v6_used) = self.pool.lock().status();
        let mut m = String::new();
        {
            let mut emit = |name: &str, help: &str, typ: &str, val: String| {
                m.push_str(&format!(
                    "# HELP {} {}\n# TYPE {} {}\n{} {}\n",
                    name, help, name, typ, name, val
                ));
            };
            emit(
                "tlsvpn_uptime_seconds",
                "Process uptime in seconds",
                "gauge",
                self.started_at.elapsed().as_secs().to_string(),
            );
            emit(
                "tlsvpn_go_goroutines",
                "Number of goroutines",
                "gauge",
                thread_count().to_string(),
            );
            emit(
                "tlsvpn_heap_alloc_bytes",
                "Heap bytes allocated and still in use",
                "gauge",
                format!("{}", (rss_mb() * 1024.0 * 1024.0) as u64),
            );
            emit(
                "tlsvpn_active_clients",
                "Number of active client sessions",
                "gauge",
                sessions.len().to_string(),
            );
            emit(
                "tlsvpn_tx_bytes_total",
                "Total bytes sent to clients",
                "counter",
                tx.to_string(),
            );
            emit(
                "tlsvpn_rx_bytes_total",
                "Total bytes received from clients",
                "counter",
                rx.to_string(),
            );
            emit(
                "tlsvpn_packets_total",
                "Total frames relayed (tx+rx)",
                "counter",
                pk.to_string(),
            );
            emit(
                "tlsvpn_ip_pool_v4_used",
                "Allocated IPv4 addresses",
                "gauge",
                v4_used.to_string(),
            );
            emit(
                "tlsvpn_ip_pool_v4_total",
                "IPv4 pool capacity",
                "gauge",
                v4_total.to_string(),
            );
            emit(
                "tlsvpn_ip_pool_v6_used",
                "Allocated IPv6 addresses",
                "gauge",
                v6_used.to_string(),
            );
            emit(
                "tlsvpn_fec_recovered_frames_total",
                "Frames recovered by XOR FEC",
                "counter",
                rec.to_string(),
            );
            emit(
                "tlsvpn_fec_lost_frames_total",
                "Frames confirmed lost despite FEC",
                "counter",
                lost.to_string(),
            );
            emit(
                "tlsvpn_port_dropped_frames_total",
                "Frames dropped due to backpressure",
                "counter",
                dropped.to_string(),
            );
            emit(
                "tlsvpn_reorder_gap_events_total",
                "Observed sequence gaps",
                "counter",
                reorder_gap.to_string(),
            );
            emit(
                "tlsvpn_reorder_timeout_flushes_total",
                "Gap timeouts that resumed delivery",
                "counter",
                reorder_flushes.to_string(),
            );
            emit(
                "tlsvpn_reorder_skipped_frames_total",
                "Missing sequence slots skipped after timeout",
                "counter",
                reorder_skipped.to_string(),
            );
            emit(
                "tlsvpn_banned_clients",
                "Currently banned clients",
                "gauge",
                self.banned.len().to_string(),
            );
            emit(
                "tlsvpn_spoofed_src_dropped_frames_total",
                "Frames dropped for declaring another session's src MAC",
                "counter",
                self.vswitch.spoof_drops().to_string(),
            );
            emit(
                "tlsvpn_broadcast_dropped_frames_total",
                "Broadcast frames dropped over the per-port flood budget",
                "counter",
                self.vswitch.flood_drops().to_string(),
            );
        }
        m
    }

    fn control(
        &self,
        action: &str,
        client_id: &str,
        level: &str,
        ttl_minutes: i64,
    ) -> Result<(), String> {
        match action {
            "kick" => {
                let session = self.sessions.read().get(client_id).cloned();
                if let Some(s) = session {
                    s.stat.force_disconnect.store(true, Ordering::Relaxed);
                    self.destroy_session(&s);
                    info!("[WebUI] Force kicked client: {}", client_id);
                }
                Ok(())
            }
            "ban" => {
                if self.banned.ban(client_id, ttl_minutes) {
                    info!("[WebUI] Banned client {} (ttl={}m)", client_id, ttl_minutes);
                    let session = self.sessions.read().get(client_id).cloned();
                    if let Some(s) = session {
                        s.stat.force_disconnect.store(true, Ordering::Relaxed);
                        self.destroy_session(&s);
                    }
                }
                Ok(())
            }
            "unban" => {
                self.banned.unban(client_id);
                info!("[WebUI] Unbanned client {}", client_id);
                Ok(())
            }
            "kickall" => {
                let sessions: Vec<_> = self.sessions.read().values().cloned().collect();
                let n = sessions.len();
                for s in sessions {
                    s.stat.force_disconnect.store(true, Ordering::Relaxed);
                    self.destroy_session(&s);
                }
                info!("[WebUI] Kicked all clients ({})", n);
                Ok(())
            }
            "loglevel" => set_runtime_log_level(level),
            // 填充策略是全局发送路径状态，不作用于单个客户端；
            // 非法值回落 legacy（对齐 Go setPadMode 的防御性回落）
            "pad_mode" => {
                let want = level.to_string();
                let actual = set_pad_mode(level);
                if actual != want {
                    warn!("[WebUI] Invalid pad_mode {:?}, using {}", want, actual);
                } else {
                    info!("[WebUI] Confusion padding -> {}", actual);
                }
                Ok(())
            }
            "gc" => Ok(()),
            _ => Err("Unknown action".into()),
        }
    }
}

// ======================= TLS 材料 =======================

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    if path.is_empty() {
        return Err(
            "server.cert is empty: this build does not auto-generate a self-signed cert \
             (see README for the openssl one-liner)"
                .into(),
        );
    }
    let f = std::fs::File::open(path).map_err(|e| format!("server.cert {}: {}", path, e))?;
    let mut r = std::io::BufReader::new(f);
    rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("server.cert {}: invalid cert PEM: {}", path, e))
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>, String> {
    if path.is_empty() {
        return Err(
            "server.key is empty: this build does not auto-generate a self-signed cert \
             (see README for the openssl one-liner)"
                .into(),
        );
    }
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).map_err(|e| format!("server.key {}: {}", path, e))?,
    );
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| format!("server.key {}: invalid key PEM: {}", path, e))?
        .ok_or_else(|| format!("server.key {}: no private key found", path))
}

/// 服务端 TLS 配置。历史上这一步的每个失败点都是 panic（unwrap / expect），
/// 报的是 "Invalid TLS cert/key" 这种看不出哪份文件出问题的话。
fn build_server_tls(cert: &str, key: &str) -> Result<Arc<ServerConfig>, String> {
    let mut cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(load_certs(cert)?, load_key(key)?)
        .map_err(|e| format!("server.cert and server.key do not match: {}", e))?;
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(cfg))
}

// ======================= 服务端主流程 =======================

pub fn start_server(args: &Args, config_path: &str, ctx: Arc<RuntimeCtx>) -> Result<(), String> {
    info!("Starting TCP TLS server process...");
    let hooks = LifecycleHooks::new(args.up.clone(), args.down.clone());
    #[cfg(target_os = "linux")]
    let mut tap_setup_error: Option<String> = None;
    #[cfg(not(target_os = "linux"))]
    let tap_setup_error: Option<String> = None;

    let (pool, gw_v4, gw_v6) = IpPool::new(&args.v4cidr, &args.v6cidr);
    let v4_mask_bits = pool.v4_mask_bits;
    let v6_mask_bits = pool.v6_mask_bits;

    let vswitch = VSwitch::new();
    // 0 = 协议边界 [2,64]：未配置时不额外限制
    let (fec_group_min, fec_group_max) =
        crate::fec::normalize_fec_group_bounds(args.fec_group_min, args.fec_group_max);
    let core = Arc::new(ServerCore {
        psk: args.psk.clone(),
        psk_hash: hash_psk(&args.psk),
        encrypt: args.encrypt,
        enc_algo: enc_algo_from_config(&args.enc_algo),
        // 强度下限解析一次，握手热路径只读整数
        min_enc: min_enc_rank(&args.min_enc),
        // 0 = 默认 1024：直接跑 --max-sessions 0 也不该变成"无上限"，否则
        // 一个裸参数就能关掉容量保护
        max_sessions: normalize_max_sessions(args.max_sessions),
        fec_group_min,
        fec_group_max,
        last_session_reap_ms: AtomicU64::new(0),
        brutal: args.brutal,
        brutal_up: args.brutal_up,
        brutal_down: args.brutal_down,
        vswitch: vswitch.clone(),
        sessions: RwLock::new(HashMap::new()),
        pool: Mutex::new(pool),
        banned: BanList::new(),
        registry: Arc::new(RwLock::new(HashMap::new())),
        started_at: Instant::now(),
        gw_v4: gw_v4.clone(),
        gw_v6: gw_v6.clone(),
        v4_mask_bits,
        v6_mask_bits,
    });

    // 源 MAC 归属校验（对齐 Go validateSrcMAC）：会话端口只能声明本会话
    // 注册的 MAC。捕获 Weak 而非 Arc——ServerCore 持有 VSwitch，捕获 Arc 会
    // 构成引用环
    {
        let weak = Arc::downgrade(&core);
        let f: Arc<dyn Fn(&str, &[u8; 6]) -> bool + Send + Sync> =
            Arc::new(move |src_port_id, mac| {
                let Some(core) = weak.upgrade() else {
                    return true;
                };
                let sessions = core.sessions.read();
                src_mac_allowed(sessions.get(src_port_id).map(|s| &s.mac_bin), mac)
            });
        core.vswitch.set_validate_mac(f);
    }

    let device: Arc<dyn TapDevice> = if args.tap == "mem" {
        info!("Using in-memory TAP backend (no real device)");
        Arc::new(MemTap)
    } else {
        // 对齐 Go server.go 的 setTapMac：服务端也尊重配置里的 mac。
        // 与客户端不同的是这里失败只告警——服务端不向任何人声明自己的 MAC，
        // 配置错了顶多是自己 TAP 的地址不符合预期，不该因此拒绝启动。
        let cfg_mac: Option<[u8; 6]> = match crate::utils::parse_config_mac(&args.mac) {
            Ok(m) => m,
            Err(e) => {
                warn!("Server failed to set tap MAC: {}", e);
                None
            }
        };
        let builder = tun_rs::DeviceBuilder::new()
            .name(&args.tap)
            .layer(tun_rs::Layer::L2)
            .mtu(args.mtu);
        let builder = if let Some(m) = cfg_mac {
            builder.mac_addr(m)
        } else {
            builder
        };
        let dev = builder.build_sync().unwrap();
        if cfg_mac.is_some() {
            info!("Interface {} MAC set to {}", args.tap, args.mac);
        }
        info!("Configuring Server TAP Interface IP...");
        // 对齐 Go：TAP 挂网关地址（网络基址+1），而不是网络号。先 up 再挂
        // 地址、v6 加 nodad，否则 web.bind=tunnel 的面板绑定不上 v6 网关。
        #[cfg(target_os = "linux")]
        if let Err(e) = crate::utils::apply_ip_cmds(&crate::utils::tap_addr_cmds(
            &args.tap,
            &core.ipv4_cidr(&gw_v4),
            &core.ipv6_cidr(&gw_v6),
        )) {
            tap_setup_error = Some(e);
        }
        Arc::new(dev)
    };

    let dev_writer = device.clone();
    let dev_reader = dev_writer.clone();

    let (tap_tx, tap_rx) = bounded::<VPNFrame>(1024);
    let tap_port = Arc::new(AsyncPort::new(TAP_PORT_ID.to_string()));
    tap_port.register_backend(Arc::new(Backend {
        ch: tap_tx,
        rtt_cache: Arc::new(AtomicU32::new(0)),
        notify: None,
    }));
    vswitch.add_port(TAP_PORT_ID.to_string(), tap_port);
    std::thread::spawn(move || {
        while let Ok(f) = tap_rx.recv() {
            if !f.data.is_empty() {
                let _ = dev_writer.send(f.data.as_slice());
            }
            // TAP 是该分支终点；Owned 直接归 Vec 池，Shared 在最后 owner 时归池。
            f.data.release();
        }
    });

    let vs_for_tap = core.vswitch.clone();
    let tap_read_size = crate::tap::tap_read_buffer_size(args.mtu);
    std::thread::spawn(move || {
        loop {
            let mut frame = acquire_frame_vec(tap_read_size);
            match dev_reader.recv(&mut frame) {
                Ok(n) if n > 0 => {
                    frame.truncate(n);
                    // VSwitch 本身用 Arc<Vec<u8>> 传递所有权/共享洪泛；直接让
                    // TAP 填充 pooled Vec，消除 temp-buffer -> pool memcpy。
                    vs_for_tap.process_frame(TAP_PORT_ID, Arc::new(frame));
                }
                Ok(_) => release_frame_vec(frame),
                Err(_) => {
                    release_frame_vec(frame);
                    break;
                }
            }
        }
    });

    let tls_config = match build_server_tls(&args.cert, &args.key) {
        Ok(c) => c,
        Err(e) => return Err(format!("Invalid configuration: {e}")),
    };

    let n_workers = if args.workers > 0 {
        args.workers.max(1) as usize
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .min(8)
            .max(1)
    };

    // 每个 worker 一个 accept 通道：acceptor 线程轮询分发，worker 在自己的
    // poll 线程里注册并接管，突破单核吞吐天花板。
    let mut accept_txs = Vec::with_capacity(n_workers);
    let mut accept_rxs = Vec::with_capacity(n_workers);
    for _ in 0..n_workers {
        let (tx, rx) = bounded::<MioTcpStream>(256);
        accept_txs.push(tx);
        accept_rxs.push(rx);
    }

    let bind_addr: String = if args.addr.starts_with(':') {
        format!("0.0.0.0{}", args.addr)
    } else {
        args.addr.clone()
    };
    let socket_addr = bind_addr
        .parse()
        .map_err(|e| format!("invalid TCP listen address {bind_addr}: {e}"))?;
    let listener = TcpListener::bind(socket_addr)
        .map_err(|e| format!("TCP Listen error on {bind_addr}: {e}"))?;

    let hook_env = HookEnv {
        mode: "server".into(),
        dev: args.tap.clone(),
        config: config_path.to_string(),
        ipv4: core.ipv4_cidr(&gw_v4),
        ipv6: core.ipv6_cidr(&gw_v6),
        gateway_v4: gw_v4.clone(),
        gateway_v6: gw_v6.clone(),
    };
    hooks.activate(hook_env.clone());
    if hooks.configured() {
        if let Some(e) = tap_setup_error {
            let cleanup = hooks.down();
            return Err(match cleanup {
                Ok(()) => format!("Server tunnel interface is not ready; refusing to run up hook: {e}"),
                Err(down) => format!("Server tunnel interface is not ready: {e}; cleanup failed: {down}"),
            });
        }
        if let Err(e) = hooks.up(hook_env) {
            let cleanup = hooks.down();
            return Err(match cleanup {
                Ok(()) => e,
                Err(down) => format!("{e}; cleanup failed: {down}"),
            });
        }
    }

    if !args.web.is_empty() {
        match args.web_bind.as_str() {
            "tunnel" => start_web_server_tunnel(
                web_port(&args.web),
                args.web_auth.clone(),
                args.web_cert.clone(),
                args.web_key.clone(),
                core.clone(),
                ctx.clone(),
                core.clone(),
            ),
            _ => start_web_server(
                args.web.clone(),
                args.web_auth.clone(),
                args.web_cert.clone(),
                args.web_key.clone(),
                core.clone(),
                ctx.clone(),
            ),
        }
    }

    let mut handles = Vec::new();
    for rx in accept_rxs {
        let core = core.clone();
        let cfg = tls_config.clone();
        handles.push(std::thread::spawn(move || worker_loop(core, cfg, rx)));
    }
    {
        let txs = accept_txs;
        handles.push(std::thread::spawn(move || acceptor_loop(listener, txs)));
    }
    for h in handles {
        let _ = h.join();
    }
    hooks.down()
}

const TOKEN_WAKE: Token = Token(1);

/// 接入线程：只负责 accept、socket 调优和轮询分发（对齐 Go 每连接一个
/// 协程的接入模型，用 accept 通道 hand-off 避免跨线程注册 mio）。
fn acceptor_loop(mut listener: TcpListener, queues: Vec<Sender<MioTcpStream>>) {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Poll init error: {}", e);
            std::process::exit(1);
        }
    };
    let mut events = Events::with_capacity(256);
    poll.registry()
        .register(&mut listener, Token(0), Interest::READABLE)
        .unwrap();
    info!("✅ Server listening for TLS connections.");

    let mut rr = 0usize;
    loop {
        if crate::client::EXIT.load(Ordering::Relaxed) {
            break;
        }
        if poll
            .poll(&mut events, Some(Duration::from_secs(1)))
            .is_err()
        {
            continue;
        }
        for event in events.iter() {
            if event.token() != Token(0) {
                continue;
            }
            while let Ok((socket, _)) = listener.accept() {
                if socket.set_nodelay(true).is_err() {
                    continue;
                }
                apply_tcp_keepalive(&socket);
                // Keep SO_RCVBUF/SO_SNDBUF untouched so Linux can autotune
                // high-BDP tunnel connections via tcp_rmem/tcp_wmem.
                let w = rr % queues.len();
                rr += 1;
                if queues[w].try_send(socket).is_err() {
                    // 对应 worker 拥塞：丢弃，客户端重连重试
                }
            }
        }
    }
}

/// 工作线程：独立的 Poll / Waker / 会话表，处理分片到本线程的连接。
/// 共享状态（会话注册表、交换机、IP 池、封禁表）均已线程安全。
fn worker_loop(
    core: Arc<ServerCore>,
    tls_config: Arc<ServerConfig>,
    accept_rx: Receiver<MioTcpStream>,
) {
    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4096);

    // 事件驱动下行：端口投递帧 → 唤醒本 worker 的 poller 并把会话 Token
    // 排入脏队列，事件循环按 Token 精准冲刷。
    let dirty_tokens: Arc<ArrayQueue<Token>> = Arc::new(ArrayQueue::new(4096));
    let loop_waker: Arc<mio::Waker> =
        Arc::new(mio::Waker::new(poll.registry(), TOKEN_WAKE).expect("Waker init"));

    let mut mio_sessions: HashMap<Token, MioSession> = HashMap::new();
    let mut unique_token: usize = 2;
    // worker 串行处理事件，可复用同一个重排输出 scratch，避免每包/每 timeout malloc。
    let mut reorder_ready: Vec<Arc<Vec<u8>>> = Vec::with_capacity(64);

    loop {
        if crate::client::EXIT.load(Ordering::Relaxed) {
            break;
        }

        // 只注册 READABLE（修复旧版 WRITABLE 恒注册导致的水平触发空转）。
        // 无重排缺口时保持 250ms 运维巡检；出现缺口后把 poll deadline 收紧到
        // 该会话的精确剩余时间，避免固定 250ms 盲等或 5ms 空转。
        let mut poll_timeout = Duration::from_millis(250);
        for sess in mio_sessions.values() {
            if let Some(c_sess) = &sess.client_session {
                if let Some(wait) = c_sess.reorder_buf.lock().next_timeout() {
                    poll_timeout = poll_timeout.min(wait);
                }
            }
        }
        poll.poll(&mut events, Some(poll_timeout))
            .unwrap();

        let mut closed_tokens: Vec<Token> = Vec::new();

        // ===== 新连接接入（acceptor 分发到本 worker） =====
        while let Ok(mut socket) = accept_rx.try_recv() {
            let remote_ip = socket
                .peer_addr()
                .map(|a| a.ip().to_string())
                .unwrap_or_default();
            if mio_sessions.len() >= 32
                || mio_sessions
                    .values()
                    .filter(|s| s.remote_ip == remote_ip)
                    .count()
                    >= 4
            {
                continue;
            }
            let t = Token(unique_token);
            unique_token += 1;
            if poll
                .registry()
                .register(&mut socket, t, Interest::READABLE)
                .is_err()
            {
                continue;
            }
            let (tx, rx) = bounded(1024);
            let backend = Arc::new(Backend {
                ch: tx,
                rtt_cache: Arc::new(AtomicU32::new(50000)),
                notify: Some(Arc::new(BackendNotify::new(
                    loop_waker.clone(),
                    dirty_tokens.clone(),
                    t,
                ))),
            });
            // 首帧是握手 JSON（<2KB）：认证前用小上限，防 10 字节帧头声明
            // 131070 长度把扫描缓冲扩到 131KB/连接；认证通过后恢复全量上限
            let mut scanner = FrameScanner::new();
            scanner.set_max_data_len(HANDSHAKE_DATA_LENGTH);
            let tls_observed = Arc::new(Mutex::new(None));
            let mut connection_tls_config = (*tls_config).clone();
            connection_tls_config.cert_resolver = Arc::new(ObservingCertResolver {
                inner: connection_tls_config.cert_resolver.clone(),
                observed: tls_observed.clone(),
            });
            let tls = ServerConnection::new(Arc::new(connection_tls_config)).unwrap();
            mio_sessions.insert(
                t,
                MioSession {
                    socket,
                    remote_ip,
                    tls,
                    tls_observed,
                    scanner,
                    rx,
                    handshake_done: false,
                    sniffed: false,
                    sniffed_inner: false,
                    client_session: None,
                    tx_backend: Some(backend),
                    last_keepalive: Instant::now(),
                    last_rx: Instant::now(),
                    rtt_timer: Instant::now(),
                    send_buf: Vec::with_capacity(70 * 1024),
                    ic_rx: None,
                    session_epoch: 0,
                    write_stalled: None,
                    brutal_applied: false,
                },
            );
        }

        // ===== 定时器扫描：保活 / 空闲 / RTT / 强踢 / 下行拉帧 =====
        let now_ms = core.started_at.elapsed().as_millis() as u64;
        let last_reap = core.last_session_reap_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last_reap) >= 1000
            && core
                .last_session_reap_ms
                .compare_exchange(last_reap, now_ms, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
        {
            let expired: Vec<_> = core
                .sessions
                .read()
                .values()
                .filter(|session| {
                    if session.stat.active_conns.load(Ordering::Acquire) != 0 {
                        return false;
                    }
                    let version = session.stat.disconnect_version.load(Ordering::Acquire);
                    matches!(
                        *session.destroy_deadline.lock(),
                        Some((deadline, expected_version))
                            if expected_version == version && Instant::now() >= deadline
                    )
                })
                .cloned()
                .collect();
            for session in expired {
                core.destroy_session(&session);
            }
        }

        for (token, sess) in mio_sessions.iter_mut() {
            let idle_time = sess.last_rx.elapsed().as_secs();
            // 15s 无下行数据视为链路死亡（对齐 Go 15s 读超时）。4s 心跳下
            // 30s = 丢 3 个心跳才判死；15s = 丢 2 个，直接缩短用户看到的
            // "connection lost: timeout" 窗口。
            if idle_time > 15 {
                debug!("closing token {:?}: no TLS receive progress for {}s", token, idle_time);
                closed_tokens.push(*token);
                continue;
            }

            if !sess.handshake_done {
                continue;
            }

            // 每 200ms 刷新 RTT（对齐 Go startRTTPoller）
            if sess.rtt_timer.elapsed() > Duration::from_millis(200) {
                if let Some(backend) = &sess.tx_backend {
                    let rtt = if idle_time >= 5 {
                        100000
                    } else {
                        get_tcp_rtt(&sess.socket)
                    };
                    backend.rtt_cache.store(rtt, Ordering::Relaxed);
                }
                sess.rtt_timer = Instant::now();
            }

            if sess.last_keepalive.elapsed() > Duration::from_secs(4)
                && sess.write_stalled.is_none()
                && !sess.tls.wants_write()
            {
                sess.send_buf.clear();
                append_padded_frame(&mut sess.send_buf, 0, &[], None);
                if sess.tls.writer().write_all(&sess.send_buf).is_ok() {
                    sess.last_keepalive = Instant::now();
                }
            }

            if let Some(c_sess) = &sess.client_session {
                if c_sess.port.is_sequence_exhausted() {
                    let mut epoch = c_sess.epoch_state.write();
                    if !epoch.instance_id.starts_with("exhausted-") {
                        epoch.instance_id = format!("exhausted-{}", gen_session_id());
                        epoch.epoch = epoch.epoch.saturating_add(1);
                        c_sess.stat.active_conns.store(0, Ordering::Release);
                        warn!(
                            "[{}] sequence space exhausted; forcing a fresh key epoch",
                            c_sess.stat.client_id
                        );
                    }
                    debug!("closing token {:?}: sequence space exhausted", token);
                    closed_tokens.push(*token);
                    continue;
                }
                if c_sess.epoch_state.read().epoch != sess.session_epoch {
                    debug!("closing token {:?}: session epoch mismatch", token);
                    closed_tokens.push(*token);
                    continue;
                }
                if c_sess.stat.force_disconnect.load(Ordering::Relaxed) {
                    debug!("closing token {:?}: forced disconnect", token);
                    closed_tokens.push(*token);
                    continue;
                }
            }

            // 写积压超过 10s 视为对端卡死（对齐 Go SetWriteDeadline(10s)）
            if let Some(stalled_at) = sess.write_stalled {
                if stalled_at.elapsed() > Duration::from_secs(10) {
                    debug!("closing token {:?}: TLS write stalled for >10s", token);
                    closed_tokens.push(*token);
                    continue;
                }
            }

            // 从端口通道拉帧成批发送（对齐 Go 下行写协程）
            let mut close = false;
            flush_outbound(sess, &mut close);
            if close {
                closed_tokens.push(*token);
            }
        }

        // ===== 读事件与数据面 =====
        for event in events.iter() {
            let token = event.token();
            if token == TOKEN_WAKE {
                // 下行帧就绪：冲刷脏 Token 对应的会话（事件驱动路径）
                while let Some(dirty) = dirty_tokens.pop() {
                    if let Some(sess) = mio_sessions.get_mut(&dirty) {
                        let mut close = false;
                        flush_outbound(sess, &mut close);
                        if close {
                            closed_tokens.push(dirty);
                        }
                    }
                }
            } else if mio_sessions.contains_key(&token) {
                let mut close = false;
                let mut tarpit = false;

                if event.is_readable() {
                    let sess = mio_sessions.get_mut(&token).unwrap();
                    // 第一层嗅探：明文首字节非 0x16 → 403
                    if !sess.sniffed {
                        let mut peek_buf = [0u8; 1];
                        match sess.socket.peek(&mut peek_buf) {
                            Ok(1) => {
                                sess.sniffed = true;
                                if peek_buf[0] != 0x16 {
                                    serve_fallback_http(&mut sess.socket, false);
                                    close = true;
                                }
                            }
                            _ => {}
                        }
                    }

                    if !close {
                        // mio readiness is edge-triggered: keep servicing this fd
                        // until the underlying socket itself returns WouldBlock.
                        // Interleave every ciphertext read with rustls processing and
                        // plaintext frame draining so neither rustls buffer can become
                        // the reason we stop before reaching EAGAIN.
                        'socket_read: loop {
                            match sess.tls.read_tls(&mut sess.socket) {
                                Ok(0) => {
                                    debug!(
                                        "closing token {:?}: tls.read_tls returned EOF",
                                        token
                                    );
                                    close = true;
                                    break 'socket_read;
                                }
                                Ok(_) => {
                                    sess.last_rx = Instant::now();
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                    break 'socket_read;
                                }
                                Err(e) => {
                                    debug!(
                                        "closing token {:?}: tls.read_tls failed: {}",
                                        token,
                                        e
                                    );
                                    close = true;
                                    break 'socket_read;
                                }
                            }

                            if let Err(e) = sess.tls.process_new_packets() {
                                debug!(
                                    "closing token {:?}: tls.process_new_packets failed: {}",
                                    token,
                                    e
                                );
                                if !sess.handshake_done {
                                    serve_fallback_http(&mut sess.socket, false);
                                }
                                close = true;
                                break 'socket_read;
                            }

                            // 第二层嗅探（对齐 Go peekBuf2 >= 0x20 检查）。
                            if !sess.sniffed_inner {
                                match sess.scanner.peek_first_byte() {
                                    Some(b) if b >= 0x20 => {
                                        let is_h2 =
                                            sess.tls.alpn_protocol() == Some(b"h2");
                                        serve_fallback_http(
                                            &mut sess.tls.writer(),
                                            is_h2,
                                        );
                                        close = true;
                                    }
                                    Some(_) => sess.sniffed_inner = true,
                                    None => {}
                                }
                            }

                            if !close {
                                process_plain_frames(
                                    sess,
                                    &core,
                                    &mut close,
                                    &mut tarpit,
                                    &mut reorder_ready,
                                );
                            }
                            if close {
                                break 'socket_read;
                            }

                            // TLS handshake/application responses generated while
                            // consuming plaintext should not accumulate while we
                            // continue draining the readable edge.
                            drain_tls(sess, &mut close);
                            if close {
                                break 'socket_read;
                            }
                        }

                        // One final flush covers data queued by the last processed
                        // frame before read_tls reached WouldBlock.
                        if !close {
                            drain_tls(sess, &mut close);
                        }
                    }
                }

                if close {
                    if let Some(mut s) = mio_sessions.remove(&token) {
                        close_session_tls(&mut s);
                        let _ = poll.registry().deregister(&mut s.socket);
                        let _ = tarpit; // 认证失败立即释放资源；不再创建无界 tarpit OS 线程。
                        on_conn_closed(s.client_session, s.tx_backend, s.session_epoch, s.brutal_applied);
                    }
                }
            }
        }

        // 先处理本轮所有可读事件，让刚到达的缺失帧有机会补洞；随后才执行超时
        // 跳过。一个逻辑会话可能有多条连接落在同一 worker，只处理一次。
        let mut seen_reorder = HashSet::new();
        let reorder_sessions: Vec<_> = mio_sessions
            .values()
            .filter_map(|sess| sess.client_session.clone())
            .filter(|session| seen_reorder.insert(Arc::as_ptr(session) as usize))
            .collect();
        for session in reorder_sessions {
            reorder_ready.clear();
            session
                .reorder_buf
                .lock()
                .flush_timeout_into(&mut reorder_ready);
            for ordered in reorder_ready.drain(..) {
                if session.mac_bin != [0u8; 6] {
                    core.vswitch.process_session_frame(
                        &session.stat.client_id,
                        session.mac_bin,
                        ordered,
                    );
                } else {
                    core.vswitch.process_frame(&session.stat.client_id, ordered);
                }
            }
        }

        // ===== 关闭定时器发现的会话连接 =====
        closed_tokens.sort();
        closed_tokens.dedup();
        for t in closed_tokens {
            if let Some(mut s) = mio_sessions.remove(&t) {
                // 定时器发现的关闭：空闲超时、序号耗尽、epoch 不匹配、强踢、
                // 写卡死、下行冲刷失败。握手拒绝等即时关闭走上面的 close 分支，
                // 两处都补发 close_notify。
                close_session_tls(&mut s);
                let _ = poll.registry().deregister(&mut s.socket);
                on_conn_closed(s.client_session, s.tx_backend, s.session_epoch, s.brutal_applied);
            }
        }
    }
}

fn process_plain_frames(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    close: &mut bool,
    tarpit: &mut bool,
    reorder_ready: &mut Vec<Arc<Vec<u8>>>,
) {
    // 共享统计按一次 TLS plaintext drain 聚合，降低多 worker 写同一 cache line 的频率。
    let mut rx_bytes_batch = 0u64;
    let mut rx_packets_batch = 0u64;

    loop {
        match sess.scanner.read_frame(&mut sess.tls.reader()) {
            Ok(Some((raw, seq))) => {
                if raw.is_empty() {
                    sess.last_rx = Instant::now();
                    continue;
                }
                let mut data = raw;

                if sess.handshake_done {
                    rx_bytes_batch =
                        rx_bytes_batch.saturating_add((data.len() + 10) as u64);
                    rx_packets_batch = rx_packets_batch.saturating_add(1);
                }

                if seq == 0 && !sess.handshake_done {
                    let outcome = handle_handshake(sess, core, &data, tarpit);
                    // 握手解析完成后不再需要原始 JSON payload，立即归还热帧池。
                    release_frame_vec(data);
                    match outcome {
                        HandshakeOutcome::Ok => {
                            sess.handshake_done = true;
                            sess.scanner.set_max_data_len(MAX_DATA_LENGTH);
                        }
                        HandshakeOutcome::Close => {
                            *close = true;
                            break;
                        }
                        HandshakeOutcome::TarpitClose => {
                            *tarpit = true;
                            *close = true;
                            break;
                        }
                    }
                } else if sess.handshake_done {
                    if seq != 0 {
                        if let Some(ic) = &sess.ic_rx {
                            let wire_len = data.len() as u32;
                            match ic.open_in_place(&mut data, seq, wire_len) {
                                Ok(plain) => {
                                    let plen = plain.len();
                                    data.truncate(plen);
                                }
                                Err(_) => {
                                    debug!("dropped tampered/foreign frame (seq={})", seq);
                                    release_frame_vec(data);
                                    continue;
                                }
                            }
                        }
                    }

                    let c_sess = match &sess.client_session {
                        Some(c) => c.clone(),
                        None => {
                            release_frame_vec(data);
                            continue;
                        }
                    };
                    let epoch = c_sess.epoch_state.read();
                    if sess.session_epoch != epoch.epoch {
                        debug!("closing session plaintext path: epoch mismatch");
                        drop(epoch);
                        release_frame_vec(data);
                        *close = true;
                        break;
                    }
                    let fec_dec = epoch.fec_dec.clone();
                    drop(epoch);
                    let data = Arc::new(data);

                    if seq == 0 {
                        if let Some(dec) = &fec_dec {
                            if fec::is_parity_frame(&data) {
                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                    deliver_to_vswitch(
                                        &c_sess,
                                        core,
                                        s,
                                        f,
                                        reorder_ready,
                                    );
                                };
                                dec.on_parity(&data, &mut sink);
                                release_shared_frame(data);
                                continue;
                            }
                        }
                    }

                    if let Some(dec) = &fec_dec {
                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                            deliver_to_vswitch(&c_sess, core, s, f, reorder_ready);
                        };
                        dec.on_data(seq, &data, &mut sink);
                    }

                    if !c_sess.dedup.lock().is_duplicate(seq) {
                        deliver_to_vswitch(&c_sess, core, seq, data, reorder_ready);
                    } else {
                        release_shared_frame(data);
                    }
                }
            }
            Ok(None) => break,
            Err(e) => {
                debug!("closing session plaintext path: frame scanner failed: {}", e);
                if !sess.handshake_done {
                    let is_h2 = sess.tls.alpn_protocol() == Some(b"h2");
                    serve_fallback_http(&mut sess.tls.writer(), is_h2);
                    while sess.tls.wants_write() {
                        let _ = sess.tls.write_tls(&mut sess.socket);
                    }
                }
                *close = true;
                break;
            }
        }
    }

    if rx_packets_batch != 0 {
        if let Some(s) = &sess.client_session {
            s.stat.rx_bytes.fetch_add(rx_bytes_batch, Ordering::Relaxed);
            s.stat
                .rx_packets
                .fetch_add(rx_packets_batch, Ordering::Relaxed);
        }
    }
}


fn deliver_to_vswitch(
    c_sess: &Arc<ClientSession>,
    core: &Arc<ServerCore>,
    seq: u32,
    frame: Arc<Vec<u8>>,
    ready: &mut Vec<Arc<Vec<u8>>>,
) {
    ready.clear();
    c_sess
        .reorder_buf
        .lock()
        .insert_into(seq, frame, ready);
    for ordered in ready.drain(..) {
        if c_sess.mac_bin != [0u8; 6] {
            core.vswitch.process_session_frame(
                &c_sess.stat.client_id,
                c_sess.mac_bin,
                ordered,
            );
        } else {
            core.vswitch.process_frame(&c_sess.stat.client_id, ordered);
        }
    }
}

/// 从端口通道拉帧成批发送（对齐 Go 下行写协程）
fn flush_outbound(sess: &mut MioSession, close: &mut bool) {
    // consumer 在真正 drain 前清 wake pending；此后并发入队会重新唤醒 poller。
    if let Some(backend) = &sess.tx_backend {
        if let Some(n) = &backend.notify {
            n.consume_wake();
        }
    }

    if sess.write_stalled.is_some() || sess.tls.wants_write() {
        drain_tls(sess, close);
        if *close || sess.tls.wants_write() {
            return;
        }
    }

    let ic_tx = sess.client_session.as_ref().and_then(|s| {
        let epoch = s.epoch_state.read();
        if epoch.epoch != sess.session_epoch {
            None
        } else {
            epoch.ic_tx.clone()
        }
    });
    if let Some(s) = &sess.client_session {
        if s.epoch_state.read().epoch != sess.session_epoch {
            *close = true;
            return;
        }
    }

    // Stay below rustls' bounded outgoing plaintext buffer. A 256KiB
    // write_all() can fail with WriteZero before ciphertext is drained.
    const TLS_WRITE_BATCH_BYTES: usize = 32 * 1024;
    let mut pulled = 0u64;
    sess.send_buf.clear();
    while let Ok(f) = sess.rx.try_recv() {
        let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };
        append_padded_frame(&mut sess.send_buf, f.seq, f.data.as_slice(), ic_ref);
        f.data.release();
        pulled += 1;
        if sess.send_buf.len() >= TLS_WRITE_BATCH_BYTES || pulled >= 2048 {
            break;
        }
    }

    if !sess.send_buf.is_empty() {
        if let Some(s) = &sess.client_session {
            if pulled != 0 {
                s.stat.tx_packets.fetch_add(pulled, Ordering::Relaxed);
            }
            s.stat
                .tx_bytes
                .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);
        }
        if let Err(e) = sess.tls.writer().write_all(&sess.send_buf) {
            debug!("closing session: tls plaintext writer failed: {}", e);
            *close = true;
            return;
        }
        sess.send_buf.clear();
    }
    drain_tls(sess, close);
}

/// 冲刷 rustls 内部积压到 socket；遇 WouldBlock 记录卡死起点
fn drain_tls(sess: &mut MioSession, close: &mut bool) {
    while sess.tls.wants_write() {
        match sess.tls.write_tls(&mut sess.socket) {
            Ok(0) => {
                debug!("closing session: tls.write_tls returned zero");
                *close = true;
                break;
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if sess.write_stalled.is_none() {
                    sess.write_stalled = Some(Instant::now());
                }
                break;
            }
            Err(e) => {
                debug!("closing session: tls.write_tls failed: {}", e);
                *close = true;
                break;
            }
        }
    }
    if !sess.tls.wants_write() {
        sess.write_stalled = None;
    }
}

// 干净断开：补发 TLS close_notify 并冲刷完记录缓冲。
// rustls 在 Drop 时不发 close_notify，而 Go 的 tls.Conn.Close() 会自动发。
// 不补发的话，被拒绝握手的探测端读到的是
// "peer closed connection without sending TLS close_notify"，而不是 EOF，
// 看起来像服务端异常崩溃而不是按预期拒绝。
// send_close_notify 在已发过致命告警时是空操作——那类连接对端已经拿到了
// 明确的错误通知，不需要再补。对端已断开时 write_tls 会直接失败，此时
// 静默放弃即可：连接反正已经没了。
fn close_session_tls(s: &mut MioSession) {
    s.tls.send_close_notify();
    while s.tls.wants_write() {
        match s.tls.write_tls(&mut s.socket) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }
}

enum HandshakeOutcome {
    Ok,
    Close,
    TarpitClose,
}

fn valid_session_token_format(token: &str) -> bool {
    token.len() == 64 && hex::decode(token).map(|raw| raw.len() == 32).unwrap_or(false)
}

fn accept_session_resume_token(epoch: &mut SessionEpochState, presented: &str) -> bool {
    if verify_random_session_token(&epoch.resume_token, presented) {
        return true;
    }
    if !epoch.pending_resume_token.is_empty()
        && verify_random_session_token(&epoch.pending_resume_token, presented)
    {
        epoch.resume_token = std::mem::take(&mut epoch.pending_resume_token);
        return true;
    }
    false
}

fn ensure_pending_resume_token(epoch: &mut SessionEpochState) -> Result<(), String> {
    if epoch.pending_resume_token.is_empty() {
        epoch.pending_resume_token = new_session_token()?;
    }
    Ok(())
}

fn response_resume_token(epoch: &SessionEpochState) -> String {
    if epoch.pending_resume_token.is_empty() {
        epoch.resume_token.clone()
    } else {
        epoch.pending_resume_token.clone()
    }
}

fn rotate_session_epoch(
    session: &Arc<ClientSession>,
    core: &Arc<ServerCore>,
    instance_id: &str,
) -> Result<(), String> {
    let mut epoch = session.epoch_state.write();
    let salt_a = new_random_salt();
    let salt_b = new_random_salt();
    let (ic_tx, ic_rx, fec_tx, fec_rx) = if core.encrypt {
        let algo = epoch.enc_algo;
        (
            Some(Arc::new(InnerCipher::gcm_for_algo(&core.psk, &salt_b, algo)?)),
            Some(Arc::new(InnerCipher::gcm_for_algo(&core.psk, &salt_a, algo)?)),
            Some(Arc::new(InnerCipher::gcm_domain_for_algo(&core.psk, &salt_b, "fec", algo)?)),
            Some(Arc::new(InnerCipher::gcm_domain_for_algo(&core.psk, &salt_a, "fec", algo)?)),
        )
    } else {
        (None, None, None, None)
    };
    let fec_dec = if session.fec_enc_k > 0 {
        Some(Arc::new(FecDecoder::new(
            session.fec_enc_k as usize,
            fec_rx,
        )))
    } else {
        None
    };
    if let Some(old) = &epoch.fec_dec {
        old.reset();
    }
    session.reorder_buf.lock().reset();
    session.dedup.lock().reset();
    if session.fec_enc_k > 0 {
        session.port.reset_epoch(session.fec_enc_k as usize, fec_tx);
    } else {
        session.port.reset_epoch(0, None);
    }
    epoch.instance_id = instance_id.to_string();
    epoch.epoch = epoch.epoch.saturating_add(1);
    epoch.salt_a = salt_a;
    epoch.salt_b = salt_b;
    epoch.ic_tx = ic_tx;
    epoch.ic_rx = ic_rx;
    epoch.fec_dec = fec_dec;
    session.stat.active_conns.store(0, Ordering::Release);
    Ok(())
}

fn handle_handshake(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    data: &[u8],
    tarpit_flag: &mut bool,
) -> HandshakeOutcome {
    let Ok(mut req) = serde_json::from_slice::<HandshakeReq>(data) else {
        warn!("Handshake data parse failed; engaging camouflage tar pit.");
        return HandshakeOutcome::TarpitClose;
    };
    debug!(
        "<= handshake request client={} proto={} instance={} fec={}/{} enc={}/{} token_present={}",
        req.client_id,
        req.protocol_version,
        req.client_instance,
        req.fec,
        req.fec_group,
        req.encrypt,
        req.enc_algo,
        !req.session_token.is_empty()
    );

    // 常量时间比较：pskHash 本身就是握手凭据，字符串 != 的逐字节短路会把匹配
    // 前缀长度泄露在响应时延里（远程时序预言机，可逐字节重建 pskHash）。
    if !constant_time_eq(req.psk.as_bytes(), core.psk_hash.as_bytes()) {
        warn!("PSK verification failed (hash mismatch).");
        return HandshakeOutcome::TarpitClose;
    }
    // 加密配置不匹配 → 焦油坑（对齐 Go）
    if req.encrypt != core.encrypt {
        warn!(
            "Encryption settings mismatch (Client: {}, Server: {})",
            req.encrypt, core.encrypt
        );
        return HandshakeOutcome::TarpitClose;
    }
    // 强度下限：运维强制 GCM 时拒绝能力不足的客户端。这里刻意**不**走焦油坑——
    // 这是运维侧的期望结果（客户端版本过旧），需要一条明确可查的失败记录。
    // 位置在会话查找之前：能力不足的客户端连接管既有会话都不该被允许。
    if core.encrypt && core.min_enc > 0 && !is_gcm_algo(req.enc_algo) {
        warn!(
            "connection refused: client cipher capability (algo={}) is below the min_enc floor (requires {})",
            req.enc_algo, core.min_enc
        );
        return HandshakeOutcome::Close;
    }
    if core.encrypt && req.enc_algo != core.enc_algo {
        warn!(
            "connection refused: client inner cipher {} ({}) does not match server enc_algo {} ({})",
            req.enc_algo,
            enc_algo_label(req.enc_algo),
            core.enc_algo,
            enc_algo_label(core.enc_algo)
        );
        return HandshakeOutcome::Close;
    }
    let client_id = req.client_id.clone();
    if client_id.is_empty() {
        warn!("connection refused: ClientID is missing");
        return HandshakeOutcome::Close;
    }
    // 格式校验：clientID 与 MAC 会大量进入日志与面板，畸形值既可能是坏客户端，
    // 也可能被用于换行注入伪造日志行。直接断链，刻意不走焦油坑——这不是探测，
    // 无需伪装成服务故障。放在封禁检查之前：畸形 ID 不该获得 ban 状态信息。
    if !is_valid_client_id(&client_id) {
        warn!(
            "connection refused: malformed ClientID (must be a UUID), length {}",
            client_id.len()
        );
        return HandshakeOutcome::Close;
    }
    if !is_valid_session_mac(&req.mac) {
        warn!(
            "[{}] connection refused: MAC must be a non-zero unicast address",
            client_id
        );
        return HandshakeOutcome::Close;
    }
    if req.protocol_version != 2 {
        warn!(
            "[{}] connection refused: unsupported protocol_version={}",
            client_id, req.protocol_version
        );
        return HandshakeOutcome::Close;
    }
    // FEC 分组大小是请求形态，不是能力位：拒绝越界请求而非夹取（对齐 Go）。
    // 本端客户端发送前已夹到协议范围，因此这条只拦畸形/第三方 peer；
    // fec_group=0 在 fec=false 时合法，必须按 req.fec 门控，
    // 否则所有非 FEC 握手都会被拒。
    if req.fec && (req.fec_group < core.fec_group_min || req.fec_group > core.fec_group_max) {
        warn!(
            "[{}] connection refused: fec_group={} outside server policy [{}, {}]",
            client_id, req.fec_group, core.fec_group_min, core.fec_group_max
        );
        return HandshakeOutcome::Close;
    }
    if !is_valid_client_instance(&req.client_instance) {
        warn!(
            "[{}] connection refused: invalid client_instance",
            client_id
        );
        return HandshakeOutcome::Close;
    }
    req.mac = canonical_mac(&req.mac).expect("validated MAC");
    let ns = uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_URL, b"my_vpn_tunnel");
    let expected_id =
        uuid::Uuid::new_v5(&ns, format!("{}{}", req.mac, core.psk).as_bytes()).to_string();
    if !constant_time_eq(client_id.as_bytes(), expected_id.as_bytes()) {
        warn!(
            "[{}] connection refused: client_id is not derived from the authenticated MAC",
            client_id
        );
        return HandshakeOutcome::Close;
    }
    if core.banned.is_banned(&client_id) {
        warn!("[{}] banned; access denied", client_id);
        return HandshakeOutcome::TarpitClose;
    }
    let mac = req.mac.clone();

    let c_sess: Arc<ClientSession> = {
        let mut sessions = core.sessions.write();
        if let Some(existing) = sessions.get(&client_id) {
            if !constant_time_eq(req.mac.as_bytes(), existing.mac.as_bytes()) {
                warn!("[{}] connection refused: MAC mismatch", client_id);
                *tarpit_flag = true;
                return HandshakeOutcome::TarpitClose;
            }
            let existing_algo = existing.epoch_state.read().enc_algo;
            if existing_algo != req.enc_algo {
                warn!(
                    "[{}] existing session uses inner cipher {} ({}), request wants {} ({}); rebuild/restart required",
                    client_id,
                    existing_algo,
                    enc_algo_label(existing_algo),
                    req.enc_algo,
                    enc_algo_label(req.enc_algo)
                );
                return HandshakeOutcome::Close;
            }
            let needs_rotation = existing.epoch_state.read().instance_id != req.client_instance;
            if needs_rotation {
                let valid_token = {
                    let mut epoch = existing.epoch_state.write();
                    accept_session_resume_token(&mut epoch, &req.session_token)
                };
                if !valid_token {
                    warn!(
                        "[{}] reconnect refused: invalid session token for a new client instance",
                        client_id
                    );
                    return HandshakeOutcome::Close;
                }
                if let Err(e) = rotate_session_epoch(existing, core, &req.client_instance) {
                    warn!("[{}] failed to rotate session key epoch: {}", client_id, e);
                    return HandshakeOutcome::Close;
                }
                {
                    let mut epoch = existing.epoch_state.write();
                    if let Err(e) = ensure_pending_resume_token(&mut epoch) {
                        warn!("[{}] failed to prepare the next session token: {}", client_id, e);
                        return HandshakeOutcome::Close;
                    }
                }
                info!(
                    "[{}] rotated session key epoch for a new client process instance",
                    client_id
                );
            } else {
                let mut epoch = existing.epoch_state.write();
                if !epoch.pending_resume_token.is_empty()
                    && verify_random_session_token(&epoch.pending_resume_token, &req.session_token)
                {
                    epoch.resume_token = std::mem::take(&mut epoch.pending_resume_token);
                }
            }
            info!(
                "[{}] ⚡ session revived before the destroy countdown expired (seamless handover)",
                client_id
            );
            *existing.destroy_deadline.lock() = None;
            if existing.stat.active_conns.load(Ordering::Acquire) >= 16 {
                warn!(
                    "[{}] connection refused: per-session physical connection limit reached",
                    client_id
                );
                return HandshakeOutcome::Close;
            }
            // sessions 写锁把“检查 + 占位”串行化；若把 fetch_add 留到锁外，
            // 多个 worker 可同时看见 15 并把会话冲到上限之外。
            existing.stat.active_conns.fetch_add(1, Ordering::AcqRel);
            existing.clone()
        } else {
            // 会话上限：达到即按认证失败处理，走伪装焦油坑——不向探测者泄露
            // 服务端容量信息。只拦新会话，既有会话的复活分支在上不受影响
            // （对齐 Go）。
            if core.max_sessions > 0 && sessions.len() >= core.max_sessions as usize {
                warn!(
                    "connection refused: session limit reached ({})",
                    core.max_sessions
                );
                return HandshakeOutcome::TarpitClose;
            }

            // MAC→IP 绑定优先（对齐 Go macToIP）
            let (mut req_v4, mut req_v6) = (req.ipv4.clone(), req.ipv6.clone());
            if !mac.is_empty() {
                let pool = core.pool.lock();
                if let Some(bind) = pool.mac_to_ip.get(&mac) {
                    req_v4 = bind.0.clone();
                    req_v6 = bind.1.clone();
                }
            }

            // FEC 协商：req.fec 即 XOR 模式，K 直接取请求值——上面的拒连闸已
            // 保证它在 [fec_group_min, fec_group_max] ⊆ [2,64] 内，无需再夹取；
            // 未请求 FEC 时为 0（不编码）。
            let fec_enc_k: i64 = if req.fec {
                req.fec_group
            } else {
                0
            };
            // 内层算法在前置闸门已按服务端 enc_algo 精确匹配；这里不再做降级。
            let salt_a = new_random_salt();
            let salt_b = new_random_salt();
            let (enc_algo, ic_tx, ic_rx) = if core.encrypt {
                let algo = core.enc_algo;
                (
                    algo,
                    Some(Arc::new(
                        InnerCipher::gcm_for_algo(&core.psk, &salt_b, algo).expect("GCM init"),
                    )),
                    Some(Arc::new(
                        InnerCipher::gcm_for_algo(&core.psk, &salt_a, algo).expect("GCM init"),
                    )),
                )
            } else {
                (ENC_ALGO_NONE, None, None)
            };
            let (fec_tx, fec_rx) = if is_gcm_algo(enc_algo) {
                (
                    Some(Arc::new(
                        InnerCipher::gcm_domain_for_algo(&core.psk, &salt_b, "fec", enc_algo)
                            .expect("FEC GCM init"),
                    )),
                    Some(Arc::new(
                        InnerCipher::gcm_domain_for_algo(&core.psk, &salt_a, "fec", enc_algo)
                            .expect("FEC GCM init"),
                    )),
                )
            } else {
                (None, None)
            };

            // 面板展示：xor K=d / off
            let fec_mode = if fec_enc_k > 0 {
                format!("xor K={}", fec_enc_k)
            } else {
                "off".to_string()
            };

            let mut pool = core.pool.lock();
            let v4ip = pool.alloc_v4(&req_v4);
            if v4ip.is_empty() {
                // 池耗尽必须拒连：空 IP 会被下游当成合法地址写进应答、注册表与
                // 统计，产生一个"有会话但无地址"的黑洞。与上限同样走焦油坑。
                warn!(
                    "connection refused: IPv4 address pool exhausted ({})",
                    core.ipv4_cidr(&core.gw_v4)
                );
                return HandshakeOutcome::TarpitClose;
            }
            let v6ip = pool.alloc_v6(&req_v6);
            if v6ip.is_empty() {
                pool.used_v4.remove(&v4ip);
                warn!(
                    "connection refused: IPv6 address pool exhausted ({})",
                    core.ipv6_cidr(&core.gw_v6)
                );
                return HandshakeOutcome::TarpitClose;
            }
            drop(pool);

            let stat = Arc::new(ClientStat::new(
                client_id.clone(),
                v4ip.clone(),
                v6ip.clone(),
                mac.clone(),
            ));
            *stat.fec_mode.lock() = fec_mode.clone();
            stat.enc_algo.store(enc_algo, Ordering::Relaxed);

            let port = Arc::new(AsyncPort::new(client_id.clone()));
            if fec_enc_k > 0 {
                port.attach_encoder(fec_enc_k as usize, fec_tx);
            }
            let fec_dec = if fec_enc_k > 0 {
                Some(Arc::new(FecDecoder::new(fec_enc_k as usize, fec_rx)))
            } else {
                None
            };

            let resume_token = if valid_session_token_format(&req.session_token) {
                req.session_token.clone()
            } else {
                match new_session_token() {
                    Ok(token) => token,
                    Err(e) => {
                        core.pool.lock().release(&mac, &v4ip, &v6ip);
                        error!("[{}] failed to generate session token: {}", client_id, e);
                        return HandshakeOutcome::Close;
                    }
                }
            };

            let mac_bin = parse_mac_key(&mac).unwrap_or_default();
            core.vswitch.add_port(client_id.clone(), port.clone());
            core.vswitch.add_static_mac(client_id.clone(), mac_bin);
            if !mac.is_empty() {
                core.pool
                    .lock()
                    .mac_to_ip
                    .insert(mac.clone(), (v4ip.clone(), v6ip.clone()));
            }
            core.registry
                .write()
                .insert(client_id.clone(), stat.clone());

            info!(
                "[{}] new logical client online (FEC={} EncAlgo={}), Assigned IPs: {}/{}, {}/{}",
                client_id, fec_mode, enc_algo, v4ip, core.v4_mask_bits, v6ip, core.v6_mask_bits
            );

            let sess = Arc::new(ClientSession {
                mac_bin,
                session_id: gen_session_id(),
                stat,
                port,
                reorder_buf: Arc::new(Mutex::new(ReorderBuffer::new())),
                dedup: Arc::new(Mutex::new(DeDuplicator::new())),
                fec_enc_k,
                mac,
                ipv4: v4ip,
                ipv6: v6ip,
                epoch_state: RwLock::new(SessionEpochState {
                    instance_id: req.client_instance.clone(),
                    epoch: 1,
                    resume_token,
                    pending_resume_token: String::new(),
                    enc_algo,
                    salt_a,
                    salt_b,
                    ic_tx,
                    ic_rx,
                    fec_dec,
                }),
                destroy_deadline: Mutex::new(None),
                created_at: Instant::now(),
                // 速率在下面的协商段才算出来，这里先留 0
                brutal_tx: AtomicU64::new(0),
                brutal_rx: AtomicU64::new(0),
                brutal_applied_conns: AtomicU64::new(0),
                brutal_error: Mutex::new(String::new()),
            });
            sess.stat.active_conns.store(1, Ordering::Release);
            sessions.insert(client_id.clone(), sess.clone());
            sess
        }
    };

    let epoch_snapshot = c_sess.epoch_state.read();
    sess.ic_rx = epoch_snapshot.ic_rx.clone();
    sess.session_epoch = epoch_snapshot.epoch;
    let response_epoch = epoch_snapshot.epoch;
    let response_enc_algo = epoch_snapshot.enc_algo;
    let response_token = response_resume_token(&epoch_snapshot);
    let (response_enc_salt, response_enc_salt2) =
        response_enc_salts(response_enc_algo, &epoch_snapshot.salt_a, &epoch_snapshot.salt_b);
    drop(epoch_snapshot);
    if let Some(b) = &sess.tx_backend {
        b.rtt_cache.store(50000, Ordering::Relaxed);
    }
    c_sess
        .port
        .register_backend(sess.tx_backend.as_ref().unwrap().clone());
    sess.client_session = Some(c_sess.clone());

    // Brutal 速率协商（对齐 Go）。两个方向的预算不能混：server_tx_rate 是
    // 服务端→客户端（下行），由本端 socket 整形，受本端下行预算约束；
    // client_tx_rate 是客户端→服务端（上行），客户端自己整形，本端只把它
    // 裁进自己的上行预算内。曾写反导致客户端面板"上行 125 配 30 上行总量"。
    let group_offer = req.brutal_groups
        && req.brutal_conns > 0 && req.brutal_conns <= 65536
        && req.brutal_conn_index >= 0 && req.brutal_conn_index < req.brutal_conns
        && req.brutal_total_tx <= MAX_BRUTAL_RATE_MBPS
        && req.brutal_total_rx <= MAX_BRUTAL_RATE_MBPS;
    let (requested_rx, requested_tx) = if group_offer {
        (req.brutal_total_rx, req.brutal_total_tx)
    } else {
        // 对端未声明 group 语义或字段越界：没有逐连接预算可裁剪，按本端配置整形
        (0, 0)
    };
    let mut server_tx_rate = core.brutal_down;
    let mut client_tx_rate = core.brutal_up;
    if requested_rx > 0 && (core.brutal_down == 0 || requested_rx < core.brutal_down) {
        server_tx_rate = requested_rx;
    }
    if requested_tx > 0 && (core.brutal_up == 0 || requested_tx < core.brutal_up) {
        client_tx_rate = requested_tx;
    }
    let server_legacy_rate_bps = if group_offer {
        split_legacy_brutal_rate_bps(server_tx_rate, req.brutal_conns as usize, req.brutal_conn_index as usize)
    } else { server_tx_rate * 1_000_000 / 8 };
    // 先记录协商预算；Brutal 必须等成功响应进入 TLS/TCP 写路径后再应用，
    // 否则 setsockopt 的异常时延会让客户端误以为应用层握手卡死。
    c_sess.brutal_tx.store(server_tx_rate, Ordering::Relaxed);
    c_sess.brutal_rx.store(client_tx_rate, Ordering::Relaxed);

    let resp = HandshakeResp {
        protocol_version: req.protocol_version,
        session_epoch: response_epoch,
        success: true,
        message: "OK".into(),
        session_id: c_sess.session_id.clone(),
        client_id,
        ipv4: core.ipv4_cidr(&c_sess.ipv4),
        ipv6: core.ipv6_cidr(&c_sess.ipv6),
        gw_v4: core.gw_v4.clone(),
        gw_v6: core.gw_v6.clone(),
        padding: generate_padding(100, 500),
        // 客户端视角的上行/下行总量：brutal_total_tx 是客户端自己整形的上行速率，
        // brutal_total_rx 是本端整形的下行速率（即客户端的 rx）。本端自己的 tx 是
        // 下行、不是上行，传反会让两端视角整个对调。
        brutal_groups: group_offer,
        brutal_total_tx: client_tx_rate,
        brutal_total_rx: server_tx_rate,
        fec: req.fec,
        fec_group: c_sess.fec_enc_k,
        encrypt: core.encrypt,
        enc_algo: response_enc_algo,
        enc_salt: response_enc_salt,
        enc_salt2: response_enc_salt2,
        session_token: response_token.clone(),
        tls: observed_tls_handshake(sess),
    };
    let resp_json = serde_json::to_vec(&resp).unwrap();
    let mut buf = Vec::with_capacity(1024);
    append_padded_frame(&mut buf, 0, &resp_json, None);
    if let Err(e) = sess.tls.writer().write_all(&buf) {
        debug!("[{}] failed to queue handshake response: {}", resp.client_id, e);
        return HandshakeOutcome::Close;
    }
    let mut close = false;
    drain_tls(sess, &mut close);
    if close {
        return HandshakeOutcome::Close;
    }

    let brutal_result = if core.brutal && server_tx_rate > 0 {
        let group_id = if group_offer { brutal_group_id("server", &response_token) } else { 0 };
        apply_tcp_brutal(&sess.socket, server_tx_rate, server_legacy_rate_bps, group_id)
    } else { BrutalApplyResult::default() };
    sess.brutal_applied = brutal_result.applied;
    if brutal_result.applied {
        c_sess.brutal_applied_conns.fetch_add(1, Ordering::Relaxed);
    }
    *c_sess.brutal_error.lock() = brutal_result.error.clone();
    HandshakeOutcome::Ok
}

/// 物理连接关闭：注销端口后端；最后一个连接断开时进入 120s 保留期
fn on_conn_closed(
    c_sess: Option<Arc<ClientSession>>,
    backend: Option<Arc<Backend>>,
    connection_epoch: u64,
    brutal_applied: bool,
) {
    if let (Some(c_sess), Some(backend)) = (c_sess, backend) {
        c_sess.port.unregister_backend(&backend.ch);
        if brutal_applied {
            let _ = c_sess.brutal_applied_conns.fetch_update(
                Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1))
            );
        }
        if c_sess.epoch_state.read().epoch != connection_epoch {
            return;
        }
        if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
            let cid = c_sess.stat.client_id.clone();
            let current_version = c_sess
                .stat
                .disconnect_version
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            info!(
                "[{}] ⚠️ all physical connections are down; entering a 120s session retention period (v={})...",
                cid, current_version
            );
            *c_sess.destroy_deadline.lock() =
                Some((Instant::now() + Duration::from_secs(120), current_version));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_with_token(token: String) -> SessionEpochState {
        SessionEpochState {
            instance_id: "instance-a".into(),
            epoch: 1,
            resume_token: token,
            pending_resume_token: String::new(),
            enc_algo: ENC_ALGO_NONE,
            salt_a: [0; ENC_SALT_SIZE],
            salt_b: [0; ENC_SALT_SIZE],
            ic_tx: None,
            ic_rx: None,
            fec_dec: None,
        }
    }

    #[test]
    fn handshake_response_carries_salts_for_both_gcm_key_sizes() {
        let salt_a = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let salt_b = [8u8, 7, 6, 5, 4, 3, 2, 1];

        for algo in [ENC_ALGO_GCM, ENC_ALGO_GCM128] {
            let (a, b) = response_enc_salts(algo, &salt_a, &salt_b);
            assert_eq!(a, hex::encode(salt_a));
            assert_eq!(b, hex::encode(salt_b));
        }

        let (a, b) = response_enc_salts(ENC_ALGO_NONE, &salt_a, &salt_b);
        assert!(a.is_empty() && b.is_empty());
    }

    #[test]
    fn session_token_rollover_survives_lost_handshake_response() {
        let current = new_session_token().unwrap();
        let mut epoch = epoch_with_token(current.clone());
        ensure_pending_resume_token(&mut epoch).unwrap();
        let pending = epoch.pending_resume_token.clone();
        assert_ne!(pending, current);
        assert_eq!(response_resume_token(&epoch), pending);

        // 模拟携带 pending 的响应丢失：旧 current 仍须可用，且重试不能覆盖 pending。
        assert!(accept_session_resume_token(&mut epoch, &current));
        ensure_pending_resume_token(&mut epoch).unwrap();
        assert_eq!(epoch.pending_resume_token, pending);

        // 客户端终于回带 pending 后才提升，旧 current 随即失效。
        assert!(accept_session_resume_token(&mut epoch, &pending));
        assert_eq!(epoch.resume_token, pending);
        assert!(epoch.pending_resume_token.is_empty());
        assert!(!accept_session_resume_token(&mut epoch, &current));
    }

    #[test]
    fn session_token_format_for_server_restart_continuity() {
        let token = new_session_token().unwrap();
        assert!(valid_session_token_format(&token));
        for bad in [String::new(), "abcd".into(), "z".repeat(64), "0".repeat(63)] {
            assert!(!valid_session_token_format(&bad), "malformed token accepted: {bad:?}");
        }
    }

    // ---------- 会话上限（档 D） ----------

    /// Go 端 server.go 的拒连条件，逐字复现以便矩阵化测试。
    /// 只作用于新建会话：既有会话走复活分支，不受容量限制影响。
    fn go_refuses_new_session(max_sessions: i32, active: usize) -> bool {
        max_sessions > 0 && active >= max_sessions as usize
    }

    #[test]
    fn session_capacity_gate_matches_go() {
        let max = 1024i32;
        assert!(!go_refuses_new_session(max, 0));
        assert!(!go_refuses_new_session(max, max as usize - 1));
        // 恰好在位即拒：上限是包含性的，不是"超出才拒"
        assert!(go_refuses_new_session(max, max as usize));
        assert!(go_refuses_new_session(max, max as usize + 1));

        for active in [0usize, 1, 1024, 100_000, usize::MAX] {
            assert!(
                !go_refuses_new_session(0, active),
                "0 必须表示不限制，否则会拒绝全部连接"
            );
        }

        assert!(go_refuses_new_session(1, 1));
        assert!(!go_refuses_new_session(1, 0));
        assert!(go_refuses_new_session(1_048_576, 1_048_576));
    }

    #[test]
    fn max_sessions_zero_normalizes_to_default() {
        // 对齐 Go applyDefaults：0 = 1024，而不是"不限制"。裸 flag 路径与
        // 配置文件路径必须给出同一个结论。
        assert_eq!(normalize_max_sessions(0), 1024);
        assert_eq!(normalize_max_sessions(-1), -1);
        assert_eq!(normalize_max_sessions(1), 1);
        assert_eq!(normalize_max_sessions(1024), 1024);
        assert_eq!(normalize_max_sessions(1_048_576), 1_048_576);
    }

    // ---------- FEC 分组策略 ----------

    /// Go 端 server.go 的拒连条件，逐字复现以便矩阵化测试。
    /// 只在 req.fec 为真时生效：fec_group=0 是"不启用 FEC"的合法表达。
    fn go_refuses_fec_group(min: i64, max: i64, fec: bool, k: i64) -> bool {
        fec && (k < min || k > max)
    }

    #[test]
    fn fec_group_bounds_zero_normalizes_to_protocol_limits() {
        // 对齐 Go applyDefaults：0 = 协议边界 [2,64]，即未配置时不额外限制。
        assert_eq!(
            crate::fec::normalize_fec_group_bounds(0, 0),
            (crate::fec::FEC_MIN_GROUP as i64, crate::fec::FEC_MAX_GROUP as i64)
        );
        assert_eq!(crate::fec::normalize_fec_group_bounds(4, 8), (4, 8));
        assert_eq!(crate::fec::normalize_fec_group_bounds(2, 0), (2, crate::fec::FEC_MAX_GROUP as i64));
        assert_eq!(
            crate::fec::normalize_fec_group_bounds(0, 16),
            (crate::fec::FEC_MIN_GROUP as i64, 16)
        );
    }

    #[test]
    fn fec_group_policy_gate_matches_go() {
        // 策略区间 [4,8]
        for k in [3i64, 2, -3, 999_999, 10_000_000] {
            assert!(
                go_refuses_fec_group(4, 8, true, k),
                "fec_group={} 低于/偏离策略下限应被拒",
                k
            );
        }
        for k in [9i64, 100, crate::fec::FEC_MAX_GROUP as i64] {
            assert!(
                go_refuses_fec_group(4, 8, true, k),
                "fec_group={} 高于策略上限应被拒",
                k
            );
        }
        // 端点与中间值放行
        for k in [4i64, 6, 8] {
            assert!(
                !go_refuses_fec_group(4, 8, true, k),
                "fec_group={} 在策略区间内应放行",
                k
            );
        }
        // 未请求 FEC 时 fec_group 无意义，任何值都必须放行——否则所有非 FEC
        // 握手（包括本端客户端发的 fec_group=0）都会被误拒。
        for k in [0i64, -1, 3, 9, 999_999] {
            assert!(
                !go_refuses_fec_group(4, 8, false, k),
                "fec=false 时 fec_group={} 不应被拒",
                k
            );
        }
        // 默认策略 = 协议边界：等价于只拦协议外取值
        assert!(go_refuses_fec_group(
            crate::fec::FEC_MIN_GROUP as i64,
            crate::fec::FEC_MAX_GROUP as i64,
            true,
            1
        ));
        assert!(go_refuses_fec_group(
            crate::fec::FEC_MIN_GROUP as i64,
            crate::fec::FEC_MAX_GROUP as i64,
            true,
            crate::fec::FEC_MAX_GROUP as i64 + 1
        ));
        assert!(!go_refuses_fec_group(
            crate::fec::FEC_MIN_GROUP as i64,
            crate::fec::FEC_MAX_GROUP as i64,
            true,
            crate::fec::FEC_MAX_GROUP as i64
        ));
    }

    // ---------- IPv4 池耗尽（档 D） ----------

    #[test]
    fn alloc_v4_exhausts_to_empty_and_release_frees_it() {
        // /30 共 4 个地址：网络号、网关、主机、广播。网关预占 + 主机位被扫描
        // 分配后，可分配地址数恰好为 1 —— 用它在测试里把池真正耗尽。
        let (mut p, gw, _) = IpPool::new("10.0.0.0/30", "fd00::/126");
        assert_eq!(gw, "10.0.0.1");
        assert_eq!(p.used_v4.len(), 1, "网关应预占用");

        let first = p.alloc_v4("");
        assert!(!first.is_empty(), "首次分配必须成功: {:?}", first);
        let v6 = p.alloc_v6("");
        assert!(!v6.is_empty(), "v6 侧同样应可分配");
        assert_eq!(p.used_v4.len(), 2);
        assert_eq!(p.used_v6.len(), 2);

        // 耗尽必须返回空串，且重复失败分配不得再消耗地址
        for _ in 0..3 {
            assert_eq!(p.alloc_v4(""), "", "耗尽后必须返回空串");
        }
        assert_eq!(p.used_v4.len(), 2, "失败的分配不得占用地址");

        // 会话销毁路径回收后，地址应重新可分配
        p.release("aa:bb:cc:dd:ee:ff", &first, &v6);
        let second = p.alloc_v4("");
        assert!(!second.is_empty(), "回收后应能再次分配");
        assert_eq!(p.alloc_v4(""), "", "再次分配后池应重新耗尽");
    }

    // ---------- 源 MAC 归属校验（档 F） ----------

    #[test]
    fn src_mac_allowed_matches_go() {
        let registered = [0xAA, 0x00, 0x00, 0x00, 0x00, 0x01];
        let other = [0xBB, 0x00, 0x00, 0x00, 0x00, 0x02];

        assert!(
            src_mac_allowed(Some(&registered), &registered),
            "本会话注册的 MAC 必须放行"
        );
        assert!(
            !src_mac_allowed(Some(&registered), &other),
            "他人 MAC 必须拒绝——这就是被堵的劫持路径"
        );
        assert!(
            !src_mac_allowed(Some(&registered), &[0u8; 6]),
            "空 MAC 帧不得借道"
        );

        // 未注册端口（本机 TAP）无法核对 → 放行
        assert!(src_mac_allowed(None, &other));
        // 未上报 MAC 的会话（注册值为全零）→ 放行保持兼容
        assert!(src_mac_allowed(Some(&[0u8; 6]), &other));
    }
}
