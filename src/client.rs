use crate::Args;
use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use crossbeam_queue::ArrayQueue;
use mio::Interest;
use parking_lot::Mutex;
use rustls::{ClientConfig, ClientConnection};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::fec::{self, clamp_fec_group, FecDecoder};
use crate::frame::*;
use crate::hooks::{HookEnv, LifecycleHooks};
use crate::net::*;
use crate::socks5::{split_host_port, Socks5Proxy};
use crate::tap::{MemTap, TapDevice};

// 重连退避参数（对齐 Go）：1s 起指数增长封顶 30s；持续在线 30s 以上
// 视为稳定连接，断开后退避归零
const RECONNECT_BACKOFF_BASE: Duration = Duration::from_secs(1);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
const RECONNECT_BACKOFF_RESET: Duration = Duration::from_secs(30);

fn reconnect_backoff_delay(attempt: u32) -> Duration {
    let shift = attempt.min(5);
    let mut d_ms = RECONNECT_BACKOFF_BASE.as_millis() as u64 * (1u64 << shift);
    let max_ms = RECONNECT_BACKOFF_MAX.as_millis() as u64;
    if d_ms > max_ms || d_ms == 0 {
        d_ms = max_ms;
    }
    // ±33% 对称抖动（对齐 Go）：把 4 条共享同一 ISP 路径的连接在时间上错开，
    // 避免 ISP 抖动时全体同步重拨。封顶阶段上界被裁到 max_ms，下界仍在 2/3 d。
    let third = d_ms / 3;
    let jitter_range = (third * 2).max(1u64) as usize;
    let jitter = crate::utils::RNG.with(|rng| {
        rng.borrow_mut().gen_range(0usize, jitter_range) as u64
    });
    let delay_ms = third * 2 + jitter;
    if delay_ms > max_ms {
        RECONNECT_BACKOFF_MAX
    } else {
        Duration::from_millis(delay_ms)
    }
}

/// 全局退出标记（信号处理置位）
pub static EXIT: AtomicBool = AtomicBool::new(false);

/// 退出时清理策略路由所需的完整参数（对齐 Go cleanPolicyRouting defer）。
///
/// 只保留最新一次安装的 spec：重复安装时旧规则已在安装前被
/// policy_routing_cmds 的 pre 阶段按 mark+table 清掉，不存在需要同时清理
/// 多组参数的情况。
static CLEANUP_INFO: std::sync::OnceLock<PolicyRoutingSpec> = std::sync::OnceLock::new();

pub fn on_exit_cleanup() {
    if let Some(spec) = CLEANUP_INFO.get() {
        clean_policy_routing(spec);
    }
}

// ======================= 自定义验证器（对齐 Go verifyCertHash） =======================

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

/// 探针/自签场景接受全部签名方案（由 ring provider 提供）
fn all_verify_schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}

#[derive(Debug)]
struct CertHashVerifier {
    expected_hash: String,
}
impl ServerCertVerifier for CertHashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // 大小写不敏感、允许冒号分隔（对齐 Go verifyCertHash）
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let got = hex::encode(hasher.finalize());
        let want = self.expected_hash.replace(':', "").to_lowercase();
        if got == want {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert SHA-256 mismatch: expected {}, got {}",
                want, got
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        all_verify_schemes()
    }
}

// ======================= 连接明细（面板展示） =======================

pub struct ConnInfo {
    pub target: String,
    pub remote: Mutex<String>,
    pub state: Mutex<String>,
    pub last_error: Mutex<String>,
    pub rtt_cache: Mutex<Arc<AtomicU32>>,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub retries: AtomicU64,
    pub linked_at: AtomicI64,
    // 本连接的内核实际状态；不能再用“无错误字符串”推断已生效。
    pub brutal: Mutex<BrutalApplyResult>,
}

impl ConnInfo {
    fn new(target: String) -> Self {
        Self {
            target,
            remote: Mutex::new(String::new()),
            state: Mutex::new("connecting".into()),
            last_error: Mutex::new(String::new()),
            rtt_cache: Mutex::new(Arc::new(AtomicU32::new(50000))),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            linked_at: AtomicI64::new(0),
            brutal: Mutex::new(BrutalApplyResult::default()),
        }
    }

    fn snapshot(&self, index: usize) -> serde_json::Value {
        let linked_at = self.linked_at.load(Ordering::Relaxed);
        let brutal = self.brutal.lock().clone();
        serde_json::json!({
            "index": index,
            "target": self.target,
            "remote": self.remote.lock().clone(),
            "state": self.state.lock().clone(),
            "last_error": self.last_error.lock().clone(),
            "rtt_ms": self.rtt_cache.lock().load(Ordering::Relaxed) / 1000,
            "tx_bytes": self.tx_bytes.load(Ordering::Relaxed),
            "rx_bytes": self.rx_bytes.load(Ordering::Relaxed),
            "retries": self.retries.load(Ordering::Relaxed),
            "brutal_applied": brutal.applied,
            "brutal_error": brutal.error,
            "brutal_rate_bps": brutal.rate_bps,
            "brutal_rate_mbps": brutal.rate_mbps,
            "brutal_version": brutal.version,
            "brutal_group_id": brutal.group_id,
            "brutal_rule_managed": brutal.rule_managed,
            "age_sec": if linked_at > 0 {
                (now_unix_ms() / 1000).saturating_sub(linked_at) as u64
            } else {
                0
            },
        })
    }
}

// ======================= 会话协商状态（对齐 Go Client 的 sessionMu 字段） =======================

#[derive(Default)]
pub struct SessionState {
    server_session_id: String,
    fec_negotiated: i64, // 0=未协商, >0=XOR 分组大小
    fec_algo: i64,
    fec_salt_key: String,
    ic_tx: Option<Arc<InnerCipher>>,
    ic_rx: Option<Arc<InnerCipher>>,
    enc_algo: i64,
    gw_v4: String,
    gw_v6: String,
    // 服务端下发的会话令牌；重连同一 client_id 时必须在握手里回带
    session_token: String,
    session_epoch: u64,
    brutal_tx: u64,
    brutal_rx: u64,
    tls: Option<TLSHandshakeInfo>,
}

// ======================= 客户端 =======================

// Match the Go receive architecture: reorder extraction must not block the TLS
// socket reader on a TAP write syscall. Batches are bounded and their Vec
// descriptors are recycled so the handoff itself does not allocate per frame.
const TAP_DELIVERY_QUEUE: usize = 256;
const TAP_DELIVERY_BATCH_CAP: usize = 64;
type TapDeliveryBatch = Vec<Arc<Vec<u8>>>;

struct TapDelivery {
    tx: Sender<TapDeliveryBatch>,
    pool_tx: Sender<TapDeliveryBatch>,
    pool_rx: Receiver<TapDeliveryBatch>,
    dropped: AtomicU64,
}

impl TapDelivery {
    fn new(tap: Arc<dyn TapDevice>) -> Self {
        let (tx, rx) = bounded::<TapDeliveryBatch>(TAP_DELIVERY_QUEUE);
        let (pool_tx, pool_rx) = bounded::<TapDeliveryBatch>(TAP_DELIVERY_QUEUE);
        let worker_pool = pool_tx.clone();
        std::thread::spawn(move || {
            while let Ok(mut batch) = rx.recv() {
                for frame in batch.drain(..) {
                    let _ = tap.send(&frame);
                    release_shared_frame(frame);
                }
                let _ = worker_pool.try_send(batch);
            }
        });
        Self {
            tx,
            pool_tx,
            pool_rx,
            dropped: AtomicU64::new(0),
        }
    }

    #[inline]
    fn acquire(&self) -> TapDeliveryBatch {
        self.pool_rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(TAP_DELIVERY_BATCH_CAP))
    }

    #[inline]
    fn recycle(&self, mut batch: TapDeliveryBatch) {
        batch.clear();
        let _ = self.pool_tx.try_send(batch);
    }

    #[inline]
    fn enqueue(&self, batch: TapDeliveryBatch) {
        if batch.is_empty() {
            self.recycle(batch);
            return;
        }
        match self.tx.try_send(batch) {
            Ok(()) => {}
            Err(TrySendError::Full(mut batch))
            | Err(TrySendError::Disconnected(mut batch)) => {
                self.dropped
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                for frame in batch.drain(..) {
                    release_shared_frame(frame);
                }
                self.recycle(batch);
            }
        }
    }
}

pub struct Client {
    pub client_id: String,
    pub psk: String,
    pub targets: Vec<String>,
    pub tap_name: String,
    pub req_v4: String,
    pub req_v6: String,
    pub sni: String,
    pub insecure: bool,
    pub cert_hash: String,
    pub fwmark: i32,
    /// 策略路由规则优先级；0 = 交给内核自动分配
    pub fwmark_priority: i64,
    /// 额外路由，iproute2 序列化语法（配置加载期已校验）
    pub extra_routes: Vec<String>,
    /// 按源地址前缀的规则，与 fwmark 相互独立（加载期已校验并补全掩码）
    pub source_rules: Vec<crate::net::SourceRule>,
    pub brutal: bool,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub conns_count: usize,
    pub fec_mode: bool,
    pub fec_group_req: usize,
    pub encrypt: bool,
    // 显式配置的内层算法：AES-256-GCM（默认）或 AES-128-GCM（性能模式）
    pub enc_algo: i64,
    // 内层加密强度下限（ENC_RANK_* 值，0 = 不限）
    pub min_enc: i64,
    pub tap: Arc<dyn TapDevice>,
    pub mac: String,
    pub tx_port: Arc<AsyncPort>,
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    tap_delivery: TapDelivery,
    pub fec_dec: Mutex<Option<Arc<FecDecoder>>>,
    pub dedup: Arc<Mutex<DeDuplicator>>,
    pub session: Mutex<SessionState>,
    // 身份状态文件路径；空串 = 不持久化（进程内测试未从文件加载配置）
    pub state_path: String,
    // 内存中的身份状态；多条物理连接的握手会并发落盘，故加锁
    pub identity: Mutex<crate::client_state::ClientState>,
    pub config: Arc<ClientConfig>,
    pub conn_infos: Vec<Arc<ConnInfo>>,
    pub socks5: Option<Arc<Socks5Proxy>>,
    // 面板统计
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub live_conns: AtomicI32,
    pub reconnects: AtomicU64,
    pub assigned_v4: Mutex<String>,
    pub assigned_v6: Mutex<String>,
    pub fec_status: Mutex<String>,
    // 策略路由实际生效状态。面板要区分"没配置"和"配置了但内核拒绝"，
    // 所以成功与错误分开记录；多次物理连接会并发安装，故加锁。
    pub pr_ok: Mutex<bool>,
    pub pr_err: Mutex<String>,
    pub enc_algo_display: AtomicI64,
    pub force_generation: AtomicU64,
    pub instance_id: Mutex<String>,
    pub sequence_rekeying: AtomicBool,
    pub started_at: Instant,
    pub hooks: Arc<LifecycleHooks>,
    pub hook_config_path: String,
    pub fatal_error: Mutex<Option<String>>,
    pub network_setup: Mutex<()>,
}

impl TunnelIpSource for Client {
    fn tunnel_addrs(&self, port: u16) -> Vec<String> {
        let mut out = Vec::new();
        for ip in [
            self.assigned_v4.lock().clone(),
            self.assigned_v6
                .lock()
                .clone()
                .trim_matches(|c| c == '[' || c == ']')
                .to_string(),
        ] {
            if ip.is_empty() {
                continue;
            }
            if ip.contains(':') {
                out.push(format!("[{}]:{}", ip, port));
            } else {
                out.push(format!("{}:{}", ip, port));
            }
        }
        out
    }
}

impl WebStatsProvider for Client {
    fn stats_json(&self) -> serde_json::Value {
        let (rec, lost) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| d.stats())
            .unwrap_or((0, 0));
        let conns: Vec<serde_json::Value> = self
            .conn_infos
            .iter()
            .enumerate()
            .map(|(i, c)| c.snapshot(i))
            .collect();
        // 发射前已归一化成 0/2/4，这里直接透传
        let enc = self.enc_algo_display.load(Ordering::Relaxed);
        let fec_status = self.fec_status.lock().clone();
        let sess = self.session.lock();
        let session_token = !sess.session_token.is_empty();
        let session_epoch = sess.session_epoch;
        let session_id = sess.server_session_id.clone();
        let negotiated_brutal_tx = sess.brutal_tx;
        let negotiated_brutal_rx = sess.brutal_rx;
        let negotiated_tls = sess.tls.clone();
        drop(sess);
        let reorder = self.reorder_buf.lock().stats();
        let local = serde_json::json!({
            "client_id": self.client_id,
            "ipv4": self.assigned_v4.lock().clone(),
            "ipv6": self.assigned_v6.lock().clone(),
            "mac": self.mac,
            "session_id": session_id,
            "session_epoch": session_epoch,
            "session_token": session_token,
            "session_encrypt": is_gcm_algo(enc),
            "active_conns": self.live_conns.load(Ordering::Relaxed),
            "tx_bytes": self.tx_bytes.load(Ordering::Relaxed),
            "rx_bytes": self.rx_bytes.load(Ordering::Relaxed),
            "tx_packets": self.tx_packets.load(Ordering::Relaxed),
            "rx_packets": self.rx_packets.load(Ordering::Relaxed),
            "fec": fec_status,
            "fec_group": self.fec_group_req,
            "enc_algo": enc,
        });

        // 协商结果：客户端模式是端到端会话的实际参数（服务端回传的取值），
        // brutal 段把"配置意图"和"内核实际状态"分开设——非 Linux 或没装 brutal
        // 模块时 apply 必然失败，混在一起就无法区分"没配置"和"配置了没生效"。
        let n: u64 = if self.conns_count == 0 { 1 } else { self.conns_count as u64 };
        let per_up_min = split_legacy_brutal_rate(self.brutal_up, n as usize, n.saturating_sub(1) as usize);
        let per_up_max = split_legacy_brutal_rate(self.brutal_up, n as usize, 0);
        let per_down_min = split_legacy_brutal_rate(self.brutal_down, n as usize, n.saturating_sub(1) as usize);
        let per_down_max = split_legacy_brutal_rate(self.brutal_down, n as usize, 0);
        // 逐连接统计 setsockopt 成功过的条数，而不是"配置了 brutal 就全算生效"
        let mut applied_conns = 0usize;
        let mut brutal_errors = Vec::<String>::new();
        for conn in &self.conn_infos {
            let result = conn.brutal.lock();
            if result.applied {
                applied_conns += 1;
            }
            if !result.error.is_empty() && !brutal_errors.contains(&result.error) {
                brutal_errors.push(result.error.clone());
            }
        }
        let brut = brutal_system_status();
        let brutal_error = if brutal_errors.is_empty() {
            brut["error"].as_str().unwrap_or("").to_string()
        } else {
            brutal_errors.join("; ")
        };
        // 策略路由生效状态。面板需要区分"没配 fwmark"和"配了但内核拒绝"，
        // 所以 applied 与 error 分开记录。
        let pr_applied = *self.pr_ok.lock();
        let pr_error = self.pr_err.lock().clone();
        let negotiate = serde_json::json!({
            "protocol_version": 2,
            "fec": self.fec_mode,
            "fec_group": self.fec_group_req,
            "enc_algo": enc,
            "pad_mode": pad_mode_name(),
            "min_enc": min_enc_label(self.min_enc),
            "session_token": session_token,
            "session_epoch": session_epoch,
            "tx_rate_mbps": negotiated_brutal_tx,
            "rx_rate_mbps": negotiated_brutal_rx,
            "tls": negotiated_tls,
            "socks5": self.socks5.is_some(),
            "policy_routing": self.fwmark > 0 && pr_applied,
            "policy_routing_error": pr_error,
            "brutal": {
                "enabled": self.brutal,
                "up_mbps": self.brutal_up,
                "down_mbps": self.brutal_down,
                "kernel_supported": brut["supported"].as_bool().unwrap_or(false),
                "kernel_current": brut["kernel_current"].as_str().unwrap_or(""),
                "kernel_available": brut["kernel_available"].clone(),
                "applied_conns": applied_conns,
                "total_conns": self.conns_count,
                "min_up_mbps": per_up_min,
                "max_up_mbps": per_up_max,
                "min_down_mbps": per_down_min,
                "max_down_mbps": per_down_max,
                "error": brutal_error,
            }
        });

        serde_json::json!({
            "mode": "client",
            "version": APP_VERSION,
            "uptime_sec": self.started_at.elapsed().as_secs(),
            "active_clients": 1,
            "clients": {"local": local},
            "global_tx_bytes": 0,
            "global_rx_bytes": 0,
            "log_level": current_log_level_name(),
            "pad_mode": pad_mode_name(),
            "dropped_frames": self.tx_port.dropped(),
            "fec": {"enabled": self.fec_mode, "parity_tx": self.tx_port.parity_sent(), "recovered": rec, "lost": lost},
            "reorder": {"gap_events": reorder.gap_events, "timeout_flushes": reorder.timeout_flushes, "skipped_frames": reorder.skipped_frames},
            "mem": {"heap_alloc_mb": rss_mb(), "sys_mb": rss_mb(), "num_goroutine": thread_count()},
            "conns": conns,
            "fec_mode": fec_status,
            "enc_algo": enc,
            "negotiate": negotiate,
        })
    }

    fn metrics_text(&self) -> String {
        let (rec, lost) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| d.stats())
            .unwrap_or((0, 0));
        let reorder = self.reorder_buf.lock().stats();
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
                "tlsvpn_tx_bytes_total",
                "Total bytes sent",
                "counter",
                self.tx_bytes.load(Ordering::Relaxed).to_string(),
            );
            emit(
                "tlsvpn_rx_bytes_total",
                "Total bytes received",
                "counter",
                self.rx_bytes.load(Ordering::Relaxed).to_string(),
            );
            emit(
                "tlsvpn_live_connections",
                "Live physical connections",
                "gauge",
                self.live_conns.load(Ordering::Relaxed).to_string(),
            );
            emit(
                "tlsvpn_reconnect_attempts_total",
                "Reconnect attempts",
                "counter",
                self.reconnects.load(Ordering::Relaxed).to_string(),
            );
            emit(
                "tlsvpn_port_dropped_frames_total",
                "Frames dropped due to backpressure",
                "counter",
                self.tx_port.dropped().to_string(),
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
                "tlsvpn_reorder_gap_events_total",
                "Observed sequence gaps",
                "counter",
                reorder.gap_events.to_string(),
            );
            emit(
                "tlsvpn_reorder_timeout_flushes_total",
                "Gap timeouts that resumed delivery",
                "counter",
                reorder.timeout_flushes.to_string(),
            );
            emit(
                "tlsvpn_reorder_skipped_frames_total",
                "Missing sequence slots skipped after timeout",
                "counter",
                reorder.skipped_frames.to_string(),
            );
        }
        m
    }

    fn control(
        &self,
        action: &str,
        _client_id: &str,
        level: &str,
        _ttl: i64,
    ) -> Result<(), String> {
        match action {
            "reconnect" => {
                self.force_generation.fetch_add(1, Ordering::SeqCst);
                info!("[WebUI] Forced reconnect triggered");
                Ok(())
            }
            "loglevel" => set_runtime_log_level(level),
            // 填充策略是全局发送路径状态；非法值回落 legacy
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

// ======================= 主流程 =======================

fn random_instance_id() -> String {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).expect("generate client instance id");
    hex::encode(id)
}

/// 把服务端下发的会话身份落盘，供进程重启后第一次握手复用既有会话。按
/// client_id（MAC+PSK 派生）绑定：配置变更后旧令牌自动失效。
fn persist_session_state(cl: &Client, session_id: &str, token: &str, epoch: u64) {
    if cl.state_path.is_empty() {
        return;
    }
    let mut st = cl.identity.lock();
    if epoch < st.session_epoch {
        return;
    }
    st.client_id = cl.client_id.clone();
    st.session_id = session_id.to_string();
    st.session_token = token.to_string();
    st.session_epoch = epoch;
    if let Err(e) = crate::client_state::save_client_state(&cl.state_path, &st) {
        warn!("Client failed to persist session state: {}", e);
    }
}

pub fn start_client(args: &Args, config_path: &str, ctx: Arc<RuntimeCtx>) -> Result<(), String> {
    info!("Starting TCP TLS client process...");

    // 进程身份落盘（<config>.state）：MAC 派生 client_id，client_id 决定服务端
    // 会话与分配的隧道 IP。三者跨进程稳定后，被杀或崩溃重启才能带着旧令牌
    // 请求安全的 epoch 轮换，而不是等 120 秒僵尸会话过期。
    let state_path = crate::client_state::client_state_path(config_path);
    let mut identity = crate::client_state::load_client_state(&state_path);

    // mac 必须写入 TAP 设备本体（对齐 Go setTapMac）。只拿它算 client_id 不够：
    // 握手声明 req.mac=配置值，而帧里的 src MAC 是内核给 TAP 随机分配的那个，
    // 服务端 src_mac_allowed 会据此丢弃本端自己的帧。
    // 优先级：配置值 > 落盘值 > 随机生成。tun-rs 每次建 TAP 都发随机 MAC，不
    // 固定就等于每次重启都是一次全新会话——换新 IP，而旧会话还要占用旧 IP
    // 满 120 秒。mem 后端同样生成并持久化随机单播 MAC，不能退化成共享 PSK
    // 下所有客户端都相同的身份。
    let apply_mac: Option<[u8; 6]> = match crate::utils::parse_config_mac(&args.mac) {
        Ok(Some(m)) => {
            info!("Interface {} MAC set to {}", args.tap, args.mac);
            Some(m)
        }
        Err(e) => {
            error!("{}", e);
            return Err(e);
        }
        Ok(None) => {
            if !identity.mac.is_empty() {
                match crate::utils::parse_config_mac(&identity.mac) {
                    Ok(Some(m)) => {
                        info!("Restored persistent TAP MAC: {}", identity.mac);
                        Some(m)
                    }
                    _ => {
                        warn!(
                            "Persisted TAP MAC {:?} is unusable; generating a new one",
                            identity.mac
                        );
                        None
                    }
                }
            } else if args.tap == "mem" {
                let gen = crate::client_state::generate_tap_mac();
                crate::utils::parse_config_mac(&gen).ok().flatten()
            } else {
                let gen = crate::client_state::generate_tap_mac();
                info!("Generated TAP MAC: {}", gen);
                crate::utils::parse_config_mac(&gen).ok().flatten()
            }
        }
    };

    let device: Arc<dyn TapDevice> = if args.tap == "mem" {
        info!("Using in-memory TAP backend (no real device)");
        Arc::new(MemTap)
    } else {
        let builder = tun_rs::DeviceBuilder::new()
            .name(&args.tap)
            .layer(tun_rs::Layer::L2)
            .mtu(args.mtu);
        // DeviceBuilder 的方法按值消费 self，mac 只能作为链上的另一节
        let builder = if let Some(m) = apply_mac {
            builder.mac_addr(m)
        } else {
            builder
        };
        let dev = builder.build_sync().unwrap();
        Arc::new(dev)
    };

    // MAC：显式指定时上面的 builder 已写入设备，这里沿用同一个值；否则读
    // TAP 的真实 MAC（Linux sysfs），仍失败则警告。client_id 依赖 MAC，与 Go 一致。
    let actual_mac = if args.mac.is_empty() {
        if !identity.mac.is_empty() {
            identity.mac.to_ascii_lowercase()
        } else if let Some(m) = apply_mac {
            format!(
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                m[0], m[1], m[2], m[3], m[4], m[5]
            )
        } else {
            let from_sys = std::fs::read_to_string(format!("/sys/class/net/{}/address", args.tap))
                .unwrap_or_else(|_| String::new())
                .trim()
                .to_string();
            if from_sys.is_empty() {
                let generated = crate::client_state::generate_tap_mac();
                warn!(
                    "Failed to read TAP MAC for '{}'; generated a persistent identity MAC {}",
                    args.tap, generated
                );
                generated
            } else {
                from_sys.to_ascii_lowercase()
            }
        }
    } else {
        args.mac.to_ascii_lowercase()
    };

    // 未显式配置时把实际生效的 MAC 落盘，下一次进程重启就回到同一个
    // client_id 与同一条隧道 IP。配置值不动状态文件：改配置就是改身份。
    if args.mac.is_empty() && identity.mac != actual_mac {
        identity.mac = actual_mac.clone();
        if let Err(e) = crate::client_state::save_client_state(&state_path, &identity) {
            warn!("Client failed to persist TAP MAC: {}", e);
        } else {
            info!("Generated and persisted TAP MAC: {}", actual_mac);
        }
    }

    let ns = uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_URL, b"my_vpn_tunnel");
    let client_id =
        uuid::Uuid::new_v5(&ns, format!("{}{}", actual_mac, args.psk).as_bytes()).to_string();
    info!("Assigned UUID v5 ClientID: {}", client_id);

    // 多服务器地址（对齐 Go parseServerAddresses）
    let targets: Vec<String> = args
        .addr
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if targets.is_empty() {
        return Err("Client addr resolved to zero endpoints; check the addr field in the config file".into());
    }

    // SOCKS5 全局代理
    let socks5: Option<Arc<Socks5Proxy>> = if args.socks5.is_empty() {
        None
    } else {
        match Socks5Proxy::parse(&args.socks5) {
            Some(p) => Some(Arc::new(p)),
            None => {
                return Err(format!("Invalid SOCKS5 proxy spec: {}", args.socks5));
            }
        }
    };
    let proxied = socks5.is_some();
    if proxied {
        info!("🧦 SOCKS5 proxy enabled: all outbound sockets go through the proxy");
        if args.fwmark <= 0 {
            warn!("⚠️  SOCKS5 is used without fwmark. If the tunnel becomes the default route, \
                   the connection to the SOCKS5 proxy may be routed into the tunnel itself and deadlock.");
        }
    }

    // TAP 读线程 → 端口（对齐 Go 客户端 TAP 读协程）
    let tx_port = Arc::new(AsyncPort::new("client_tx_port".to_string()));
    {
        let dev = device.clone();
        let port = tx_port.clone();
        // MTU 不含 L2 头；默认 1500 + headroom 仍落入 2KB thread-local 热池。
        let tap_read_size = crate::tap::tap_read_buffer_size(args.mtu);
        std::thread::spawn(move || {
            loop {
                if EXIT.load(Ordering::Relaxed) {
                    return;
                }
                let mut frame = acquire_frame_vec(tap_read_size);
                match dev.recv(&mut frame) {
                    Ok(n) if n > 0 => {
                        frame.truncate(n);
                        // TAP 读线程天然持有唯一 pooled Vec：直接把所有权交给
                        // AsyncPort/backend，避免每帧 Arc 控制块 allocation/free。
                        port.write_owned_frame(frame);
                    }
                    Ok(_) => release_frame_vec(frame),
                    Err(_) => {
                        release_frame_vec(frame);
                        if EXIT.load(Ordering::Relaxed) {
                            return;
                        }
                        std::thread::sleep(Duration::from_secs(1));
                    }
                }
            }
        });
    }

    let reorder_buf = Arc::new(Mutex::new(ReorderBuffer::new()));
    let tap_delivery = TapDelivery::new(device.clone());
    // 重排 timeout 不再单独起 5ms 轮询线程；物理连接的 mio poll deadline
    // 会合并 session reorder deadline，仅在真实 gap 存在时提前唤醒。

    let config = build_tls_config(args);

    let fec_group_req = if args.fec {
        clamp_fec_group(if args.fec_group == 0 {
            4
        } else {
            args.fec_group as usize
        })
    } else {
        0
    };

    let conn_infos: Vec<Arc<ConnInfo>> = (0..args.conns as usize)
        .map(|i| Arc::new(ConnInfo::new(targets[i % targets.len()].clone())))
        .collect();

    // 冷启动回带：状态文件按 client_id（MAC+PSK 派生）绑定，配置变更后旧令牌
    // 自动失效；带上令牌的第一次握手就能接回既有会话，不必等 120 秒销毁期。
    let session = {
        let mut ss = SessionState::default();
        if identity.client_id == client_id && !identity.session_id.is_empty() {
            ss.server_session_id = identity.session_id.clone();
            ss.session_epoch = identity.session_epoch;
            if !identity.session_token.is_empty() {
                ss.session_token = identity.session_token.clone();
                info!(
                    "Restored session token for {}; next handshake will rejoin the existing session",
                    identity.session_id
                );
            }
        }
        ss
    };

    let client = Client {
        client_id: client_id.clone(),
        psk: args.psk.clone(),
        targets,
        tap_name: args.tap.clone(),
        req_v4: args.req_v4.clone(),
        req_v6: args.req_v6.clone(),
        sni: args.sni.clone(),
        insecure: args.insecure,
        cert_hash: args.cert_sha256.clone(),
        fwmark: args.fwmark,
        fwmark_priority: args.fwmark_priority,
        extra_routes: args.extra_routes.clone(),
        source_rules: args.source_rules.clone(),
        brutal: args.brutal,
        brutal_up: args.brutal_up,
        brutal_down: args.brutal_down,
        conns_count: args.conns.max(1) as usize,
        fec_mode: args.fec,
        fec_group_req,
        encrypt: args.encrypt,
        enc_algo: enc_algo_from_config(&args.enc_algo),
        // 强度下限解析一次，协商热路径只读整数
        min_enc: min_enc_rank(&args.min_enc),
        tap: device.clone(),
        mac: actual_mac.clone(),
        tx_port: tx_port.clone(),
        reorder_buf: reorder_buf.clone(),
        tap_delivery,
        fec_dec: Mutex::new(None),
        dedup: Arc::new(Mutex::new(DeDuplicator::new())),
        session: Mutex::new(session),
        state_path,
        identity: Mutex::new(identity),
        config: config.clone(),
        conn_infos,
        socks5: socks5.clone(),
        tx_bytes: AtomicU64::new(0),
        rx_bytes: AtomicU64::new(0),
        tx_packets: AtomicU64::new(0),
        rx_packets: AtomicU64::new(0),
        live_conns: AtomicI32::new(0),
        reconnects: AtomicU64::new(0),
        assigned_v4: Mutex::new(String::new()),
        assigned_v6: Mutex::new(String::new()),
        fec_status: Mutex::new("off".into()),
        pr_ok: Mutex::new(false),
        pr_err: Mutex::new(String::new()),
        enc_algo_display: AtomicI64::new(0),
        force_generation: AtomicU64::new(0),
        instance_id: Mutex::new(random_instance_id()),
        sequence_rekeying: AtomicBool::new(false),
        started_at: Instant::now(),
        hooks: Arc::new(LifecycleHooks::new(args.up.clone(), args.down.clone())),
        hook_config_path: config_path.to_string(),
        fatal_error: Mutex::new(None),
        network_setup: Mutex::new(()),
    };
    let client = Arc::new(client);

    if !args.web.is_empty() {
        match args.web_bind.as_str() {
            "tunnel" => start_web_server_tunnel(
                web_port(&args.web),
                args.web_auth.clone(),
                args.web_cert.clone(),
                args.web_key.clone(),
                client.clone(),
                ctx.clone(),
                client.clone(),
            ),
            _ => start_web_server(
                args.web.clone(),
                args.web_auth.clone(),
                args.web_cert.clone(),
                args.web_key.clone(),
                client.clone(),
                ctx.clone(),
            ),
        }
    }

    if args.conns < 2 && args.fec {
        warn!(
            "FEC is enabled but conns < 2. XOR parity is suppressed on a single TCP path because \
             TCP head-of-line blocking prevents parity from overtaking missing data; parity resumes when a second path is active."
        );
    }

    // 每条物理连接一个线程（对齐 Go 的 connIndex 协程）
    let mut handles = Vec::new();
    for conn_index in 0..client.conns_count {
        let cl = client.clone();
        let ci = cl.conn_infos[conn_index].clone();
        handles.push(std::thread::spawn(move || {
            conn_loop(&cl, conn_index, &ci);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    on_exit_cleanup();
    let down_result = client.hooks.down();
    if let Some(fatal) = client.fatal_error.lock().take() {
        return match down_result {
            Ok(()) => Err(fatal),
            Err(cleanup) => Err(format!("{fatal}; cleanup failed: {cleanup}")),
        };
    }
    down_result
}

fn build_tls_config(args: &Args) -> Arc<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    if args.insecure {
        #[derive(Debug)]
        struct DummyVerifier;
        impl ServerCertVerifier for DummyVerifier {
            fn verify_server_cert(
                &self,
                _e: &CertificateDer<'_>,
                _i: &[CertificateDer<'_>],
                _s: &ServerName<'_>,
                _ocsp: &[u8],
                _now: UnixTime,
            ) -> Result<ServerCertVerified, rustls::Error> {
                Ok(ServerCertVerified::assertion())
            }
            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &CertificateDer<'_>,
                _dss: &DigitallySignedStruct,
            ) -> Result<HandshakeSignatureValid, rustls::Error> {
                Ok(HandshakeSignatureValid::assertion())
            }
            fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
                all_verify_schemes()
            }
        }
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(DummyVerifier));
    } else if !args.cert_sha256.is_empty() {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(CertHashVerifier {
                expected_hash: args.cert_sha256.clone(),
            }));
    }
    Arc::new(config)
}

/// 单条物理连接的完整生命周期（对齐 Go dialAndServe）
fn conn_loop(cl: &Arc<Client>, conn_index: usize, ci: &Arc<ConnInfo>) {
    let mut attempt: u32 = 0;
    let mut seen_generation = cl.force_generation.load(Ordering::Acquire);
    loop {
        if EXIT.load(Ordering::Relaxed) {
            return;
        }
        if cl.force_generation.load(Ordering::Acquire) != seen_generation {
            seen_generation = cl.force_generation.load(Ordering::Acquire);
            attempt = 0; // 面板触发强制重连：立即重拨
        }
        cl.reconnects.fetch_add(1, Ordering::Relaxed);
        ci.retries.fetch_add(1, Ordering::Relaxed);

        let linked = dial_and_serve(cl, conn_index, ci);

        // 长连接断开后以短间隔立即重试（对齐 Go reconnectBackoffReset）
        if linked >= RECONNECT_BACKOFF_RESET {
            attempt = 0;
        }
        let delay = reconnect_backoff_delay(attempt);
        if EXIT.load(Ordering::Relaxed) {
            return;
        }
        if linked.is_zero() {
            warn!(
                "[Conn {}] Tunnel down: {}. Reconnecting in {:?}...",
                conn_index,
                ci.last_error.lock(),
                delay
            );
        } else {
            info!(
                "[Conn {}] Tunnel closed, reconnecting in {:?}...",
                conn_index, delay
            );
        }
        attempt += 1;

        // 退避等待（可被强制重连打断）
        let deadline = Instant::now() + delay;
        while Instant::now() < deadline {
            if EXIT.load(Ordering::Relaxed) {
                return;
            }
            let generation = cl.force_generation.load(Ordering::Acquire);
            if generation != seen_generation {
                seen_generation = generation;
                attempt = 0;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn dial_target(cl: &Arc<Client>, target: &str) -> std::io::Result<std::net::TcpStream> {
    let stream = if let Some(proxy) = &cl.socks5 {
        let (host, port) = split_host_port(target);
        #[cfg(target_os = "linux")]
        {
            let proxy_stream = dial_with_mark(&proxy.host, proxy.port, cl.fwmark)?;
            proxy.connect_over(proxy_stream, &host, port)?
        }
        #[cfg(not(target_os = "linux"))]
        {
            proxy.connect(&host, port)?
        }
    } else {
        dial_with_mark_host(target, cl.fwmark)?
    };
    // SOCKS 握手使用有界阻塞超时；进入隧道数据面前清除它们，再统一安装
    // TCP_NODELAY/keepalive。不要显式设置 SO_RCVBUF/SO_SNDBUF：Linux 未被
    // setsockopt 锁定时会按 tcp_rmem/tcp_wmem 自动调优高 BDP 连接。
    stream.set_read_timeout(None)?;
    stream.set_write_timeout(None)?;
    stream.set_nodelay(true)?;
    apply_tcp_keepalive(&stream);
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn dial_with_mark_host(target: &str, mark: i32) -> std::io::Result<std::net::TcpStream> {
    let (host, port) = split_host_port(target);
    dial_with_mark(&host, port, mark)
}
#[cfg(not(target_os = "linux"))]
fn dial_with_mark_host(target: &str, _mark: i32) -> std::io::Result<std::net::TcpStream> {
    let (host, port) = split_host_port(target);
    std::net::TcpStream::connect((host.as_str(), port))
}

/// 建立一条物理连接并服务到断开。返回在线时长（退避归零判断用）。
///
/// rustls 不支持多线程并发读写，这里采用每连接单线程 + 独立 mio::Poll 的
/// 事件循环（与 Go 双协程等效：poll 超时 5ms 兼顾端口通道的及时拉取，
/// 可读事件即时唤醒保证下行延迟）。
fn dial_and_serve(cl: &Arc<Client>, conn_index: usize, ci: &Arc<ConnInfo>) -> Duration {
    let reconnect_generation = cl.force_generation.load(Ordering::Acquire);
    let linked_at = Instant::now();
    let target = cl.targets[conn_index % cl.targets.len()].clone();

    if cl.socks5.is_some() {
        info!(
            "[Conn {}] Initiating connection to {} via SOCKS5...",
            conn_index, target
        );
    } else {
        info!("[Conn {}] Initiating connection...", conn_index);
    }

    let raw = match dial_target(cl, &target) {
        Ok(s) => s,
        Err(e) => {
            *ci.state.lock() = "retrying".into();
            *ci.last_error.lock() = e.to_string();
            return Duration::ZERO;
        }
    };
    *ci.remote.lock() = raw.peer_addr().map(|a| a.to_string()).unwrap_or_default();
    *ci.state.lock() = "connecting".into();

    // 1. 先只计算 Brutal 预算，不在 TLS / TLSVPN 握手前切拥塞控制。
    // Brutal 是数据面优化；与 Go 一致，必须等应用层 HandshakeResp 成功后再启用。
    let conns = cl.conns_count as u64;
    let client_tx_rate_bps = split_legacy_brutal_rate_bps(cl.brutal_up, conns as usize, conn_index);
    let instance_id = cl.instance_id.lock().clone();
    let brutal_group = brutal_group_id("client", &instance_id);
    *ci.brutal.lock() = BrutalApplyResult::default();

    // 2. TLS 连接与握手（10s 超时对齐 Go SetDeadline）
    let server_name = match ServerName::try_from(cl.sni.clone()) {
        Ok(n) => n,
        Err(_) => {
            error!("[Conn {}] Invalid SNI: {}", conn_index, cl.sni);
            return Duration::ZERO;
        }
    };
    let mut tls = match ClientConnection::new(cl.config.clone(), server_name) {
        Ok(t) => t,
        Err(e) => {
            *ci.last_error.lock() = format!("tls init: {}", e);
            return Duration::ZERO;
        }
    };

    let _ = raw.set_nonblocking(true);
    let std_for_rtt = raw.try_clone().ok();
    let mut poll = match mio::Poll::new() {
        Ok(p) => p,
        Err(e) => {
            *ci.last_error.lock() = format!("poll init: {}", e);
            return Duration::ZERO;
        }
    };
    let mut events = mio::Events::with_capacity(64);
    let mut sock = mio::net::TcpStream::from_std(raw);
    let _ = poll.registry().register(
        &mut sock,
        TOKEN_CONN,
        Interest::READABLE | Interest::WRITABLE,
    );

    let hs_deadline = Instant::now() + Duration::from_secs(10);
    while tls.is_handshaking() {
        match tls.complete_io(&mut sock) {
            Ok(_) => {}
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if Instant::now() > hs_deadline {
                    *ci.last_error.lock() = "uTLS handshake timeout".into();
                    return Duration::ZERO;
                }
                if poll
                    .poll(&mut events, Some(Duration::from_millis(50)))
                    .is_err()
                {
                    return Duration::ZERO;
                }
            }
            Err(e) => {
                *ci.last_error.lock() = format!("uTLS handshake failed: {}", e);
                return Duration::ZERO;
            }
        }
    }
    // 握手完成后默认只关注可读，避免永久 WRITABLE interest 导致空转。
    // 数据面只有在 write_tls() 真正返回 WouldBlock 时才临时订阅 WRITABLE。
    let _ = poll
        .registry()
        .reregister(&mut sock, TOKEN_CONN, client_socket_interest(false));

    // rustls defaults its outgoing application-data/TLS-record buffers to 64 KiB.
    // A 64 KiB plaintext write expands slightly after record headers/tags, so the
    // default limit can return a short plaintext write / WriteZero. Give one batch
    // explicit headroom while keeping the buffer bounded per physical connection.
    tls.set_buffer_limit(Some(128 * 1024));

    // 3. 握手请求（对齐 Go）
    // 会话令牌：上一次握手收到的令牌，重连同一 client_id 时回带
    let session_token = cl.session.lock().session_token.clone();
    let req = HandshakeReq {
        protocol_version: 2,
        client_instance: instance_id,
        client_id: cl.client_id.clone(),
        psk: hash_psk(&cl.psk),
        mac: cl.mac.clone(),
        ipv4: cl.req_v4.clone(),
        ipv6: cl.req_v6.clone(),
        padding: generate_padding(100, 500),
        fec: cl.fec_mode,
        fec_group: if cl.fec_mode {
            cl.fec_group_req as i64
        } else {
            0
        },
        brutal_groups: true,
        brutal_total_tx: cl.brutal_up,
        brutal_total_rx: cl.brutal_down,
        brutal_conns: cl.conns_count as i64,
        brutal_conn_index: conn_index as i64,
        encrypt: cl.encrypt,
        enc_algo: if cl.encrypt { cl.enc_algo } else { ENC_ALGO_NONE },
        session_token,
    };
    let req_json = serde_json::to_vec(&req).unwrap();
    let mut send_buf = Vec::with_capacity(2 * 1024);
    write_stream_frame(&mut send_buf, &req_json);
    if tls.writer().write_all(&send_buf).is_err() {
        *ci.last_error.lock() = "handshake write failed".into();
        return Duration::ZERO;
    }
    let resp = match tls_exchange_resp(
        cl,
        &mut tls,
        &mut sock,
        &mut poll,
        &mut events,
        conn_index,
        ci,
    ) {
        Some(r) => r,
        None => return Duration::ZERO,
    };
    if resp.protocol_version != 2 {
        *ci.last_error.lock() = format!(
            "unsupported server protocol version {}",
            resp.protocol_version
        );
        return Duration::ZERO;
    }

    // TLS + TLSVPN 握手都已完成，现在才启用 Brutal。优先采用服务端裁剪后的
    // group 总预算；若对端未返回 group 语义，则兼容旧端，按本地逐连接预算应用。
    if cl.brutal && client_tx_rate_bps > 0 && cl.socks5.is_none() {
        let (total_rate, legacy_bps) =
            if resp.brutal_groups && resp.brutal_total_tx > 0 {
                (
                    resp.brutal_total_tx,
                    split_legacy_brutal_rate_bps(
                        resp.brutal_total_tx,
                        cl.conns_count,
                        conn_index,
                    ),
                )
            } else {
                (cl.brutal_up, client_tx_rate_bps)
            };
        *ci.brutal.lock() = apply_tcp_brutal(&sock, total_rate, legacy_bps, brutal_group);
    }

    // 4. 内层加密协商（对齐 Go）
    if resp.encrypt != cl.encrypt {
        *ci.last_error.lock() = "server encryption mismatch".into();
        return Duration::ZERO;
    }

    // 内层算法由配置显式固定。gcm256 保持兼容默认；gcm128 是 opt-in 性能模式。
    // 内层加密算法由配置显式选择：gcm256 是兼容默认，gcm128 是性能模式。
    // 两者 wire format 相同但 KDF label 隔离；服务端响应必须与请求完全一致。
    let mut enc_algo = ENC_ALGO_NONE;
    let mut ic_tx: Option<Arc<InnerCipher>> = None;
    let mut ic_rx: Option<Arc<InnerCipher>> = None;
    let mut fec_tx: Option<Arc<InnerCipher>> = None;
    let mut fec_rx: Option<Arc<InnerCipher>> = None;
    if cl.encrypt {
        if resp.enc_algo != cl.enc_algo {
            *ci.last_error.lock() = format!(
                "server negotiated inner cipher {} ({}), want {} ({})",
                resp.enc_algo,
                enc_algo_label(resp.enc_algo),
                cl.enc_algo,
                enc_algo_label(cl.enc_algo)
            );
            warn!("[Conn {}] {}", conn_index, *ci.last_error.lock());
            return Duration::ZERO;
        }
        let (stx, srx) = match (hex::decode(&resp.enc_salt), hex::decode(&resp.enc_salt2)) {
            (Ok(a), Ok(b)) if a.len() == ENC_SALT_SIZE && b.len() == ENC_SALT_SIZE => (a, b),
            _ => {
                *ci.last_error.lock() = "server sent invalid enc salts".into();
                warn!("[Conn {}] {}", conn_index, *ci.last_error.lock());
                return Duration::ZERO;
            }
        };
        match (
            InnerCipher::gcm_for_algo(&cl.psk, &stx, resp.enc_algo),
            InnerCipher::gcm_for_algo(&cl.psk, &srx, resp.enc_algo),
        ) {
            (Ok(tx), Ok(rx)) => {
                ic_tx = Some(Arc::new(tx));
                ic_rx = Some(Arc::new(rx));
            }
            (e1, e2) => {
                *ci.last_error.lock() =
                    format!("GCM cipher init failed: {:?}/{:?}", e1.err(), e2.err());
                warn!("[Conn {}] {}", conn_index, *ci.last_error.lock());
                return Duration::ZERO;
            }
        }
        fec_tx = InnerCipher::gcm_domain_for_algo(&cl.psk, &stx, "fec", resp.enc_algo)
            .ok()
            .map(Arc::new);
        fec_rx = InnerCipher::gcm_domain_for_algo(&cl.psk, &srx, "fec", resp.enc_algo)
            .ok()
            .map(Arc::new);
        enc_algo = resp.enc_algo;
    }

    if cl.min_enc > 0 && !is_gcm_algo(enc_algo) {
        *ci.state.lock() = "retrying".into();
        *ci.last_error.lock() = format!(
            "server negotiated inner cipher {} is below min_enc {:?}",
            enc_algo, MIN_ENC_GCM
        );
        warn!("[Conn {}] {}", conn_index, *ci.last_error.lock());
        return Duration::ZERO;
    }

    // 5. 会话级协商（对齐 Go sessionMu 段）
    let mut use_xor_fec = false;
    {
        let mut st = cl.session.lock();
        if cl.fec_mode && st.fec_negotiated == 0 {
            if resp.fec_group >= fec::FEC_MIN_GROUP as i64 {
                st.fec_negotiated = resp.fec_group;
                *cl.fec_status.lock() = format!("xor K={}", resp.fec_group);
                info!(
                    "[Conn {}] XOR FEC negotiated: K={} (overhead 1/{})",
                    conn_index, resp.fec_group, resp.fec_group
                );
            } else {
                // 服务端协商不出可用分组（fec_group < 2）：本次不开 FEC，
                // fec_negotiated 保持 0，后续连接继续重试
                *cl.fec_status.lock() = "off".into();
                warn!(
                    "[Conn {}] FEC requested but server negotiated fec_group={}, FEC disabled",
                    conn_index, resp.fec_group
                );
            }
        }
        if cl.fec_mode && st.fec_negotiated > 0 {
            use_xor_fec = true;
            // FEC 编解码器绑定当前会话加密器与盐：会话/盐变化即重建
            let rebuild_needed = {
                let dec_guard = cl.fec_dec.lock();
                dec_guard.is_none() || st.fec_algo != enc_algo || st.fec_salt_key != resp.enc_salt
            };
            if rebuild_needed {
                if let Some(old) = cl.fec_dec.lock().as_ref() {
                    old.reset();
                }
                let negotiated = st.fec_negotiated as usize;
                *cl.fec_dec.lock() = Some(Arc::new(FecDecoder::new(negotiated, fec_rx.clone())));
                cl.tx_port.reset_epoch(negotiated, fec_tx.clone());
                st.fec_algo = enc_algo;
                st.fec_salt_key = resp.enc_salt.clone();
            }
        }
        if st.enc_algo != enc_algo {
            st.enc_algo = enc_algo;
            st.ic_tx = ic_tx.clone();
            st.ic_rx = ic_rx.clone();
        }
        let is_new_session =
            st.server_session_id != resp.session_id || st.session_epoch != resp.session_epoch;
        if is_new_session {
            st.server_session_id = resp.session_id.clone();
            st.session_epoch = resp.session_epoch;
        }
        st.gw_v4 = resp.gw_v4.clone();
        st.gw_v6 = resp.gw_v6.clone();
        if resp.brutal_groups {
            st.brutal_tx = resp.brutal_total_tx;
            st.brutal_rx = resp.brutal_total_rx;
        }
        // 记下服务端下发的会话令牌，供后续重连回带。服务端未开启
        // session_token 时该字段为空，行为与旧版一致（对齐 Go）。
        st.session_token = resp.session_token.clone();
        // 服务端返回的是它实际看到的 ClientHello；旧服务端没有该可选字段时清空，
        // 避免重连到旧节点后面板继续展示上一个节点的陈旧观测值。
        st.tls = resp.tls.clone();
        // 落盘：进程重启后第一次握手就能回带令牌接回同一会话
        persist_session_state(
            cl,
            &resp.session_id,
            &resp.session_token,
            resp.session_epoch,
        );
        *cl.assigned_v4.lock() = resp.ipv4.split('/').next().unwrap_or("").to_string();
        *cl.assigned_v6.lock() = resp.ipv6.split('/').next().unwrap_or("").to_string();
        // 取值：0=明文，2=AES-256-GCM，4=AES-128-GCM。
        cl.enc_algo_display.store(enc_algo, Ordering::Relaxed);

        if is_new_session {
            if !use_xor_fec {
                cl.tx_port.reset_epoch(0, None);
            }
            cl.sequence_rekeying.store(false, Ordering::Release);
            info!(
                "[Conn {}] 🔄 server reset the session; flushing stale local receive buffers...",
                conn_index
            );
            drop(st);
            cl.reorder_buf.lock().reset();
            cl.dedup.lock().reset();
        }
    }

    // 6. 配置接口与策略路由（Linux；对齐 Go setupInterface/setupPolicyRouting）
    let network_setup_guard = cl.network_setup.lock();
    let mut readiness_error: Option<String> = None;
    if cl.tap_name != "mem" {
        #[cfg(target_os = "linux")]
        if let Err(e) = setup_interface(cl, &resp.ipv4, &resp.ipv6) {
            warn!("tunnel interface configuration failed: {e}");
            readiness_error = Some(e);
        }
        // 规则与路由由本进程自管，用户不需要（也不应）再写一份 systemd drop-in：
        // 两者并存时同一条 fwmark 规则会按 priority 竞争，结果取决于内核裁决顺序。
        let pr_spec = PolicyRoutingSpec {
            mark: cl.fwmark,
            priority: cl.fwmark_priority,
            tap_name: cl.tap_name.clone(),
            gw_v4: resp.gw_v4.clone(),
            gw_v6: resp.gw_v6.clone(),
            extra_routes: cl.extra_routes.clone(),
            source_rules: cl.source_rules.clone(),
        };
        match setup_policy_routing(&pr_spec) {
            Ok(()) => {
                *cl.pr_ok.lock() = true;
                *cl.pr_err.lock() = String::new();
            }
            Err(e) => {
                // 上抛而不是吞掉：半装状态（有规则没路由）比明确报错更糟
                warn!("policy routing: {e}");
                *cl.pr_ok.lock() = false;
                *cl.pr_err.lock() = e.clone();
                if readiness_error.is_none() {
                    readiness_error = Some(e);
                }
            }
        }
        let _ = CLEANUP_INFO.set(pr_spec);
    }

    if cl.hooks.configured() {
        let hook_env = HookEnv {
            mode: "client".into(),
            dev: cl.tap_name.clone(),
            config: cl.hook_config_path.clone(),
            ipv4: resp.ipv4.clone(),
            ipv6: resp.ipv6.clone(),
            gateway_v4: resp.gw_v4.clone(),
            gateway_v6: resp.gw_v6.clone(),
        };
        let hook_result = if let Some(e) = readiness_error {
            cl.hooks.activate(hook_env);
            Err(format!("cannot run lifecycle up hook before tunnel networking is ready: {e}"))
        } else {
            cl.hooks.up(hook_env)
        };
        if let Err(e) = hook_result {
            *ci.last_error.lock() = e.clone();
            let mut fatal = cl.fatal_error.lock();
            if fatal.is_none() {
                *fatal = Some(e);
            }
            EXIT.store(true, Ordering::SeqCst);
            return Duration::ZERO;
        }
    }
    drop(network_setup_guard);

    // 7. 注册端口后端。RTT/reorder deadline 合并进本连接 mio loop，
    // 不再为每条物理连接额外创建 RTT timer thread。
    let conn_waker: Arc<mio::Waker> =
        Arc::new(mio::Waker::new(poll.registry(), TOKEN_WAKE).expect("Waker init"));
    let rtt_cache = Arc::new(AtomicU32::new(50000));
    let (tx, rx) = bounded(1024);
    let backend = Arc::new(Backend {
        ch: tx.clone(),
        rtt_cache: rtt_cache.clone(),
        notify: Some(Arc::new(BackendNotify::new(
            conn_waker.clone(),
            // 客户端只看 TOKEN_WAKE，本队列用于复用统一通知结构。
            Arc::new(ArrayQueue::new(1)),
            TOKEN_WAKE,
        ))),
    });
    cl.tx_port.register_backend(backend.clone());

    cl.live_conns.fetch_add(1, Ordering::Relaxed);
    *ci.rtt_cache.lock() = rtt_cache.clone();
    ci.linked_at.store(now_unix_ms() / 1000, Ordering::Relaxed);
    *ci.state.lock() = "up".into();
    *ci.last_error.lock() = String::new();

    // 8. 主事件循环：读事件 → 解帧处理；拉取端口通道 → 成帧发送；保活。
    let mut scanner = FrameScanner::new();
    let mut last_keepalive = Instant::now();
    let mut last_rx = Instant::now();
    let mut last_write_progress = Instant::now();
    // Keep WRITABLE disabled on the hot path. Enable it only after the
    // kernel socket actually backpressures write_tls(), then remove it
    // again as soon as rustls ciphertext is fully drained.
    let mut write_blocked = false;
    let mut next_rtt_refresh = Instant::now();
    let proxied = cl.socks5.is_some();
    let mut conn_closed = false;
    let mut close_reason = String::new();

    // rustls' connection buffer limit above is 128 KiB, leaving ciphertext
    // headroom for one 64 KiB plaintext batch while matching the Go/uTLS batching
    // ceiling. The buffer remains bounded; write_tls() still drains to EAGAIN.
    const TLS_WRITE_BATCH_BYTES: usize = 64 * 1024;
    send_buf.clear();
    send_buf.reserve((TLS_WRITE_BATCH_BYTES + 4096).saturating_sub(send_buf.capacity()));
    while !conn_closed && !EXIT.load(Ordering::Relaxed) {
        if cl.tx_port.is_sequence_exhausted() {
            close_reason = "sequence space exhausted".into();
            if cl
                .sequence_rekeying
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                *cl.instance_id.lock() = random_instance_id();
                cl.force_generation.fetch_add(1, Ordering::SeqCst);
                warn!("client sequence space exhausted; rotating instance and reconnecting with fresh keys");
            }
            break;
        }
        if cl.force_generation.load(Ordering::Acquire) != reconnect_generation {
            close_reason = "forced reconnect generation changed".into();
            break;
        }

        // 把 RTT 刷新与重排 gap deadline 合并进同一个 poll timeout。
        // 无 gap 时不会再有独立的 5ms reorder 轮询线程。
        let now = Instant::now();
        let mut poll_timeout = Duration::from_secs(1);
        if !proxied {
            poll_timeout = poll_timeout.min(next_rtt_refresh.saturating_duration_since(now));
        }
        let reorder_wait = cl.reorder_buf.lock().next_timeout();
        if let Some(wait) = reorder_wait {
            poll_timeout = poll_timeout.min(wait);
        }
        // BackendNotify coalesces producer wakeups. One wake can therefore
        // represent more than one TLS plaintext batch. If frames remain
        // queued after the previous 32 KiB drain and rustls is not blocked
        // on socket writes, poll nonblocking so we service that backlog
        // immediately while still observing socket readability.
        poll_timeout = clamp_poll_for_tx_backlog(
            poll_timeout,
            !rx.is_empty(),
            tls.wants_write(),
        );
        if let Err(e) = poll.poll(&mut events, Some(poll_timeout)) {
            close_reason = format!("mio poll failed: {e}");
            break;
        }

        let mut woken = false;
        let mut readable = false;
        for ev in events.iter() {
            if ev.token() == TOKEN_WAKE {
                woken = true;
            } else if ev.token() == TOKEN_CONN && ev.is_readable() {
                readable = true;
            }
        }

        // RTT 采样在连接线程内完成，消除每连接一个 200ms sleeper thread。
        if !proxied && Instant::now() >= next_rtt_refresh {
            if let Some(s) = std_for_rtt.as_ref() {
                let rtt = get_tcp_rtt(s);
                if rtt > 0 {
                    rtt_cache.store(rtt, Ordering::Relaxed);
                }
            }
            next_rtt_refresh = Instant::now() + Duration::from_millis(200);
        }

        // A gap timeout can release a burst. Queue it while still holding the
        // reorder lock so multiple physical connections cannot enqueue ready batches
        // out of sequence; the TAP syscall itself runs on the delivery worker.
        if reorder_wait.is_some() {
            flush_reorder_to_tap(&cl);
        }

        // ---- 下行读取：mio 是边沿触发，必须真正 drain socket 到 WouldBlock。----
        // 每次 read_tls 后立即 process_new_packets + drain plaintext，避免 rustls
        // 的 bounded encrypted/plaintext buffers 在高速流量下先填满，从而留下
        // 一个仍 readable 但再也没有新 edge 的 socket。
        let mut rx_bytes_batch = 0u64;
        let mut rx_packets_batch = 0u64;
        let fec_dec = if use_xor_fec {
            cl.fec_dec.lock().clone()
        } else {
            None
        };

        if readable {
            'socket_read: loop {
                match tls.read_tls(&mut sock) {
                    Ok(0) => {
                        close_reason = "tls.read_tls returned EOF".into();
                        conn_closed = true;
                        break 'socket_read;
                    }
                    Ok(_) => {
                        last_rx = Instant::now();
                        if let Err(e) = tls.process_new_packets() {
                            close_reason = format!("tls.process_new_packets failed: {e}");
                            conn_closed = true;
                            break 'socket_read;
                        }
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break 'socket_read;
                    }
                    Err(e) => {
                        close_reason = format!("tls.read_tls failed: {e}");
                        conn_closed = true;
                        break 'socket_read;
                    }
                }

                // Drain all plaintext made available by this TLS read before
                // attempting another socket read. This keeps rustls buffers bounded
                // while still draining the edge-triggered fd all the way to EAGAIN.
                loop {
                    match scanner.read_frame(&mut tls.reader()) {
                        Ok(Some((raw, seq))) => {
                            if raw.is_empty() {
                                continue;
                            }
                            let mut data = raw;
                            rx_bytes_batch =
                                rx_bytes_batch.saturating_add((data.len() + 10) as u64);
                            rx_packets_batch = rx_packets_batch.saturating_add(1);

                            if seq != 0 {
                                if let Some(ic) = &ic_rx {
                                    let wire_len = data.len() as u32;
                                    match ic.open_in_place(&mut data, seq, wire_len) {
                                        Ok(plain) => {
                                            let n = plain.len();
                                            data.truncate(n);
                                        }
                                        Err(_) => {
                                            debug!(
                                                "dropped tampered/foreign frame (seq={})",
                                                seq
                                            );
                                            release_frame_vec(data);
                                            continue;
                                        }
                                    }
                                }
                            }

                            let data = Arc::new(data);
                            if seq == 0 {
                                if let Some(dec) = &fec_dec {
                                    if fec::is_parity_frame(&data) {
                                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                            deliver_to_tap(&cl, s, f);
                                        };
                                        dec.on_parity(&data, &mut sink);
                                        release_shared_frame(data);
                                        continue;
                                    }
                                }
                            }

                            if let Some(dec) = &fec_dec {
                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                    deliver_to_tap(&cl, s, f);
                                };
                                dec.on_data(seq, &data, &mut sink);
                            }

                            if !cl.dedup.lock().is_duplicate(seq) {
                                deliver_to_tap(&cl, seq, data);
                            } else {
                                release_shared_frame(data);
                            }
                        }
                        Ok(None) => break,
                        Err(e) => {
                            close_reason = format!("frame scanner failed: {e}");
                            conn_closed = true;
                            break 'socket_read;
                        }
                    }
                }
            }
        }

        if rx_packets_batch != 0 {
            cl.rx_bytes.fetch_add(rx_bytes_batch, Ordering::Relaxed);
            cl.rx_packets
                .fetch_add(rx_packets_batch, Ordering::Relaxed);
            ci.rx_bytes.fetch_add(rx_bytes_batch, Ordering::Relaxed);
        }

        // ---- 上行：端口唤醒时拉帧成批发送 ----
        let ic_tx_ref = ic_tx.as_deref();
        send_buf.clear();
        let mut tx_packets_batch = 0u64;
        if !tls.wants_write() && (woken || !rx.is_empty()) {
            if let Some(n) = &backend.notify {
                // Only clear pending when we are actually going to drain the
                // backend queue. If TLS is socket-backpressured, leave pending
                // set and retry from the periodic poll loop once ciphertext drains.
                n.consume_wake();
            }
            while let Ok(f) = rx.try_recv() {
                let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };
                append_padded_frame(&mut send_buf, f.seq, f.data.as_slice(), ic_ref);
                f.data.release();
                tx_packets_batch += 1;
                if send_buf.len() >= TLS_WRITE_BATCH_BYTES {
                    break;
                }
            }
        }

        if send_buf.is_empty()
            && !tls.wants_write()
            && last_keepalive.elapsed() > Duration::from_secs(4)
        {
            append_padded_frame(&mut send_buf, 0, &[], None);
        }
        if !send_buf.is_empty() {
            let wire_bytes = send_buf.len() as u64;
            if let Err(e) = tls.writer().write_all(&send_buf) {
                close_reason = format!("tls plaintext writer failed: {e}");
                break;
            }
            if tx_packets_batch != 0 {
                cl.tx_packets
                    .fetch_add(tx_packets_batch, Ordering::Relaxed);
            }
            cl.tx_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
            ci.tx_bytes.fetch_add(wire_bytes, Ordering::Relaxed);
            last_keepalive = Instant::now();
            // 仅清长度，保留 capacity 给下一批。
            send_buf.clear();
        }

        // 冲刷写队列（非阻塞；WouldBlock 等下次 poll 后重试）
        while tls.wants_write() {
            match tls.write_tls(&mut sock) {
                Ok(0) => {
                    close_reason = "tls.write_tls returned zero".into();
                    conn_closed = true;
                    break;
                }
                Ok(_) => {
                    last_write_progress = Instant::now();
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    // Normally the data loop listens only for READABLE. Once
                    // the kernel socket backpressures, subscribe to WRITABLE so
                    // send-buffer recovery wakes us immediately instead of
                    // waiting for the RTT/reorder timer.
                    if !write_blocked {
                        if let Err(reg_err) = poll.registry().reregister(
                            &mut sock,
                            TOKEN_CONN,
                            client_socket_interest(true),
                        ) {
                            close_reason = format!(
                                "mio reregister writable after TLS backpressure failed: {reg_err}"
                            );
                            conn_closed = true;
                        } else {
                            write_blocked = true;
                        }
                    }
                    break
                }
                Err(e) => {
                    close_reason = format!("tls.write_tls failed: {e}");
                    conn_closed = true;
                    break;
                }
            }
        }

        if write_blocked && !tls.wants_write() && !conn_closed {
    if let Err(reg_err) = poll.registry().reregister(
        &mut sock,
        TOKEN_CONN,
        client_socket_interest(false),
    ) {
        close_reason = format!(
            "mio restore read-only interest after TLS drain failed: {reg_err}"
        );
        conn_closed = true;
    } else {
        write_blocked = false;
    }
}

        if last_write_progress.elapsed() > Duration::from_secs(10) {
            close_reason = "write stalled for >10s".into();
            warn!("write stalled for >10s; closing the connection");
            conn_closed = true;
        }
        if last_rx.elapsed() > Duration::from_secs(15) {
            close_reason = "no TLS receive progress for >15s".into();
            conn_closed = true;
        }
    }

    if close_reason.is_empty() {
        close_reason = "connection loop ended without an explicit reason".into();
    }
    warn!("[Conn {}] data loop closing: {}", conn_index, close_reason);

    tls.send_close_notify();
    while tls.wants_write() {
        match tls.write_tls(&mut sock) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
    }

    cl.tx_port.unregister_backend(&tx);
    cl.live_conns.fetch_sub(1, Ordering::Relaxed);
    *ci.state.lock() = "retrying".into();
    linked_at.elapsed()
}

/// Inject one data/recovered frame into reorder and hand any newly contiguous
/// output to the dedicated TAP writer. Enqueue happens under the reorder lock:
/// this is nonblocking and preserves strict order across physical connections.
fn deliver_to_tap(cl: &Arc<Client>, seq: u32, frame: Arc<Vec<u8>>) {
    let mut ready = cl.tap_delivery.acquire();
    let mut reorder = cl.reorder_buf.lock();
    reorder.insert_into(seq, frame, &mut ready);
    if ready.is_empty() {
        drop(reorder);
        cl.tap_delivery.recycle(ready);
    } else {
        cl.tap_delivery.enqueue(ready);
    }
}

fn flush_reorder_to_tap(cl: &Arc<Client>) {
    let mut ready = cl.tap_delivery.acquire();
    let mut reorder = cl.reorder_buf.lock();
    reorder.flush_timeout_into(&mut ready);
    if ready.is_empty() {
        drop(reorder);
        cl.tap_delivery.recycle(ready);
    } else {
        cl.tap_delivery.enqueue(ready);
    }
}

#[inline]
fn client_socket_interest(write_blocked: bool) -> Interest {
    if write_blocked {
        Interest::READABLE | Interest::WRITABLE
    } else {
        Interest::READABLE
    }
}

#[inline]
fn clamp_poll_for_tx_backlog(
    base: Duration,
    tx_backlog: bool,
    tls_wants_write: bool,
) -> Duration {
    if tx_backlog && !tls_wants_write {
        Duration::ZERO
    } else {
        base
    }
}

#[cfg(test)]
mod tx_poll_tests {
    use super::{clamp_poll_for_tx_backlog, client_socket_interest};
    use std::time::Duration;

    #[test]
    fn writable_interest_is_only_enabled_for_real_backpressure() {
        let normal = client_socket_interest(false);
        assert!(normal.is_readable());
        assert!(!normal.is_writable());

        let blocked = client_socket_interest(true);
        assert!(blocked.is_readable());
        assert!(blocked.is_writable());
    }

    #[test]
    fn queued_tx_without_tls_backpressure_never_sleeps() {
        assert_eq!(
            clamp_poll_for_tx_backlog(Duration::from_millis(200), true, false),
            Duration::ZERO
        );
    }

    #[test]
    fn no_backlog_keeps_timer_and_tls_backpressure_does_not_spin() {
        let base = Duration::from_millis(200);
        assert_eq!(clamp_poll_for_tx_backlog(base, false, false), base);
        assert_eq!(clamp_poll_for_tx_backlog(base, true, true), base);
    }
}

const TOKEN_CONN: mio::Token = mio::Token(1);
const TOKEN_WAKE: mio::Token = mio::Token(2);

/// 等待握手响应帧（5s 超时，对齐 Go SetReadDeadline(5s) 后 ReadFrame）
fn tls_exchange_resp(
    _cl: &Arc<Client>,
    tls: &mut ClientConnection,
    sock: &mut mio::net::TcpStream,
    poll: &mut mio::Poll,
    events: &mut mio::Events,
    conn_index: usize,
    ci: &Arc<ConnInfo>,
) -> Option<HandshakeResp> {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut scanner = FrameScanner::new();
    // 首帧是握手响应（<2KB）：收紧上限防畸形帧头撑大缓冲。本函数只读握手响应，
    // 数据面用的是主循环里另一个扫描器（默认全量上限）
    scanner.set_max_data_len(HANDSHAKE_DATA_LENGTH);
    loop {
        // 尽力冲刷请求
        while tls.wants_write() {
            match tls.write_tls(sock) {
                Ok(0) => return None,
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(_) => return None,
            }
        }
        match scanner.read_frame(&mut tls.reader()) {
            Ok(Some((data, _seq))) => {
                if data.is_empty() {
                    continue; // 空帧（心跳）不是握手响应
                }
                let parsed = serde_json::from_slice::<HandshakeResp>(&data);
                release_frame_vec(data);
                if let Ok(r) = parsed {
                    if r.success {
                        debug!(
							"[Conn {}] <= handshake response session={} proto={} epoch={} fec={}/{} enc={}/{} token_present={}",
							conn_index,
							r.session_id,
							r.protocol_version,
							r.session_epoch,
							r.fec,
							r.fec_group,
							r.encrypt,
							r.enc_algo,
							!r.session_token.is_empty()
						);
                        return Some(r);
                    }
                    *ci.last_error.lock() = "handshake rejected".into();
                    return None;
                }
            }
            Ok(None) => {
                // 需要更多数据：读 socket
                let mut got = false;
                loop {
                    match tls.read_tls(sock) {
                        Ok(0) => return None,
                        Ok(_) => {
                            got = true;
                        }
                        Err(e)
                            if e.kind() == std::io::ErrorKind::WouldBlock
                                || e.kind() == std::io::ErrorKind::TimedOut =>
                        {
                            break
                        }
                        Err(_) => return None,
                    }
                }
                if got {
                    if tls.process_new_packets().is_err() {
                        return None;
                    }
                } else {
                    if Instant::now() > deadline {
                        *ci.last_error.lock() = "handshake timeout".into();
                        return None;
                    }
                    if poll.poll(events, Some(Duration::from_millis(20))).is_err() {
                        return None;
                    }
                }
            }
            Err(e) => {
                *ci.last_error.lock() = e.to_string();
                return None;
            }
        }
    }
}

// Linux 下用 ip 命令配置接口地址；命令序列（顺序、nodad、replace）见
// utils::tap_addr_cmds，那是 web.bind=tunnel 能绑上 v6 隧道 IP 的前提。
#[cfg(target_os = "linux")]
fn setup_interface(cl: &Arc<Client>, v4cidr: &str, v6cidr: &str) -> Result<(), String> {
    crate::utils::apply_ip_cmds(&crate::utils::tap_addr_cmds(&cl.tap_name, v4cidr, v6cidr))
}
