use crate::Args;
use aes::Aes256;
use crossbeam_channel::bounded;
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

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::fec::{self, clamp_fec_group, FecDecoder};
use crate::frame::*;
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
    let mut d = RECONNECT_BACKOFF_BASE * (1u32 << shift);
    if d > RECONNECT_BACKOFF_MAX || d.is_zero() {
        d = RECONNECT_BACKOFF_MAX;
    }
    // 25% 随机抖动（对齐 Go：d - d/8 + jitter/2）
    let jitter = crate::utils::RNG.with(|rng| {
        let j = (d / 4).as_millis() as usize;
        Duration::from_millis(rng.borrow_mut().gen_range(0, j.max(1)) as u64)
    });
    d - d / 8 + jitter / 2
}

/// 全局退出标记（信号处理置位）
pub static EXIT: AtomicBool = AtomicBool::new(false);

/// 退出时清理策略路由所需的信息（对齐 Go cleanPolicyRouting defer）
static CLEANUP_INFO: std::sync::OnceLock<(String, i32, String, String)> =
    std::sync::OnceLock::new();

pub fn on_exit_cleanup() {
    if let Some((tap, fwmark, gw4, gw6)) = CLEANUP_INFO.get() {
        clean_policy_routing(tap, *fwmark, gw4, gw6);
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
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // 证书哈希锁定模式下信任服务器签名（对齐 Go InsecureVerify 语义）
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
        }
    }

    fn snapshot(&self, index: usize) -> serde_json::Value {
        let linked_at = self.linked_at.load(Ordering::Relaxed);
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
    fec_negotiated: i64, // 0=未协商, >0=XOR 分组大小, -1=服务端不支持
    fec_algo: i64,
    fec_salt_key: String,
    ic_tx: Option<Arc<InnerCipher>>,
    ic_rx: Option<Arc<InnerCipher>>,
    enc_algo: i64,
    gw_v4: String,
    gw_v6: String,
}

// ======================= 客户端 =======================

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
    pub brutal: bool,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub conns_count: usize,
    pub fec_mode: bool,
    pub fec_group_req: usize,
    pub encrypt: bool,
    pub tap: Arc<dyn TapDevice>,
    pub mac: String,
    pub tx_port: Arc<AsyncPort>,
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    pub fec_dec: Mutex<Option<Arc<FecDecoder>>>,
    pub dedup: Arc<Mutex<DeDuplicator>>,
    pub ic_legacy: Option<Arc<InnerCipher>>,
    pub session: Mutex<SessionState>,
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
    pub enc_algo_display: AtomicI64,
    pub force_reconnect: AtomicBool,
    pub started_at: Instant,
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
        let mut enc = self.enc_algo_display.load(Ordering::Relaxed);
        if enc == 0 && self.encrypt {
            enc = 1; // legacy CTR 依旧算"已加密"（对齐 Go）
        }
        let fec_status = self.fec_status.lock().clone();
        let local = serde_json::json!({
            "client_id": self.client_id,
            "ipv4": self.assigned_v4.lock().clone(),
            "ipv6": self.assigned_v6.lock().clone(),
            "mac": self.mac,
            "active_conns": self.live_conns.load(Ordering::Relaxed),
            "tx_bytes": self.tx_bytes.load(Ordering::Relaxed),
            "rx_bytes": self.rx_bytes.load(Ordering::Relaxed),
            "tx_packets": self.tx_packets.load(Ordering::Relaxed),
            "rx_packets": self.rx_packets.load(Ordering::Relaxed),
            "fec": fec_status,
            "enc_algo": enc,
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
            "dropped_frames": self.tx_port.dropped(),
            "fec": {"enabled": self.fec_mode, "parity_tx": self.tx_port.parity_sent(), "recovered": rec, "lost": lost},
            "mem": {"heap_alloc_mb": rss_mb(), "sys_mb": rss_mb(), "num_goroutine": thread_count()},
            "conns": conns,
            "fec_mode": fec_status,
            "enc_algo": enc,
        })
    }

    fn metrics_text(&self) -> String {
        let (rec, lost) = self
            .fec_dec
            .lock()
            .as_ref()
            .map(|d| d.stats())
            .unwrap_or((0, 0));
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
                self.force_reconnect.store(true, Ordering::Relaxed);
                info!("[WebUI] Forced reconnect triggered");
                Ok(())
            }
            "loglevel" => set_runtime_log_level(level),
            "gc" => Ok(()),
            _ => Err("Unknown action".into()),
        }
    }
}

// ======================= 主流程 =======================

pub fn start_client(args: &Args) {
    info!("Starting TCP TLS client process...");
    let device: Arc<dyn TapDevice> = if args.tap == "mem" {
        info!("Using in-memory TAP backend (no real device)");
        Arc::new(MemTap)
    } else {
        let dev = tun_rs::DeviceBuilder::new()
            .name(&args.tap)
            .layer(tun_rs::Layer::L2)
            .mtu(args.mtu)
            .build_sync()
            .unwrap();
        Arc::new(dev)
    };

    // MAC：优先显式指定；否则读真实网卡 MAC（Linux sysfs），仍失败则警告。
    // 注意 client_id 依赖 MAC，与 Go 一致。
    let actual_mac = if args.mac.is_empty() {
        let from_sys = std::fs::read_to_string(format!("/sys/class/net/{}/address", args.tap))
            .unwrap_or_else(|_| String::new())
            .trim()
            .to_string();
        if from_sys.is_empty() {
            warn!(
                "Failed to determine real MAC for TAP '{}'; using all-zero MAC \
                 (client_id will be identical across such hosts!)",
                args.tap
            );
            "00:00:00:00:00:00".to_string()
        } else {
            from_sys
        }
    } else {
        args.mac.clone()
    };

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
        error!("Client addr 解析结果为空，请检查配置文件中的 addr 字段");
        return;
    }

    // SOCKS5 全局代理
    let socks5: Option<Arc<Socks5Proxy>> = if args.socks5.is_empty() {
        None
    } else {
        match Socks5Proxy::parse(&args.socks5) {
            Some(p) => Some(Arc::new(p)),
            None => {
                error!("Invalid SOCKS5 proxy spec: {}", args.socks5);
                return;
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
    let tx_port = Arc::new(AsyncPort::new("client_tx_port".to_string(), args.fec));
    {
        let dev = device.clone();
        let port = tx_port.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 65536];
            loop {
                if EXIT.load(Ordering::Relaxed) {
                    return;
                }
                match dev.recv(&mut buf) {
                    Ok(n) if n > 0 => {
                        port.write_frame(Arc::new(buf[..n].to_vec()));
                    }
                    Ok(_) => {}
                    Err(_) => {
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
    // 重排就绪帧写 TAP 线程
    {
        let reorder = reorder_buf.clone();
        let dev = device.clone();
        std::thread::spawn(move || loop {
            if EXIT.load(Ordering::Relaxed) {
                return;
            }
            let ready = reorder.lock().flush_timeout();
            for f in ready {
                let _ = dev.send(&f);
            }
            std::thread::sleep(Duration::from_millis(5));
        });
    }

    let config = build_tls_config(args);

    let ic_legacy = if args.encrypt {
        Some(Arc::new(InnerCipher::legacy(&args.psk)))
    } else {
        None
    };

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
        brutal: args.brutal,
        brutal_up: args.brutal_up,
        brutal_down: args.brutal_down,
        conns_count: args.conns.max(1) as usize,
        fec_mode: args.fec,
        fec_group_req,
        encrypt: args.encrypt,
        tap: device.clone(),
        mac: actual_mac.clone(),
        tx_port: tx_port.clone(),
        reorder_buf: reorder_buf.clone(),
        fec_dec: Mutex::new(None),
        dedup: Arc::new(Mutex::new(DeDuplicator::new())),
        ic_legacy,
        session: Mutex::new(SessionState::default()),
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
        enc_algo_display: AtomicI64::new(0),
        force_reconnect: AtomicBool::new(false),
        started_at: Instant::now(),
    };
    let client = Arc::new(client);

    if !args.web.is_empty() {
        start_web_server(args.web.clone(), args.web_auth.clone(), client.clone());
    }

    if args.conns < 2 && args.fec {
        warn!(
            "FEC is enabled but conns < 2. Multipath redundancy needs conns >= 2; \
               FEC will only guard against queue-overflow drops on the single link."
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
    loop {
        if EXIT.load(Ordering::Relaxed) {
            return;
        }
        if cl.force_reconnect.swap(false, Ordering::Relaxed) {
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
            if cl.force_reconnect.swap(false, Ordering::Relaxed) {
                attempt = 0;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn dial_target(cl: &Arc<Client>, target: &str) -> std::io::Result<std::net::TcpStream> {
    if let Some(proxy) = &cl.socks5 {
        let (host, port) = split_host_port(target);
        proxy.connect(&host, port)
    } else {
        // 统一走带 SO_MARK 的拨号器（对齐 Go newBaseDialer：直连与代理两种
        // 模式下 KeepAlive/mark 都在本层设置）
        let stream = dial_with_mark_host(target, cl.fwmark)?;
        stream.set_nodelay(true)?;
        apply_tcp_keepalive(&stream);
        apply_socket_buffers(&stream);
        Ok(stream)
    }
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

    // 1. Brutal 速率均分（对齐 Go；brutal 关闭时仍上报速率供服务端裁剪）
    let conns = cl.conns_count as u64;
    let client_tx_rate = if cl.brutal_up / conns == 0 && cl.brutal_up > 0 {
        1
    } else {
        cl.brutal_up / conns
    };
    let client_rx_rate = if cl.brutal_down / conns == 0 && cl.brutal_down > 0 {
        1
    } else {
        cl.brutal_down / conns
    };
    if cl.brutal && client_tx_rate > 0 && cl.socks5.is_none() {
        apply_tcp_brutal(&raw, client_tx_rate);
    }

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
    // 握手完成后只关注可读（修复写就绪恒触发导致的空转）
    let _ = poll
        .registry()
        .reregister(&mut sock, TOKEN_CONN, Interest::READABLE);

    // 3. 握手请求（对齐 Go）
    let req = HandshakeReq {
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
        brutal_tx: client_tx_rate,
        brutal_rx: client_rx_rate,
        encrypt: cl.encrypt,
        enc_algo: CLIENT_ENC_ALGO_SUPPORT,
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

    // 4. 内层加密协商（对齐 Go）
    let mut enc_algo = ENC_ALGO_LEGACY_CTR;
    let mut ic_tx: Option<Arc<InnerCipher>> = None;
    let mut ic_rx: Option<Arc<InnerCipher>> = None;
    if cl.encrypt {
        if resp.enc_algo >= ENC_ALGO_GCM {
            let salt_tx = hex::decode(&resp.enc_salt).ok();
            let salt_rx = hex::decode(&resp.enc_salt2).ok();
            if let (Some(stx), Some(srx)) = (salt_tx, salt_rx) {
                if stx.len() == ENC_SALT_SIZE && srx.len() == ENC_SALT_SIZE {
                    match (
                        InnerCipher::gcm(&cl.psk, &stx),
                        InnerCipher::gcm(&cl.psk, &srx),
                    ) {
                        (Ok(tx), Ok(rx)) => {
                            ic_tx = Some(Arc::new(tx));
                            ic_rx = Some(Arc::new(rx));
                            enc_algo = ENC_ALGO_GCM;
                        }
                        (e1, e2) => {
                            warn!(
                                "[Conn {}] GCM cipher init failed, falling back to legacy CTR: {:?}/{:?}",
                                conn_index,
                                e1.err(),
                                e2.err()
                            );
                        }
                    }
                } else {
                    warn!(
                        "[Conn {}] Server sent invalid enc salts, falling back to legacy CTR",
                        conn_index
                    );
                }
            }
        } else {
            info!(
                "[Conn {}] Server lacks GCM support, using legacy CTR inner encryption",
                conn_index
            );
        }
        if ic_tx.is_none() {
            ic_tx = cl.ic_legacy.clone();
            ic_rx = cl.ic_legacy.clone();
        }
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
                st.fec_negotiated = -1;
                *cl.fec_status.lock() = "dup".into();
                info!("[Conn {}] Server lacks XOR FEC support, falling back to legacy duplication mode", conn_index);
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
                *cl.fec_dec.lock() = Some(Arc::new(FecDecoder::new(negotiated, ic_rx.clone())));
                cl.tx_port.attach_encoder(negotiated, ic_tx.clone());
                st.fec_algo = enc_algo;
                st.fec_salt_key = resp.enc_salt.clone();
            }
        }
        if st.enc_algo != enc_algo {
            st.enc_algo = enc_algo;
            st.ic_tx = ic_tx.clone();
            st.ic_rx = ic_rx.clone();
        }
        let is_new_session = st.server_session_id != resp.session_id;
        if is_new_session {
            st.server_session_id = resp.session_id.clone();
        }
        st.gw_v4 = resp.gw_v4.clone();
        st.gw_v6 = resp.gw_v6.clone();
        *cl.assigned_v4.lock() = resp.ipv4.split('/').next().unwrap_or("").to_string();
        *cl.assigned_v6.lock() = resp.ipv6.split('/').next().unwrap_or("").to_string();
        cl.enc_algo_display.store(
            if enc_algo == ENC_ALGO_GCM { 2 } else { 1 },
            Ordering::Relaxed,
        );

        if is_new_session {
            info!(
                "[Conn {}] 🔄 检测到服务端重置了会话，正在清理本地旧的接收缓冲池...",
                conn_index
            );
            drop(st);
            cl.reorder_buf.lock().reset();
            cl.dedup.lock().reset();
        }
    }

    // 6. 配置接口与策略路由（Linux；对齐 Go setupInterface/setupPolicyRouting）
    if cl.tap_name != "mem" {
        #[cfg(target_os = "linux")]
        setup_interface(cl, &resp.ipv4, &resp.ipv6);
        setup_policy_routing(&cl.tap_name, cl.fwmark, &resp.gw_v4, &resp.gw_v6);
        let _ = CLEANUP_INFO.set((
            cl.tap_name.clone(),
            cl.fwmark,
            resp.gw_v4.clone(),
            resp.gw_v6.clone(),
        ));
    }

    // 7. 注册端口后端 + RTT 轮询线程
    // 事件驱动：端口投递帧 → 唤醒本连接的 mio poller，主循环可真正阻塞
    let conn_waker: Arc<mio::Waker> =
        Arc::new(mio::Waker::new(poll.registry(), TOKEN_WAKE).expect("Waker init"));
    let rtt_cache = Arc::new(AtomicU32::new(50000));
    let (tx, rx) = bounded(1024);
    cl.tx_port.register_backend(Arc::new(Backend {
        ch: tx.clone(),
        rtt_cache: rtt_cache.clone(),
        notify: Some(Arc::new(BackendNotify::new(
            conn_waker.clone(),
            // 客户端单连接：dirty 队列仅作协议占位，唤醒本身即信号
            Arc::new(ArrayQueue::new(1)),
            TOKEN_WAKE,
        ))),
    }));
    let rtt_stop = Arc::new(AtomicBool::new(false));
    {
        // 对齐 Go startRTTPoller：200ms 巡检 TCP_INFO；代理模式下无端到端
        // RTT 语义，保持默认估值（Go asTCPConn nil 路径）
        let sock_for_rtt = std_for_rtt;
        let proxied = cl.socks5.is_some();
        let stop = rtt_stop.clone();
        let cache = rtt_cache.clone();
        std::thread::spawn(move || {
            let sock = sock_for_rtt;
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(200));
                if let (false, Some(s)) = (proxied, sock.as_ref()) {
                    let rtt = get_tcp_rtt(s);
                    if rtt > 0 {
                        cache.store(rtt, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    cl.live_conns.fetch_add(1, Ordering::Relaxed);
    *ci.rtt_cache.lock() = rtt_cache.clone();
    ci.linked_at.store(now_unix_ms() / 1000, Ordering::Relaxed);
    *ci.state.lock() = "up".into();
    *ci.last_error.lock() = String::new();

    // 8. 主事件循环：读事件 → 解帧处理；拉取端口通道 → 成帧发送；保活
    let mut scanner = FrameScanner::new();
    let mut last_keepalive = Instant::now();
    let mut last_rx = Instant::now();
    let mut conn_closed = false;

    while !conn_closed && !EXIT.load(Ordering::Relaxed) {
        // 阻塞等待：socket 可读或端口 Waker 唤醒；1s 超时兜底保活/空闲检查
        if poll
            .poll(&mut events, Some(Duration::from_secs(1)))
            .is_err()
        {
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

        // ---- 下行读取（仅 socket 可读时）----
        let mut got_rx = false;
        if readable {
            loop {
                match tls.read_tls(&mut sock) {
                    Ok(0) => {
                        break;
                    }
                    Ok(_) => {
                        got_rx = true;
                    }
                    Err(e)
                        if e.kind() == std::io::ErrorKind::WouldBlock
                            || e.kind() == std::io::ErrorKind::TimedOut =>
                    {
                        break
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            if got_rx {
                last_rx = Instant::now();
                if tls.process_new_packets().is_err() {
                    conn_closed = true;
                }
            }
        }

        // ---- 帧处理：解密 → FEC/去重/重排 → TAP ----
        loop {
            match scanner.read_frame(&mut tls.reader()) {
                Ok(Some((raw, seq))) => {
                    let mut data = raw;
                    cl.rx_bytes
                        .fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                    cl.rx_packets.fetch_add(1, Ordering::Relaxed);
                    ci.rx_bytes
                        .fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                    if data.is_empty() {
                        continue;
                    }
                    // 内层解密（GCM 校验失败丢弃，对齐 Go openInPlace）
                    if seq != 0 {
                        if let Some(ic) = &ic_rx {
                            let wire_len = data.len() as u32;
                            match ic.open_in_place(&mut data, seq, wire_len) {
                                Ok(plain) => {
                                    let n = plain.len();
                                    data.truncate(n);
                                }
                                Err(_) => {
                                    debug!("dropped tampered/foreign frame (seq={})", seq);
                                    continue;
                                }
                            }
                        }
                    }
                    let data = Arc::new(data);
                    // XOR 校验帧 → FEC 解码器，恢复帧注入重排缓冲后写 TAP
                    if seq == 0 && use_xor_fec {
                        let dec = cl.fec_dec.lock().clone();
                        if let Some(dec) = dec {
                            if fec::is_parity_frame(&data) {
                                let mut sink = make_tap_sink(&cl);
                                dec.on_parity(&data, &mut sink);
                                continue;
                            }
                        }
                    }
                    if use_xor_fec {
                        let dec = cl.fec_dec.lock().clone();
                        if let Some(dec) = dec {
                            let mut sink = make_tap_sink(&cl);
                            dec.on_data(seq, &data, &mut sink);
                            continue;
                        }
                    }
                    // 去重 + 重排
                    if !cl.dedup.lock().is_duplicate(seq) {
                        let ready = cl.reorder_buf.lock().insert(seq, data);
                        for ordered in ready {
                            let _ = cl.tap.send(&ordered);
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    break;
                }
            }
        }

        // ---- 上行：端口唤醒或定时兜底时拉帧成批发送 ----
        let ic_tx_ref = ic_tx.as_deref();
        send_buf.clear();
        if woken {
            while let Ok(f) = rx.try_recv() {
                let ic_ref = if f.seq != 0 { ic_tx_ref } else { None };
                append_padded_frame(&mut send_buf, f.seq, &f.data, ic_ref);
                cl.tx_packets.fetch_add(1, Ordering::Relaxed);
                if send_buf.len() >= 64 * 1024 {
                    break;
                }
            }
        }
        // 保活：4s 无业务帧也发一帧（对齐 Go keepAliveTicker）
        if send_buf.is_empty() && last_keepalive.elapsed() > Duration::from_secs(4) {
            append_padded_frame(&mut send_buf, 0, &[], None);
        }
        if !send_buf.is_empty() {
            cl.tx_bytes
                .fetch_add(send_buf.len() as u64, Ordering::Relaxed);
            ci.tx_bytes
                .fetch_add(send_buf.len() as u64, Ordering::Relaxed);
            if tls.writer().write_all(&send_buf).is_err() {
                break;
            }
            last_keepalive = Instant::now();
            send_buf = Vec::new();
        }
        // 冲刷写队列（非阻塞；WouldBlock 等下次 poll 后写事件/重试）
        while tls.wants_write() {
            match tls.write_tls(&mut sock) {
                Ok(0) => {
                    break;
                }
                Ok(_) => {}
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break
                }
                Err(_) => {
                    break;
                }
            }
        }

        // 空闲保护：30s 无任何下行数据视为链路死亡（对齐 Go 30s 读超时）
        if last_rx.elapsed() > Duration::from_secs(30) {
            conn_closed = true;
        }
    }

    rtt_stop.store(true, Ordering::Relaxed);
    cl.tx_port.unregister_backend(&tx);
    cl.live_conns.fetch_sub(1, Ordering::Relaxed);
    *ci.state.lock() = "retrying".into();
    linked_at.elapsed()
}

/// 恢复帧注入重排缓冲后写 TAP 的通用回调
fn make_tap_sink(cl: &Arc<Client>) -> impl FnMut(u32, Arc<Vec<u8>>) + '_ {
    move |s: u32, f: Arc<Vec<u8>>| {
        let ready = cl.reorder_buf.lock().insert(s, f);
        for ordered in ready {
            let _ = cl.tap.send(&ordered);
        }
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
                if let Ok(r) = serde_json::from_slice::<HandshakeResp>(&data) {
                    if r.success {
                        debug!(
                            "[Conn {}] <= 收到握手响应 (HandshakeResp): {:?}",
                            conn_index, r
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

// Linux 下用 ip 命令配置接口地址（对齐 Go setupInterface 的 AddrReplace 语义）
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn setup_interface(cl: &Arc<Client>, v4cidr: &str, v6cidr: &str) {
    if v4cidr != "/" && !v4cidr.is_empty() {
        Command::new("ip")
            .args(["addr", "replace", v4cidr, "dev", &cl.tap_name])
            .output()
            .ok();
    }
    if v6cidr != "/" && !v6cidr.is_empty() {
        Command::new("ip")
            .args(["-6", "addr", "replace", v6cidr, "dev", &cl.tap_name])
            .output()
            .ok();
    }
    Command::new("ip")
        .args(["link", "set", "dev", &cl.tap_name, "up"])
        .output()
        .ok();
}
