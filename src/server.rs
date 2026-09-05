use crate::Args;
use crossbeam_channel::{bounded, Receiver, Sender};
use crossbeam_queue::ArrayQueue;
use mio::net::{TcpListener, TcpStream as MioTcpStream};
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};
use rustls::{ServerConfig, ServerConnection};
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::fec::{self, clamp_fec_group, FecDecoder};
use crate::frame::*;
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
    pub fec_dec: Option<Arc<FecDecoder>>,
    pub fec_enc_k: i64,
    pub mac: String,
    pub ipv4: String,
    pub ipv6: String,
    pub enc_algo: i64,
    pub salt_a: [u8; ENC_SALT_SIZE], // c2s 盐（客户端加密/服务端解密）
    pub salt_b: [u8; ENC_SALT_SIZE], // s2c 盐（服务端加密/客户端解密）
    pub ic_tx: Option<Arc<InnerCipher>>,
    pub ic_rx: Option<Arc<InnerCipher>>,
    pub created_at: Instant,
}

struct MioSession {
    socket: MioTcpStream,
    tls: ServerConnection,
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
    write_stalled: Option<Instant>,
}

// ======================= 服务端共享状态（面板/控制用） =======================

pub struct ServerCore {
    pub psk: String,
    pub psk_hash: String,
    pub encrypt: bool,
    pub brutal: bool,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub ic_legacy: Option<Arc<InnerCipher>>,
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
}

impl ServerCore {
    fn ipv4_cidr(&self, ip: &str) -> String {
        format!("{}/{}", ip, self.v4_mask_bits)
    }
    fn ipv6_cidr(&self, ip: &str) -> String {
        format!("{}/{}", ip, self.v6_mask_bits)
    }

    /// 会话销毁：移除注册表/交换机端口/统计/IP（对齐 Go destroyTimer）
    fn destroy_session(&self, cid: &str, mac: &str, ipv4: &str, ipv6: &str) {
        self.sessions.write().remove(cid);
        self.vswitch.remove_port(cid);
        self.registry.write().remove(cid);
        self.pool.lock().release(mac, ipv4, ipv6);
        info!("[{}] 💀 会话超时彻底销毁，释放 IP 及内存资源", cid);
    }
}

impl WebStatsProvider for ServerCore {
    fn stats_json(&self) -> serde_json::Value {
        let sessions = self.sessions.read();
        let mut clients = serde_json::Map::new();
        let mut rec = 0u64;
        let mut lost = 0u64;
        let mut parity = 0u64;
        for (id, s) in sessions.iter() {
            if let Some(dec) = &s.fec_dec {
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
            parity += s.port.parity_sent();
            clients.insert(
                id.clone(),
                serde_json::json!({
                    "ipv4": s.ipv4, "ipv6": s.ipv6, "mac": s.mac,
                    "active_conns": s.stat.active_conns.load(Ordering::Relaxed),
                    "tx_bytes": s.stat.tx_bytes.load(Ordering::Relaxed),
                    "rx_bytes": s.stat.rx_bytes.load(Ordering::Relaxed),
                    "tx_packets": s.stat.tx_packets.load(Ordering::Relaxed),
                    "rx_packets": s.stat.rx_packets.load(Ordering::Relaxed),
                    "fec": s.stat.fec_mode.lock().clone(),
                    "enc_algo": s.stat.enc_algo.load(Ordering::Relaxed),
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
        serde_json::json!({
            "mode": "server",
            "version": APP_VERSION,
            "uptime_sec": self.started_at.elapsed().as_secs(),
            "active_clients": sessions.len(),
            "clients": clients,
            "global_tx_bytes": 0,
            "global_rx_bytes": 0,
            "log_level": current_log_level_name(),
            "dropped_frames": 0,
            "fec": {"enabled": true, "parity_tx": parity, "recovered": rec, "lost": lost},
            "mem": {"heap_alloc_mb": rss_mb(), "sys_mb": rss_mb(), "num_goroutine": thread_count()},
            "ip_pool": {"v4_used": v4_used, "v4_total": v4_total, "v6_used": v6_used},
            "banned": banned,
            "mac_table": macs,
        })
    }

    fn metrics_text(&self) -> String {
        let sessions = self.sessions.read();
        let (mut tx, mut rx, mut pk) = (0u64, 0u64, 0u64);
        let (mut rec, mut lost) = (0u64, 0u64);
        for s in sessions.values() {
            tx += s.stat.tx_bytes.load(Ordering::Relaxed);
            rx += s.stat.rx_bytes.load(Ordering::Relaxed);
            pk += s.stat.tx_packets.load(Ordering::Relaxed)
                + s.stat.rx_packets.load(Ordering::Relaxed);
            if let Some(dec) = &s.fec_dec {
                let (r, l) = dec.stats();
                rec += r;
                lost += l;
            }
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
                "tlsvpn_banned_clients",
                "Currently banned clients",
                "gauge",
                self.banned.len().to_string(),
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
                if let Some(s) = self.sessions.read().get(client_id) {
                    s.stat.force_disconnect.store(true, Ordering::Relaxed);
                    info!("[WebUI] Force kicked client: {}", client_id);
                }
                Ok(())
            }
            "ban" => {
                if self.banned.ban(client_id, ttl_minutes) {
                    info!("[WebUI] Banned client {} (ttl={}m)", client_id, ttl_minutes);
                    if let Some(s) = self.sessions.read().get(client_id) {
                        s.stat.force_disconnect.store(true, Ordering::Relaxed);
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
                let n = self.sessions.read().len();
                for s in self.sessions.read().values() {
                    s.stat.force_disconnect.store(true, Ordering::Relaxed);
                }
                info!("[WebUI] Kicked all clients ({})", n);
                Ok(())
            }
            "loglevel" => set_runtime_log_level(level),
            "gc" => Ok(()),
            _ => Err("Unknown action".into()),
        }
    }
}

// ======================= TLS 材料 =======================

fn load_certs(path: &str) -> Vec<rustls::pki_types::CertificateDer<'static>> {
    let f =
        std::fs::File::open(path).unwrap_or_else(|e| panic!("Cannot open cert {}: {}", path, e));
    let mut r = std::io::BufReader::new(f);
    rustls_pemfile::certs(&mut r)
        .collect::<Result<Vec<_>, _>>()
        .expect("invalid cert PEM")
}

fn load_key(path: &str) -> rustls::pki_types::PrivateKeyDer<'static> {
    let mut reader = std::io::BufReader::new(
        std::fs::File::open(path).unwrap_or_else(|e| panic!("Cannot open key {}: {}", path, e)),
    );
    rustls_pemfile::private_key(&mut reader)
        .expect("invalid key PEM")
        .expect("no private key found")
}

// ======================= 服务端主流程 =======================

pub fn start_server(args: &Args) {
    info!("Starting TCP TLS server process...");
    let ic_legacy = if args.encrypt {
        Some(Arc::new(InnerCipher::legacy(&args.psk)))
    } else {
        None
    };

    let (pool, gw_v4, gw_v6) = IpPool::new(&args.v4cidr, &args.v6cidr);
    let v4_mask_bits = pool.v4_mask_bits;
    let v6_mask_bits = pool.v6_mask_bits;

    let vswitch = VSwitch::new();
    let core = Arc::new(ServerCore {
        psk: args.psk.clone(),
        psk_hash: hash_psk(&args.psk),
        encrypt: args.encrypt,
        brutal: args.brutal,
        brutal_up: args.brutal_up,
        brutal_down: args.brutal_down,
        ic_legacy,
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
        info!("Configuring Server TAP Interface IP...");
        // 对齐 Go：TAP 配置网关地址（网络基址+1），而非网络号
        Command::new("ip")
            .args(["addr", "add", &core.ipv4_cidr(&gw_v4), "dev", &args.tap])
            .output()
            .ok();
        Command::new("ip")
            .args([
                "-6",
                "addr",
                "add",
                &core.ipv6_cidr(&gw_v6),
                "dev",
                &args.tap,
            ])
            .output()
            .ok();
        Command::new("ip")
            .args(["link", "set", "dev", &args.tap, "up"])
            .output()
            .ok();
        Arc::new(dev)
    };

    if !args.web.is_empty() {
        start_web_server(args.web.clone(), args.web_auth.clone(), core.clone());
    }

    let dev_writer = device.clone();
    let dev_reader = dev_writer.clone();

    let (tap_tx, tap_rx) = bounded::<VPNFrame>(1024);
    let tap_port = Arc::new(AsyncPort::new("TAP_LOCAL".to_string(), false));
    tap_port.register_backend(Arc::new(Backend {
        ch: tap_tx,
        rtt_cache: Arc::new(AtomicU32::new(0)),
        notify: None,
    }));
    vswitch.add_port("TAP_LOCAL".to_string(), tap_port);
    std::thread::spawn(move || {
        while let Ok(f) = tap_rx.recv() {
            if !f.data.is_empty() {
                let _ = dev_writer.send(&f.data);
            }
        }
    });

    let vs_for_tap = core.vswitch.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if let Ok(n) = dev_reader.recv(&mut buf) {
                if n > 0 {
                    vs_for_tap.process_frame("TAP_LOCAL", Arc::new(buf[..n].to_vec()));
                }
            }
        }
    });

    let certs = load_certs(&args.cert);
    let key = load_key(&args.key);
    let mut tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Invalid TLS cert/key");
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls_config);

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

    let mut handles = Vec::new();
    for rx in accept_rxs {
        let core = core.clone();
        let cfg = tls_config.clone();
        handles.push(std::thread::spawn(move || worker_loop(core, cfg, rx)));
    }
    {
        let txs = accept_txs;
        handles.push(std::thread::spawn(move || acceptor_loop(bind_addr, txs)));
    }
    for h in handles {
        let _ = h.join();
    }
}

const TOKEN_WAKE: Token = Token(1);

/// 接入线程：只负责 accept、socket 调优和轮询分发（对齐 Go 每连接一个
/// 协程的接入模型，用 accept 通道 hand-off 避免跨线程注册 mio）。
fn acceptor_loop(bind_addr: String, queues: Vec<Sender<MioTcpStream>>) {
    let mut poll = match Poll::new() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Poll init error: {}", e);
            std::process::exit(1);
        }
    };
    let mut events = Events::with_capacity(256);
    let mut listener = match TcpListener::bind(bind_addr.parse().unwrap()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("TCP Listen error: {}", e);
            std::process::exit(1);
        }
    };
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
                apply_socket_buffers(&socket);
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

    loop {
        if crate::client::EXIT.load(Ordering::Relaxed) {
            break;
        }

        // 只注册 READABLE（修复旧版 WRITABLE 恒注册导致的水平触发空转）。
        // 数据下行由 Waker 唤醒；250ms 超时仅用于保活/RTT/空闲等定时巡检。
        poll.poll(&mut events, Some(Duration::from_millis(250)))
            .unwrap();

        let mut closed_tokens: Vec<Token> = Vec::new();

        // ===== 新连接接入（acceptor 分发到本 worker） =====
        while let Ok(mut socket) = accept_rx.try_recv() {
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
            mio_sessions.insert(
                t,
                MioSession {
                    socket,
                    tls: ServerConnection::new(tls_config.clone()).unwrap(),
                    scanner: FrameScanner::new(),
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
                    write_stalled: None,
                },
            );
        }

        // ===== 定时器扫描：保活 / 空闲 / RTT / 强踢 / 下行拉帧 =====
        for (token, sess) in mio_sessions.iter_mut() {
            let idle_time = sess.last_rx.elapsed().as_secs();
            if idle_time > 30 {
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

            if sess.last_keepalive.elapsed() > Duration::from_secs(4) {
                sess.send_buf.clear();
                append_padded_frame(&mut sess.send_buf, 0, &[], None);
                let _ = sess.tls.writer().write_all(&sess.send_buf);
                sess.last_keepalive = Instant::now();
            }

            if let Some(c_sess) = &sess.client_session {
                if c_sess.stat.force_disconnect.load(Ordering::Relaxed) {
                    closed_tokens.push(*token);
                    continue;
                }
            }

            // 写积压超过 10s 视为对端卡死（对齐 Go SetWriteDeadline(10s)）
            if let Some(stalled_at) = sess.write_stalled {
                if stalled_at.elapsed() > Duration::from_secs(10) {
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
                        let mut progress = false;
                        loop {
                            match sess.tls.read_tls(&mut sess.socket) {
                                Ok(0) => {
                                    close = true;
                                    break;
                                }
                                Ok(_) => {
                                    progress = true;
                                }
                                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                Err(_) => {
                                    close = true;
                                    break;
                                }
                            }
                        }
                        if progress {
                            sess.last_rx = Instant::now();
                        }

                        if progress && !close {
                            if sess.tls.process_new_packets().is_ok() {
                                // 第二层嗅探（对齐 Go peekBuf2 >= 0x20 检查）：
                                // TLS 明文流首字节为探测流量 → 回 403
                                if !sess.sniffed_inner {
                                    match sess.scanner.peek_first_byte() {
                                        Some(b) if b >= 0x20 => {
                                            let is_h2 = sess.tls.alpn_protocol() == Some(b"h2");
                                            serve_fallback_http(&mut sess.tls.writer(), is_h2);
                                            close = true;
                                        }
                                        Some(_) => sess.sniffed_inner = true,
                                        None => {}
                                    }
                                }
                                if !close {
                                    process_plain_frames(sess, &core, &mut close, &mut tarpit);
                                }
                            } else {
                                if !sess.handshake_done {
                                    serve_fallback_http(&mut sess.socket, false);
                                }
                                close = true;
                            }
                        }

                        // 冲刷 TLS 积压：握手期（ServerHello 等）与数据期共用；
                        // 写入遇 WouldBlock 时下次 poll 后继续
                        if !close {
                            drain_tls(sess, &mut close);
                        }
                    }
                }

                if close {
                    if let Some(mut s) = mio_sessions.remove(&token) {
                        let _ = poll.registry().deregister(&mut s.socket);
                        if tarpit {
                            // 剥离 Mio，把 socket 丢给独立线程执行慢速伪装
                            let std_sock = into_std_tcp(s.socket);
                            if let Some(sock) = std_sock {
                                let _ = sock.set_nonblocking(false);
                                std::thread::spawn(move || camouflage_probe(sock));
                            }
                        }
                        on_conn_closed(&core, s.client_session, s.tx_backend);
                    }
                }
            }
        }

        // ===== 关闭定时器发现的会话连接 =====
        closed_tokens.sort();
        closed_tokens.dedup();
        for t in closed_tokens {
            if let Some(mut s) = mio_sessions.remove(&t) {
                let _ = poll.registry().deregister(&mut s.socket);
                on_conn_closed(&core, s.client_session, s.tx_backend);
            }
        }
    }
}

/// mio TcpStream → 原生 TcpStream（消耗所有权；用于焦油坑线程）
fn into_std_tcp(s: MioTcpStream) -> Option<std::net::TcpStream> {
    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        Some(unsafe { std::net::TcpStream::from_raw_fd(s.into_raw_fd()) })
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
        Some(unsafe { std::net::TcpStream::from_raw_socket(s.into_raw_socket()) })
    }
}

fn process_plain_frames(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    close: &mut bool,
    tarpit: &mut bool,
) {
    loop {
        match sess.scanner.read_frame(&mut sess.tls.reader()) {
            Ok(Some((raw, seq))) => {
                let mut data = raw;
                if let Some(s) = &sess.client_session {
                    s.stat
                        .rx_bytes
                        .fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                    s.stat.rx_packets.fetch_add(1, Ordering::Relaxed);
                }

                if seq == 0 && !sess.handshake_done {
                    match handle_handshake(sess, core, &data, tarpit) {
                        HandshakeOutcome::Ok => sess.handshake_done = true,
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
                    if data.is_empty() {
                        continue;
                    }
                    // 内层解密（GCM 校验失败丢弃，对齐 Go openInPlace）
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
                                    continue;
                                }
                            }
                        }
                    }
                    let c_sess = match &sess.client_session {
                        Some(c) => c.clone(),
                        None => continue,
                    };
                    let data = Arc::new(data);
                    // XOR 校验帧 → 会话级 FEC 解码器
                    if seq == 0 {
                        if let Some(dec) = &c_sess.fec_dec {
                            if fec::is_parity_frame(&data) {
                                let mut sink = make_sink(&c_sess, core);
                                dec.on_parity(&data, &mut sink);
                                continue;
                            }
                        }
                    }
                    if let Some(dec) = &c_sess.fec_dec {
                        let mut sink = make_sink(&c_sess, core);
                        dec.on_data(seq, &data, &mut sink);
                    }
                    // 去重 + 重排，理顺后交交换机
                    if !c_sess.dedup.lock().is_duplicate(seq) {
                        let ready = c_sess.reorder_buf.lock().insert(seq, data);
                        for ordered in ready {
                            core.vswitch.process_frame(&c_sess.stat.client_id, ordered);
                        }
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
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
}

fn make_sink(c_sess: &Arc<ClientSession>, core: &Arc<ServerCore>) -> impl FnMut(u32, Arc<Vec<u8>>) {
    let reorder = c_sess.reorder_buf.clone();
    let cid = c_sess.stat.client_id.clone();
    let vs = core.vswitch.clone();
    move |seq: u32, f: Arc<Vec<u8>>| {
        let ready = reorder.lock().insert(seq, f);
        for ordered in ready {
            vs.process_frame(&cid, ordered);
        }
    }
}

/// 从端口通道拉帧成批发送（对齐 Go 下行写协程）
fn flush_outbound(sess: &mut MioSession, close: &mut bool) {
    // 写积压未消化时不继续拉帧（防内存膨胀，等 10s 卡死保护或恢复）
    if sess.write_stalled.is_some() {
        // 仍尝试继续冲刷 rustls 内部队列
        drain_tls(sess, close);
        return;
    }
    let ic_tx = sess.client_session.as_ref().and_then(|s| s.ic_tx.clone());
    let mut pulled = 0usize;
    sess.send_buf.clear();
    while let Ok(f) = sess.rx.try_recv() {
        let ic_ref = if f.seq != 0 { ic_tx.as_deref() } else { None };
        append_padded_frame(&mut sess.send_buf, f.seq, &f.data, ic_ref);
        if let Some(s) = &sess.client_session {
            s.stat.tx_packets.fetch_add(1, Ordering::Relaxed);
        }
        pulled += 1;
        if sess.send_buf.len() >= 64 * 1024 || pulled >= 1024 {
            break;
        }
    }
    if !sess.send_buf.is_empty() {
        if let Some(s) = &sess.client_session {
            s.stat
                .tx_bytes
                .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);
        }
        let _ = sess.tls.writer().write_all(&sess.send_buf);
        sess.send_buf.clear();
    }
    drain_tls(sess, close);
}

/// 冲刷 rustls 内部积压到 socket；遇 WouldBlock 记录卡死起点
fn drain_tls(sess: &mut MioSession, close: &mut bool) {
    while sess.tls.wants_write() {
        match sess.tls.write_tls(&mut sess.socket) {
            Ok(0) => {
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
            Err(_) => {
                *close = true;
                break;
            }
        }
    }
    if !sess.tls.wants_write() {
        sess.write_stalled = None;
    }
}

enum HandshakeOutcome {
    Ok,
    Close,
    TarpitClose,
}

fn handle_handshake(
    sess: &mut MioSession,
    core: &Arc<ServerCore>,
    data: &[u8],
    tarpit_flag: &mut bool,
) -> HandshakeOutcome {
    let Ok(req) = serde_json::from_slice::<HandshakeReq>(data) else {
        warn!("握手数据解析失败. 开启伪装焦油坑.");
        return HandshakeOutcome::TarpitClose;
    };
    debug!("<= 收到客户端握手请求 (HandshakeReq): {:?}", req);

    if req.psk != core.psk_hash {
        warn!("PSK 验证失败 (Hash不匹配).");
        return HandshakeOutcome::TarpitClose;
    }
    // 加密配置不匹配 → 焦油坑（对齐 Go）
    if req.encrypt != core.encrypt {
        warn!(
            "加密配置不匹配 (Client: {}, Server: {})",
            req.encrypt, core.encrypt
        );
        return HandshakeOutcome::TarpitClose;
    }
    let client_id = req.client_id.clone();
    if client_id.is_empty() {
        warn!("拒绝连接: 缺少 ClientID");
        return HandshakeOutcome::Close;
    }
    if core.banned.is_banned(&client_id) {
        warn!("[{}] 已封禁，拒绝接入", client_id);
        return HandshakeOutcome::TarpitClose;
    }
    let mac = req.mac.clone();

    let c_sess: Arc<ClientSession> = {
        let mut sessions = core.sessions.write();
        if let Some(existing) = sessions.get(&client_id) {
            if req.mac != existing.mac {
                warn!("[{}] 拒绝连接: MAC 不匹配", client_id);
                *tarpit_flag = true;
                return HandshakeOutcome::TarpitClose;
            }
            info!("[{}] ⚡ 会话在销毁倒计时内成功复活！(无缝接续)", client_id);
            existing.clone()
        } else {
            // MAC→IP 绑定优先（对齐 Go macToIP）
            let (mut req_v4, mut req_v6) = (req.ipv4.clone(), req.ipv6.clone());
            if !mac.is_empty() {
                let pool = core.pool.lock();
                if let Some(bind) = pool.mac_to_ip.get(&mac) {
                    req_v4 = bind.0.clone();
                    req_v6 = bind.1.clone();
                }
            }

            // FEC 协商：req.fec && fec_group >= 2 → XOR 模式
            let fec_enc_k: i64 = if req.fec && req.fec_group >= fec::FEC_MIN_GROUP as i64 {
                clamp_fec_group(req.fec_group.max(0) as usize) as i64
            } else {
                0
            };
            // 内层加密协商：双方均声明 GCM 时启用，会话盐随机
            let salt_a = new_random_salt();
            let salt_b = new_random_salt();
            let (enc_algo, ic_tx, ic_rx) = if core.encrypt {
                if req.enc_algo >= ENC_ALGO_GCM {
                    (
                        ENC_ALGO_GCM,
                        Some(Arc::new(
                            InnerCipher::gcm(&core.psk, &salt_b).expect("GCM init"),
                        )),
                        Some(Arc::new(
                            InnerCipher::gcm(&core.psk, &salt_a).expect("GCM init"),
                        )),
                    )
                } else {
                    (
                        ENC_ALGO_LEGACY_CTR,
                        core.ic_legacy.clone(),
                        core.ic_legacy.clone(),
                    )
                }
            } else {
                (ENC_ALGO_LEGACY_CTR, None, None)
            };

            let fec_mode = if fec_enc_k > 0 {
                format!("xor K={}", fec_enc_k)
            } else if req.fec {
                "dup".to_string()
            } else {
                "off".to_string()
            };

            let (v4ip, v6ip) = {
                let mut pool = core.pool.lock();
                (pool.alloc_v4(&req_v4), pool.alloc_v6(&req_v6))
            };

            let stat = Arc::new(ClientStat::new(
                client_id.clone(),
                v4ip.clone(),
                v6ip.clone(),
                mac.clone(),
            ));
            *stat.fec_mode.lock() = fec_mode.clone();
            stat.enc_algo.store(
                if enc_algo == ENC_ALGO_GCM {
                    2
                } else if core.encrypt {
                    1
                } else {
                    0
                },
                Ordering::Relaxed,
            );

            let port = Arc::new(AsyncPort::new(client_id.clone(), req.fec && fec_enc_k == 0));
            if fec_enc_k > 0 {
                port.attach_encoder(fec_enc_k as usize, ic_tx.clone());
            }
            let fec_dec = if fec_enc_k > 0 {
                Some(Arc::new(FecDecoder::new(fec_enc_k as usize, ic_rx.clone())))
            } else {
                None
            };

            core.vswitch.add_port(client_id.clone(), port.clone());
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
                "[{}] 新逻辑 Client 上线 (FEC={} EncAlgo={}), Assigned IPs: {}/{}, {}/{}",
                client_id, fec_mode, enc_algo, v4ip, core.v4_mask_bits, v6ip, core.v6_mask_bits
            );

            let sess = Arc::new(ClientSession {
                session_id: gen_session_id(),
                stat,
                port,
                reorder_buf: Arc::new(Mutex::new(ReorderBuffer::new())),
                dedup: Arc::new(Mutex::new(DeDuplicator::new())),
                fec_dec,
                fec_enc_k,
                mac,
                ipv4: v4ip,
                ipv6: v6ip,
                enc_algo,
                salt_a,
                salt_b,
                ic_tx,
                ic_rx,
                created_at: Instant::now(),
            });
            sessions.insert(client_id.clone(), sess.clone());
            sess
        }
    };

    sess.ic_rx = c_sess.ic_rx.clone();
    c_sess.stat.active_conns.fetch_add(1, Ordering::Relaxed);
    if let Some(b) = &sess.tx_backend {
        b.rtt_cache.store(50000, Ordering::Relaxed);
    }
    c_sess
        .port
        .register_backend(sess.tx_backend.as_ref().unwrap().clone());
    sess.client_session = Some(c_sess.clone());

    // Brutal 速率协商（对齐 Go）
    let mut server_tx_rate = core.brutal_up;
    let mut client_tx_rate = core.brutal_down;
    if req.brutal_rx > 0 && (core.brutal_up == 0 || req.brutal_rx < core.brutal_up) {
        server_tx_rate = req.brutal_rx;
    }
    if req.brutal_tx > 0 && (core.brutal_down == 0 || req.brutal_tx < core.brutal_down) {
        client_tx_rate = req.brutal_tx;
    }
    if core.brutal && server_tx_rate > 0 {
        apply_tcp_brutal(&sess.socket, server_tx_rate);
    }

    let (enc_salt, enc_salt2) = if c_sess.enc_algo == ENC_ALGO_GCM {
        (hex::encode(c_sess.salt_a), hex::encode(c_sess.salt_b))
    } else {
        (String::new(), String::new())
    };
    let resp = HandshakeResp {
        success: true,
        message: "OK".into(),
        session_id: c_sess.session_id.clone(),
        client_id,
        ipv4: core.ipv4_cidr(&c_sess.ipv4),
        ipv6: core.ipv6_cidr(&c_sess.ipv6),
        gw_v4: core.gw_v4.clone(),
        gw_v6: core.gw_v6.clone(),
        padding: generate_padding(100, 500),
        brutal_tx: server_tx_rate,
        brutal_rx: client_tx_rate,
        fec: req.fec,
        fec_group: c_sess.fec_enc_k,
        encrypt: core.encrypt,
        enc_algo: c_sess.enc_algo,
        enc_salt,
        enc_salt2,
    };
    let resp_json = serde_json::to_vec(&resp).unwrap();
    let mut buf = Vec::with_capacity(1024);
    append_padded_frame(&mut buf, 0, &resp_json, None);
    let _ = sess.tls.writer().write_all(&buf);
    let mut close = false;
    drain_tls(sess, &mut close);
    if close {
        return HandshakeOutcome::Close;
    }
    HandshakeOutcome::Ok
}

/// 物理连接关闭：注销端口后端；最后一个连接断开时进入 120s 保留期
fn on_conn_closed(
    core: &Arc<ServerCore>,
    c_sess: Option<Arc<ClientSession>>,
    backend: Option<Arc<Backend>>,
) {
    if let (Some(c_sess), Some(backend)) = (c_sess, backend) {
        c_sess.port.unregister_backend(&backend.ch);
        if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
            let cid = c_sess.stat.client_id.clone();
            let current_version = c_sess
                .stat
                .disconnect_version
                .fetch_add(1, Ordering::Relaxed)
                + 1;
            info!(
                "[{}] ⚠️ 客户端所有物理连接已断开，会话进入 120 秒保留期 (版本: {})...",
                cid, current_version
            );
            let core = core.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(120));
                // 双重校验：连接数归零且版本一致才销毁（对齐 Go destroyTimer）
                if c_sess.stat.active_conns.load(Ordering::Relaxed) == 0
                    && c_sess.stat.disconnect_version.load(Ordering::Relaxed) == current_version
                {
                    core.destroy_session(
                        &c_sess.stat.client_id,
                        &c_sess.mac,
                        &c_sess.ipv4,
                        &c_sess.ipv6,
                    );
                } else {
                    info!(
                        "[{}] ⚡ 发现较新的重连事件，取消本次销毁动作",
                        c_sess.stat.client_id
                    );
                }
            });
        }
    }
}
