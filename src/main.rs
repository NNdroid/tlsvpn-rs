use aes::Aes256;
use byteorder::{BigEndian, ByteOrder};
use clap::Parser;
use crossbeam_channel::{bounded, Receiver, Sender};
use crossbeam_queue::ArrayQueue;
use ctr::cipher::{KeyIvInit, StreamCipher};
use lazy_static::lazy_static;
use mio::net::{TcpListener, TcpStream as MioTcpStream};
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tiny_http::{Header, Method, Response, Server as HttpServer};
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

// ========================================================
// 0. IP 转换工具函数
// ========================================================
fn ip4_to_u32(ip: &str) -> u32 {
    u32::from_be_bytes(
        Ipv4Addr::from_str(ip)
            .unwrap_or(Ipv4Addr::new(10, 0, 0, 1))
            .octets(),
    )
}
fn u32_to_ip4(val: u32) -> String {
    Ipv4Addr::from(val).to_string()
}
fn ip6_to_u128(ip: &str) -> u128 {
    u128::from_be_bytes(
        Ipv6Addr::from_str(ip)
            .unwrap_or(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
            .octets(),
    )
}
fn u128_to_ip6(val: u128) -> String {
    Ipv6Addr::from(val).to_string()
}

// ========================================================
// 0.1 超轻量伪随机数引擎 (零外部依赖)
// ========================================================
pub struct FastRand(u64);
impl FastRand {
    pub fn new() -> Self {
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        let mut state = d.as_nanos() as u64;
        if state == 0 {
            state = 1;
        }
        Self(state)
    }
    pub fn next_u32(&mut self) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 as u32
    }
    pub fn gen_range(&mut self, min: usize, max: usize) -> usize {
        if max <= min {
            return min;
        }
        min + (self.next_u32() as usize % (max - min))
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(4) {
            let r = self.next_u32().to_ne_bytes();
            let len = chunk.len();
            chunk.copy_from_slice(&r[..len]);
        }
    }
}
thread_local! {
    static RNG: std::cell::RefCell<FastRand> = std::cell::RefCell::new(FastRand::new());
}

// ========================================================
// 1. 命令行参数定义
// ========================================================
#[derive(Parser, Debug)]
#[command(name = "tlsvpn", about = "Rust Implementation of TLSVPN", long_about = None)]
struct Args {
    #[arg(long, default_value = "", help = "server or client")]
    mode: String,
    #[arg(long, default_value = "quic_secret", help = "Pre-shared key")]
    psk: String,
    #[arg(long, default_value = "tap0", help = "Name of the TAP device")]
    tap: String,
    #[arg(long, default_value = "", help = "Specify MAC address for TAP device")]
    mac: String,
    #[arg(long, default_value = "0.0.0.0:4000", help = "Listen/Target address")]
    addr: String,
    #[arg(
        long,
        default_value = "info",
        help = "Log level (trace, debug, info, warn, error)"
    )]
    loglevel: String,
    #[arg(
        long,
        default_value = "10.0.0.0/24",
        help = "IPv4 CIDR block (Server only)"
    )]
    v4cidr: String,
    #[arg(
        long,
        default_value = "fd00::/64",
        help = "IPv6 CIDR block (Server only)"
    )]
    v6cidr: String,
    #[arg(long, default_value = "", help = "TLS Certificate file (Server only)")]
    cert: String,
    #[arg(long, default_value = "", help = "TLS Key file (Server only)")]
    key: String,
    #[arg(long, default_value = "", help = "Requested IPv4 (Client only)")]
    req_v4: String,
    #[arg(long, default_value = "", help = "Requested IPv6 (Client only)")]
    req_v6: String,
    #[arg(
        long,
        default_value = "www.cloudflare.com",
        help = "SNI for TLS (Client only)"
    )]
    sni: String,
    #[arg(long, default_value_t = false, help = "Skip TLS verify (Client only)")]
    insecure: bool,
    #[arg(
        long,
        default_value = "",
        help = "Verify server cert SHA256 (Client only)"
    )]
    cert_sha256: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "Policy routing fwmark (Client only)"
    )]
    fwmark: i32,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable TCP Brutal congestion control"
    )]
    brutal: bool,
    #[arg(long, default_value_t = 100, help = "Brutal upload rate limit in Mbps")]
    brutal_up: u64,
    #[arg(
        long,
        default_value_t = 500,
        help = "Brutal download rate limit in Mbps"
    )]
    brutal_down: u64,
    #[arg(
        long,
        default_value_t = 1,
        help = "Number of concurrent TCP connections"
    )]
    conns: i32,
    #[arg(long, default_value_t = false, help = "Enable Packet Duplication FEC")]
    fec: bool,
    #[arg(
        long,
        default_value = "",
        help = "Start Web Dashboard on specified address"
    )]
    web: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable inner payload AES-CTR XOR encryption"
    )]
    encrypt: bool,
}

// ========================================================
// 2. 日志、内存池与加密工具
// ========================================================
fn init_logger(level_str: &str) {
    let level = match level_str.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .finish(),
    )
    .ok();
}

const MAX_FRAME_SIZE: usize = 65536;

lazy_static! {
    static ref FRAME_POOL: ArrayQueue<Vec<u8>> = ArrayQueue::new(4096);
    static ref PADDING_CACHE: Vec<u8> = {
        let mut cache = vec![0u8; 1024 * 1024];
        let mut rng = FastRand::new();
        rng.fill(&mut cache);
        cache
    };
}

pub fn get_frame() -> Vec<u8> {
    FRAME_POOL
        .pop()
        .unwrap_or_else(|| Vec::with_capacity(MAX_FRAME_SIZE))
}

pub fn put_frame(mut frame: Vec<u8>) {
    if frame.capacity() >= 1500 && frame.capacity() <= MAX_FRAME_SIZE {
        frame.clear();
        let _ = FRAME_POOL.push(frame);
    }
}

pub fn hash_psk(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn get_cipher_context(psk: &str) -> (Vec<u8>, Vec<u8>) {
    let mut k_hasher = Sha256::new();
    k_hasher.update(format!("{}_enc_key", psk).as_bytes());
    let key = k_hasher.finalize().to_vec();

    let mut i_hasher = Sha256::new();
    i_hasher.update(format!("{}_enc_iv", psk).as_bytes());
    let iv = i_hasher.finalize()[..16].to_vec();

    (key, iv)
}

pub fn xor_crypt_in_place(data: &mut [u8], seq: u32, key: &[u8], base_iv: &[u8]) {
    if data.is_empty() || key.is_empty() {
        return;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(base_iv);
    BigEndian::write_u32(&mut iv[12..16], seq);
    let mut cipher = Aes256Ctr::new_from_slices(key, &iv).unwrap();
    cipher.apply_keystream(data);
}

fn get_padding_length(data_len: usize) -> usize {
    RNG.with(|rng| {
        let mut r = rng.borrow_mut();
        if data_len == 0 {
            return 100 + r.gen_range(0, 201);
        }
        if data_len < 200 {
            return 300 + r.gen_range(0, 200);
        }
        if data_len < 800 {
            return 100 + r.gen_range(0, 200);
        }
        r.gen_range(0, 100)
    })
}

fn append_tls_frame(buf: &mut Vec<u8>, seq: u32, data: &[u8], key: &[u8], iv: &[u8]) {
    let pad_len = get_padding_length(data.len());
    let start_idx = buf.len();
    buf.extend_from_slice(&[0; 10]);

    BigEndian::write_u32(&mut buf[start_idx..start_idx + 4], data.len() as u32);
    BigEndian::write_u16(&mut buf[start_idx + 4..start_idx + 6], pad_len as u16);
    BigEndian::write_u32(&mut buf[start_idx + 6..start_idx + 10], seq);

    if !data.is_empty() {
        let data_start = buf.len();
        buf.extend_from_slice(data);
        if seq != 0 && !key.is_empty() {
            xor_crypt_in_place(&mut buf[data_start..], seq, key, iv);
        }
    }

    if pad_len > 0 {
        let offset = RNG.with(|rng| rng.borrow_mut().gen_range(0, PADDING_CACHE.len() - pad_len));
        buf.extend_from_slice(&PADDING_CACHE[offset..offset + pad_len]);
    }
}

const H2_403_RESPONSE: &[u8] = &[
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x05, 0x01, 0x05, 0x00, 0x00, 0x00, 0x01, 0x08, 0x03, b'4', b'0', b'3',
];

fn serve_fallback_http<W: Write>(mut writer: W, is_h2: bool) {
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
}

// 模拟慢速探测阻力 (焦油坑)，防止主动探测扫描
fn camouflage_probe<W: Write>(mut writer: W) {
    let mut junk = vec![0u8; 500];
    loop {
        std::thread::sleep(Duration::from_millis(RNG.with(|rng| rng.borrow_mut().gen_range(50, 200)) as u64));
        let len = RNG.with(|rng| rng.borrow_mut().gen_range(100, 400));
        junk[0] = 0x00;
        junk[1] = len as u8;
        if writer.write_all(&junk[..len + 2]).is_err() {
            break;
        }
        let _ = writer.flush();
    }
}

// ========================================================
// 3. Linux TCP Brutal 与 Netlink 策略路由
// ========================================================
#[cfg(target_os = "linux")]
fn apply_tcp_brutal<S: AsRawFd>(stream: &S, rate_mbps: u64) {
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
fn apply_tcp_brutal<S: AsRawFd>(_stream: &S, rate_mbps: u64) {
    warn!("TCP Brutal requested ({} Mbps) but only supported on Linux.", rate_mbps);
}

#[cfg(target_os = "linux")]
fn get_tcp_rtt<S: AsRawFd>(stream: &S) -> u32 {
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
fn get_tcp_rtt<S: AsRawFd>(_stream: &S) -> u32 {
    50000
}

fn setup_policy_routing(tap_name: &str, fwmark: i32, gw_v4: &str, gw_v6: &str) {
    if fwmark <= 0 {
        return;
    }
    info!("🔀 Configuring Policy Routing for fwmark {} via {}", fwmark, tap_name);
    Command::new("ip").args(["rule", "del", "fwmark", &fwmark.to_string(), "table", &fwmark.to_string()]).output().ok();
    Command::new("ip").args(["rule", "add", "fwmark", &fwmark.to_string(), "table", &fwmark.to_string()]).output().ok();
    Command::new("ip").args(["route", "replace", "default", "via", gw_v4, "dev", tap_name, "table", &fwmark.to_string()]).output().ok();
    Command::new("ip").args(["-6", "rule", "del", "fwmark", &fwmark.to_string(), "table", &fwmark.to_string()]).output().ok();
    Command::new("ip").args(["-6", "rule", "add", "fwmark", &fwmark.to_string(), "table", &fwmark.to_string()]).output().ok();
    Command::new("ip").args(["-6", "route", "replace", "default", "via", gw_v6, "dev", tap_name, "table", &fwmark.to_string()]).output().ok();
}

// ========================================================
// 4. 协议模型
// ========================================================
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct HandshakeReq {
    pub client_id: String,
    pub psk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_tx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_rx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct HandshakeResp {
    pub success: bool,
    pub message: String,
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw_v6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_tx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_rx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<bool>,
}

// ========================================================
// 5. 网络引擎: 去重器、重组器、扫描器与 VSwitch
// ========================================================

// 高速环形去重器 (用于 FEC 过滤)
pub struct DeDuplicator {
    set: HashSet<u32>,
    ring: [u32; 4096],
    idx: usize,
}

impl DeDuplicator {
    pub fn new() -> Self {
        Self {
            set: HashSet::with_capacity(4096),
            ring: [0; 4096],
            idx: 0,
        }
    }
    pub fn is_duplicate(&mut self, seq: u32) -> bool {
        if seq == 0 { return false; }
        if self.set.contains(&seq) { return true; }
        
        let oldest = self.ring[self.idx];
        if oldest != 0 { self.set.remove(&oldest); }
        
        self.ring[self.idx] = seq;
        self.set.insert(seq);
        self.idx = (self.idx + 1) % 4096;
        false
    }
}

pub struct ReorderBuffer {
    next_seq: u32,
    buffer: BTreeMap<u32, Vec<u8>>,
    last_out_of_order: Option<Instant>,
}

impl ReorderBuffer {
    pub fn new() -> Self {
        Self {
            next_seq: 1,
            buffer: BTreeMap::new(),
            last_out_of_order: None,
        }
    }

    pub fn insert(&mut self, seq: u32, data: Vec<u8>) -> Vec<Vec<u8>> {
        if seq == 0 { return vec![data]; }
        let mut ready = Vec::new();
        let diff = seq.wrapping_sub(self.next_seq);

        if diff > 0x80000000 { return ready; }

        if diff == 0 {
            ready.push(data);
            self.next_seq = self.next_seq.wrapping_add(1);
            if self.next_seq == 0 { self.next_seq = 1; }

            while let Some(next_data) = self.buffer.remove(&self.next_seq) {
                ready.push(next_data);
                self.next_seq = self.next_seq.wrapping_add(1);
                if self.next_seq == 0 { self.next_seq = 1; }
            }
            if self.buffer.is_empty() { self.last_out_of_order = None; }
        } else {
            self.buffer.insert(seq, data);
            if self.last_out_of_order.is_none() {
                self.last_out_of_order = Some(Instant::now());
            }

            // 对齐 Go 的 20ms 卡死熔断机制
            let timeout = self.last_out_of_order
                .map(|t| t.elapsed() > Duration::from_millis(20))
                .unwrap_or(false);

            if self.buffer.len() > 1024 || timeout {
                if let Some((&lowest_seq, _)) = self.buffer.iter().next() {
                    self.next_seq = lowest_seq;
                    while let Some(next_data) = self.buffer.remove(&self.next_seq) {
                        ready.push(next_data);
                        self.next_seq = self.next_seq.wrapping_add(1);
                        if self.next_seq == 0 { self.next_seq = 1; }
                    }
                }
                if self.buffer.is_empty() {
                    self.last_out_of_order = None;
                } else {
                    self.last_out_of_order = Some(Instant::now());
                }
            }
        }
        ready
    }
}

pub struct FrameScanner {
    buffer: Vec<u8>,
}

impl FrameScanner {
    pub fn new() -> Self {
        Self { buffer: Vec::with_capacity(65536 * 4) }
    }
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<(Vec<u8>, u32)>> {
        let mut temp = [0u8; 16384];
        loop {
            match reader.read(&mut temp) {
                Ok(0) => break,
                Ok(n) => self.buffer.extend_from_slice(&temp[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        if self.buffer.len() >= 10 {
            let data_len = BigEndian::read_u32(&self.buffer[0..4]) as usize;
            let pad_len = BigEndian::read_u16(&self.buffer[4..6]) as usize;
            let seq = BigEndian::read_u32(&self.buffer[6..10]);
            let total_len = data_len + pad_len;

            if total_len > 65536 * 2 {
                self.buffer.clear();
                return Err(io::Error::new(ErrorKind::InvalidData, "Invalid frame header"));
            }

            if self.buffer.len() >= 10 + total_len {
                let mut data = get_frame();
                data.clear();
                data.extend_from_slice(&self.buffer[10..10 + data_len]);
                self.buffer.drain(0..10 + total_len);
                return Ok(Some((data, seq)));
            }
        }
        Ok(None)
    }
}

#[derive(Clone)]
pub struct VPNFrame {
    pub seq: u32,
    pub data: Vec<u8>,
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
        self.backends.write().retain(|b| !b.ch.same_channel(ch_to_remove));
    }

    pub fn write_frame(&self, frame: Vec<u8>) {
        let backends = self.backends.read();
        if backends.is_empty() { return; }

        if self.fec_mode {
            let mut valid_backends = Vec::new();
            for backend in backends.iter() {
                if backend.ch.len() < backend.ch.capacity().unwrap_or(4096) - 100 {
                    valid_backends.push(backend);
                }
            }
            if !valid_backends.is_empty() {
                let mut seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                if seq == 0 { seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1); }
                let vpn_frame = VPNFrame { seq, data: frame };
                let batch = vec![vpn_frame];
                for backend in valid_backends {
                    let _ = backend.ch.try_send(batch.clone());
                }
            }
        } else {
            let mut best_backend = None;
            let mut min_score = u32::MAX;

            for b in backends.iter() {
                let q_len = b.ch.len();
                if q_len >= b.ch.capacity().unwrap_or(4096) - 100 { continue; }

                let rtt = b.rtt_cache.load(Ordering::Relaxed);
                let penalty = if q_len > 10 { (q_len as u32 - 10) * 1000 } else { 0 };
                let score = rtt + penalty;

                if score < min_score {
                    min_score = score;
                    best_backend = Some(b);
                }
            }

            if let Some(b) = best_backend.or_else(|| backends.first()) {
                if b.ch.len() < b.ch.capacity().unwrap_or(4096) - 100 {
                    let mut seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
                    if seq == 0 { seq = self.tx_seq.fetch_add(1, Ordering::Relaxed).wrapping_add(1); }
                    let vpn_frame = VPNFrame { seq, data: frame };
                    let _ = b.ch.try_send(vec![vpn_frame]);
                }
            }
        }
    }
}

struct MacEntry {
    port_id: String,
    updated_at: Instant,
}

pub struct VSwitch {
    ports: RwLock<HashMap<String, Arc<AsyncPort>>>,
    mac_table: RwLock<HashMap<[u8; 6], MacEntry>>,
}

impl VSwitch {
    fn new() -> Arc<Self> {
        let vs = Arc::new(Self {
            ports: Default::default(),
            mac_table: Default::default(),
        });

        // 启动后台 MAC 垃圾回收协程对齐 Go 版本
        let vs_clone = vs.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_secs(300)); // 每 5 分钟执行一次
                let mut table = vs_clone.mac_table.write();
                table.retain(|_, entry| entry.updated_at.elapsed() < Duration::from_secs(1800)); // 剔除 30 分钟前的缓存
            }
        });

        vs
    }

    fn add_port(&self, id: String, port: Arc<AsyncPort>) {
        self.ports.write().insert(id, port);
    }

    fn remove_port(&self, id: &str) {
        self.ports.write().remove(id);
        self.mac_table.write().retain(|_, entry| entry.port_id != id);
    }

    fn process_frame(&self, src_port_id: &str, frame: Vec<u8>) {
        if frame.len() < 14 { return; }
        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&frame[0..6]);
        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&frame[6..12]);

        let mut need_update = true;
        {
            let table = self.mac_table.read();
            if let Some(entry) = table.get(&src_mac) {
                if entry.port_id == src_port_id && entry.updated_at.elapsed() < Duration::from_secs(5) {
                    need_update = false;
                }
            }
        }
        if need_update {
            self.mac_table.write().insert(src_mac, MacEntry { port_id: src_port_id.to_string(), updated_at: Instant::now() });
        }

        let mut target_port_id = None;
        if (dst_mac[0] & 1) == 0 {
            if let Some(entry) = self.mac_table.read().get(&dst_mac) {
                target_port_id = Some(entry.port_id.clone());
            }
        }

        if let Some(target) = target_port_id {
            if target != src_port_id {
                if let Some(port) = self.ports.read().get(&target) {
                    port.write_frame(frame);
                }
            }
        } else {
            let ports = self.ports.read();
            for (id, port) in ports.iter() {
                if id != src_port_id {
                    port.write_frame(frame.clone());
                }
            }
        }
    }
}

// ========================================================
// 6. 服务端状态结构与 Web UI 服务器
// ========================================================
pub struct ClientStat {
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub mac: String,
    pub active_conns: AtomicU32,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub force_disconnect: AtomicBool,
}

impl ClientStat {
    pub fn new(id: String, ipv4: String, ipv6: String, mac: String) -> Self {
        Self {
            client_id: id,
            ipv4,
            ipv6,
            mac,
            active_conns: AtomicU32::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            force_disconnect: AtomicBool::new(false),
        }
    }
}

type StatRegistry = Arc<RwLock<HashMap<String, Arc<ClientStat>>>>;

pub struct ClientSession {
    stat: Arc<ClientStat>,
    port: Arc<AsyncPort>,
    reorder_buf: Arc<Mutex<ReorderBuffer>>,
    dedup: Arc<Mutex<DeDuplicator>>,
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>VPN Dashboard (Rust Edition)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .card { background: #1e1e1e; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); margin-bottom: 20px; }
        h1, h2 { margin-top: 0; color: #bb86fc; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #2c2c2c; }
        .btn { padding: 6px 12px; background-color: #cf6679; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #ff7597; }
        .speed { color: #03dac6; font-weight: bold; } 
    </style>
</head>
<body>
    <h1>🚀 VPN Dashboard (<span id="mode">加载中...</span>)</h1>
    <div class="card">
        <h2>系统状态</h2>
        <p>活跃连接数/设备: <strong id="active-clients">0</strong></p>
        <p>总发送: <strong id="total-tx">0 B</strong> | 总接收: <strong id="total-rx">0 B</strong></p>
        <p>总上传速率: <strong id="total-tx-speed" class="speed">0 B/s</strong> | 总下载速率: <strong id="total-rx-speed" class="speed">0 B/s</strong></p>
    </div>
    <div class="card" id="clients-container">
        <h2>客户端列表 / 本机详情</h2>
        <table>
            <thead>
                <tr>
                    <th>ID / Name</th>
                    <th>IPv4</th>
                    <th>MAC</th>
                    <th>TCP连接数</th>
                    <th>TX (发)</th>
                    <th>RX (收)</th>
                    <th>↑ 上传速率</th>
                    <th>↓ 下载速率</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="clients-body">
            </tbody>
        </table>
    </div>

    <script>
        function formatBytes(bytes, isSpeed = false) {
            if (bytes === 0 || isNaN(bytes)) return '0 ' + (isSpeed ? 'B/s' : 'B');
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            const unit = sizes[i] + (isSpeed ? '/s' : '');
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + unit;
        }

        let previousClients = {};
        let lastFetchTime = 0;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                const now = performance.now();
                let timeDelta = lastFetchTime ? (now - lastFetchTime) / 1000 : 2; 
                lastFetchTime = now;

                document.getElementById('mode').innerText = data.mode.toUpperCase();
                document.getElementById('active-clients').innerText = data.active_clients;
                
                let tbody = '';
                let totalTx = 0, totalRx = 0;
                let totalTxSpeed = 0, totalRxSpeed = 0;
                const currentClientsState = {};

                const processClient = (id, c) => {
                    totalTx += c.tx_bytes;
                    totalRx += c.rx_bytes;
                    let txSpeed = 0;
                    let rxSpeed = 0;
                    
                    if (previousClients[id]) {
                        txSpeed = Math.max(0, (c.tx_bytes - previousClients[id].tx_bytes) / timeDelta);
                        rxSpeed = Math.max(0, (c.rx_bytes - previousClients[id].rx_bytes) / timeDelta);
                    }
                    
                    currentClientsState[id] = { tx_bytes: c.tx_bytes, rx_bytes: c.rx_bytes };
                    totalTxSpeed += txSpeed;
                    totalRxSpeed += rxSpeed;

                    return '<tr>' +
                        '<td>' + (id.length > 8 ? id.substring(0,8) + '...' : id) + '</td>' +
                        '<td>' + c.ipv4 + '</td>' +
                        '<td>' + c.mac + '</td>' +
                        '<td>' + c.active_conns + '</td>' +
                        '<td>' + formatBytes(c.tx_bytes) + '</td>' +
                        '<td>' + formatBytes(c.rx_bytes) + '</td>' +
                        '<td class="speed">' + formatBytes(txSpeed, true) + '</td>' +
                        '<td class="speed">' + formatBytes(rxSpeed, true) + '</td>' +
                        '<td>' + (data.mode === 'server' ? '<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>' : '-') + '</td>' +
                    '</tr>';
                };

                for (const [id, c] of Object.entries(data.clients)) {
                    tbody += processClient(id, c);
                }

                previousClients = currentClientsState;
                document.getElementById('clients-body').innerHTML = tbody;
                document.getElementById('total-tx').innerText = formatBytes(totalTx);
                document.getElementById('total-rx').innerText = formatBytes(totalRx);
                document.getElementById('total-tx-speed').innerText = formatBytes(totalTxSpeed, true);
                document.getElementById('total-rx-speed').innerText = formatBytes(totalRxSpeed, true);

            } catch (err) { console.error("API Error", err); }
        }

        async function kickClient(id) {
            if(!confirm("确定要强制断开该客户端吗？")) return;
            await fetch('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'kick', client_id: id })
            });
            fetchStats();
        }

        setInterval(fetchStats, 2000);
        fetchStats();
    </script>
</body>
</html>"#;

fn start_web_server(addr: String, mode: String, registry: StatRegistry) {
    std::thread::spawn(move || {
        let server = HttpServer::http(&addr).expect("Web Server bind failed");
        info!("🚀 Web Dashboard started at http://{}", addr);

        #[allow(unused_mut)]
        for mut request in server.incoming_requests() {
            match (request.method(), request.url()) {
                (&Method::Get, "/") => {
                    let response = Response::from_string(DASHBOARD_HTML).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap(),
                    );
                    let _ = request.respond(response);
                }
                (&Method::Get, "/api/stats") => {
                    let lock = registry.read();
                    let mut views = HashMap::new();
                    for (k, v) in lock.iter() {
                        views.insert(k.clone(), serde_json::json!({
                            "client_id": v.client_id, "ipv4": v.ipv4, "mac": v.mac,
                            "active_conns": v.active_conns.load(Ordering::Relaxed),
                            "tx_bytes": v.tx_bytes.load(Ordering::Relaxed), "rx_bytes": v.rx_bytes.load(Ordering::Relaxed),
                        }));
                    }
                    let json = serde_json::json!({ "mode": mode, "active_clients": views.len(), "clients": views }).to_string();
                    let response = Response::from_string(json).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    );
                    let _ = request.respond(response);
                }
                (&Method::Post, "/api/control") => {
                    let mut content = String::new();
                    request.as_reader().read_to_string(&mut content).unwrap();
                    #[derive(serde::Deserialize)]
                    struct ControlReq { action: String, client_id: String }

                    if let Ok(req) = serde_json::from_str::<ControlReq>(&content) {
                        if req.action == "kick" && mode == "server" {
                            if let Some(client) = registry.read().get(&req.client_id) {
                                client.force_disconnect.store(true, Ordering::Relaxed);
                                info!("[WebUI] Force kicked client: {}", req.client_id);
                            }
                        }
                    }
                    let response = Response::from_string(r#"{"status":"ok"}"#).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    );
                    let _ = request.respond(response);
                }
                _ => {
                    let _ = request.respond(Response::from_string("Not Found").with_status_code(404));
                }
            }
        }
    });
}

// ========================================================
// 7. 启动模式：服务端逻辑 (Mio Reactor)
// ========================================================
fn start_server(args: &Args) {
    info!("Starting Server Mode on {}...", args.addr);
    let psk_hash = hash_psk(&args.psk);
    let (cipher_key, cipher_iv) = if args.encrypt {
        get_cipher_context(&args.psk)
    } else {
        (vec![], vec![])
    };

    let v4_gw = args.v4cidr.split('/').next().unwrap_or("10.0.0.1").to_string();
    let v6_gw = args.v6cidr.split('/').next().unwrap_or("fd00::1").to_string();
    let v4_mask = args.v4cidr.split('/').nth(1).unwrap_or("24").to_string();
    let v6_mask = args.v6cidr.split('/').nth(1).unwrap_or("64").to_string();

    let mut v4_counter = ip4_to_u32(&v4_gw) + 1;
    let mut v6_counter = ip6_to_u128(&v6_gw) + 1;

    let ip_bindings: Arc<RwLock<HashMap<String, (String, String)>>> = Arc::new(RwLock::new(HashMap::new()));
    let used_ips: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    used_ips.write().insert(v4_gw.clone());
    used_ips.write().insert(v6_gw.clone());

    let vswitch = VSwitch::new();
    let (tap_tx, tap_rx) = bounded::<Vec<VPNFrame>>(4096);
    let tap_port = Arc::new(AsyncPort::new("TAP_LOCAL".to_string(), args.fec));
    vswitch.add_port("TAP_LOCAL".to_string(), tap_port.clone());

    let device = tun_rs::DeviceBuilder::new().name(&args.tap).layer(tun_rs::Layer::L2).mtu(1500).build_sync().unwrap();

    info!("Configuring Server TAP Interface IP...");
    Command::new("ip").args(["addr", "add", &args.v4cidr, "dev", &args.tap]).output().ok();
    Command::new("ip").args(["-6", "addr", "add", &args.v6cidr, "dev", &args.tap]).output().ok();
    Command::new("ip").args(["link", "set", "dev", &args.tap, "up"]).output().ok();
	
    let stats_registry = Arc::new(RwLock::new(HashMap::new()));
    if !args.web.is_empty() {
        start_web_server(args.web.clone(), "server".to_string(), stats_registry.clone());
    }

    let dev_writer = Arc::new(device);
    let dev_reader = dev_writer.clone();

    let tap_tx_backend = Arc::new(Backend { ch: tap_tx, rtt_cache: Arc::new(AtomicU32::new(0)) });
    tap_port.register_backend(tap_tx_backend);
    std::thread::spawn(move || {
        while let Ok(frames) = tap_rx.recv() {
            for f in frames {
                if !f.data.is_empty() { let _ = dev_writer.send(&f.data); }
            }
        }
    });

    let vswitch_clone = vswitch.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if let Ok(n) = dev_reader.recv(&mut buf) {
                if n > 0 { vswitch_clone.process_frame("TAP_LOCAL", buf[..n].to_vec()); }
            }
        }
    });

    let cert_file = std::fs::File::open(&args.cert).expect("Cannot open cert");
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader).unwrap().into_iter().map(rustls::Certificate).collect();

    let key = {
        let load_key = || -> Option<rustls::PrivateKey> {
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
                if !keys.is_empty() { return Some(rustls::PrivateKey(keys.remove(0))); }
            }
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::rsa_private_keys(&mut reader) {
                if !keys.is_empty() { return Some(rustls::PrivateKey(keys.remove(0))); }
            }
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::ec_private_keys(&mut reader) {
                if !keys.is_empty() { return Some(rustls::PrivateKey(keys.remove(0))); }
            }
            None
        };
        load_key().expect("Failed to load private key.")
    };

    let mut tls_config = ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, key).unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls_config);

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4096);
    let mut server = TcpListener::bind(args.addr.parse().unwrap()).unwrap();
    poll.registry().register(&mut server, Token(0), Interest::READABLE).unwrap();

    struct MioSession {
        socket: MioTcpStream,
        tls: ServerConnection,
        scanner: FrameScanner,
        rx: Receiver<Vec<VPNFrame>>,
        handshake_done: bool,
        sniffed: bool, // 新增前置嗅探标志
        client_session: Option<Arc<ClientSession>>,
        tx_backend: Option<Arc<Backend>>,
        last_keepalive: Instant,
        last_rx: Instant,
        send_buf: Vec<u8>,
    }

    let mut mio_sessions: HashMap<Token, MioSession> = HashMap::new();
    let active_client_sessions: Arc<RwLock<HashMap<String, Arc<ClientSession>>>> = Arc::new(RwLock::new(HashMap::new()));
    let mut unique_token = 1;

    info!("✅ Server listening for TLS connections.");

    loop {
        poll.poll(&mut events, Some(Duration::from_millis(2))).unwrap();
        let mut closed_tokens = Vec::new();

        for (token, sess) in mio_sessions.iter_mut() {
            let idle_time = sess.last_rx.elapsed().as_secs();

            if idle_time > 15 {
                closed_tokens.push(*token);
                continue;
            }

            if idle_time >= 5 {
                if let Some(backend) = &sess.tx_backend {
                    backend.rtt_cache.store(100000, Ordering::Relaxed);
                }
            }

            if sess.handshake_done && sess.last_keepalive.elapsed() > Duration::from_secs(10) {
                sess.send_buf.clear();
                append_tls_frame(&mut sess.send_buf, 0, &[], &[], &[]);
                let _ = sess.tls.writer().write_all(&sess.send_buf);
                sess.last_keepalive = Instant::now();
            }

            if let Some(c_sess) = &sess.client_session {
                if c_sess.stat.force_disconnect.load(Ordering::Relaxed) {
                    closed_tokens.push(*token);
                    continue;
                }
            }

            if sess.handshake_done {
                while sess.tls.wants_write() {
                    match sess.tls.write_tls(&mut sess.socket) {
                        Ok(0) => { closed_tokens.push(*token); break; }
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => { closed_tokens.push(*token); break; }
                    }
                }

                if !sess.tls.wants_write() {
                    let mut pulled = 0;
                    sess.send_buf.clear();

                    while let Ok(frames) = sess.rx.try_recv() {
                        for f in frames {
							append_tls_frame(&mut sess.send_buf, f.seq, &f.data, &cipher_key, &cipher_iv);
							if let Some(s) = &sess.client_session { s.stat.tx_packets.fetch_add(1, Ordering::Relaxed); }
							if !f.data.is_empty() { put_frame(f.data); }
						}
                        pulled += 1;

                        if sess.send_buf.len() >= 32768 {
                            if let Some(s) = &sess.client_session { s.stat.tx_bytes.fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed); }
                            let _ = sess.tls.writer().write_all(&sess.send_buf);
                            sess.send_buf.clear();

                            while sess.tls.wants_write() {
                                match sess.tls.write_tls(&mut sess.socket) {
                                    Ok(0) => { closed_tokens.push(*token); break; }
                                    Ok(_) => {}
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                    Err(_) => { closed_tokens.push(*token); break; }
                                }
                            }
                            if sess.tls.wants_write() || closed_tokens.contains(token) { break; }
                        }
                        if pulled >= 1024 { break; }
                    }

                    if !sess.send_buf.is_empty() && !closed_tokens.contains(token) {
                        if let Some(s) = &sess.client_session { s.stat.tx_bytes.fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed); }
                        let _ = sess.tls.writer().write_all(&sess.send_buf);
                        while sess.tls.wants_write() {
                            match sess.tls.write_tls(&mut sess.socket) {
                                Ok(0) => { closed_tokens.push(*token); break; }
                                Ok(_) => {}
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(_) => { closed_tokens.push(*token); break; }
                            }
                        }
                    }
                }
            }
        }

        closed_tokens.sort(); 
        closed_tokens.dedup();
        for t in closed_tokens {
            if let Some(mut s) = mio_sessions.remove(&t) {
                let _ = poll.registry().deregister(&mut s.socket);
                if let (Some(c_sess), Some(backend)) = (s.client_session, s.tx_backend) {
                    c_sess.port.unregister_backend(&backend.ch);
                    if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
                        let cid = &c_sess.stat.client_id;
                        active_client_sessions.write().remove(cid);
                        vswitch.remove_port(cid);
                        stats_registry.write().remove(cid);
                        info!("[{}] Client Offline.", cid);
                    }
                }
            }
        }

        for event in events.iter() {
            let token = event.token();
            if token == Token(0) {
                while let Ok((mut socket, _)) = server.accept() {
                    socket.set_nodelay(true).unwrap();
                    let t = Token(unique_token);
                    unique_token += 1;
                    poll.registry().register(&mut socket, t, Interest::READABLE | Interest::WRITABLE).unwrap();

                    let (tx, rx) = bounded(4096);
                    mio_sessions.insert(t, MioSession {
                        socket, tls: ServerConnection::new(tls_config.clone()).unwrap(), scanner: FrameScanner::new(), rx,
                        handshake_done: false, sniffed: false, client_session: None, tx_backend: Some(Arc::new(Backend { ch: tx, rtt_cache: Arc::new(AtomicU32::new(50000)) })),
                        last_keepalive: Instant::now(), last_rx: Instant::now(), send_buf: Vec::with_capacity(65536 * 4),
                    });
                }
            } else if let Some(sess) = mio_sessions.get_mut(&token) {
                let mut close = false;
                let mut tarpit = false;

                if event.is_readable() {
                    // 对齐 Go: 读取前嗅探首字节，若不是 0x16 则返回 HTTP 403 后断开
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
                            _ => {} // 如果 Peek 失败等待下一次事件
                        }
                    }

                    if !close {
                        let mut progress = false;
                        loop {
                            match sess.tls.read_tls(&mut sess.socket) {
                                Ok(0) => { close = true; break; }
                                Ok(_) => { progress = true; }
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(_) => { close = true; break; }
                            }
                        }
                        if progress { sess.last_rx = Instant::now(); }

                        if progress && !close {
                            if sess.tls.process_new_packets().is_ok() {
                                loop {
                                    match sess.scanner.read_frame(&mut sess.tls.reader()) {
                                        Ok(Some((mut data, seq))) => {
                                            if let Some(s) = &sess.client_session {
                                                s.stat.rx_bytes.fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                                                s.stat.rx_packets.fetch_add(1, Ordering::Relaxed);
                                            }

                                            if seq == 0 && !sess.handshake_done {
                                                if let Ok(req) = serde_json::from_slice::<HandshakeReq>(&data) {
                                                    if req.psk == psk_hash {
                                                        sess.handshake_done = true;
                                                        let assigned_v4; let assigned_v6;
                                                        let c_sess = {
                                                            let mut sessions_lock = active_client_sessions.write();
                                                            if let Some(exist) = sessions_lock.get(&req.client_id) {
                                                                assigned_v4 = exist.stat.ipv4.clone();
                                                                assigned_v6 = exist.stat.ipv6.clone();
                                                                exist.clone()
                                                            } else {
                                                                let mut bindings = ip_bindings.write();
                                                                let mut used = used_ips.write();

                                                                let (v4, v6) = if let Some(existing) = bindings.get(&req.client_id) {
                                                                    existing.clone()
                                                                } else {
                                                                    let v4 = if let Some(req_ip) = req.ipv4.filter(|s| !s.is_empty()) {
                                                                        let just_ip = req_ip.split('/').next().unwrap_or(&req_ip).to_string();
                                                                        if used.contains(&just_ip) {
                                                                            let res = format!("{}/{}", u32_to_ip4(v4_counter), v4_mask); v4_counter += 1; res
                                                                        } else { if req_ip.contains('/') { req_ip } else { format!("{}/{}", req_ip, v4_mask) } }
                                                                    } else { let res = format!("{}/{}", u32_to_ip4(v4_counter), v4_mask); v4_counter += 1; res };

                                                                    let v6 = if let Some(req_ip) = req.ipv6.filter(|s| !s.is_empty()) {
                                                                        let just_ip = req_ip.split('/').next().unwrap_or(&req_ip).to_string();
                                                                        if used.contains(&just_ip) {
                                                                            let res = format!("{}/{}", u128_to_ip6(v6_counter), v6_mask); v6_counter += 1; res
                                                                        } else { if req_ip.contains('/') { req_ip } else { format!("{}/{}", req_ip, v6_mask) } }
                                                                    } else { let res = format!("{}/{}", u128_to_ip6(v6_counter), v6_mask); v6_counter += 1; res };

                                                                    bindings.insert(req.client_id.clone(), (v4.clone(), v6.clone()));
                                                                    used.insert(v4.split('/').next().unwrap_or(&v4).to_string());
                                                                    used.insert(v6.split('/').next().unwrap_or(&v6).to_string());
                                                                    (v4, v6)
                                                                };
                                                                assigned_v4 = v4; assigned_v6 = v6;

                                                                let stat = Arc::new(ClientStat::new(req.client_id.clone(), assigned_v4.clone(), assigned_v6.clone(), req.mac.clone().unwrap_or_default()));
                                                                stats_registry.write().insert(req.client_id.clone(), stat.clone());

                                                                let port = Arc::new(AsyncPort::new(req.client_id.clone(), req.fec.unwrap_or(false)));
                                                                vswitch.add_port(req.client_id.clone(), port.clone());

                                                                let new_sess = Arc::new(ClientSession {
                                                                    stat, port,
                                                                    reorder_buf: Arc::new(Mutex::new(ReorderBuffer::new())),
                                                                    dedup: Arc::new(Mutex::new(DeDuplicator::new())),
                                                                });
                                                                sessions_lock.insert(req.client_id.clone(), new_sess.clone());
                                                                new_sess
                                                            }
                                                        };

                                                        c_sess.stat.active_conns.fetch_add(1, Ordering::Relaxed);
                                                        if let Some(b) = &sess.tx_backend { b.rtt_cache.store(50000, Ordering::Relaxed); }
                                                        c_sess.port.register_backend(sess.tx_backend.clone().unwrap());
                                                        sess.client_session = Some(c_sess.clone());

                                                        let server_tx_rate = if req.brutal_rx.unwrap_or(0) > 0 && (args.brutal_up == 0 || req.brutal_rx.unwrap() < args.brutal_up) { req.brutal_rx.unwrap() } else { args.brutal_up };
                                                        let client_tx_rate = if req.brutal_tx.unwrap_or(0) > 0 && (args.brutal_down == 0 || req.brutal_tx.unwrap() < args.brutal_down) { req.brutal_tx.unwrap() } else { args.brutal_down };

                                                        if args.brutal && server_tx_rate > 0 { apply_tcp_brutal(&sess.socket, server_tx_rate); }

                                                        let resp = HandshakeResp {
                                                            success: true, message: "OK".into(), client_id: req.client_id,
                                                            ipv4: assigned_v4, ipv6: assigned_v6, gw_v4: Some(v4_gw.clone()), gw_v6: Some(v6_gw.clone()),
                                                            padding: None, brutal_tx: Some(server_tx_rate), brutal_rx: Some(client_tx_rate), fec: req.fec, encrypt: Some(args.encrypt),
                                                        };
                                                        let resp_json = serde_json::to_vec(&resp).unwrap();
                                                        sess.send_buf.clear();
                                                        append_tls_frame(&mut sess.send_buf, 0, &resp_json, &[], &[]);
                                                        let _ = sess.tls.writer().write_all(&sess.send_buf);

                                                        while sess.tls.wants_write() {
                                                            match sess.tls.write_tls(&mut sess.socket) {
                                                                Ok(0) => { close = true; break; }
                                                                Ok(_) => {}
                                                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                                                Err(_) => { close = true; break; }
                                                            }
                                                        }
                                                    } else {
                                                        // PSK 不匹配，触发混淆探测阻力(焦油坑)
                                                        warn!("PSK 验证失败，将连接送入焦油坑");
                                                        tarpit = true;
														close = true;
														break;
                                                    }
                                                } else {
													warn!("非法协议格式，将连接送入焦油坑");
                                                    tarpit = true;
													close = true;
													break; // 解析失败，当成扫描器送入焦油坑
                                                }
                                            } else if sess.handshake_done {
                                                if data.is_empty() { continue; }
                                                if let Some(c_sess) = &sess.client_session {
                                                    if args.encrypt && seq != 0 { xor_crypt_in_place(&mut data, seq, &cipher_key, &cipher_iv); }
                                                    
                                                    // 对齐去重判断
                                                    if !c_sess.dedup.lock().is_duplicate(seq) {
                                                        let ready_frames = c_sess.reorder_buf.lock().insert(seq, data);
                                                        for ordered_data in ready_frames {
                                                            vswitch.process_frame(&c_sess.stat.client_id, ordered_data);
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            if !sess.handshake_done {
                                                let is_h2 = sess.tls.alpn_protocol() == Some(b"h2");
                                                serve_fallback_http(&mut sess.tls.writer(), is_h2);
                                                while sess.tls.wants_write() { let _ = sess.tls.write_tls(&mut sess.socket); }
                                            }
                                            close = true; break;
                                        }
                                    }
                                }
                            } else {
                                if !sess.handshake_done { serve_fallback_http(&mut sess.socket, false); }
                                close = true;
                            }
                        }
                    }
                }

                if event.is_writable() && !close {
                    while sess.tls.wants_write() {
                        match sess.tls.write_tls(&mut sess.socket) {
                            Ok(0) => { close = true; break; }
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => { close = true; break; }
                        }
                    }
                }

                if close {
                    let mut s = mio_sessions.remove(&token).unwrap();
                    let _ = poll.registry().deregister(&mut s.socket);
                    
                    if tarpit {
                        // 剥离 Mio，将 Socket 丢给单独的线程执行慢速伪装
                        let socket = s.socket;
                        std::thread::spawn(move || { camouflage_probe(socket); });
                    }
                    
                    if let (Some(c_sess), Some(backend)) = (s.client_session, s.tx_backend) {
                        c_sess.port.unregister_backend(&backend.ch);
                        if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
                            let cid = &c_sess.stat.client_id;
                            active_client_sessions.write().remove(cid);
                            vswitch.remove_port(cid);
                            stats_registry.write().remove(cid);
                        }
                    }
                }
            }
        }
    }
}

// ========================================================
// 8. 启动模式：客户端逻辑
// ========================================================

// 自定义验证器，用于对齐 Go 客户端的 SHA256 哈希证书校验功能
struct CertHashVerifier {
    expected_hash: String,
}
impl rustls::client::ServerCertVerifier for CertHashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let hash_str = hex::encode(hasher.finalize());
        if hash_str == self.expected_hash {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!("cert SHA-256 mismatch: expected {}", self.expected_hash)))
        }
    }
}

fn start_client(args: &Args) {
    info!("Starting Client Mode towards {}...", args.addr);
    let psk_hash = hash_psk(&args.psk);
    let (cipher_key, cipher_iv) = if args.encrypt { get_cipher_context(&args.psk) } else { (vec![], vec![]) };

    let actual_mac = if args.mac.is_empty() { "00:00:00:00:00:00".to_string() } else { args.mac.clone() };
    let mut hasher = Sha256::new();
    hasher.update(actual_mac.as_bytes()); hasher.update(args.psk.as_bytes());
    let client_id = hex::encode(hasher.finalize());

    let my_stat = Arc::new(ClientStat::new(client_id.clone(), args.req_v4.clone(), args.req_v6.clone(), actual_mac.clone()));
    let stats_registry = Arc::new(RwLock::new(HashMap::new()));
    stats_registry.write().insert("local".into(), my_stat.clone());

    if !args.web.is_empty() { start_web_server(args.web.clone(), "client".to_string(), stats_registry.clone()); }

    let (tap_tx, tap_rx) = bounded::<Vec<u8>>(4096);
    let tx_port = Arc::new(AsyncPort::new("CLIENT_UPLINK".to_string(), args.fec));
    let reorder_buf = Arc::new(Mutex::new(ReorderBuffer::new()));
    let dedup = Arc::new(Mutex::new(DeDuplicator::new())); // 客户端也增加去重器

    let device = tun_rs::DeviceBuilder::new().name(&args.tap).layer(tun_rs::Layer::L2).mtu(1500).build_sync().unwrap();
    let dev_writer = Arc::new(device);
    let dev_reader = dev_writer.clone();

    std::thread::spawn(move || {
        while let Ok(data) = tap_rx.recv() { let _ = dev_writer.send(&data); }
    });

    let port_clone = tx_port.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if let Ok(n) = dev_reader.recv(&mut buf) {
                if n > 0 { 
					let mut frame = get_frame();
					frame.clear();
					frame.extend_from_slice(&buf[..n]);
					port_clone.write_frame(frame); 
				}
            }
        }
    });

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(ta.subject, ta.spki, ta.name_constraints)
    }));

    let mut config = ClientConfig::builder().with_safe_defaults().with_root_certificates(root_store).with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    if args.insecure {
        struct DummyVerifier;
        impl rustls::client::ServerCertVerifier for DummyVerifier {
            fn verify_server_cert(&self, _e: &rustls::Certificate, _i: &[rustls::Certificate], _s: &rustls::ServerName, _scts: &mut dyn Iterator<Item = &[u8]>, _ocsp: &[u8], _now: std::time::SystemTime) -> Result<rustls::client::ServerCertVerified, rustls::Error> { Ok(rustls::client::ServerCertVerified::assertion()) }
        }
        config.dangerous().set_certificate_verifier(Arc::new(DummyVerifier));
    } else if !args.cert_sha256.is_empty() {
        // 装配指定的 Hash Verification 对齐 Go 版本逻辑
        config.dangerous().set_certificate_verifier(Arc::new(CertHashVerifier { expected_hash: args.cert_sha256.clone() }));
    }
    
    let client_config = Arc::new(config);

    for i in 0..args.conns {
        let addr = args.addr.clone(); let sni = args.sni.clone(); let cid = client_id.clone(); let p_hash = psk_hash.clone();
        let port = tx_port.clone(); let c_key = cipher_key.clone(); let c_iv = cipher_iv.clone(); let encrypt = args.encrypt;
        let fec = args.fec; let t_tx = tap_tx.clone(); let brutal = args.brutal; let brutal_up = args.brutal_up;
        let brutal_down = args.brutal_down; let config_clone = client_config.clone(); let tap_name = args.tap.clone();

        let mac_arg = if actual_mac.is_empty() { None } else { Some(actual_mac.clone()) };
        let v4_arg = if args.req_v4.is_empty() { None } else { Some(args.req_v4.clone()) };
        let v6_arg = if args.req_v6.is_empty() { None } else { Some(args.req_v6.clone()) };

        let local_stat = my_stat.clone(); 
        let reorder_clone = reorder_buf.clone(); 
        let dedup_clone = dedup.clone();
        let conns_count = args.conns as u64;

        std::thread::spawn(move || {
            loop {
                info!("[Conn {}] Connecting...", i);
                let mut socket = match std::net::TcpStream::connect(&addr) {
                    Ok(s) => s,
                    Err(_) => { std::thread::sleep(Duration::from_secs(3)); continue; }
                };

                socket.set_nodelay(true).unwrap(); socket.set_nonblocking(true).unwrap();

                let server_name = sni.as_str().try_into().unwrap();
                let mut tls = ClientConnection::new(config_clone.clone(), server_name).unwrap();

                let client_tx_rate = if brutal_up > 0 { std::cmp::max(1, brutal_up / conns_count) } else { 0 };
                let client_rx_rate = if brutal_down > 0 { std::cmp::max(1, brutal_down / conns_count) } else { 0 };

                let req = HandshakeReq {
                    client_id: cid.clone(), psk: p_hash.clone(), mac: mac_arg.clone(), ipv4: v4_arg.clone(), ipv6: v6_arg.clone(),
                    padding: None, brutal_tx: if brutal { Some(client_tx_rate) } else { None }, brutal_rx: if brutal { Some(client_rx_rate) } else { None },
                    fec: Some(fec), encrypt: Some(encrypt),
                };
                let req_json = serde_json::to_vec(&req).unwrap();

                let mut send_buf = Vec::with_capacity(65536 * 4);
                append_tls_frame(&mut send_buf, 0, &req_json, &[], &[]);
                let _ = tls.writer().write_all(&send_buf);

                let mut scanner = FrameScanner::new(); let mut handshake_ok = false;
                let start_time = Instant::now();

                while start_time.elapsed() < Duration::from_secs(5) {
                    while tls.wants_write() {
                        match tls.write_tls(&mut socket) {
                            Ok(0) => break, Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break, Err(_) => break,
                        }
                    }
                    match tls.read_tls(&mut socket) {
                        Ok(0) => break,
                        Ok(_) => {
                            if tls.process_new_packets().is_ok() {
                                while let Ok(Some((data, seq))) = scanner.read_frame(&mut tls.reader()) {
                                    if seq == 0 {
                                        if let Ok(resp) = serde_json::from_slice::<HandshakeResp>(&data) {
                                            if resp.success && resp.encrypt == Some(encrypt) {
                                                handshake_ok = true;
                                                if brutal && resp.brutal_rx.unwrap_or(0) > 0 { apply_tcp_brutal(&socket, resp.brutal_rx.unwrap()); }
                                                if i == 0 {
                                                    Command::new("ip").args(["addr", "add", &resp.ipv4, "dev", &tap_name]).output().ok();
                                                    Command::new("ip").args(["-6", "addr", "add", &resp.ipv6, "dev", &tap_name]).output().ok();
                                                    Command::new("ip").args(["link", "set", "dev", &tap_name, "up"]).output().ok();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                    if handshake_ok { break; }
                    std::thread::sleep(Duration::from_millis(2));
                }

                if !handshake_ok { std::thread::sleep(Duration::from_secs(3)); continue; }

                local_stat.active_conns.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = bounded(4096);
                let rtt = Arc::new(AtomicU32::new(50000));
                port.register_backend(Arc::new(Backend { ch: tx.clone(), rtt_cache: rtt.clone() }));

                let mut last_keepalive = Instant::now(); let mut last_rx = Instant::now(); let mut rtt_timer = Instant::now();

                loop {
                    let mut is_active = false;
                    let idle_time = last_rx.elapsed().as_secs();

                    if idle_time > 15 { break; }
                    if idle_time >= 5 { rtt.store(100000, Ordering::Relaxed); } 
                    else if rtt_timer.elapsed() > Duration::from_millis(200) { rtt.store(get_tcp_rtt(&socket), Ordering::Relaxed); rtt_timer = Instant::now(); }

                    let mut close = false;

                    while tls.wants_write() {
                        is_active = true;
                        match tls.write_tls(&mut socket) {
                            Ok(0) => { close = true; break; } Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
                            Err(_) => { close = true; break; }
                        }
                    }
                    if close { break; }

                    if !tls.wants_write() {
                        let mut pulled = 0; send_buf.clear();
                        while let Ok(frames) = rx.try_recv() {
                            is_active = true;
                            for f in frames {
                                append_tls_frame(&mut send_buf, f.seq, &f.data, &c_key, &c_iv);
                                local_stat.tx_packets.fetch_add(1, Ordering::Relaxed);
								if !f.data.is_empty() { put_frame(f.data); }
                            }
                            pulled += 1;
                            if send_buf.len() >= 32768 {
                                if tls.writer().write_all(&send_buf).is_ok() { local_stat.tx_bytes.fetch_add(send_buf.len() as u64, Ordering::Relaxed); }
                                send_buf.clear();
                                while tls.wants_write() {
                                    match tls.write_tls(&mut socket) {
                                        Ok(0) => { close = true; break; } Ok(_) => {}
                                        Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
                                        Err(_) => { close = true; break; }
                                    }
                                }
                                if tls.wants_write() || close { break; }
                            }
                            if pulled >= 1024 { break; }
                        }

                        if !send_buf.is_empty() && !close {
                            if tls.writer().write_all(&send_buf).is_ok() { local_stat.tx_bytes.fetch_add(send_buf.len() as u64, Ordering::Relaxed); }
                            while tls.wants_write() {
                                match tls.write_tls(&mut socket) {
                                    Ok(0) => { close = true; break; } Ok(_) => {}
                                    Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
                                    Err(_) => { close = true; break; }
                                }
                            }
                        }
                    }
                    if close { break; }

                    if last_keepalive.elapsed() > Duration::from_secs(10) {
                        send_buf.clear(); append_tls_frame(&mut send_buf, 0, &[], &[], &[]);
                        let _ = tls.writer().write_all(&send_buf); last_keepalive = Instant::now();
                    }

                    loop {
                        match tls.read_tls(&mut socket) {
                            Ok(0) => { close = true; break; } Ok(_) => { is_active = true; last_rx = Instant::now(); }
                            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => break,
                            Err(_) => { close = true; break; }
                        }
                    }

                    if is_active && !close {
                        if tls.process_new_packets().is_ok() {
                            while let Ok(Some((mut data, seq))) = scanner.read_frame(&mut tls.reader()) {
                                local_stat.rx_bytes.fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                                local_stat.rx_packets.fetch_add(1, Ordering::Relaxed);

                                if data.is_empty() { continue; }
                                if encrypt && seq != 0 { xor_crypt_in_place(&mut data, seq, &c_key, &c_iv); }
                                
                                if !dedup_clone.lock().is_duplicate(seq) {
                                    let ready_frames = reorder_clone.lock().insert(seq, data);
                                    for ordered_data in ready_frames { let _ = t_tx.try_send(ordered_data); }
                                }
                            }
                        } else { close = true; }
                    }

                    if close { break; }
                    if !is_active { std::thread::sleep(Duration::from_millis(1)); }
                }

                port.unregister_backend(&tx);
                local_stat.active_conns.fetch_sub(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(3));
            }
        });
    }

    if args.fwmark > 0 { setup_policy_routing(&args.tap, args.fwmark, "10.0.0.1", "fd00::1"); }
    loop { std::thread::sleep(Duration::from_secs(60)); }
}

// ========================================================
// 9. 主程序
// ========================================================
fn main() {
    let args = Args::parse();
    init_logger(&args.loglevel);

    lazy_static::initialize(&PADDING_CACHE);

    if args.mode == "server" {
        start_server(&args);
    } else if args.mode == "client" {
        start_client(&args);
    } else {
        error!("Usage: tlsvpn --mode <server|client> [OPTIONS]");
    }
}