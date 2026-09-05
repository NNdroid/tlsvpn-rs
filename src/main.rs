use clap::Parser;
use std::sync::atomic::Ordering;
use tracing::error;

// mimalloc：每帧多次 malloc/free 的场景下比系统分配器快 10-20%
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod buffer;
pub mod client;
pub mod crypto;
pub mod fec;
pub mod frame;
pub mod net;
pub mod server;
pub mod socks5;
pub mod tap;
pub mod utils;

use crate::api::init_logging;
use crate::buffer::*;
use crate::client::*;
use crate::server::*;

/// 命令行参数（与 Go flag 集合对齐；同时支持 JSON 配置文件）
#[derive(Parser, Debug, Clone, Default)]
#[command(name = "tlsvpn", about = "Rust Implementation of TLSVPN", long_about = None)]
pub struct Args {
    #[arg(long, default_value = "", help = "server or client")]
    pub mode: String,
    #[arg(long, default_value = "quic_secret", help = "Pre-shared key")]
    pub psk: String,
    #[arg(long, default_value = "tap0", help = "Name of the TAP device")]
    pub tap: String,
    #[arg(
        long,
        default_value = "",
        help = "Specify MAC address for TAP device (Client/Server)"
    )]
    pub mac: String,
    #[arg(
        long,
        default_value = "0.0.0.0:4000",
        help = "Server: listen address | Client: target addresses (comma-separated)"
    )]
    pub addr: String,
    #[arg(
        long,
        default_value = "info",
        help = "Log level (trace, debug, info, warn, error)"
    )]
    pub loglevel: String,
    #[arg(
        long,
        default_value = "10.0.0.0/24",
        help = "IPv4 CIDR block (Server only)"
    )]
    pub v4cidr: String,
    #[arg(
        long,
        default_value = "fd00::/64",
        help = "IPv6 CIDR block (Server only)"
    )]
    pub v6cidr: String,
    #[arg(long, default_value = "", help = "TLS Certificate file (Server only)")]
    pub cert: String,
    #[arg(long, default_value = "", help = "TLS Key file (Server only)")]
    pub key: String,
    #[arg(
        long = "req_v4",
        alias = "req-v4",
        default_value = "",
        help = "Requested IPv4 (Client only)"
    )]
    pub req_v4: String,
    #[arg(
        long = "req_v6",
        alias = "req-v6",
        default_value = "",
        help = "Requested IPv6 (Client only)"
    )]
    pub req_v6: String,
    #[arg(
        long,
        default_value = "www.cloudflare.com",
        help = "SNI for TLS (Client only)"
    )]
    pub sni: String,
    #[arg(long, default_value_t = false, help = "Skip TLS verify (Client only)")]
    pub insecure: bool,
    #[arg(
        long = "cert_sha256",
        alias = "cert-sha256",
        default_value = "",
        help = "Verify server cert SHA256 (Client only)"
    )]
    pub cert_sha256: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "Policy routing fwmark (Client only)"
    )]
    pub fwmark: i32,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable TCP Brutal congestion control"
    )]
    pub brutal: bool,
    #[arg(
        long = "brutal_up",
        alias = "brutal-up",
        default_value_t = 100,
        help = "Brutal upload rate limit in Mbps"
    )]
    pub brutal_up: u64,
    #[arg(
        long = "brutal_down",
        alias = "brutal-down",
        default_value_t = 500,
        help = "Brutal download rate limit in Mbps"
    )]
    pub brutal_down: u64,
    #[arg(
        long,
        default_value_t = 1,
        help = "Number of concurrent TCP connections for Load Balancing"
    )]
    pub conns: i32,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable FEC over Multipath (XOR parity when the server supports it, else packet duplication)"
    )]
    pub fec: bool,
    #[arg(
        long = "fec_group",
        alias = "fec-group",
        default_value_t = 4,
        help = "XOR FEC group size K (2-64); parity overhead is 1/K"
    )]
    pub fec_group: i64,
    #[arg(
        long,
        default_value = "",
        help = "Start Web Dashboard on specified address"
    )]
    pub web: String,
    #[arg(
        long = "web_auth",
        alias = "web-auth",
        default_value = "",
        help = "Basic Auth for the Web Dashboard as user:pass"
    )]
    pub web_auth: String,
    #[arg(
        long,
        default_value_t = false,
        help = "Enable inner payload encryption (AES-256-GCM with per-session salts when the peer supports it)"
    )]
    pub encrypt: bool,
    #[arg(
        long,
        default_value = "",
        help = "Route ALL outbound sockets through a SOCKS5 proxy (Client only). \
                Format: [user:pass@]host:port, socks5://host:port or socks5h://host:port"
    )]
    pub socks5: String,
    #[arg(
        long,
        default_value_t = 0,
        help = "Server worker threads (0 = auto, one per CPU up to 8)"
    )]
    pub workers: i32,
    #[arg(
        long,
        default_value_t = 1500,
        value_parser = clap::value_parser!(u16),
        help = "TAP device MTU (larger = fewer frames/syscalls; set on BOTH ends)"
    )]
    pub mtu: u16,
    /// 内部字段：由配置文件加载时跳过 clap 解析
    #[arg(skip)]
    pub from_file: bool,
}

// ======================= JSON 配置文件（对齐 Go config.go） =======================

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ConfigFile {
    mode: String,
    psk: String,
    tap: String,
    mac: String,
    addr: String,
    log_level: String,
    encrypt: bool,
    socks5: String,
    brutal: bool,
    brutal_up: u64,
    brutal_down: u64,
    workers: i32,
    mtu: u16,
    web: WebConfigFile,
    server: ServerConfigFile,
    client: ClientConfigFile,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct WebConfigFile {
    addr: String,
    auth: String,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ServerConfigFile {
    v4_cidr: String,
    v6_cidr: String,
    cert: String,
    key: String,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ClientConfigFile {
    req_v4: String,
    req_v6: String,
    sni: String,
    insecure: bool,
    cert_sha256: String,
    fwmark: i32,
    conns: i32,
    fec: bool,
    fec_group: i64,
}

/// 读取 JSON 配置并填充默认值（对齐 Go loadConfigFile + applyDefaults）
fn load_config_file(path: &str) -> Result<Args, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;
    let cfg: ConfigFile =
        serde_json::from_str(&raw).map_err(|e| format!("parse config {}: {}", path, e))?;

    let mut args = Args {
        mode: cfg.mode.clone(),
        psk: if cfg.psk.is_empty() {
            "quic_secret".into()
        } else {
            cfg.psk
        },
        tap: if cfg.tap.is_empty() {
            "tap0".into()
        } else {
            cfg.tap
        },
        mac: cfg.mac,
        addr: cfg.addr.clone(),
        loglevel: if cfg.log_level.is_empty() {
            "info".into()
        } else {
            cfg.log_level
        },
        encrypt: cfg.encrypt,
        socks5: cfg.socks5,
        workers: cfg.workers,
        mtu: cfg.mtu,
        brutal: cfg.brutal,
        brutal_up: if cfg.brutal_up == 0 {
            100
        } else {
            cfg.brutal_up
        },
        brutal_down: if cfg.brutal_down == 0 {
            500
        } else {
            cfg.brutal_down
        },
        web: cfg.web.addr,
        web_auth: cfg.web.auth,
        v4cidr: if cfg.server.v4_cidr.is_empty() {
            "10.0.0.0/24".into()
        } else {
            cfg.server.v4_cidr
        },
        v6cidr: if cfg.server.v6_cidr.is_empty() {
            "fd00::/64".into()
        } else {
            cfg.server.v6_cidr
        },
        cert: cfg.server.cert,
        key: cfg.server.key,
        req_v4: cfg.client.req_v4,
        req_v6: cfg.client.req_v6,
        sni: if cfg.client.sni.is_empty() {
            "www.cloudflare.com".into()
        } else {
            cfg.client.sni
        },
        insecure: cfg.client.insecure,
        cert_sha256: cfg.client.cert_sha256,
        fwmark: cfg.client.fwmark,
        conns: if cfg.client.conns == 0 {
            1
        } else {
            cfg.client.conns
        },
        fec: cfg.client.fec,
        fec_group: if cfg.client.fec_group == 0 {
            4
        } else {
            cfg.client.fec_group
        },
        from_file: true,
    };
    if args.mode == "server" && args.addr.is_empty() {
        args.addr = "0.0.0.0:4000".into();
    }
    Ok(args)
}

fn validate_args(args: &Args) -> Result<(), String> {
    if args.addr.is_empty() {
        return Err("addr is required".into());
    }
    if args.mode == "client" {
        if args.conns < 1 {
            return Err("client conns must be >= 1".into());
        }
        if !(2..=64).contains(&args.fec_group) {
            return Err("client fec_group must be in [2, 64]".into());
        }
        if args.fwmark < 0 {
            return Err("client fwmark must be >= 0".into());
        }
        if !args.cert_sha256.is_empty() {
            let cleaned = args.cert_sha256.replace(':', "").to_lowercase();
            if cleaned.len() != 64 {
                return Err("client cert_sha256 must be 64 hex chars (sha256)".into());
            }
        }
    }
    Ok(())
}

fn main() {
    // -print-config：输出示例 JSON 模板并退出（对齐 Go -print-config）
    if std::env::args().any(|a| a == "--print-config") {
        println!("{}", example_config_json());
        return;
    }

    // rustls 0.23 需要显式选择 crypto provider（ring：无 cmake/NASM 依赖）
    let _ = rustls::crypto::ring::default_provider().install_default();

    let parsed = Args::parse();

    // JSON 配置文件优先（对齐 Go -c 语义；-c <path> 忽略其余 flag）
    let config_path = std::env::args()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| std::env::args().nth(i + 1));
    let args = match config_path {
        Some(path) => match load_config_file(&path) {
            Ok(a) => {
                println!("Loaded configuration from {}", path);
                a
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        },
        None => parsed,
    };

    init_logging(&args.loglevel);

    lazy_static::initialize(&PADDING_CACHE);

    if args.psk == "quic_secret" {
        tracing::warn!("⚠️  PSK is the default value — change it via -psk or the config file!");
    }
    if let Err(e) = validate_args(&args) {
        error!("Invalid configuration: {}", e);
        std::process::exit(1);
    }

    install_signal_handler();

    match args.mode.as_str() {
        "server" => {
            if args.fec {
                tracing::warn!("client FEC settings are ignored in server mode");
            }
            start_server(&args);
        }
        "client" => {
            start_client(&args);
            on_exit_cleanup();
        }
        other => {
            eprintln!("Usage: tlsvpn -c config.json   (or --mode server|client with flags)");
            let _ = other;
            std::process::exit(1);
        }
    }
    tracing::info!("Program exited gracefully.");
}

fn install_signal_handler() {
    ctrlc::set_handler(|| {
        tracing::info!("Received termination signal, shutting down...");
        EXIT.store(true, Ordering::SeqCst);
        // 给工作线程一点时间完成清理
        client::on_exit_cleanup();
        std::process::exit(0);
    })
    .ok();
}

#[cfg(test)]
mod tests {
    use crate::buffer::*;
    use crate::crypto::*;
    use crate::frame::*;
    use std::io::Read;
    use std::time::Instant;

    struct InfiniteReader {
        data: Vec<u8>,
        pos: usize,
        reads: usize,
    }

    impl Read for InfiniteReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.reads > 0 {
                self.reads = 0;
                return Err(std::io::Error::new(std::io::ErrorKind::WouldBlock, ""));
            }
            let available = self.data.len() - self.pos;
            let to_copy = std::cmp::min(buf.len(), available);
            buf[..to_copy].copy_from_slice(&self.data[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            if self.pos >= self.data.len() {
                self.pos = 0;
            }
            self.reads += 1;
            Ok(to_copy)
        }
    }

    #[test]
    #[ignore = "benchmark: long-running (1M iterations); run with `cargo test -- --ignored`"]
    fn bench_protocol_throughput() {
        let ic = InnerCipher::legacy("benchmark_secret_key");
        let payload = vec![0u8; 1400];

        let mut frame_buf = Vec::new();
        append_padded_frame(&mut frame_buf, 1, &payload, Some(&ic));

        let mut scanner = FrameScanner::new();
        let mut reader = InfiniteReader {
            data: frame_buf.clone(),
            pos: 0,
            reads: 0,
        };

        let iter_count = 1_000_000;
        let start = Instant::now();
        for _ in 0..iter_count {
            let (mut data, seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
            let wire_len = data.len() as u32;
            ic.open_in_place(&mut data, seq, wire_len).unwrap();
            drop(data);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total_bytes = (iter_count as f64) * (payload.len() as f64);
        let mb_per_sec = (total_bytes / 1024.0 / 1024.0) / elapsed;
        println!("Protocol Throughput: {:.2} MB/s", mb_per_sec);
    }
}

/// 与 Go 端 exampleConfigJSON 逐字段一致的模板（两端配置文件可互换）
fn example_config_json() -> String {
    format!(
        r#"{{
  "mode": "client",
  "psk": "change-me-please",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "encrypt": true,
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "workers": {},
  "mtu": 1500,
  "socks5": "",
  "tap": "tap0",
  "mac": "",
  "web": {{
    "addr": ":8080",
    "auth": "admin:change-me",
  }},
  "client": {{
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0
  }},
  "server": {{
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": ""
  }}
}}"#,
        num_cpus_hint()
    )
}

fn num_cpus_hint() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}
