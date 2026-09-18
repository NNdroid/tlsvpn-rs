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
        long = "web_bind",
        alias = "web-bind",
        default_value = "all",
        help = "Dashboard listen scope: all (default) or tunnel (tunnel IP only)"
    )]
    pub web_bind: String,
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
    #[arg(
        long = "pad-mode",
        default_value = "",
        help = "Confusion padding: legacy | bucket | off (default bucket)"
    )]
    pub pad_mode: String,
    #[arg(
        long = "min-enc",
        default_value = "",
        help = "Minimum inner encryption strength: ctr | gcm (reject weaker negotiation)"
    )]
    pub min_enc: String,
    #[arg(
        long = "session-token",
        default_value_t = false,
        help = "Server: require the session token issued on the original TLS connection \
                for re-attaching to a live session"
    )]
    pub session_token: bool,
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
    // 空串 = 无下限（与旧版一致）；见 min_enc_rank
    #[serde(default)]
    min_enc: String,
    // 空串 = 默认 bucket（与 Go applyDefaults 一致）
    #[serde(default)]
    pad_mode: String,
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
    bind: String,
    // Go 版把面板 HTTPS 证书放在这里（web.cert / web.key）。Rust 版面板目前
    // 只走明文 HTTP，无法消费这两个值，但必须能解析——Go 的示例配置里恒有
    // 它们，留空即代表"不启用面板 HTTPS"，丢弃不改变任何行为。
    #[allow(dead_code)]
    cert: String,
    #[allow(dead_code)]
    key: String,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ServerConfigFile {
    v4_cidr: String,
    v6_cidr: String,
    cert: String,
    key: String,
    // 重连接入既有会话时必须回带会话令牌（opt-in，默认关闭）
    #[serde(default)]
    session_token: bool,
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
        pad_mode: cfg.pad_mode,
        min_enc: cfg.min_enc,
        socks5: cfg.socks5,
        workers: cfg.workers,
        // Go 的配置文件不含 mtu 字段；缺省必须取 flag 默认值 1500，
        // 否则 0 会被当成合法 MTU 传给 TAP 设备
        mtu: if cfg.mtu == 0 { 1500 } else { cfg.mtu },
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
        web_bind: if cfg.web.bind.is_empty() {
            "all".into()
        } else {
            cfg.web.bind
        },
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
        session_token: cfg.server.session_token,
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

    // JSON 配置文件优先（对齐 Go -c 语义；-c <path> 忽略其余 flag）。
    // 必须先于 Args::parse() 判定：clap 不认识 -c/--config，会直接以
    // "unexpected argument" 退出，配置文件路径将完全不可用。
    let argv: Vec<String> = std::env::args().collect();
    let config_path = argv
        .iter()
        .position(|a| a == "-c" || a == "--config")
        .and_then(|i| argv.get(i + 1))
        .cloned();
    let args = match config_path {
        Some(ref path) => match load_config_file(path) {
            Ok(a) => {
                println!("Loaded configuration from {}", path);
                a
            }
            Err(e) => {
                eprintln!("{}", e);
                std::process::exit(1);
            }
        },
        None => Args::parse(),
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
    use crate::{ConfigFile, example_config_json, load_config_file};
    use std::io::Read;
    use std::time::Instant;

    // ---------- 配置文件兼容性（与 Go 仓库 config.*.json 逐字段对齐） ----------

    // Go 仓库 config.server.json 的原样内容
    const GO_SERVER_CONFIG: &str = r#"{
  "mode": "server",
  "psk": "change-me-please",
  "addr": ":4000",
  "log_level": "info",
  "encrypt": true,
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "tap": "tap0",
  "mac": "",
  "web": {
    "addr": ":8080",
    "bind": "tunnel",
    "auth": "admin:change-me",
    "cert": "",
    "key": ""
  },
  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "session_token": false
  }
}
"#;

    // Go 仓库 config.client.json 的原样内容
    const GO_CLIENT_CONFIG: &str = r#"{
  "mode": "client",
  "psk": "change-me-please",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "encrypt": true,
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "socks5": "",
  "tap": "tap0",
  "mac": "",
  "web": {
    "addr": ":8080",
    "bind": "tunnel",
    "auth": "admin:change-me",
    "cert": "",
    "key": ""
  },
  "client": {
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0
  }
}
"#;

    #[test]
    fn go_config_files_parse_verbatim() {
        // Go 的配置文件必须能被 Rust 原样读入（含 pad_mode / server.session_token /
        // web.cert / web.key），否则 -c 指向 Go 配置时启动直接失败。
        for (name, raw) in [("server", GO_SERVER_CONFIG), ("client", GO_CLIENT_CONFIG)] {
            let cfg = serde_json::from_str::<ConfigFile>(raw)
                .unwrap_or_else(|e| panic!("Go {} 配置解析失败: {}", name, e));
            assert_eq!(cfg.mode, name);
            assert_eq!(cfg.pad_mode, "bucket", "{} 配置的 pad_mode 未读入", name);
            assert!(!cfg.server.session_token, "{} 配置的 session_token 未读入", name);
            // Go 配置不含 workers / mtu / min_enc，缺省值必须与 flag 默认一致
            assert_eq!(cfg.workers, 0);
            assert_eq!(cfg.mtu, 0, "mtu 缺省应由 load_config_file 归一到 1500");
            assert!(cfg.min_enc.is_empty());
        }
    }

    #[test]
    fn go_config_files_parse_without_new_fields() {
        // 反向兼容：删掉三档新增字段（以及 web.cert/web.key）后同样可解析，
        // 即旧版 Rust 配置不被新字段污染。
        for (name, raw) in [("server", GO_SERVER_CONFIG), ("client", GO_CLIENT_CONFIG)] {
            let mut v: serde_json::Value = serde_json::from_str(raw).unwrap();
            let top = v.as_object_mut().unwrap();
            top.remove("pad_mode");
            top.remove("min_enc");
            if let Some(s) = top.get_mut("server").and_then(|s| s.as_object_mut()) {
                s.remove("session_token");
            }
            if let Some(w) = top.get_mut("web").and_then(|w| w.as_object_mut()) {
                w.remove("cert");
                w.remove("key");
            }
            let cfg = serde_json::from_value::<ConfigFile>(v)
                .unwrap_or_else(|e| panic!("Go {} 配置去字段后解析失败: {}", name, e));
            assert!(cfg.pad_mode.is_empty(), "{}: pad_mode 缺省应为空串", name);
            assert!(cfg.min_enc.is_empty(), "{}: min_enc 缺省应为空串", name);
            assert!(!cfg.server.session_token, "{}: session_token 缺省应为 false", name);
        }
    }

    #[test]
    fn config_file_still_rejects_unknown_fields() {
        // 兼容三档字段不是靠放开 deny_unknown_fields 实现的
        let raw = GO_SERVER_CONFIG.replace(
            "\"pad_mode\": \"bucket\",",
            "\"pad_mode\": \"bucket\", \"typo_key\": true,",
        );
        assert!(
            serde_json::from_str::<ConfigFile>(&raw).is_err(),
            "拼写错误的未知字段必须报错，否则配置静默失效"
        );
    }

    #[test]
    fn example_config_json_is_parseable() {
        // 模板本身就是最容易被改坏的配置样例
        let raw = example_config_json();
        let cfg = serde_json::from_str::<ConfigFile>(&raw)
            .unwrap_or_else(|e| panic!("--print-config 模板解析失败: {}", e));
        assert_eq!(cfg.mode, "client");
        assert_eq!(cfg.min_enc, "gcm");
        assert_eq!(cfg.pad_mode, "bucket");
        assert!(!cfg.server.session_token);
    }

    #[test]
    fn load_config_file_defaults_mtu_and_workers() {
        // Go 配置文件不含 mtu/workers；缺省必须取 flag 默认值而非 0
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tlsvpn-cfgtest-{}.json", std::process::id()));
        std::fs::write(&path, GO_CLIENT_CONFIG).unwrap();
        let args = load_config_file(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(args.mtu, 1500);
        assert_eq!(args.workers, 0);
        assert_eq!(args.conns, 4);
        assert_eq!(args.pad_mode, "bucket");
        assert!(args.min_enc.is_empty());
    }

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
  "min_enc": "gcm",
  "pad_mode": "bucket",
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
    "bind": "all",
    "cert": "",
    "key": ""
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
    "key": "",
    "session_token": false
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
