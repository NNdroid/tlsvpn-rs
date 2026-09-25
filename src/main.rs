use std::sync::atomic::Ordering;
use std::sync::Arc;
use tracing::{error, info, warn};

// mimalloc：每帧多次 malloc/free 的场景下比系统分配器快 10-20%
#[global_allocator]
static GLOBAL_ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

pub mod api;
pub mod buffer;
pub mod client;
pub mod client_state;
pub mod crypto;
pub mod fec;
pub mod frame;
pub mod hooks;
pub mod net;
pub mod server;
pub mod socks5;
pub mod tap;
pub mod utils;

use crate::api::{init_logging, RuntimeCtx};
use crate::buffer::*;
use crate::client::*;
use crate::server::*;

/// 运行时配置。config.json 是唯一配置面：本结构不再对接 clap，
/// 只由 load_config_file 从 ConfigFile 构造，server/client 按字段名消费。
#[derive(Debug, Clone, Default)]
pub struct Args {
    pub mode: String,
    pub psk: String,
    pub tap: String,
    pub mac: String,
    pub addr: String,
    pub loglevel: String,
    pub up: String,
    pub down: String,
    pub v4cidr: String,
    pub v6cidr: String,
    pub cert: String,
    pub key: String,
    pub req_v4: String,
    pub req_v6: String,
    pub sni: String,
    pub insecure: bool,
    pub cert_sha256: String,
    pub interface_manager: String,
    pub fwmark: i32,
    // 策略路由规则优先级（0 = 交给内核自动分配），与 extra_routes 一起描述
    // 客户端侧 fwmark 表的内容。
    pub fwmark_priority: i64,
    pub extra_routes: Vec<String>,
    // 按源地址前缀的规则，用于转发流量的回程路由（NPT 网关场景）
    pub source_rules: Vec<crate::net::SourceRule>,
    pub brutal: bool,
    pub brutal_up: u64,
    pub brutal_down: u64,
    pub conns: i32,
    pub fec: bool,
    pub fec_group: i64,
    pub web: String,
    pub web_auth: String,
    pub web_bind: String,
    // 面板 HTTPS 凭据：两者都非空时面板走 https，否则明文 http。
    // 只填一个视为配置错误（validate_args 挡下）。
    pub web_cert: String,
    pub web_key: String,
    pub encrypt: bool,
    pub enc_algo: String, // gcm256（默认）| gcm128（显式性能模式）
    // 配置文件里是否显式写了 encrypt。bool 无法自辨"字段缺失"与"显式 false"，
    // 靠这个标记让 main 能给运维一条明确提示。不参与任何运行时逻辑。
    pub encrypt_present: bool,
    pub socks5: String,
    pub workers: i32,
    pub mtu: u16,
    pub pad_mode: String,
    pub min_enc: String,
    pub max_sessions: i32,
    // 服务端接受的对端 FEC 分组大小 K 的区间（默认 = 协议边界，不额外限制）。
    // 越界的 FEC 请求按请求形态错误拒连，不夹取：见 server::handle_handshake。
    pub fec_group_min: i64,
    pub fec_group_max: i64,
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
    up: String,
    down: String,
    encrypt: bool,
    #[serde(default)]
    enc_algo: String,
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
    // 面板 HTTPS：两者都非空即启用（tiny_http ssl-rustls），只填一个报配置
    // 错误。留空 = 明文 HTTP，Go 的示例配置里恒有这两项所以必须能解析。
    cert: String,
    key: String,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ServerConfigFile {
    v4_cidr: String,
    v6_cidr: String,
    cert: String,
    key: String,
    // 并发会话数上限（0 = 默认 1024）。Go 示例配置恒含此字段：不声明的话
    // deny_unknown_fields 会让 -c 指向 Go 的 config.server.json 直接解析失败。
    #[serde(default)]
    max_sessions: i32,
    // 服务端接受的对端 FEC 分组大小 K 的区间（0 = 协议边界 [2,64]）。
    // 与 max_sessions 一样必须声明：Go 的示例配置恒含这两项，不声明的话
    // deny_unknown_fields 会让 -c 指向 Go 的 config.server.json 直接解析失败。
    #[serde(default)]
    fec_group_min: i64,
    #[serde(default)]
    fec_group_max: i64,
}

#[derive(serde::Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
struct ClientConfigFile {
    #[serde(default)]
    interface_manager: String,
    req_v4: String,
    req_v6: String,
    sni: String,
    insecure: bool,
    cert_sha256: String,
    fwmark: i32,
    // 策略路由规则优先级，0 = 交给内核自动分配。它和 extra_routes 都必须
    // 声明：Go 的示例配置恒含这两项，deny_unknown_fields 会让 -c 指向 Go 的
    // config.client.json 直接解析失败。
    #[serde(default)]
    fwmark_priority: i64,
    #[serde(default)]
    extra_routes: Vec<String>,
    #[serde(default)]
    source_rules: Vec<crate::net::SourceRule>,
    conns: i32,
    fec: bool,
    fec_group: i64,
}

/// 读取 JSON 配置并填充默认值（对齐 Go loadConfigFile + applyDefaults）
fn load_config_file(path: &str) -> Result<Args, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("read config: {}", e))?;

    // 唯一例外是 encrypt：bool 无法自辨"字段缺失"与"显式 false"，而这里
    // 是唯一还能看到原始 JSON 的地方。未写 encrypt 按开启处理——模板一直输出
    // true，省略字段若仍按零值 false 处理，整条链路会静默跑明文，与模板读起来
    // 完全相反。要显式关闭必须写 "encrypt": false。
    let mut raw_value: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("parse config {}: {}", path, e))?;
    let encrypt_present = raw_value
        .get("encrypt")
        .and_then(|e| e.as_bool())
        .is_some();

    // server.session_token 已从配置契约删除：resume token 是 protocol v2 的强制属性。
    // 升级时仍接受旧配置中的该键，但无论 true/false 都忽略；其余未知字段继续由
    // deny_unknown_fields 严格拒绝，避免拼写错误静默失效。
    if let Some(server) = raw_value
        .get_mut("server")
        .and_then(serde_json::Value::as_object_mut)
    {
        server.remove("session_token");
    }

    let mut cfg: ConfigFile =
        serde_json::from_value(raw_value).map_err(|e| format!("parse config {}: {}", path, e))?;

    // source_rules 的 from 要就地补全成带掩码的形式，安装逻辑才不用自己推断地址族；
    // 表号没有可推导的默认值，漏写必须在启动前报出来。放在这里而不是 validate_args
    // —— 校验要写回规范化结果，而 validate_args 只拿到 &Args。
    if cfg.mode == "client" {
        crate::net::validate_source_rules(&mut cfg.client.source_rules)
            .map_err(|e| format!("parse config {}: {}", path, e))?;
    }

    // 区间默认取协议边界，即未配置时不额外限制
    let (fec_group_min, fec_group_max) =
        crate::fec::normalize_fec_group_bounds(cfg.server.fec_group_min, cfg.server.fec_group_max);
    let mut args = Args {
        mode: cfg.mode.clone(),
        psk: cfg.psk,
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
        up: cfg.up,
        down: cfg.down,
        encrypt: if encrypt_present { cfg.encrypt } else { true },
        enc_algo: if (if encrypt_present { cfg.encrypt } else { true }) {
            if cfg.enc_algo.is_empty() { "gcm256".into() } else { cfg.enc_algo }
        } else {
            cfg.enc_algo
        },
        encrypt_present,
        pad_mode: cfg.pad_mode,
        min_enc: if (if encrypt_present { cfg.encrypt } else { true }) && cfg.min_enc.is_empty() {
            "gcm".into()
        } else {
            cfg.min_enc
        },
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
        web_cert: cfg.web.cert,
        web_key: cfg.web.key,
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
        // 0 = 默认 1024（对齐 Go applyDefaults）；客户端模式下该值无人消费
        max_sessions: if cfg.server.max_sessions == 0 {
            1024
        } else {
            cfg.server.max_sessions
        },
        fec_group_min,
        fec_group_max,
        req_v4: cfg.client.req_v4,
        req_v6: cfg.client.req_v6,
        sni: if cfg.client.sni.is_empty() {
            "www.cloudflare.com".into()
        } else {
            cfg.client.sni
        },
        insecure: cfg.client.insecure,
        cert_sha256: cfg.client.cert_sha256,
        interface_manager: if cfg.client.interface_manager.is_empty() {
            "self".into()
        } else {
            cfg.client.interface_manager
        },
        fwmark: cfg.client.fwmark,
        // 0 是"交给内核分配"的保留值，不做默认填充（对齐 Go applyDefaults）
        fwmark_priority: cfg.client.fwmark_priority,
        extra_routes: cfg.client.extra_routes,
        source_rules: cfg.client.source_rules,
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
    };
    if args.mode == "server" && args.addr.is_empty() {
        args.addr = "0.0.0.0:4000".into();
    }
    Ok(args)
}

/// 配置里给的路径必须是存在的普通文件。
///
/// 这类值（server.cert/key、web.cert/key）以前都是启动阶段才碰，坏值的表现
/// 是一个 panic（`Cannot open cert ...`）或者面板线程每 2 秒重试一次，
/// 都不如启动前一条说清楚哪个键、哪个文件、为什么的报错。
fn config_file_readable(label: &str, path: &str) -> Result<(), String> {
    match std::fs::metadata(path) {
        Ok(m) if m.is_file() => Ok(()),
        Ok(_) => Err(format!("{} is not a regular file: {}", label, path)),
        Err(e) => Err(format!("{} {} unreadable: {}", label, path, e)),
    }
}

fn validate_hook_path(name: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    if value.contains(['\0', '\r', '\n']) {
        return Err(format!("{} hook path contains control characters", name));
    }
    // Path::is_absolute follows the build host.  Accept a leading slash too so
    // Windows-side config tooling can validate a Linux deployment file.
    if !std::path::Path::new(value).is_absolute() && !value.starts_with('/') {
        return Err(format!("{} hook must be an absolute executable path", name));
    }
    Ok(())
}

fn validate_args(args: &Args) -> Result<(), String> {
    validate_hook_path("up", &args.up)?;
    validate_hook_path("down", &args.down)?;
    if args.brutal_up > crate::net::MAX_BRUTAL_RATE_MBPS
        || args.brutal_down > crate::net::MAX_BRUTAL_RATE_MBPS
    {
        return Err(format!(
            "brutal_up/brutal_down must not exceed {} Mbps",
            crate::net::MAX_BRUTAL_RATE_MBPS
        ));
    }
    if args.mode == "client" && args.conns > 65536 {
        return Err("client.conns must not exceed 65536".into());
    }
    // mode 闭集校验，文案与 Go Validate 逐字一致
    match args.mode.as_str() {
        "server" | "client" => {}
        "" => return Err("mode is required (server or client)".into()),
        other => {
            return Err(format!(
                "invalid mode {:?} (must be server or client)",
                other
            ))
        }
    }
    if args.addr.is_empty() {
        return Err("addr is required".into());
    }
    match args.psk.trim().to_ascii_lowercase().as_str() {
        "" => return Err("psk is required; generate a high-entropy random secret".into()),
        "quic_secret" | "change-me" | "change-me-please" | "replace-with-a-random-secret" => {
            return Err(
                "psk uses a known placeholder; replace it with a high-entropy random secret".into(),
            )
        }
        _ => {}
    }
    // log_level 是闭集（对齐 Go 的 zapcore.Level.UnmarshalText）。之前不校验，
    // 任意拼错的串都塞进 EnvFilter，只会得到「日志行为莫名变化」这种最难受的
    // 失败模式。校验假设 Args 已归一化（load_config_file 会给 "info"），
    // 与 Go Validate 只跑在 applyDefaults 之后的配置上保持一致。
    match args.loglevel.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => {}
        other => {
            return Err(format!(
                "invalid log_level {:?} (want trace, debug, info, warn or error)",
                other
            ))
        }
    }
    // mac 格式：只用于算 client_id 时拼错不会报错，静默变成另一台客户端。
    if !args.mac.is_empty() && !crate::utils::is_valid_session_mac(&args.mac) {
        return Err(format!(
            "invalid mac {:?} (want a non-zero unicast aa:bb:cc:dd:ee:ff address)",
            args.mac
        ));
    }
    // web.bind 闭集；未知值历史上会被当成 "all" 静默处理
    match args.web_bind.as_str() {
        "" | "all" | "tunnel" => {}
        other => return Err(format!("invalid web.bind {:?} (want all or tunnel)", other)),
    }
    // web.auth 必须带冒号。check_basic_auth 对非空串一律要求 Basic 头，
    // 写 "admin" 这种没有冒号的值会让面板对所有人 401。
    if !args.web_auth.is_empty() && !args.web_auth.contains(':') {
        return Err(format!(
            "invalid web.auth {:?} (want user:password)",
            args.web_auth
        ));
    }
    if args.web_auth.eq_ignore_ascii_case("admin:change-me")
        || args
            .web_auth
            .eq_ignore_ascii_case("admin:replace-with-a-random-password")
    {
        return Err("web.auth uses a known placeholder; replace it with a unique password".into());
    }
    if !args.web.is_empty() && args.web_auth.is_empty() {
        return Err("web.auth is required whenever the dashboard is enabled".into());
    }
    // web.cert / web.key：都空 = 明文 HTTP，都非空 = HTTPS，只填一个是错的
    // （tiny_http 需要一个成对的 SslConfig）。必须在启动前断掉：否则面板管理
    // 线程会在绑定阶段才发现读不到文件，每轮重试一次，面板一直起不来。
    let (has_cert, has_key) = (!args.web_cert.is_empty(), !args.web_key.is_empty());
    if has_cert != has_key {
        return Err(if has_cert {
            "web.key is required when web.cert is set".into()
        } else {
            "web.cert is required when web.key is set".into()
        });
    }
    if has_cert {
        if let Err(e) = config_file_readable("web.cert", &args.web_cert) {
            return Err(e);
        }
        if let Err(e) = config_file_readable("web.key", &args.web_key) {
            return Err(e);
        }
    }
    if !args.web.is_empty()
        && args.web_bind == "all"
        && crate::utils::web_addr_is_public(&args.web)
        && (!has_cert || !has_key)
    {
        return Err(
            "web.cert and web.key are required for a non-loopback dashboard listener".into(),
        );
    }
    if args.mode == "server" {
        // parse_v4_cidr / parse_v6_cidr 遇到不可解析的串会回落到默认网段，
        // 垃圾 CIDR 必须在这里断掉而不是变成悄悄换地址池（对齐 Go net.ParseCIDR）
        if !crate::utils::is_valid_cidr(&args.v4cidr, false) {
            return Err(format!("invalid server.v4_cidr {:?}", args.v4cidr));
        }
        if !crate::utils::is_valid_cidr(&args.v6cidr, true) {
            return Err(format!("invalid server.v6_cidr {:?}", args.v6cidr));
        }
        // 服务端 TLS 证书只校验配对：这个构建不会像 Go 那样留空自动生成自签
        // 证书，但示例配置里写的 server.crt/server.key 本来就是要用户先生成
        // 的，所以「文件存在性」留到实际加载时判，那里给的是可操作的报错。
        if args.cert.is_empty() != args.key.is_empty() {
            return Err(if args.cert.is_empty() {
                "server.key is set but server.cert is empty".into()
            } else {
                "server.cert is set but server.key is empty".into()
            });
        }
    }
    // 配置加载层强校验；set_pad_mode 的 bucket 回落只兜住面板热更路径
    if !crypto::pad_mode_valid(&args.pad_mode) {
        return Err(crypto::pad_mode_invalid_error(&args.pad_mode));
    }
    match args.enc_algo.as_str() {
        "" | "gcm256" | "gcm128" => {}
        _ => {
            return Err(format!(
                "invalid enc_algo {:?} (want gcm256 or gcm128)",
                args.enc_algo
            ))
        }
    }
    if !args.enc_algo.is_empty() && !args.encrypt {
        return Err(format!("enc_algo {:?} requires encrypt=true", args.enc_algo));
    }
    // min_enc 取大小写敏感的闭集；"any" 与空串等价（都等于不设下限）
    match args.min_enc.as_str() {
        "" | "any" | "gcm" => {}
        _ => return Err(crypto::min_enc_invalid_error(&args.min_enc)),
    }
    // 关着 encrypt 配 min_enc 是矛盾配置：没有内层加密谈何强度下限
    if !args.min_enc.is_empty() && !args.encrypt {
        return Err(format!("min_enc {:?} requires encrypt=true", args.min_enc));
    }
    if args.mode == "client" {
        // 直接构造 Args 的嵌入方/单元测试可能绕过 load_config_file；空值与 Go
        // applyDefaults 一样按 self 处理，只有显式请求未实现的 netifd 才拒绝。
        if !args.interface_manager.is_empty() && args.interface_manager != "self" {
            return Err(format!(
                "client.interface_manager {:?} is unsupported by tlsvpn-rs (want self)",
                args.interface_manager
            ));
        }
        if args.conns < 1 {
            return Err("client conns must be >= 1".into());
        }
        if !(2..=64).contains(&args.fec_group) {
            return Err("client fec_group must be in [2, 64]".into());
        }
        if args.fwmark < 0 {
            return Err("client fwmark must be >= 0".into());
        }
        // 0 是"交给内核分配"的保留值。上界写常量而不写字面量：对齐 Go 的
        // 32 位 int 溢出问题，字面量 4294967295 在某些平台直接编不过。
        if args.fwmark_priority < 0 || args.fwmark_priority > u32::MAX as i64 {
            return Err(format!(
                "client.fwmark_priority {} must be a uint32 in [0, 4294967295]",
                args.fwmark_priority
            ));
        }
        // 路由串在配置加载期就拦下来，而不是等隧道握手后才报 parse 失败。
        // source_rules 同理，但它的校验要写回规范化结果，所以在 load_config_file
        // 里做（validate_args 只有 &Args）。
        if let Err(e) = crate::net::validate_extra_routes(&args.extra_routes) {
            return Err(e);
        }
        if !args.cert_sha256.is_empty() {
            let cleaned = args.cert_sha256.replace(':', "").to_lowercase();
            if cleaned.len() != 64 || !cleaned.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err("client cert_sha256 must be 64 hex chars (sha256)".into());
            }
        }
        if args.insecure && !args.cert_sha256.is_empty() {
            return Err("client.insecure and client.cert_sha256 cannot be enabled together".into());
        }
    }
    // 上限是拒绝服务阀值：负数无意义，超大值等于关掉保护（对齐 Go Validate）
    if args.mode == "server" && !(0..=1 << 20).contains(&args.max_sessions) {
        return Err(format!(
            "server.max_sessions {} out of range [0, 1048576]",
            args.max_sessions
        ));
    }
    // FEC 分组策略区间：两端都必须落在协议允许范围内，且 min <= max
    // （错误文案与 Go Validate 逐字一致）。校验跑在归一化之后：Args::default()
    // 与绕过 load_config_file 的调用方都不会自己填默认值。
    if args.mode == "server" {
        let (lo, hi) = (
            crate::fec::FEC_MIN_GROUP as i64,
            crate::fec::FEC_MAX_GROUP as i64,
        );
        let (fec_group_min, fec_group_max) =
            crate::fec::normalize_fec_group_bounds(args.fec_group_min, args.fec_group_max);
        if fec_group_min < lo || fec_group_min > hi {
            return Err(format!(
                "server.fec_group_min {} must be in [{}, {}]",
                fec_group_min, lo, hi
            ));
        }
        if fec_group_max < lo || fec_group_max > hi {
            return Err(format!(
                "server.fec_group_max {} must be in [{}, {}]",
                fec_group_max, lo, hi
            ));
        }
        if fec_group_min > fec_group_max {
            return Err(format!(
                "server.fec_group_min {} must be <= fec_group_max {}",
                fec_group_min, fec_group_max
            ));
        }
    }
    Ok(())
}


/// 从 argv 提取配置文件路径：`-c path`、`--config path`、`--config=path`。
/// 除 --print-config 外这是唯一被识别的命令行面。
fn parse_config_arg() -> Option<String> {
    let argv: Vec<String> = std::env::args().collect();
    for (i, a) in argv.iter().enumerate() {
        if let Some(p) = a.strip_prefix("--config=") {
            return Some(p.to_string());
        }
        if a == "-c" || a == "--config" {
            return argv.get(i + 1).cloned();
        }
    }
    None
}

fn main() {
    // -print-config：输出示例 JSON 模板并退出（对齐 Go -print-config）
    if std::env::args().any(|a| a == "--print-config") {
        println!("{}", example_config_json());
        return;
    }

    // rustls 0.23 需要显式选择 crypto provider（ring：无 cmake/NASM 依赖）
    let _ = rustls::crypto::ring::default_provider().install_default();

    // config.json 是唯一配置面：-c 必填，其余参数一律来自 JSON 字段。
    let config_path = match parse_config_arg() {
        Some(p) => p,
        None => {
            eprintln!("Usage: tlsvpn -c config.json");
            eprintln!("       tlsvpn --print-config > config.json   # 生成模板后编辑");
            std::process::exit(2);
        }
    };
    let args = match load_config_file(&config_path) {
        Ok(a) => {
            println!("Loaded configuration from {}", config_path);
            a
        }
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // 校验必须先于 init_logging：log_level 本身就是被校验的字段，而
    // init_logging 拿它建过滤器。拼错的值会被 EnvFilter 当成「只接受名叫该串的
    // target」的指令，连下面这条报错都会被过滤掉——结果只剩一个无声的非零退出
    // 码，用户完全不知道哪里错了（e2e 的 cfg badlog 用例就是这样发现的）。
    if let Err(e) = validate_args(&args) {
        eprintln!("Invalid configuration: {}", e);
        std::process::exit(1);
    }

    init_logging(&args.loglevel);

    if !args.encrypt_present {
        warn!(
            "Config does not set 'encrypt'; defaulting to enabled. Write \"encrypt\": false to run without inner encryption"
        );
    }

    lazy_static::initialize(&PADDING_CACHE);

    if args.psk == "quic_secret" {
        tracing::warn!("⚠️  PSK is the default value — change it in the config file!");
    }

    // 面板安全提示：绑了对外地址、又没开认证、也没上 HTTPS 时明确告警。对齐
    // Go main.go 的同一条检查——只告警不拒绝，内网测试盒子确实常这么配。
    // 只告一次、只在启动时：面板地址是启动参数，运行中不会变。
    if !args.web.is_empty()
        && args.web_auth.is_empty()
        && (args.web_cert.is_empty() || args.web_key.is_empty())
        && crate::utils::web_addr_is_public(&args.web)
    {
        warn!(
            "⚠️  Web dashboard binds a non-loopback address ({}) without auth and without HTTPS. Consider web.auth in the config.",
            args.web
        );
    }

    // 填充策略全局生效（发送路径读取），面板可热更。
    // 空串 = 默认 bucket（对齐 Go Config.applyDefaults）。
    let pad_cfg = if args.pad_mode.is_empty() {
        crypto::PAD_MODE_BUCKET
    } else {
        args.pad_mode.as_str()
    };
    let pad_actual = crypto::set_pad_mode(pad_cfg);
    if pad_actual != pad_cfg {
        warn!("Invalid pad_mode {:?}, using {}", args.pad_mode, pad_actual);
    } else {
        info!("Confusion padding: {}", pad_actual);
    }

    install_signal_handler();

    // 填在错的模式里就等于白填：不会报错，只是静默不起作用。只对「填了且非
    // 默认值」的项提示，默认值说明配置里根本没写，不值得刷一条 warning。
    let mut ignored = Vec::new();
    if args.mode == "server" {
        if !args.req_v4.is_empty() {
            ignored.push("client.req_v4");
        }
        if !args.req_v6.is_empty() {
            ignored.push("client.req_v6");
        }
        if args.sni != "www.cloudflare.com" {
            ignored.push("client.sni");
        }
        if args.insecure {
            ignored.push("client.insecure");
        }
        if !args.cert_sha256.is_empty() {
            ignored.push("client.cert_sha256");
        }
        if args.fwmark != 0 {
            ignored.push("client.fwmark");
        }
        if args.fwmark_priority != 0 {
            ignored.push("client.fwmark_priority");
        }
        if !args.extra_routes.is_empty() {
            ignored.push("client.extra_routes");
        }
        if !args.source_rules.is_empty() {
            ignored.push("client.source_rules");
        }
        if args.conns != 1 {
            ignored.push("client.conns");
        }
        if args.fec {
            ignored.push("client.fec");
        }
        if args.fec_group != 4 {
            ignored.push("client.fec_group");
        }
    } else if args.mode == "client" {
        if args.v4cidr != "10.0.0.0/24" {
            ignored.push("server.v4_cidr");
        }
        if args.v6cidr != "fd00::/64" {
            ignored.push("server.v6_cidr");
        }
        if !args.cert.is_empty() {
            ignored.push("server.cert");
        }
        if !args.key.is_empty() {
            ignored.push("server.key");
        }
        if args.max_sessions != 1024 {
            ignored.push("server.max_sessions");
        }
        if args.fec_group_min != crate::fec::FEC_MIN_GROUP as i64 {
            ignored.push("server.fec_group_min");
        }
        if args.fec_group_max != crate::fec::FEC_MAX_GROUP as i64 {
            ignored.push("server.fec_group_max");
        }
    }
    if !ignored.is_empty() {
        warn!(
            "ignored (mode={} has no effect on them): {}",
            args.mode,
            ignored.join(", ")
        );
    }

    let run_result = match args.mode.as_str() {
        "server" => {
            start_server(
                &args,
                &config_path,
                Arc::new(RuntimeCtx::from_args(&args, &config_path)),
            )
        }
        "client" => {
            start_client(
                &args,
                &config_path,
                Arc::new(RuntimeCtx::from_args(&args, &config_path)),
            )
        }
        other => {
            Err(format!(
                "Invalid configuration: unknown mode {:?} (want \"server\" or \"client\")",
                other
            ))
        }
    };
    if let Err(e) = run_result {
        error!("{}", e);
        std::process::exit(1);
    }
    tracing::info!("Program exited gracefully.");
}

fn install_signal_handler() {
    ctrlc::set_handler(|| {
        if EXIT.swap(true, Ordering::SeqCst) {
            tracing::error!("Received a second termination signal; forcing exit");
            std::process::exit(130);
        }
        tracing::info!("Received termination signal, shutting down...");
    })
    .ok();
}

#[cfg(test)]
mod tests {
    use crate::crypto::*;
    use crate::frame::*;
    use crate::{example_config_json, load_config_file, validate_args, Args, ConfigFile};
    use std::io::Read;
    use std::time::Instant;

    #[test]
    fn lifecycle_hook_paths_must_be_absolute() {
        assert!(super::validate_hook_path("up", "relative.sh").is_err());
        assert!(super::validate_hook_path("up", "/etc/openvpn/up.sh").is_ok());
        assert!(super::validate_hook_path("down", "").is_ok());
        assert!(super::validate_hook_path("down", "/tmp/bad\npath").is_err());
    }

    // ---------- 配置文件兼容性（与 Go 仓库 config.*.json 逐字段对齐） ----------

    // Go 仓库 config.server.json 的原样内容
    const GO_SERVER_CONFIG: &str = r#"{
  "mode": "server",
  "psk": "test-only-high-entropy-secret-4e390397818f",
  "addr": ":4000",
  "log_level": "info",
  "up": "",
  "down": "",
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
    "auth": "admin:test-only-password-9b9f5d25",
    "cert": "",
    "key": ""
  },
  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "max_sessions": 1024
  }
}
"#;

    // Go 仓库 config.client.json 的原样内容
    const GO_CLIENT_CONFIG: &str = r#"{
  "mode": "client",
  "psk": "test-only-high-entropy-secret-4e390397818f",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "up": "",
  "down": "",
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
    "auth": "admin:test-only-password-9b9f5d25",
    "cert": "",
    "key": ""
  },
  "client": {
    "interface_manager": "self",
    "conns": 4,
    "fec": true,
    "fec_group": 4,
    "sni": "www.cloudflare.com",
    "insecure": false,
    "cert_sha256": "",
    "req_v4": "",
    "req_v6": "",
    "fwmark": 0,
    "fwmark_priority": 0,
    "extra_routes": [],
    "source_rules": []
  }
}
"#;

    #[test]
    fn go_config_files_parse_verbatim() {
        // Go 的当前配置文件必须能被 Rust 原样读入（含 pad_mode / web.cert /
        // web.key），否则 -c 指向 Go 配置时启动直接失败。
        for (name, raw) in [("server", GO_SERVER_CONFIG), ("client", GO_CLIENT_CONFIG)] {
            let cfg = serde_json::from_str::<ConfigFile>(raw)
                .unwrap_or_else(|e| panic!("Go {} 配置解析失败: {}", name, e));
            assert_eq!(cfg.mode, name);
            if name == "client" {
                assert_eq!(cfg.client.interface_manager, "self");
            }
            assert_eq!(cfg.pad_mode, "bucket", "{} 配置的 pad_mode 未读入", name);
            // Go 配置不含 workers / mtu / min_enc，缺省值必须与 flag 默认一致
            assert_eq!(cfg.workers, 0);
            assert_eq!(cfg.mtu, 0, "mtu 缺省应由 load_config_file 归一到 1500");
            assert!(cfg.min_enc.is_empty());
            // 会话上限是 Go 加固版配置的新字段；server 配置给了 1024，
            // client 配置没有该字段（缺省 0 = 加载后归一为 1024）
            assert_eq!(
                cfg.server.max_sessions,
                if name == "server" { 1024 } else { 0 },
                "{} 配置的 max_sessions 未按预期读入",
                name
            );
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
                s.remove("max_sessions");
            }
            if let Some(c) = top.get_mut("client").and_then(|c| c.as_object_mut()) {
                c.remove("interface_manager");
            }
            if let Some(w) = top.get_mut("web").and_then(|w| w.as_object_mut()) {
                w.remove("cert");
                w.remove("key");
            }
            let cfg = serde_json::from_value::<ConfigFile>(v)
                .unwrap_or_else(|e| panic!("Go {} 配置去字段后解析失败: {}", name, e));
            assert!(cfg.pad_mode.is_empty(), "{}: pad_mode 缺省应为空串", name);
            assert!(cfg.min_enc.is_empty(), "{}: min_enc 缺省应为空串", name);
            assert_eq!(
                cfg.server.max_sessions, 0,
                "{}: max_sessions 缺省应为 0",
                name
            );
        }
    }

    #[test]
    fn interface_manager_defaults_to_self_and_rejects_netifd() {
        let mut without = serde_json::from_str::<serde_json::Value>(GO_CLIENT_CONFIG).unwrap();
        without["client"].as_object_mut().unwrap().remove("interface_manager");

        let dir = std::env::temp_dir();
        let path = dir.join(format!("tlsvpn-interface-manager-{}.json", std::process::id()));
        std::fs::write(&path, serde_json::to_vec(&without).unwrap()).unwrap();
        let args = load_config_file(path.to_str().unwrap()).unwrap();
        assert_eq!(args.interface_manager, "self");

        let mut netifd = serde_json::from_str::<serde_json::Value>(GO_CLIENT_CONFIG).unwrap();
        netifd["client"]["interface_manager"] = serde_json::json!("netifd");
        std::fs::write(&path, serde_json::to_vec(&netifd).unwrap()).unwrap();
        let args = load_config_file(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        let err = validate_args(&args).unwrap_err();
        assert!(err.contains("unsupported by tlsvpn-rs"), "unexpected error: {err}");
    }

    #[test]
    fn max_sessions_default_and_validation_match_go() {
        // 0 = 默认 1024；越界值直接拒绝（对齐 Go applyDefaults + Validate）
        for given in [0i32, 42, 1048576] {
            let dir = std::env::temp_dir();
            let path = dir.join(format!("tlsvpn-ms-{}-{}.json", std::process::id(), given));
            let raw = GO_SERVER_CONFIG.replace(
                "\"max_sessions\": 1024",
                &format!("\"max_sessions\": {}", given),
            );
            std::fs::write(&path, &raw).unwrap();
            let args = load_config_file(path.to_str().unwrap()).unwrap();
            let _ = std::fs::remove_file(&path);
            let want = if given == 0 { 1024 } else { given };
            assert_eq!(
                args.max_sessions, want,
                "max_sessions={} 应归一为 {}",
                given, want
            );
            assert!(
                validate_args(&args).is_ok(),
                "max_sessions={} 应通过校验",
                given
            );
        }

        // Args::default() 未经归一化，这里补齐 load_config_file 会给的默认值
        let mut a = Args::default();
        a.mode = "server".into();
        a.psk = "test-only-high-entropy-secret-4e390397818f".into();
        a.addr = "0.0.0.0:4000".into();
        a.loglevel = "info".into();
        a.v4cidr = "10.0.0.0/24".into();
        a.v6cidr = "fd00::/64".into();
        assert!(validate_args(&a).is_ok(), "flag 默认值应通过校验");
        for bad in [-1i32, (1 << 20) + 1] {
            a.max_sessions = bad;
            assert!(validate_args(&a).is_err(), "max_sessions={} 应被拒绝", bad);
        }
        a.max_sessions = 0;
        assert!(validate_args(&a).is_ok(), "max_sessions=0（默认）应放行");
        // 客户端模式下该字段不参与校验（Go Validate 同样只在 server 分支检查）
        a.mode = "client".into();
        a.conns = 4;
        a.fec_group = 4;
        a.max_sessions = -1;
        assert!(validate_args(&a).is_ok(), "client 模式不校验 max_sessions");
    }

    #[test]
    fn fec_group_policy_default_and_validation_match_go() {
        // Go 配置样例里没写这两个键：解析必须通过并落到协议边界。
        // 这也是 deny_unknown_fields 的镜像要求——新增键若未声明，Go 的配置
        // 文件会被整个拒掉。
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tlsvpn-fec-absent-{}.json", std::process::id()));
        std::fs::write(&path, GO_SERVER_CONFIG).unwrap();
        let args = load_config_file(path.to_str().unwrap()).unwrap();
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            (args.fec_group_min, args.fec_group_max),
            (2, 64),
            "缺省应为协议边界，即未配置时不额外限制"
        );
        assert!(validate_args(&args).is_ok(), "缺省区间应通过校验");

        for (min, max) in [(0i32, 0), (4, 8), (2, 64), (32, 32)] {
            let path = dir.join(format!(
                "tlsvpn-fec-{}-{}-{}.json",
                std::process::id(),
                min,
                max
            ));
            let raw = GO_SERVER_CONFIG.replace(
                "\"max_sessions\": 1024",
                &format!(
                    "\"max_sessions\": 1024,\n    \"fec_group_min\": {},\n    \"fec_group_max\": {}",
                    min, max
                ),
            );
            std::fs::write(&path, &raw).unwrap();
            let args = load_config_file(path.to_str().unwrap()).unwrap();
            let _ = std::fs::remove_file(&path);
            let want: (i64, i64) = (
                if min == 0 { 2 } else { min as i64 },
                if max == 0 { 64 } else { max as i64 },
            );
            assert_eq!(
                (args.fec_group_min, args.fec_group_max),
                want,
                "[{} {}] 应归一为 {:?}",
                min, max, want
            );
            assert!(
                validate_args(&args).is_ok(),
                "fec_group {:?} 应通过校验",
                want
            );
        }

        // Args::default() 未经归一化，两个端点都是 0；validate_args 内部自行归一，
        // 因此 flag 默认路径不需要调用方先填边界。
        let mut a = Args::default();
        a.mode = "server".into();
        a.psk = "test-only-high-entropy-secret-4e390397818f".into();
        a.addr = "0.0.0.0:4000".into();
        a.loglevel = "info".into();
        a.v4cidr = "10.0.0.0/24".into();
        a.v6cidr = "fd00::/64".into();
        assert!(validate_args(&a).is_ok(), "flag 默认值应通过校验");
        for (min, max) in [(-1i64, 8), (1, 8), (4, 65), (9, 4), (4, -1)] {
            a.fec_group_min = min;
            a.fec_group_max = max;
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("fec_group"),
                "fec_group [{} {}] 的报错应指名该字段，实际: {}",
                min,
                max,
                err
            );
        }
        // 客户端模式下这是服务端策略，不参与校验
        a.mode = "client".into();
        a.conns = 4;
        a.fec_group = 4;
        a.fec_group_min = -1;
        a.fec_group_max = 65;
        assert!(validate_args(&a).is_ok(), "client 模式不校验 fec 策略区间");
    }

    #[test]
    fn legacy_session_token_is_accepted_but_ignored() {
        for legacy in [false, true] {
            let mut v: serde_json::Value = serde_json::from_str(GO_SERVER_CONFIG).unwrap();
            v["server"]["session_token"] = serde_json::json!(legacy);
            let dir = std::env::temp_dir();
            let path = dir.join(format!(
                "tlsvpn-legacy-session-token-{}-{}.json",
                std::process::id(),
                legacy
            ));
            std::fs::write(&path, serde_json::to_vec(&v).unwrap()).unwrap();
            let args = load_config_file(path.to_str().unwrap())
                .unwrap_or_else(|e| panic!("legacy session_token={} rejected: {}", legacy, e));
            let _ = std::fs::remove_file(&path);
            assert_eq!(args.mode, "server");
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
        assert_eq!(cfg.enc_algo, "");
        assert_eq!(cfg.min_enc, "gcm");
        assert_eq!(cfg.pad_mode, "bucket");
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
        assert_eq!(args.enc_algo, "gcm256");
        assert_eq!(args.min_enc, "gcm");
    }

    #[test]
    fn encrypt_defaults_to_true_when_absent() {
        // 未写 encrypt 必须按开启处理：-print-config 模板一直输出 true，省略
        // 字段若仍按 Go 零值 false 处理，整条链路会静默跑明文，与模板读起来
        // 完全相反。要显式关闭必须写 "encrypt": false。
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tlsvpn-enc-{}.json", std::process::id()));
        let cases = [
            (
                r#"{"mode":"client","psk":"x","addr":"1.2.3.4:1"}"#,
                false,
                true,
            ),
            (
                r#"{"mode":"client","psk":"x","addr":"1.2.3.4:1","encrypt":true}"#,
                true,
                true,
            ),
            (
                r#"{"mode":"client","psk":"x","addr":"1.2.3.4:1","encrypt":false}"#,
                true,
                false,
            ),
        ];
        for (json, want_present, want_encrypt) in cases {
            std::fs::write(&path, json).unwrap();
            let args = load_config_file(path.to_str().unwrap()).unwrap();
            assert_eq!(
                args.encrypt_present, want_present,
                "encrypt 存在性判断不符: {}",
                json
            );
            assert_eq!(
                args.encrypt, want_encrypt,
                "encrypt 归一化结果不符: {}",
                json
            );
        }
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn min_enc_validation_matches_go() {
        // Args::default() 未经归一化，log_level 显式给默认值
        let mut a = Args::default();
        a.mode = "client".into();
        a.psk = "test-only-high-entropy-secret-4e390397818f".into();
        a.addr = "127.0.0.1:1".into();
        a.loglevel = "info".into();
        a.conns = 4;
        a.fec_group = 4;
        a.encrypt = true;

        // 闭集取值全部放行
        for v in ["", "any", "gcm"] {
            a.min_enc = v.into();
            assert!(
                validate_args(&a).is_ok(),
                "min_enc {:?} + encrypt=true 应放行",
                v
            );
        }

        // 随旧协议兼容一并移除的档位：现在必须被拒绝，不能被静默接受成"无下限"
        for v in ["ctr", "legacy"] {
            a.min_enc = v.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("invalid min_enc"),
                "min_enc {:?} 已随旧算法移除，必须被拒绝，实际: {}",
                v,
                err
            );
        }

        // 大小写敏感（Go Validate 的 switch 区分大小写）
        a.min_enc = "GCM".into();
        let err = validate_args(&a).unwrap_err();
        assert!(
            err.contains("invalid min_enc"),
            "min_enc \"GCM\" 应被拒绝（Go 侧同样拒绝），实际: {}",
            err
        );

        // 非法值
        a.min_enc = "bogus".into();
        assert!(validate_args(&a).is_err(), "min_enc \"bogus\" 应被拒绝");

        // encrypt=false 时不允许配置 min_enc
        a.encrypt = false;
        a.min_enc = "gcm".into();
        let err = validate_args(&a).unwrap_err();
        assert!(
            err.contains("requires encrypt=true"),
            "encrypt=false 配 min_enc 应报错，实际: {}",
            err
        );
        // 空串例外：无下限不需要 encrypt
        a.min_enc = String::new();
        assert!(
            validate_args(&a).is_ok(),
            "min_enc 空串 + encrypt=false 是旧版行为，必须放行"
        );
    }

    /// 回归：这些字段历史上要么完全无效，要么无效值被静默降级。
    /// 校验必须落在配置加载层，而不是运行时悄悄出错。
    #[test]
    fn validate_args_rejects_garbage_in_previously_ignored_fields() {
        // 合法基线：client 模式不需要地址池，v4/v6 cidr 留空即可。
        // validate_args 假设 Args 已归一化，所以 log_level 显式给默认值。
        let mut a = Args::default();
        a.mode = "client".into();
        a.psk = "test-only-high-entropy-secret-4e390397818f".into();
        a.addr = "10.0.0.1:4000".into();
        a.loglevel = "info".into();
        a.conns = 1;
        a.fec_group = 4;
        a.max_sessions = 1024;
        assert!(validate_args(&a).is_ok(), "基线配置应通过校验");

        // log_level 闭集（大小写不敏感，与 Go 一致地要求非空）
        for good in ["trace", "Debug", "INFO", "warn", "error"] {
            a.loglevel = good.into();
            assert!(validate_args(&a).is_ok(), "log_level {:?} 应通过校验", good);
        }
        for bad in ["", "verbose", "information", "tracee", " ", "infox", "off"] {
            a.loglevel = bad.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("invalid log_level"),
                "log_level {:?} 应被拒绝，实际: {}",
                bad,
                err
            );
        }

        // mac：空串合法（未设置），其余必须是 aa:bb:cc:dd:ee:ff
        a.loglevel = "info".into();
        for good in ["", "00:1a:2b:3c:4d:5e", "AA:BB:CC:DD:EE:FF"] {
            a.mac = good.into();
            assert!(validate_args(&a).is_ok(), "mac {:?} 应通过校验", good);
        }
        for bad in [
            "00:1a:2b:3c:4d:5",
            "00:1a:2b:3c:4d:5e:6f",
            "zz:11:22:33:44:55",
            "00-1a-2b-3c-4d-5e",
            "001a2b3c4d5e",
            "1",
        ] {
            a.mac = bad.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("invalid mac"),
                "mac {:?} 应被拒绝，实际: {}",
                bad,
                err
            );
        }
        a.mac = String::new();

        // web.auth：非空时必须带冒号，否则面板对所有人 401。
        // "a:b:c" 和 ":" 与 Go ensureBasicAuthFormat 一致地放行（只看有没有冒号）。
        for good in ["", "admin:secret", "a:b:c", ":"] {
            a.web_auth = good.into();
            assert!(validate_args(&a).is_ok(), "web.auth {:?} 应通过校验", good);
        }
        for bad in ["admin", " admin", "secret ", "nopass"] {
            a.web_auth = bad.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("invalid web.auth"),
                "web.auth {:?} 应被拒绝，实际: {}",
                bad,
                err
            );
        }
        a.web_auth = String::new();

        // web.bind 闭集：未知值历史上会被当成 "all"
        for good in ["", "all", "tunnel"] {
            a.web_bind = good.into();
            assert!(validate_args(&a).is_ok(), "web.bind {:?} 应通过校验", good);
        }
        for bad in ["Any", "TUNNEL", "tunnel:", "all ", "tunnels"] {
            a.web_bind = bad.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("invalid web.bind"),
                "web.bind {:?} 应被拒绝，实际: {}",
                bad,
                err
            );
        }
        a.web_bind = String::new();

        // server 地址池：垃圾 CIDR 历史上被静默回落到默认网段
        a.mode = "server".into();
        a.addr = "0.0.0.0:4000".into();
        for (v4, v6, good) in [
            ("10.0.0.0/24", "fd00::/64", true),
            ("192.168.1.1", "::ffff:10.0.0.0/120", true),
            ("10.0.0.0/32", "fd00::/128", true),
            ("10.0.0.0/33", "fd00::/64", false),
            ("not-a-cidr", "fd00::/64", false),
            ("10.0.0.0/24", "fd00::zzz/64", false),
            ("10.0.0.0/24", "10.0.0.0/24", false),
            ("10.0.0.0/24", "fd00::", true),
        ] {
            a.v4cidr = v4.into();
            a.v6cidr = v6.into();
            if good {
                assert!(validate_args(&a).is_ok(), "v4={v4:?} v6={v6:?} 应通过校验");
            } else {
                let err = validate_args(&a).unwrap_err();
                assert!(
                    err.contains("invalid server."),
                    "v4={v4:?} v6={v6:?} 应被拒绝，实际: {}",
                    err
                );
            }
        }
        // client 模式不校验地址池（Go Validate 同样只在 server 分支检查）
        a.mode = "client".into();
        assert!(validate_args(&a).is_ok(), "client 模式不校验 v4/v6_cidr");

        // web.cert / web.key 只填一个是错的：tiny_http 需要一个成对的 SslConfig，
        // 拆开填只会让面板监听永远起不来
        for (c, k) in [("only.crt", ""), ("", "only.key")] {
            a.web_cert = c.into();
            a.web_key = k.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.contains("required when"),
                "web 证书/私钥只填一个应被拒绝（cert={c:?} key={k:?}），实际: {err}"
            );
            a.web_cert = String::new();
            a.web_key = String::new();
        }
        // 示例配置里这两个键恒为空串 = 明文 HTTP，必须放行
        assert!(
            validate_args(&a).is_ok(),
            "web 证书都空应放行（面板走 HTTP）"
        );

        // server.cert / server.key 同样只校验配对：示例配置里的 server.crt /
        // server.key 本来就是要用户先 openssl 生成的，所以「文件存在性」留给
        // 加载期判，那里给的是能告诉用户怎么办的一条报错而不是 panic。
        a.mode = "server".into();
        a.addr = "0.0.0.0:4000".into();
        for (c, k) in [("only.crt", ""), ("", "only.key")] {
            a.cert = c.into();
            a.key = k.into();
            let err = validate_args(&a).unwrap_err();
            assert!(
                err.starts_with("server.") && err.contains("empty"),
                "server 证书/私钥只填一个应被拒绝（cert={c:?} key={k:?}），实际: {err}"
            );
            a.cert = String::new();
            a.key = String::new();
        }
        assert!(
            validate_args(&a).is_ok(),
            "server 证书都空应放行（加载期再报缺证书）"
        );
    }

    #[test]
    fn validate_args_rejects_brutal_kernel_and_connection_overflow() {
        let mut args = Args::default();
        args.mode = "client".into();
        args.psk = "test-only-high-entropy-secret-4e390397818f".into();
        args.addr = "10.0.0.1:4000".into();
        args.loglevel = "info".into();
        args.conns = 1;
        args.fec_group = 4;
        args.max_sessions = 1024;
        args.brutal_up = crate::net::MAX_BRUTAL_RATE_MBPS + 1;
        assert!(validate_args(&args).unwrap_err().contains("brutal_up/brutal_down"));

        args.brutal_up = 100;
        args.conns = 65537;
        assert!(validate_args(&args).unwrap_err().contains("client.conns"));
    }

    struct InfiniteReader {
        data: Vec<u8>,
        pos: usize,
    }

    impl Read for InfiniteReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let available = self.data.len() - self.pos;
            let to_copy = std::cmp::min(buf.len(), available);
            buf[..to_copy].copy_from_slice(&self.data[self.pos..self.pos + to_copy]);
            self.pos += to_copy;
            if self.pos >= self.data.len() {
                self.pos = 0;
            }
            Ok(to_copy)
        }
    }

    #[test]
    #[ignore = "benchmark: long-running (1M iterations); run with `cargo test -- --ignored`"]
    fn bench_protocol_throughput() {
        let ic = InnerCipher::gcm("benchmark_secret_key", &[7u8; ENC_SALT_SIZE])
            .expect("gcm init");
        let payload = vec![0u8; 1400];

        let mut frame_buf = Vec::new();
        append_padded_frame(&mut frame_buf, 1, &payload, Some(&ic));

        let mut scanner = FrameScanner::new();
        let mut reader = InfiniteReader {
            data: frame_buf.clone(),
            pos: 0,
        };

        let iter_count = 1_000_000;
        let start = Instant::now();
        for _ in 0..iter_count {
            let (mut data, seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
            let wire_len = data.len() as u32;
            ic.open_in_place(&mut data, seq, wire_len).unwrap();
            crate::buffer::release_frame_vec(data);
        }
        let elapsed = start.elapsed().as_secs_f64();
        let total_bytes = (iter_count as f64) * (payload.len() as f64);
        let mb_per_sec = (total_bytes / 1024.0 / 1024.0) / elapsed;
        println!("Protocol Throughput: {:.2} MB/s", mb_per_sec);
    }
}

/// 与 Go 端 exampleConfigJSON 逐字段一致的模板（两端配置文件可互换）
/// -print-config 模板。刻意只放 Go/Rust 都能解析的字段：workers 和 mtu 是
/// Rust 专属配置项，Go 用 json.Decoder.DisallowUnknownFields，模板里出现
/// 它们就等于 --print-config 的输出在 Go 版上直接解析失败。要调就自己加。
fn example_config_json() -> &'static str {
    r#"{
  "mode": "client",
  "psk": "REPLACE-WITH-A-RANDOM-SECRET",
  "addr": "203.0.113.10:4000,[2001:db8::10]:4000",
  "log_level": "info",
  "up": "",
  "down": "",
  "encrypt": true,
  "min_enc": "gcm",
  "pad_mode": "bucket",
  "brutal": true,
  "brutal_up": 100,
  "brutal_down": 500,
  "socks5": "",
  "tap": "tap0",
  "mac": "",
  "web": {
    "addr": ":8080",
    "auth": "admin:REPLACE-WITH-A-RANDOM-PASSWORD",
    "bind": "tunnel",
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
    "fwmark": 0,
    "fwmark_priority": 0,
    "extra_routes": [],
    "source_rules": []
  },
  "server": {
    "v4_cidr": "10.0.0.0/24",
    "v6_cidr": "fd00::/64",
    "cert": "",
    "key": "",
    "max_sessions": 1024
  }
}"#
}

// ---------- 仓库根目录的示例配置 ----------

#[test]
fn example_configs_in_repo_root_load_and_validate() {
    // config.server.json / config.client.json 是用户克隆后直接 -c 的起点，
    // 必须原样通过加载（deny_unknown_fields）+ 校验，否则示例即失效。
    let mut psks = Vec::new();
    for (file, mode) in [
        ("config.server.json", "server"),
        ("config.client.json", "client"),
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(file);
        let mut args = load_config_file(path.to_str().unwrap())
            .unwrap_or_else(|e| panic!("{} 加载失败: {}", file, e));
        assert!(
            validate_args(&args).is_err(),
            "{} 的占位凭据必须阻止直接启动",
            file
        );
        args.psk = "test-only-high-entropy-secret-4e390397818f".into();
        args.web_auth = "admin:test-only-password-9b9f5d25".into();
        validate_args(&args).unwrap_or_else(|e| panic!("{} 校验失败: {}", file, e));
        assert_eq!(args.mode, mode, "{} 的 mode 不对", file);
        assert_eq!(args.pad_mode, "bucket", "{} 的 pad_mode 未按模板", file);
        assert_eq!(args.mtu, 1500, "{} 未声明 mtu，应取默认 1500", file);
        assert_eq!(
            args.workers, 0,
            "{} 未声明 workers，应取默认（自动按 CPU 核数）",
            file
        );
        psks.push(args.psk);
    }
    // 两份示例的 psk 必须一致，否则开箱即不通
    assert_eq!(psks[0], psks[1], "server/client 示例的 psk 不一致");
}
