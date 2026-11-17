//! MCP 端点认证（对齐 Go mcp_auth.go）。
//!
//! 6 种认证模式：inherit_web | none | basic | bearer | api_key | oauth_jwt。
//! MCP 共享 Web listener/TLS/port，但可用与 dashboard 不同的认证策略。
//! 认证失败也入访问日志：谁在撞路径、撞凭据是公网暴露面最重要的审计信号。
//!
//! 凭据统一归一为不可重放的 sha256 verifier（`sha256:<hex>`）存储/比较，
//! 绝不明文落盘。API key header 默认 X-API-Key；deploy 决定在哪个 listener
//! 服务 MCP；path 是秘密材料的一部分（空则加载时生成随机 80bit 路径）。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use base64ct::Encoding;
use crate::api::ct_eq;
use crate::mcp_access::McpAccessLine;

pub const MCP_AUTH_INHERIT_WEB: &str = "inherit_web";
pub const MCP_AUTH_NONE: &str = "none";
pub const MCP_AUTH_BASIC: &str = "basic";
pub const MCP_AUTH_BEARER: &str = "bearer";
pub const MCP_AUTH_API_KEY: &str = "api_key";
pub const MCP_AUTH_OAUTH_JWT: &str = "oauth_jwt";

pub const MCP_DEPLOY_INTERNAL: &str = "internal";
pub const MCP_DEPLOY_PUBLIC: &str = "public";
pub const MCP_DEPLOY_BOTH: &str = "both";

const MCP_CREDENTIAL_HASH_PREFIX: &str = "sha256:";
pub const MCP_DEFAULT_API_KEY_HEADER: &str = "X-API-Key";
const MCP_AUTH_THROTTLE_MAX: usize = 10;
const MCP_AUTH_THROTTLE_WIN: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Default)]
pub struct McpOAuthJwtConfig {
    pub jwks_url: String,
    pub issuer: String,
    pub audience: String,
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub required_scopes: Vec<String>,
}

/// 运行时 MCP 配置（从配置文件转换 + apply_defaults；对齐 Go MCPConfig）。
#[derive(Clone, Debug, Default)]
pub struct McpAuthConfig {
    pub auth_mode: String,
    pub username: String,
    /// 归一化的 `sha256:<hex>` verifier（空=未配置）。
    pub credential_hash: String,
    pub api_key_header: String,
    pub deploy: String,
    pub path: String,
    pub oauth: McpOAuthJwtConfig,
}

impl McpAuthConfig {
    /// 从配置文件字段构造并应用默认值（对齐 Go applyDefaults）。
    pub fn from_file(
        auth_mode: &str,
        username: &str,
        credential: &str,
        api_key_header: &str,
        deploy: &str,
        path: &str,
        oauth: &McpOAuthJwtConfig,
    ) -> Self {
        let mut cfg = Self {
            auth_mode: normalize_auth_mode(auth_mode),
            username: username.to_string(),
            credential_hash: normalize_static_credential(credential),
            api_key_header: if api_key_header.trim().is_empty() {
                MCP_DEFAULT_API_KEY_HEADER.to_string()
            } else {
                api_key_header.trim().to_string()
            },
            deploy: if deploy.trim().is_empty() {
                MCP_DEPLOY_INTERNAL.to_string()
            } else {
                deploy.to_string()
            },
            path: path.trim().to_string(),
            oauth: oauth.clone(),
        };
        // Path 空则生成随机（所有 deploy 面都生成，不回落 /mcp）。
        if cfg.path.is_empty() {
            if let Ok(p) = mcp_random_path() {
                cfg.path = p;
            }
        }
        cfg.oauth.jwks_url = cfg.oauth.jwks_url.trim().to_string();
        cfg.oauth.issuer = cfg.oauth.issuer.trim().trim_end_matches('/').to_string();
        cfg.oauth.audience = cfg.oauth.audience.trim().to_string();
        cfg.oauth.resource = cfg.oauth.resource.trim().to_string();
        for s in &mut cfg.oauth.authorization_servers {
            *s = s.trim().trim_end_matches('/').to_string();
        }
        if cfg.oauth.authorization_servers.is_empty() && !cfg.oauth.issuer.is_empty() {
            cfg.oauth.authorization_servers = vec![cfg.oauth.issuer.clone()];
        }
        for s in &mut cfg.oauth.required_scopes {
            *s = s.trim().to_string();
        }
        cfg
    }

    /// 校验配置合法性（对齐 Go Validate；apply_defaults 之后调用）。
    pub fn validate(&self) -> Result<(), String> {
        match self.deploy.as_str() {
            "" | "internal" | "public" | "both" => {}
            other => return Err(format!("invalid web.mcp.deploy {other:?} (want internal, public or both)")),
        }
        if self.path.is_empty() {
            return Err("web.mcp.path is required; a random path is generated on load, reload the configuration to materialize it".into());
        }
        if !valid_mcp_path(&self.path) {
            return Err(format!("invalid web.mcp.path {:?} (want a path starting with /, no //, length 2..128, no whitespace or control characters)", self.path));
        }
        match self.auth_mode.as_str() {
            MCP_AUTH_INHERIT_WEB | MCP_AUTH_NONE => Ok(()),
            MCP_AUTH_BASIC => {
                if self.username.trim().is_empty() {
                    return Err("web.mcp.username is required for basic authentication".into());
                }
                if !valid_static_credential_hash(&self.credential_hash) {
                    return Err("web.mcp.credential is required for basic authentication".into());
                }
                Ok(())
            }
            MCP_AUTH_BEARER | MCP_AUTH_API_KEY => {
                if !valid_static_credential_hash(&self.credential_hash) {
                    return Err(format!("web.mcp.credential is required for {} authentication", self.auth_mode));
                }
                if self.auth_mode == MCP_AUTH_API_KEY {
                    let h = self.api_key_header.trim();
                    if !valid_http_header_name(h) {
                        return Err(format!("invalid web.mcp.api_key_header {h:?}"));
                    }
                    if h.eq_ignore_ascii_case("Authorization")
                        || h.eq_ignore_ascii_case("Cookie")
                        || h.eq_ignore_ascii_case("Host")
                        || h.eq_ignore_ascii_case("Content-Length")
                    {
                        return Err(format!("web.mcp.api_key_header {h:?} is reserved; use a dedicated header such as X-API-Key"));
                    }
                }
                Ok(())
            }
            MCP_AUTH_OAUTH_JWT => self.oauth.validate(),
            other => Err(format!("invalid web.mcp.auth_mode {other:?} (want inherit_web, none, basic, bearer, api_key or oauth_jwt)")),
        }
    }

    pub fn effective_path(&self) -> &str {
        self.path.trim()
    }

    /// 判断请求路径是否命中 MCP 端点（允许尾部 "/"）。
    pub fn matches_path(&self, request_path: &str) -> bool {
        let p = self.effective_path();
        !p.is_empty() && (request_path == p || request_path == format!("{p}/"))
    }

    /// 是否在内网 web listener 上服务 MCP。
    pub fn deploy_allows_internal(&self) -> bool {
        self.deploy != MCP_DEPLOY_PUBLIC
    }

    /// 是否在公网 VPN listener 上服务 MCP。
    pub fn deploy_allows_public(&self) -> bool {
        self.deploy == MCP_DEPLOY_PUBLIC || self.deploy == MCP_DEPLOY_BOTH
    }
}

impl McpOAuthJwtConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.jwks_url.is_empty() {
            return Err("web.mcp.oauth.jwks_url is required for oauth_jwt authentication".into());
        }
        if self.issuer.is_empty() {
            return Err("web.mcp.oauth.issuer is required for oauth_jwt authentication".into());
        }
        if self.audience.is_empty() {
            return Err("web.mcp.oauth.audience is required for oauth_jwt authentication".into());
        }
        if self.resource.is_empty() {
            return Err("web.mcp.oauth.resource is required for oauth_jwt authentication".into());
        }
        for (name, raw) in [("jwks_url", &self.jwks_url), ("issuer", &self.issuer), ("resource", &self.resource)] {
            validate_mcp_https_url(raw).map_err(|e| format!("invalid web.mcp.oauth.{name}: {e}"))?;
        }
        let servers = if self.authorization_servers.is_empty() {
            vec![self.issuer.clone()]
        } else {
            self.authorization_servers.clone()
        };
        for raw in &servers {
            validate_mcp_https_url(raw).map_err(|e| format!("invalid web.mcp.oauth.authorization_servers entry {raw:?}: {e}"))?;
        }
        let mut seen = std::collections::HashSet::new();
        for scope in &self.required_scopes {
            let scope = scope.trim();
            if scope.is_empty() {
                return Err("web.mcp.oauth.required_scopes must not contain empty values".into());
            }
            if scope.contains(' ') || scope.contains('\t') || scope.contains('\r') || scope.contains('\n') {
                return Err(format!("invalid OAuth scope {scope:?}"));
            }
            if !seen.insert(scope.to_string()) {
                return Err(format!("duplicate OAuth scope {scope:?}"));
            }
        }
        Ok(())
    }
}

/// 生成 /<20 hex> 的不可猜 MCP 端点路径（80 bit 熵）。
pub fn mcp_random_path() -> Result<String, String> {
    let mut buf = [0u8; 10];
    getrandom::getrandom(&mut buf).map_err(|e| format!("generate mcp path: {e}"))?;
    Ok(format!("/{}", hex::encode(buf)))
}

/// 校验配置的 MCP 端点路径：单个路径段，以 / 开头、无 //、长度 2..128、无空白/控制字符。
fn valid_mcp_path(p: &str) -> bool {
    if p.len() < 2 || p.len() > 128 {
        return false;
    }
    if !p.starts_with('/') {
        return false;
    }
    if p.contains("//") {
        return false;
    }
    !p.bytes().any(|b| b <= 0x20 || b == 0x7f)
}

fn valid_http_header_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.bytes().all(|c| {
        c.is_ascii_alphanumeric()
            || matches!(c, b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~')
    })
}

pub(crate) fn validate_mcp_https_url(raw: &str) -> Result<(), String> {
    // 简化校验：必须是绝对 URL、无 userinfo/fragment、scheme https（http 仅 loopback）。
    let Some(rest) = raw.strip_prefix("https://") else {
        // http 仅 loopback（localhost / 回环 IP）允许。
        if let Some(host) = raw.strip_prefix("http://") {
            let host = host.split('/').next().unwrap_or("");
            let host = host.split('@').last().unwrap_or(host);
            let host_no_port = host.split(':').next().unwrap_or(host);
            let host_trimmed = host_no_port.trim_matches(['[', ']']);
            if host_trimmed.eq_ignore_ascii_case("localhost") || host_trimmed.parse::<std::net::IpAddr>().map_or(false, |ip| ip.is_loopback()) {
                return Ok(());
            }
            return Err("plain HTTP is only allowed for loopback addresses".into());
        }
        return Err("must be an absolute URL".into());
    };
    if rest.is_empty() || rest.split('/').next().unwrap_or("").is_empty() {
        return Err("must be an absolute URL".into());
    }
    if raw.contains('@') {
        return Err("URL userinfo is not allowed".into());
    }
    if raw.contains('#') {
        return Err("URL fragments are not allowed".into());
    }
    Ok(())
}

fn normalize_auth_mode(mode: &str) -> String {
    let mode = mode.trim().to_lowercase();
    if mode.is_empty() {
        MCP_AUTH_INHERIT_WEB.to_string()
    } else {
        mode
    }
}

/// 归一化静态凭据为 `sha256:<hex>` verifier（明文则哈希，已哈希则原样小写）。
pub fn normalize_static_credential(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.to_lowercase().starts_with(MCP_CREDENTIAL_HASH_PREFIX) {
        let raw = &value[MCP_CREDENTIAL_HASH_PREFIX.len()..];
        return format!("{MCP_CREDENTIAL_HASH_PREFIX}{}", raw.trim().to_lowercase());
    }
    let sum = sha256_bytes(value.as_bytes());
    format!("{MCP_CREDENTIAL_HASH_PREFIX}{}", hex::encode(sum))
}

fn valid_static_credential_hash(value: &str) -> bool {
    let Some(raw) = value.strip_prefix(MCP_CREDENTIAL_HASH_PREFIX) else {
        return false;
    };
    if raw.len() != 64 {
        return false;
    }
    hex::decode(raw).is_ok()
}

/// 常量时间凭据匹配：got 明文 vs stored 的 `sha256:<hex>` verifier。
pub fn mcp_credential_matches(got: &str, stored: &str) -> bool {
    let stored = normalize_static_credential(stored);
    if !valid_static_credential_hash(&stored) {
        return false;
    }
    let Ok(want) = hex::decode(stored.trim_start_matches(MCP_CREDENTIAL_HASH_PREFIX)) else {
        return false;
    };
    let Ok(want) = <[u8; 32]>::try_from(want) else {
        return false;
    };
    let got_hash = sha256_bytes(got.as_bytes());
    crate::web_parity::constant_time_32(&got_hash, &want)
}

fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// MCP 认证失败的按 IP 限速器（对齐 Go ipFailThrottle）。
struct IpFailThrottle {
    fails: HashMap<String, Vec<Instant>>,
    max: usize,
    win: Duration,
}

impl IpFailThrottle {
    fn new(max: usize, win: Duration) -> Self {
        Self { fails: HashMap::new(), max, win }
    }

    fn blocked(&mut self, ip: &str) -> bool {
        let now = Instant::now();
        if let Some(list) = self.fails.get_mut(ip) {
            list.retain(|ts| now.duration_since(*ts) < self.win);
            if list.is_empty() {
                self.fails.remove(ip);
                return false;
            }
            return list.len() >= self.max;
        }
        false
    }

    fn record(&mut self, ip: &str) {
        self.fails.entry(ip.to_string()).or_default().push(Instant::now());
    }

    fn reset(&mut self, ip: &str) {
        self.fails.remove(ip);
    }
}

lazy_static::lazy_static! {
    static ref MCP_AUTH_THROTTLER: Mutex<IpFailThrottle> = Mutex::new(IpFailThrottle::new(MCP_AUTH_THROTTLE_MAX, MCP_AUTH_THROTTLE_WIN));
}

pub struct McpAuthError {
    pub status: i32,
    pub message: String,
}

/// 认证结果：Ok = 通过（重置限速），Err = 失败（记录限速 + 访问日志）。
#[allow(clippy::too_many_arguments)]
pub fn authenticate(
    auth_mode: &str,
    username: &str,
    credential_hash: &str,
    #[allow(unused_variables)] api_key_header: &str,
    oauth: &McpOAuthJwtConfig,
    web_auth: &str,
    web_session_valid: bool,
    basic_credential: Option<&str>,
    bearer_token: Option<&str>,
    api_key: Option<&str>,
    remote: &str,
) -> Result<(), McpAuthError> {
    let start = Instant::now();
    let fail = |msg: &str| {
        let mut t = MCP_AUTH_THROTTLER.lock().unwrap();
        // 仅真实认证失败（401）限速；insufficient_scope 是配置问题而非攻击。
        let blocked = t.blocked(remote);
        if !blocked {
            t.record(remote);
        }
        if blocked {
            crate::mcp_access::add_mcp_access(McpAccessLine {
                seq: 0, time: String::new(), remote: remote.to_string(),
                level: "warn".into(), method: "auth".into(), tool: String::new(),
                status: Some(429), dur_ms: Some(start.elapsed().as_millis() as i64),
                msg: "throttled: too many failed authentication attempts".into(),
            });
            return McpAuthError { status: 429, message: "too_many_attempts".into() };
        }
        crate::mcp_access::add_mcp_access(McpAccessLine {
            seq: 0, time: String::new(), remote: remote.to_string(),
            level: "warn".into(), method: "auth".into(), tool: String::new(),
            status: Some(401), dur_ms: Some(start.elapsed().as_millis() as i64),
            msg: msg.to_string(),
        });
        McpAuthError { status: 401, message: "unauthorized".into() }
    };

    let err = match auth_mode {
        MCP_AUTH_NONE => None,
        MCP_AUTH_INHERIT_WEB => {
            if web_auth.is_empty() {
                None
            } else {
                let basic_ok = basic_credential.map(|c| ct_eq(c, web_auth)).unwrap_or(false);
                if web_session_valid || basic_ok { None } else { Some("invalid inherited Web credential") }
            }
        }
        MCP_AUTH_BASIC => {
            let ok = basic_credential
                .and_then(|c| c.split_once(':'))
                .map(|(user, pass)| ct_eq(user, username) && mcp_credential_matches(pass, credential_hash))
                .unwrap_or(false);
            if ok { None } else { Some("invalid MCP basic credential") }
        }
        MCP_AUTH_BEARER => {
            let ok = bearer_token.map(|t| mcp_credential_matches(t, credential_hash)).unwrap_or(false);
            if ok { None } else { Some("invalid MCP bearer token") }
        }
        MCP_AUTH_API_KEY => {
            let ok = api_key.map(|k| mcp_credential_matches(k, credential_hash)).unwrap_or(false);
            if ok { None } else { Some("invalid MCP API key") }
        }
        MCP_AUTH_OAUTH_JWT => {
            let Some(token) = bearer_token else {
                return Err(McpAuthError { status: 401, message: "unauthorized".into() });
            };
            match crate::mcp_oauth::verify_oauth_jwt(token, oauth) {
                Ok(()) => None,
                // 对齐 Go：insufficient_scope 是配置问题而非攻击，返回 403 且不限速
                // （限速会惩罚合法但 scope 配置错的客户端）。
                Err(e) if e.is_insufficient_scope() => {
                    crate::mcp_access::add_mcp_access(McpAccessLine {
                        seq: 0, time: String::new(), remote: remote.to_string(),
                        level: "warn".into(), method: "auth".into(), tool: String::new(),
                        status: Some(403), dur_ms: Some(start.elapsed().as_millis() as i64),
                        msg: e.to_string(),
                    });
                    return Err(McpAuthError { status: 403, message: "insufficient_scope".into() });
                }
                Err(e) => Some(Box::leak(e.to_string().into_boxed_str()) as &str),
            }
        }
        other => Some(Box::leak(format!("unsupported MCP authentication mode {other:?}").into_boxed_str()) as &str),
    };

    if let Some(msg) = err {
        return Err(fail(msg));
    }
    MCP_AUTH_THROTTLER.lock().unwrap().reset(remote);
    Ok(())
}

/// OAuth 保护资源 metadata 端点（/.well-known/oauth-protected-resource）。
pub fn oauth_metadata_json(cfg: &McpOAuthJwtConfig) -> serde_json::Value {
    let mut servers = cfg.authorization_servers.clone();
    if servers.is_empty() && !cfg.issuer.is_empty() {
        servers = vec![cfg.issuer.clone()];
    }
    serde_json::json!({
        "resource": cfg.resource,
        "authorization_servers": servers,
        "scopes_supported": cfg.required_scopes,
        "bearer_methods_supported": ["header"],
    })
}

pub fn is_mcp_metadata_path(path: &str) -> bool {
    path == "/.well-known/oauth-protected-resource" || path == "/.well-known/oauth-protected-resource/mcp"
}

/// 提取 Bearer token（Authorization: Bearer <token>）。
pub fn bearer_token(header: &str) -> Option<String> {
    let value = header.trim();
    let lower = value.to_ascii_lowercase();
    if !lower.starts_with("bearer ") {
        return None;
    }
    let token = value[7..].trim();
    if token.is_empty() { None } else { Some(token.to_string()) }
}

/// 从 Authorization 提取 Basic 凭据（user:pass），base64 解码。
pub fn basic_credential(header: &str) -> Option<String> {
    let value = header.trim();
    let encoded = value.strip_prefix("Basic ")?;
    let decoded = base64ct::Base64::decode_vec(encoded.trim()).ok()?;
    String::from_utf8(decoded).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_oauth() -> McpOAuthJwtConfig {
        McpOAuthJwtConfig::default()
    }

    #[test]
    fn credential_verifier_hashes_plaintext_and_preserves_hash() {
        // 明文 → sha256:<hex>
        let h = normalize_static_credential("secret");
        assert!(h.starts_with(MCP_CREDENTIAL_HASH_PREFIX));
        assert_eq!(h.len(), MCP_CREDENTIAL_HASH_PREFIX.len() + 64);
        // 已哈希 → 原样（小写）
        let again = normalize_static_credential(&h);
        assert_eq!(again, h);
        // 匹配
        assert!(mcp_credential_matches("secret", &h));
        assert!(!mcp_credential_matches("wrong", &h));
    }

    #[test]
    fn authenticate_none_always_passes() {
        let r = authenticate(
            MCP_AUTH_NONE, "", "", "", &empty_oauth(), "", false, None, None, None, "127.0.0.1:10001",
        );
        assert!(r.is_ok());
    }

    #[test]
    fn authenticate_basic_success_and_failure() {
        let hash = normalize_static_credential("pass");
        // 正确凭据
        let ok = authenticate(
            MCP_AUTH_BASIC, "admin", &hash, "", &empty_oauth(), "", false,
            Some("admin:pass"), None, None, "127.0.0.1:10002",
        );
        assert!(ok.is_ok());
        // 错误密码 → 401
        let err = authenticate(
            MCP_AUTH_BASIC, "admin", &hash, "", &empty_oauth(), "", false,
            Some("admin:wrong"), None, None, "127.0.0.1:10003",
        );
        assert_eq!(err.unwrap_err().status, 401);
    }

    #[test]
    fn authenticate_bearer_and_api_key() {
        let hash = normalize_static_credential("tok123");
        // bearer
        let ok = authenticate(
            MCP_AUTH_BEARER, "", &hash, "", &empty_oauth(), "", false,
            None, Some("tok123"), None, "127.0.0.1:10004",
        );
        assert!(ok.is_ok());
        // api_key（默认 X-API-Key）
        let ok = authenticate(
            MCP_AUTH_API_KEY, "", &hash, "X-API-Key", &empty_oauth(), "", false,
            None, None, Some("tok123"), "127.0.0.1:10005",
        );
        assert!(ok.is_ok());
    }

    #[test]
    fn bearer_and_basic_extraction() {
        assert_eq!(bearer_token("Bearer abc").as_deref(), Some("abc"));
        assert_eq!(bearer_token("Basic abc"), None);
        // Basic: user:pass base64
        let b64 = base64ct::Base64::encode_string(b"admin:secret");
        assert_eq!(basic_credential(&format!("Basic {b64}")).as_deref(), Some("admin:secret"));
    }

    #[test]
    fn path_matching_allows_trailing_slash() {
        let cfg = McpAuthConfig {
            path: "/mcp".into(),
            ..Default::default()
        };
        assert!(cfg.matches_path("/mcp"));
        assert!(cfg.matches_path("/mcp/"));
        assert!(!cfg.matches_path("/mcp/x"));
        assert!(!cfg.matches_path("/other"));
    }

    #[test]
    fn validate_rejects_invalid_modes_and_paths() {
        let mut cfg = McpAuthConfig::from_file("bad_mode", "", "", "", "public", "/mcp", &empty_oauth());
        assert!(cfg.validate().is_err(), "invalid auth_mode rejected");
        let mut cfg = McpAuthConfig::from_file("basic", "admin", "pw", "", "public", "/mcp", &empty_oauth());
        assert!(cfg.validate().is_ok());
        // 路径不能含空白
        cfg.path = "/m c p".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn oauth_metadata_json_has_resource_and_scopes() {
        let mut oauth = McpOAuthJwtConfig {
            resource: "https://issuer/mcp".into(),
            authorization_servers: vec!["https://issuer".into()],
            required_scopes: vec!["mcp:read".into()],
            ..Default::default()
        };
        let meta = oauth_metadata_json(&oauth);
        assert_eq!(meta["resource"], "https://issuer/mcp");
        assert_eq!(meta["authorization_servers"][0], "https://issuer");
        assert_eq!(meta["scopes_supported"][0], "mcp:read");
        // authorization_servers 为空时回落 issuer
        oauth.authorization_servers.clear();
        oauth.issuer = "https://issuer".into();
        let meta = oauth_metadata_json(&oauth);
        assert_eq!(meta["authorization_servers"][0], "https://issuer");
    }
}
