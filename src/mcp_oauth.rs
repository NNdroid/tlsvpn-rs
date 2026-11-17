//! OAuth JWT 验证（对齐 Go mcp_auth.go verifyMCPOAuthJWT）。
//!
//! 用 ring 做 RSA/EC/Ed25519 签名验证，自实现 JWKS 解析（base64url→ring 公钥）。
//! 与 Go 的 golang-jwt/jwt/v5 行为对齐：
//! - 允许算法 RS256/384/512、PS256/384/512、ES256/384/512、EdDSA
//! - exp 必需（30s leeway）、iss 精确匹配、aud 精确匹配
//! - JWKS 拉取仅 HTTPS（loopback HTTP 允许）、1MB 上限、重定向 ≤3、5s 超时、
//!   缓存 10 分钟；kid 未命中时强制刷新一次
//! - scope/scp 提取，缺失 required_scopes 返回 `InsufficientScope`（→403 不限速）
//!
//! 已知限制：ring 0.17 不提供 P-521 的 ECDSA 验证算法，因此 ES512 返回明确
//! 的 "unsupported" 错误而非静默接受——不会冒充已验证。

use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

use base64ct::{Base64UrlUnpadded, Encoding};
use ring::signature;

use crate::mcp_auth::{validate_mcp_https_url, McpOAuthJwtConfig};

const JWKS_MAX_BYTES: usize = 1 << 20;
const JWKS_CACHE_TTL: Duration = Duration::from_secs(10 * 60);
const JWKS_TIMEOUT: Duration = Duration::from_secs(5);
const JWKS_MAX_REDIRECTS: usize = 3;
const JWT_LEEWAY: Duration = Duration::from_secs(30);

/// OAuth 验证错误：区分「scope 不足」（配置问题→403 不限速）与其他失败（→401 限速）。
#[derive(Debug, Clone)]
pub enum McpOAuthError {
    InsufficientScope(String),
    Other(String),
}

impl McpOAuthError {
    pub fn is_insufficient_scope(&self) -> bool {
        matches!(self, McpOAuthError::InsufficientScope(_))
    }
    pub fn other(msg: impl Into<String>) -> Self {
        McpOAuthError::Other(msg.into())
    }
}

impl std::fmt::Display for McpOAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            McpOAuthError::InsufficientScope(m) => write!(f, "mcp oauth token has insufficient scope: {m}"),
            McpOAuthError::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for McpOAuthError {}

fn b64u_decode(value: &str) -> Result<Vec<u8>, String> {
    Base64UrlUnpadded::decode_vec(value.trim()).map_err(|e| format!("invalid base64url: {e}"))
}

// ======================= JWK 表示 =======================

#[derive(Clone)]
enum EcCurve {
    P256,
    P384,
    P521,
}

/// 解析后的 JWK 公钥，可换算为 ring 验证句柄。
#[derive(Clone)]
enum JwkKey {
    Rsa { n: Vec<u8>, e: Vec<u8> },
    Ec { curve: EcCurve, x: Vec<u8>, y: Vec<u8> },
    Ed25519 { x: Vec<u8> },
}

struct JwksCacheEntry {
    keys: HashMap<String, JwkKey>,
    anonymous: Vec<JwkKey>,
    expires: Instant,
}

lazy_static::lazy_static! {
    static ref JWKS_CACHE: std::sync::Mutex<HashMap<String, JwksCacheEntry>> =
        std::sync::Mutex::new(HashMap::new());
}

#[derive(serde::Deserialize)]
struct JwkJson {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    kid: String,
    #[serde(default, rename = "use")]
    use_: String,
    #[serde(default)]
    #[allow(dead_code)]
    alg: String,
    #[serde(default)]
    n: String,
    #[serde(default)]
    e: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
    #[serde(default)]
    y: String,
}

#[derive(serde::Deserialize)]
struct JwksJson {
    #[serde(default)]
    keys: Vec<JwkJson>,
}

/// 解析单个 JWK（对齐 Go parseMCPJWK），返回 (kid, key)。`use` 非空且 != "sig" 时跳过。
fn parse_jwk(jwk: JwkJson) -> Result<(String, JwkKey), String> {
    if !jwk.use_.is_empty() && jwk.use_ != "sig" {
        return Err("JWK use is not sig".into());
    }
    let key = match jwk.kty.as_str() {
        "RSA" => {
            let n = b64u_decode(&jwk.n)?;
            if n.is_empty() {
                return Err("invalid RSA modulus".into());
            }
            let e_bytes = b64u_decode(&jwk.e)?;
            if e_bytes.is_empty() || e_bytes.len() > 4 {
                return Err("invalid RSA exponent".into());
            }
            let mut e: u32 = 0;
            for b in &e_bytes {
                e = (e << 8) | u32::from(*b);
            }
            if e < 3 {
                return Err("invalid RSA exponent".into());
            }
            // e 保持 JWK 提供的最小大端字节表示（ring 的 RsaPublicKeyComponents
            // 不接受前导零；Go 的 rsa.PublicKey.E 是 int，语义一致）。
            JwkKey::Rsa { n, e: e_bytes }
        }
        "EC" => {
            let curve = match jwk.crv.as_str() {
                "P-256" => EcCurve::P256,
                "P-384" => EcCurve::P384,
                "P-521" => EcCurve::P521,
                other => return Err(format!("unsupported EC curve {other:?}")),
            };
            let x = b64u_decode(&jwk.x)?;
            let y = b64u_decode(&jwk.y)?;
            if x.is_empty() || y.is_empty() {
                return Err("invalid EC coordinates".into());
            }
            JwkKey::Ec { curve, x, y }
        }
        "OKP" => {
            if jwk.crv != "Ed25519" {
                return Err(format!("unsupported OKP curve {:?}", jwk.crv));
            }
            let x = b64u_decode(&jwk.x)?;
            if x.len() != 32 {
                return Err("invalid Ed25519 public key".into());
            }
            JwkKey::Ed25519 { x }
        }
        other => return Err(format!("unsupported JWK kty {other:?}")),
    };
    Ok((jwk.kid.clone(), key))
}

// ======================= JWKS 拉取与缓存 =======================

fn fetch_jwks(url: &str, force: bool) -> Result<JwksCacheEntry, McpOAuthError> {
    let now = Instant::now();
    {
        let cache = JWKS_CACHE.lock().unwrap();
        if !force {
            if let Some(entry) = cache.get(url) {
                if now < entry.expires {
                    return Ok(clone_entry(entry));
                }
            }
        }
    }
    let body = http_get_jwks(url)?;
    let set: JwksJson = serde_json::from_slice(&body)
        .map_err(|e| McpOAuthError::other(format!("decode JWKS: {e}")))?;
    if set.keys.is_empty() {
        return Err(McpOAuthError::other("JWKS contains no keys"));
    }
    let mut entry = JwksCacheEntry {
        keys: HashMap::new(),
        anonymous: Vec::new(),
        expires: now + JWKS_CACHE_TTL,
    };
    for jwk in set.keys {
        let (kid, key) = match parse_jwk(jwk) {
            Ok(k) => k,
            Err(_) => continue,
        };
        if kid.is_empty() {
            entry.anonymous.push(key);
        } else {
            entry.keys.insert(kid, key);
        }
    }
    if entry.keys.is_empty() && entry.anonymous.is_empty() {
        return Err(McpOAuthError::other("JWKS contains no supported signature keys"));
    }
    JWKS_CACHE.lock().unwrap().insert(url.to_string(), clone_entry(&entry));
    Ok(entry)
}

fn clone_entry(entry: &JwksCacheEntry) -> JwksCacheEntry {
    JwksCacheEntry {
        keys: entry.keys.clone(),
        anonymous: entry.anonymous.clone(),
        expires: entry.expires,
    }
}

/// 用 ureq 拉取 JWKS：仅 HTTPS（loopback HTTP 允许）、1MB 上限、重定向 ≤3、5s 超时。
fn http_get_jwks(url: &str) -> Result<Vec<u8>, McpOAuthError> {
    validate_mcp_https_url(url).map_err(McpOAuthError::other)?;
    let agent = ureq::AgentBuilder::new()
        .timeout(JWKS_TIMEOUT)
        .redirects(JWKS_MAX_REDIRECTS as u32)
        .build();
    let resp = agent
        .get(url)
        .set("Accept", "application/json")
        .call()
        .map_err(|e| McpOAuthError::other(format!("fetch JWKS: {e}")))?;
    let mut body = Vec::new();
    resp.into_reader()
        .take((JWKS_MAX_BYTES + 1) as u64)
        .read_to_end(&mut body)
        .map_err(|e| McpOAuthError::other(format!("read JWKS: {e}")))?;
    if body.len() > JWKS_MAX_BYTES {
        return Err(McpOAuthError::other("JWKS exceeds maximum size"));
    }
    Ok(body)
}

// ======================= JWT 解析与验证 =======================

#[derive(serde::Deserialize)]
struct JwtHeader {
    #[serde(default)]
    alg: String,
    #[serde(default)]
    kid: String,
}

#[derive(serde::Deserialize, Default)]
struct JwtClaims {
    #[serde(default)]
    exp: Option<i64>,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    aud: Option<serde_json::Value>,
    #[serde(default)]
    scope: Option<serde_json::Value>,
    #[serde(default)]
    scp: Option<serde_json::Value>,
}

fn select_jwt_key(
    kid: &str,
    jwks_url: &str,
) -> Result<JwkKey, McpOAuthError> {
    let select = |entry: &JwksCacheEntry| -> Option<JwkKey> {
        if !kid.is_empty() {
            return entry.keys.get(kid).cloned();
        }
        if entry.keys.len() + entry.anonymous.len() != 1 {
            return None;
        }
        entry
            .keys
            .values()
            .next()
            .cloned()
            .or_else(|| entry.anonymous.first().cloned())
    };
    let entry = fetch_jwks(jwks_url, false)?;
    if let Some(key) = select(&entry) {
        return Ok(key);
    }
    if !kid.is_empty() {
        let entry = fetch_jwks(jwks_url, true)?;
        if let Some(key) = select(&entry) {
            return Ok(key);
        }
        return Err(McpOAuthError::other(format!("JWT kid {kid:?} not found in JWKS")));
    }
    Err(McpOAuthError::other("JWT has no kid and JWKS does not contain exactly one usable key"))
}

fn alg_rs(alg: &str) -> Option<&'static ring::signature::RsaParameters> {
    match alg {
        "RS256" => Some(&signature::RSA_PKCS1_2048_8192_SHA256),
        "RS384" => Some(&signature::RSA_PKCS1_2048_8192_SHA384),
        "RS512" => Some(&signature::RSA_PKCS1_2048_8192_SHA512),
        _ => None,
    }
}

fn alg_ps(alg: &str) -> Option<&'static ring::signature::RsaParameters> {
    match alg {
        "PS256" => Some(&signature::RSA_PSS_2048_8192_SHA256),
        "PS384" => Some(&signature::RSA_PSS_2048_8192_SHA384),
        "PS512" => Some(&signature::RSA_PSS_2048_8192_SHA512),
        _ => None,
    }
}

fn alg_ec(alg: &str, curve: &EcCurve) -> Option<&'static dyn signature::VerificationAlgorithm> {
    match (alg, curve) {
        ("ES256", EcCurve::P256) => Some(&signature::ECDSA_P256_SHA256_ASN1),
        ("ES384", EcCurve::P384) => Some(&signature::ECDSA_P384_SHA384_ASN1),
        // ring 0.17 不提供 P-521 ECDSA 验证算法；ES512 明确不支持。
        _ => None,
    }
}

fn verify_signature(key: &JwkKey, alg: &str, message: &[u8], sig: &[u8]) -> Result<(), McpOAuthError> {
    let ok = match key {
        JwkKey::Rsa { n, e } => {
            let components = ring::signature::RsaPublicKeyComponents { n: n.as_slice(), e: e.as_slice() };
            if let Some(v) = alg_rs(alg).or_else(|| alg_ps(alg)) {
                components.verify(v, message, sig).is_ok()
            } else {
                return Err(McpOAuthError::other(format!("JWT alg {alg:?} is incompatible with selected JWK")));
            }
        }
        JwkKey::Ec { curve, x, y } => {
            let Some(v) = alg_ec(alg, curve) else {
                if matches!(alg, "ES512") {
                    return Err(McpOAuthError::other("ES512 is not supported by ring (no P-521 verification algorithm)"));
                }
                return Err(McpOAuthError::other(format!("JWT alg {alg:?} is incompatible with selected JWK")));
            };
            // 未压缩 SEC1 公钥：04 || x || y。
            let mut sec1 = Vec::with_capacity(1 + x.len() + y.len());
            sec1.push(0x04);
            sec1.extend_from_slice(x);
            sec1.extend_from_slice(y);
            let key = signature::UnparsedPublicKey::new(v, &sec1);
            key.verify(message, sig).is_ok()
        }
        JwkKey::Ed25519 { x } => {
            if alg != "EdDSA" {
                return Err(McpOAuthError::other(format!("JWT alg {alg:?} is incompatible with selected JWK")));
            }
            let key = signature::UnparsedPublicKey::new(&signature::ED25519, x.as_slice());
            key.verify(message, sig).is_ok()
        }
    };
    if ok {
        Ok(())
    } else {
        Err(McpOAuthError::other("invalid JWT signature"))
    }
}

fn extract_scopes(claims: &JwtClaims) -> Vec<String> {
    let mut out = Vec::new();
    let mut add = |v: &serde_json::Value| {
        match v {
            serde_json::Value::String(s) => {
                for part in s.split_whitespace() {
                    out.push(part.to_string());
                }
            }
            serde_json::Value::Array(arr) => {
                for item in arr {
                    if let serde_json::Value::String(s) = item {
                        for part in s.split_whitespace() {
                            out.push(part.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    };
    if let Some(v) = &claims.scope {
        add(v);
    }
    if let Some(v) = &claims.scp {
        add(v);
    }
    out
}

fn aud_matches(aud: &Option<serde_json::Value>, expected: &str) -> bool {
    let Some(aud) = aud else { return false };
    match aud {
        serde_json::Value::String(s) => s == expected,
        serde_json::Value::Array(arr) => arr
            .iter()
            .any(|v| v.as_str().map_or(false, |s| s == expected)),
        _ => false,
    }
}

/// 验证 OAuth JWT（对齐 Go verifyMCPOAuthJWT）。成功返回 Ok(())。
pub fn verify_oauth_jwt(token: &str, cfg: &McpOAuthJwtConfig) -> Result<(), McpOAuthError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(McpOAuthError::other("malformed JWT"));
    }
    let header_b64 = parts[0];
    let payload_b64 = parts[1];
    let sig = b64u_decode(parts[2]).map_err(McpOAuthError::other)?;

    let header: JwtHeader = serde_json::from_slice(&b64u_decode(header_b64).map_err(McpOAuthError::other)?)
        .map_err(|e| McpOAuthError::other(format!("decode JWT header: {e}")))?;
    let payload_bytes = b64u_decode(payload_b64).map_err(McpOAuthError::other)?;
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| McpOAuthError::other(format!("decode JWT claims: {e}")))?;

    let alg = header.alg.as_str();
    if !matches!(
        alg,
        "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512" | "ES256" | "ES384"
            | "ES512" | "EdDSA"
    ) {
        return Err(McpOAuthError::other(format!("unsupported JWT alg {alg:?}")));
    }

    // exp 必需 + 30s leeway
    let exp = claims.exp.ok_or_else(|| McpOAuthError::other("JWT is missing exp claim"))?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    if now_unix >= exp + JWT_LEEWAY.as_secs() as i64 {
        return Err(McpOAuthError::other("JWT is expired"));
    }

    // iss 精确匹配（对齐 Go jwt.WithIssuer）
    if let Some(iss) = &claims.iss {
        if iss != &cfg.issuer {
            return Err(McpOAuthError::other("JWT issuer mismatch"));
        }
    } else {
        return Err(McpOAuthError::other("JWT is missing iss claim"));
    }

    // aud 精确匹配（对齐 Go jwt.WithAudience）
    if !aud_matches(&claims.aud, &cfg.audience) {
        return Err(McpOAuthError::other("JWT audience mismatch"));
    }

    // 选择并验证签名
    let key = select_jwt_key(&header.kid, &cfg.jwks_url)?;
    let message = format!("{header_b64}.{payload_b64}");
    verify_signature(&key, alg, message.as_bytes(), &sig)?;

    // scope 检查（无 required_scopes 则直接通过）
    if cfg.required_scopes.is_empty() {
        return Ok(());
    }
    let granted: std::collections::HashSet<String> = extract_scopes(&claims).into_iter().collect();
    for required in &cfg.required_scopes {
        if !granted.contains(required) {
            return Err(McpOAuthError::InsufficientScope(format!("missing {required:?}")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // 测试向量：openssl 生成的 RSA-2048 密钥 + RS256 JWT（exp=2100-01-01 永不
    // 过期），iss=https://issuer.example.com aud=tlsvpn-mcp-test scope="mcp:read other"。
    const TEST_N: &str = "8XoiZMyIOkjbeQ2mE_lIK7TBwrS2UWcT_l0wVXN4m5pfmCwa0Sq_DaUYj9JwPXAjKFJanlaeZt_kLpdefYzE6WyaEA8h54ABqYLThlKXewr1FQZlZsj7IbUqFpr19ndgFHB_YQ1DbIjxskt9Kvltiz2BZtyWon1rtrXrr_7C0uGFlUmqqqyyu9AWU3NS_zu_Fm9WsRsJjYEqVBQAy9qEg1hMsyes3YmyoY_IGU1qBu3NYGmW6pbBD7BXIbjcInErCikiXxlgnq1VzVZb0SqPRaW2bqqcH7tlcSZelbjObfPMUdyNgBH5aouel_3d0Gg5JjqvSPgO256yxc4vhIfKxw";
    const TEST_E: &str = "AQAB";
    const TEST_JWT: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRsc3Zwbi10ZXN0LWtleSJ9.eyJpc3MiOiJodHRwczovL2lzc3Vlci5leGFtcGxlLmNvbSIsImF1ZCI6InRsc3Zwbi1tY3AtdGVzdCIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzk0OTE0ODgwLCJzY29wZSI6Im1jcDpyZWFkIG90aGVyIn0.KIEqbZ-bTxE9BXOMZEN5ALgiDU-2jHhzMqF6O3T5EsQfSGMBYZwH7UA-GCvp_LS6E_mMvOBZaSENinKFhkI8ym4Y0RtIffnHQk3DUXH_p5JsihZznA_FI9B57BSWVeaVDy5PEpQUT7t-Z8s47YjDtfHplnnBXDX63LWI0Gfp9PY8-UJXyZBjr3JnOkSnJ5A1Q2PRO81vwlspGISth3RODVn9OsxvieyGu8U3GECvAOZDx2054d2UB3cGEAsf_Tkrf9ZjYjmqyxxFlXPd06bYRv1hXl-PtDVSSSkAS9xmb7Ji_voamkt7VAc_9wE7gLAq8qkL5NzkGfDMIlQBLXImew";
    const TEST_ISS: &str = "https://issuer.example.com";
    const TEST_AUD: &str = "tlsvpn-mcp-test";

    fn test_cfg() -> McpOAuthJwtConfig {
        McpOAuthJwtConfig {
            jwks_url: "https://issuer.example.com/jwks".into(),
            issuer: TEST_ISS.into(),
            audience: TEST_AUD.into(),
            resource: "https://issuer.example.com/mcp".into(),
            authorization_servers: vec![TEST_ISS.into()],
            required_scopes: vec!["mcp:read".into()],
        }
    }

    #[test]
    fn b64u_roundtrip_and_invalid() {
        assert!(b64u_decode("AQAB").unwrap() == vec![0x01, 0x00, 0x01]);
        assert!(b64u_decode("!!!!").is_err());
    }

    #[test]
    fn rsa_jwk_parses() {
        let jwk = JwkJson {
            kty: "RSA".into(),
            kid: "tlsvpn-test-key".into(),
            use_: "sig".into(),
            alg: "RS256".into(),
            n: TEST_N.into(),
            e: TEST_E.into(),
            crv: String::new(),
            x: String::new(),
            y: String::new(),
        };
        let (kid, key) = parse_jwk(jwk).expect("valid RSA JWK");
        assert_eq!(kid, "tlsvpn-test-key");
        assert!(matches!(key, JwkKey::Rsa { .. }));
    }

    #[test]
    fn aud_matches_string_and_array() {
        assert!(aud_matches(&Some(json!("tlsvpn-mcp-test")), "tlsvpn-mcp-test"));
        assert!(aud_matches(&Some(json!(["other", "tlsvpn-mcp-test"])), "tlsvpn-mcp-test"));
        assert!(!aud_matches(&Some(json!("wrong")), "tlsvpn-mcp-test"));
        assert!(!aud_matches(&None, "tlsvpn-mcp-test"));
    }

    #[test]
    fn scope_extraction_handles_string_and_array() {
        let claims = JwtClaims {
            scope: Some(json!("mcp:read other")),
            ..Default::default()
        };
        let scopes = extract_scopes(&claims);
        assert!(scopes.contains(&"mcp:read".to_string()));
        assert!(scopes.contains(&"other".to_string()));

        let claims = JwtClaims {
            scp: Some(json!(["a", "b"])),
            ..Default::default()
        };
        let scopes = extract_scopes(&claims);
        assert_eq!(scopes, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn alg_compatibility_checks() {
        assert!(alg_rs("RS256").is_some());
        assert!(alg_rs("ES256").is_none());
        assert!(alg_ps("PS384").is_some());
        assert!(alg_ec("ES256", &EcCurve::P256).is_some());
        assert!(alg_ec("ES512", &EcCurve::P521).is_none(), "ES512 unsupported in ring");
        assert!(alg_ec("ES256", &EcCurve::P384).is_none());
    }

    /// 端到端：tiny_http 起 JWKS 服务器，verify_oauth_jwt 完整验证 RS256 JWT。
    /// 覆盖 JWKS 拉取/缓存、kid 选择、签名验证、claims（iss/aud/exp）、scope。
    #[test]
    fn verify_oauth_jwt_rs256_end_to_end() {
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"tlsvpn-test-key","use":"sig","alg":"RS256","n":"{TEST_N}","e":"{TEST_E}"}}]}}"#
        );
        let addr = std::net::TcpListener::bind("127.0.0.1:0").expect("bind jwks server");
        let local = addr.local_addr().unwrap();
        let server_addr = local.clone();
        let body_for_thread = jwks_body.clone();
        let handle = std::thread::spawn(move || {
            // 非阻塞 accept：处理请求后超时退出（避免 join 死锁）。写响应后
            // shutdown(Write) 发 FIN（而非 drop 发 RST），避免 Windows 上 ureq
            // 读到 RST 报 "远程主机强迫关闭" 网络错误。
            use std::io::Write;
            let _ = addr.set_nonblocking(true);
            let mut served = 0;
            let mut idle = 0;
            while served < 4 && idle < 500 {
                match addr.accept() {
                    Ok((mut stream, _)) => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_for_thread.len(),
                            body_for_thread
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.shutdown(std::net::Shutdown::Write);
                        served += 1;
                        idle = 0;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        idle += 1;
                    }
                    Err(_) => break,
                }
            }
        });

        let mut cfg = test_cfg();
        cfg.jwks_url = format!("http://{server_addr}/jwks");
        // 验证成功（scope 含 mcp:read）
        let ok = verify_oauth_jwt(TEST_JWT, &cfg);
        assert!(ok.is_ok(), "expected valid JWT to pass, got {:?}", ok.err());

        // 缺 scope → InsufficientScope（403 语义）
        let mut cfg_missing = test_cfg();
        cfg_missing.jwks_url = format!("http://{server_addr}/jwks");
        cfg_missing.required_scopes = vec!["admin:all".into()];
        let err = verify_oauth_jwt(TEST_JWT, &cfg_missing).unwrap_err();
        assert!(err.is_insufficient_scope(), "expected InsufficientScope, got {err:?}");

        let _ = handle.join();
    }

    #[test]
    fn verify_oauth_jwt_rejects_bad_signature() {
        let jwks_body = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"tlsvpn-test-key","use":"sig","alg":"RS256","n":"{TEST_N}","e":"{TEST_E}"}}]}}"#
        );
        let addr = std::net::TcpListener::bind("127.0.0.1:0").expect("bind jwks server");
        let server_addr = addr.local_addr().unwrap();
        let body_for_thread = jwks_body.clone();
        let handle = std::thread::spawn(move || {
            // 非阻塞 accept + 超时退出（避免 join 死锁）；shutdown(Write) 发 FIN。
            use std::io::Write;
            let _ = addr.set_nonblocking(true);
            let mut served = 0;
            let mut idle = 0;
            while served < 2 && idle < 500 {
                match addr.accept() {
                    Ok((mut stream, _)) => {
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body_for_thread.len(),
                            body_for_thread
                        );
                        let _ = stream.write_all(resp.as_bytes());
                        let _ = stream.shutdown(std::net::Shutdown::Write);
                        served += 1;
                        idle = 0;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        idle += 1;
                    }
                    Err(_) => break,
                }
            }
        });
        let mut cfg = test_cfg();
        cfg.jwks_url = format!("http://{server_addr}/jwks");
        // 构造 base64url 合法但签名错误的 token：解码原签名、翻转首字节、重编码。
        // 这保证 b64u 解码成功、签名验证失败（而非解码阶段失败），从而真正
        // 走到 JWKS 拉取 + 签名校验路径。
        let sig_b64 = TEST_JWT.rsplit('.').next().unwrap();
        let mut sig_bytes = b64u_decode(sig_b64).expect("valid test signature b64u");
        sig_bytes[0] ^= 0xff;
        let tampered_sig = Base64UrlUnpadded::encode_string(&sig_bytes);
        let unsigned = &TEST_JWT[..TEST_JWT.len() - sig_b64.len() - 1];
        let tampered = format!("{unsigned}.{tampered_sig}");
        let err = verify_oauth_jwt(&tampered, &cfg).unwrap_err();
        assert!(!err.is_insufficient_scope());
        let _ = handle.join();
    }
}
