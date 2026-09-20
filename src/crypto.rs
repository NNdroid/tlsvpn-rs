use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::utils::*;

// 与 Go 端 crypto.go 对齐的算法常量。只有一种内层算法，历史上还有
// 0=AES-CTR 与 3=GCM-v2，已随旧协议兼容一并移除。
pub const ENC_ALGO_NONE: i64 = 0;
pub const ENC_ALGO_GCM: i64 = 2;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_NONCE_SIZE: usize = 12;
pub const ENC_SALT_SIZE: usize = 8;

// 客户端握手请求里声明的本端最高算法支持（对齐 Go clientEncAlgoSupport）。
// 服务端要求完全相等：声明不了 GCM 的对端一律拒连，不做弱降级。
pub const CLIENT_ENC_ALGO_SUPPORT: i64 = ENC_ALGO_GCM;

type HmacSha256 = Hmac<Sha256>;

pub fn hash_psk(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    hex::encode(hasher.finalize())
}

/// 常量时间比较（对齐 Go hmac.Equal / subtle.ConstantTimeCompare）。
///
/// PSK 哈希与会话复活分支的 MAC 都是对端可控的等长秘密（pskHash 本身就是握手
/// 凭据）。字符串 `!=` 逐字节短路，响应时延会泄露匹配前缀长度：那是远程时序
/// 预言机，攻击者可逐字节重建 pskHash 而无需知道 PSK 本身。
/// 长度不等直接 false——长度本身是公开的（两侧均为 64 位 hex），不是秘密。
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// PSK 派生的 32 字节密钥材料（hash_psk 的二进制形式，对齐 Go pskKey）
fn psk_key(psk: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn session_token_mac(psk: &str, session_id: &str) -> HmacSha256 {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(&psk_key(psk)).expect("HMAC accepts any key length");
    mac.update(b"session-token-v1");
    mac.update(session_id.as_bytes());
    mac
}

/// 会话令牌 = hex(HMAC-SHA256(key = sha256(psk), msg = "session-token-v1" ‖ sessionID))
///
/// 身份伪造的根因是"共享 PSK + 自报 MAC"：client_id 完全由 (mac, psk) 推导，
/// 任何持密者只要知道目标 MAC 就能算出对方 client_id，触发会话复活分支接管
/// 其隧道流量。令牌只在受害者的 TLS 会话内下发一次，重连时必须回带——
/// 第三方从未见过它，因此无法冒充既有会话。首次接入仍走 PSK 校验。
pub fn compute_session_token(psk: &str, session_id: &str) -> String {
    hex::encode(session_token_mac(psk, session_id).finalize().into_bytes())
}

/// 常量时间比较令牌（对齐 Go verifySessionToken 的 hmac.Equal）。
/// 非 32 字节的 hex 直接判失败，不 panic。
pub fn verify_session_token(psk: &str, session_id: &str, want: &str) -> bool {
    let want_tag = match hex::decode(want) {
        Ok(b) if b.len() == 32 => b,
        _ => return false,
    };
    session_token_mac(psk, session_id)
        .verify_slice(&want_tag)
        .is_ok()
}

pub fn new_session_token() -> Result<String, String> {
    let mut token = [0u8; 32];
    getrandom::getrandom(&mut token).map_err(|e| format!("generate session token: {}", e))?;
    Ok(hex::encode(token))
}

pub fn verify_random_session_token(stored: &str, want: &str) -> bool {
    stored.len() == 64 && want.len() == 64 && constant_time_eq(stored.as_bytes(), want.as_bytes())
}

pub fn generate_padding(min: usize, max: usize) -> String {
    let len = RNG.with(|rng| rng.borrow_mut().gen_range(min, max + 1));
    let mut buf = vec![0u8; len];
    RNG.with(|rng| rng.borrow_mut().fill(&mut buf));
    hex::encode(buf)
}

/// 混淆填充策略（对齐 Go frame.go 的 padCode*）。
/// 发送路径按整数码分派，接收路径完全不看它——pad_len 在帧头里自带。
pub const PAD_OFF: u8 = 0;
pub const PAD_BUCKET: u8 = 1;

pub const PAD_MODE_OFF: &str = "off";
pub const PAD_MODE_BUCKET: &str = "bucket";

/// 进程初值就是 bucket（对齐 Go 的 init()）：配置加载前也按同一策略发包，
/// 不会出现一段窗口按别的策略。
static PAD_MODE_CODE: AtomicU8 = AtomicU8::new(PAD_BUCKET);

// pad_mode 是进程级全局状态。Rust 测试默认并行，改它的用例必须串行；
// 这里只放锁，策略分派不持锁，避免发送热路径出现同步开销。
#[cfg(test)]
pub static PAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 小帧填充目标桶（覆盖 MTU 1500 常见帧及其含标签长度）
const PAD_BUCKETS: [usize; 10] = [128, 256, 384, 512, 768, 1024, 1280, 1600, 2048, 4096];

/// 切换填充策略（非法值回落 bucket），返回实际生效的策略名。
/// 空串也算非法 → bucket；配置层的"空串即 bucket"改写必须在此之前完成。
pub fn set_pad_mode(mode: &str) -> String {
    match mode {
        PAD_MODE_OFF => PAD_MODE_CODE.store(PAD_OFF, Ordering::Relaxed),
        _ => {
            PAD_MODE_CODE.store(PAD_BUCKET, Ordering::Relaxed);
            return PAD_MODE_BUCKET.to_string();
        }
    }
    mode.to_string()
}

pub fn pad_mode_name() -> String {
    if PAD_MODE_CODE.load(Ordering::Relaxed) == PAD_OFF {
        PAD_MODE_OFF.to_string()
    } else {
        PAD_MODE_BUCKET.to_string()
    }
}

/// 当前策略下该线路长度应加多少填充。
/// wire_len 必须是线路长度（明文 + GCM 标签），不是明文长度。
pub fn pad_length(wire_len: usize) -> usize {
    if PAD_MODE_CODE.load(Ordering::Relaxed) == PAD_OFF {
        0
    } else {
        pad_bucket(wire_len)
    }
}

/// 填充到固定长度桶；超出最大桶的 jumbo 帧只加小额随机填充，
/// 不为抗流量分析付过大带宽代价。
pub fn pad_bucket(wire_len: usize) -> usize {
    let record_len = 10usize.saturating_add(wire_len);
    for &b in PAD_BUCKETS.iter() {
        if record_len < b {
            return b - record_len;
        }
    }
    RNG.with(|rng| 1 + rng.borrow_mut().gen_range(0, 100))
}

/// 校验 pad_mode 取值（配置加载层，对齐 Go Config.Validate）。
/// 空串合法：等价于默认 bucket。
pub fn pad_mode_valid(mode: &str) -> bool {
    mode.is_empty() || mode == PAD_MODE_OFF || mode == PAD_MODE_BUCKET
}

/// 配置加载层的错误文案，与 Go Validate 逐字一致
pub fn pad_mode_invalid_error(mode: &str) -> String {
    format!(
        "invalid pad_mode {:?} (want {} or {})",
        mode, PAD_MODE_OFF, PAD_MODE_BUCKET
    )
}

// ======================= 加密强度下限（min_enc） =======================
//
// 旧实现里"是否加密"是布尔开关：一端把 encrypt 关掉，整条链路（含 FEC 校验帧）
// 就只剩 TLS 一层。min_enc 把开关换成强度下限，允许运维强制"低于 GCM 一律拒连"。
//
// 取值："" 或 "any"（无下限）、"gcm"。只有一种内层算法，下限只剩"是否必须有
// GCM"这一种语义。

// 强度下限的解析结果（0 = 不设下限）。历史上还有 CTR 一档，只有单一算法后
// 下限只剩"是否必须有 GCM"，两端都是 `enc_algo != ENC_ALGO_GCM` 的直接比较。
pub const ENC_RANK_NONE: i64 = 0;
pub const ENC_RANK_GCM: i64 = 2;

pub const MIN_ENC_GCM: &str = "gcm";

/// 解析最低强度配置；0 表示不设下限
pub fn min_enc_rank(mode: &str) -> i64 {
    match mode.trim().to_ascii_lowercase().as_str() {
        MIN_ENC_GCM => ENC_RANK_GCM,
        _ => ENC_RANK_NONE,
    }
}

/// 对端声明的算法位集是否恰好等于某算法。
/// 刻意用精确比较而非 >=：Go 侧正是因为 >= 比出了 bug——未知算法值
/// 会被误判为"满足 GCM 下限"。
pub fn enc_algo_supported(declared: i64, want: i64) -> bool {
    declared == want
}

/// 配置加载层的错误文案，与 Go Validate 逐字一致
pub fn min_enc_invalid_error(mode: &str) -> String {
    format!("invalid min_enc {:?} (want gcm, any or empty)", mode)
}

/// GCM 密钥派生标签（对齐 Go gcmKeyLabel）；FEC 校验帧追加 "_fec"。
/// 与 Go 逐字节一致是互通的前提，不得单独改动。
pub const GCM_KEY_LABEL: &str = "_enc_key";

/// 按标签派生 AES-256 key。psk 与标签直接拼接后取 SHA-256，
/// 顺序与 Go 的 sha256(psk + label) 一致。
fn derive_key_labeled(psk: &str, label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", psk, label).as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// 每会话随机的方向盐（crypto/rand 等价物，对齐 Go newRandomSalt）
pub fn new_random_salt() -> [u8; ENC_SALT_SIZE] {
    let mut s = [0u8; ENC_SALT_SIZE];
    getrandom::getrandom(&mut s).expect("Failed to generate encryption salt");
    s
}

/// 内层载荷加密器（对齐 Go 的 innerCipher）。只有一种算法：AES-256-GCM，
/// nonce = seq(4BE) || salt(8B)，AAD = wireLen(4BE) || seq(4BE)，密文后附
/// 16B 标签（线路 dataLen = 明文长 + 16）。
pub enum InnerCipher {
    Gcm {
        aead: Aes256Gcm,
        salt: [u8; ENC_SALT_SIZE],
    },
}

type GcmNonce = aes_gcm::Nonce<aes_gcm::aead::consts::U12>;

impl InnerCipher {
    pub fn gcm(psk: &str, salt: &[u8]) -> Result<InnerCipher, String> {
        Self::gcm_domain(psk, salt, "data")
    }

    /// 按密钥域构造 GCM 加密器："data" 是帧载荷，"fec" 是校验帧——
    /// 两个域用独立密钥，避免同一 AES 密钥跨用途复用。
    pub fn gcm_domain(psk: &str, salt: &[u8], domain: &str) -> Result<InnerCipher, String> {
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!(
                "encryption salt must be {} bytes, got {}",
                ENC_SALT_SIZE,
                salt.len()
            ));
        }
        if domain != "data" && domain != "fec" {
            return Err(format!("unknown GCM domain {:?}", domain));
        }
        let label = if domain == "fec" {
            format!("{}_fec", GCM_KEY_LABEL)
        } else {
            GCM_KEY_LABEL.to_string()
        };
        let key = derive_key_labeled(psk, &label);
        let aead = Aes256Gcm::new(&key.into());
        let mut s = [0u8; ENC_SALT_SIZE];
        s.copy_from_slice(salt);
        Ok(InnerCipher::Gcm { aead, salt: s })
    }

    pub fn is_gcm(&self) -> bool {
        matches!(self, InnerCipher::Gcm { .. })
    }

    /// 该加密器在线路上额外占用的字节数（对齐 Go tagLen）
    pub fn tag_len(&self) -> usize {
        match self {
            InnerCipher::Gcm { .. } => GCM_TAG_SIZE,
        }
    }

    fn gcm_nonce(&self, seq: u32) -> GcmNonce {
        let InnerCipher::Gcm { salt, .. } = self;
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        nonce[0..4].copy_from_slice(&seq.to_be_bytes());
        nonce[4..].copy_from_slice(salt);
        *Nonce::from_slice(&nonce)
    }
}

fn gcm_aad(wire_len: u32, seq: u32) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[0..4].copy_from_slice(&wire_len.to_be_bytes());
    aad[4..8].copy_from_slice(&seq.to_be_bytes());
    aad
}

impl InnerCipher {
    /// 就地加密 region 的前 pt_len 字节；region 必须预留 tag_len() 空间。
    /// 对齐 Go sealInPlace：region = [明文 pt_len][标签空间]。
    pub fn seal_in_place(&self, region: &mut [u8], pt_len: usize, seq: u32, wire_len: u32) {
        if pt_len == 0 {
            return;
        }
        match self {
            InnerCipher::Gcm { aead, .. } => {
                let (ct, tag_space) = region.split_at_mut(pt_len);
                let tag = aead
                    .encrypt_in_place_detached(&self.gcm_nonce(seq), &gcm_aad(wire_len, seq), ct)
                    .expect("GCM encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_slice());
            }
        }
    }

    /// 就地解密并校验，成功后 data 截断为明文。
    /// GCM 校验失败返回 Err（对齐 Go openInPlace）。
    pub fn open_in_place<'a>(
        &self,
        data: &'a mut [u8],
        seq: u32,
        wire_len: u32,
    ) -> Result<&'a mut [u8], ()> {
        if data.is_empty() {
            return Ok(data);
        }
        match self {
            InnerCipher::Gcm { aead, .. } => {
                if data.len() < GCM_TAG_SIZE {
                    return Err(());
                }
                let (ct, tag) = data.split_at_mut(data.len() - GCM_TAG_SIZE);
                let tag_arr = Tag::from_slice(tag);
                aead.decrypt_in_place_detached(
                    &self.gcm_nonce(seq),
                    &gcm_aad(wire_len, seq),
                    ct,
                    tag_arr,
                )
                .map_err(|_| ())?;
                Ok(ct)
            }
        }
    }

    /// 解密 src（GCM 时含标签）写入 dst，返回明文切片。对齐 Go openTo，
    /// 供 FEC 校验载荷解密使用；aad 必须与 seal 时一致。
    pub fn open_to<'a>(
        &self,
        dst: &'a mut [u8],
        src: &[u8],
        seq: u32,
        aad: &[u8],
    ) -> Result<&'a mut [u8], ()> {
        match self {
            InnerCipher::Gcm { aead, .. } => {
                if src.len() < GCM_TAG_SIZE {
                    return Err(());
                }
                let (ct, tag) = src.split_at(src.len() - GCM_TAG_SIZE);
                if dst.len() < ct.len() {
                    return Err(());
                }
                let out = &mut dst[..ct.len()];
                out.copy_from_slice(ct);
                let tag_arr = Tag::from_slice(tag);
                aead.decrypt_in_place_detached(&self.gcm_nonce(seq), aad, out, tag_arr)
                    .map_err(|_| ())?;
                Ok(&mut dst[..ct.len()])
            }
        }
    }
}

pub fn gen_session_id() -> String {
    let mut buf = [0u8; 16];
    RNG.with(|rng| rng.borrow_mut().fill(&mut buf));
    hex::encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 与线上比较对象同形的定长材料（pskHash / 会话令牌均为 64 位 hex）
    const HASH64: [u8; 64] = *b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn constant_time_eq_correctness() {
        assert!(constant_time_eq(&HASH64, &HASH64), "相等输入必须通过");
        assert!(constant_time_eq(b"", b""), "两侧空切片视为相等");

        // 任一位置的错配都必须失败——覆盖"前 N-1 字节相同"的所有 N
        for at in 0..HASH64.len() {
            let mut other = HASH64;
            other[at] ^= 0x01;
            assert!(
                !constant_time_eq(&HASH64, &other),
                "第 {at} 字节错配必须失败"
            );
        }
        // 多字节错配
        let mut other = HASH64;
        other[0] ^= 0xFF;
        other[63] ^= 0xFF;
        assert!(!constant_time_eq(&HASH64, &other));
        // 长度不等：长度本身是公开信息，直接判失败
        assert!(!constant_time_eq(&HASH64, &HASH64[..63]));
        assert!(!constant_time_eq(&HASH64, &HASH64[1..]));
        let mut longer = HASH64.to_vec();
        longer.push(HASH64[0]);
        assert!(
            !constant_time_eq(&HASH64, &longer),
            "前缀全等但更长必须失败（不能退化成 starts_with）"
        );
        assert!(!constant_time_eq(&HASH64, &[]));
    }

    #[test]
    fn constant_time_eq_timing_does_not_leak_prefix() {
        // 锁定"不逐字节短路"的语义：错配发生在第 0 字节还是最后一个字节，
        // 总耗时必须是同量级。真正的保证来自异或折叠，这个测试是防回退的
        // 绊线——有人换回 == 或 starts_with 时会在这里炸掉。
        // 用 64KB 放大差距（64 字节上短路差异被常数项淹没，无法区分）。
        let a = vec![0xABu8; 64 * 1024];
        let mut early = a.clone();
        early[0] ^= 0x01;
        let mut late = a.clone();
        let last = late.len() - 1;
        late[last] ^= 0x01;

        const ROUNDS: usize = 16;
        let measure = |x: &[u8], y: &[u8]| -> std::time::Duration {
            let t = std::time::Instant::now();
            for _ in 0..ROUNDS {
                std::hint::black_box(!constant_time_eq(
                    std::hint::black_box(x),
                    std::hint::black_box(y),
                ));
            }
            t.elapsed()
        };
        let early_dt = measure(&a, &early);
        let late_dt = measure(&a, &late);

        // 阈值来自实测：异或折叠两侧都 ~19µs（比值 1.0）；== 短路是 100ns vs
        // 38µs（比值 ~380）。20 倍足够宽以吸收 CI 抖动，仍能挡住短路实现。
        // 刻意不设绝对下限——短路实现的首字节样本本身就是极小值，任何 ms 级
        // 下限都会把它放过去（8ms 下限实测漏过 == 短路）。
        let budget = early_dt.saturating_mul(20);
        assert!(
            late_dt <= budget,
            "末字节错配 ({late_dt:?}) 显著慢于首字节错配 ({early_dt:?})：\
             比较在短路，前缀长度会通过时延泄露"
        );
    }

    // 黄金向量由 Go 端 computeSessionToken 直接产出（main_test.go 的算法），
    // 并与 openssl dgst -sha256 -mac HMAC -macopt hexkey:<sha256(psk)> 交叉核对。
    // 改这里任何一位都意味着与 Go 端会话令牌不再互通。
    const KAT: [(&str, &str, &str); 4] = [
        (
            "rotate_me_please",
            "550e8400-e29b-41d4-a716-446655440000",
            "74b97373c9d7850945c3366d6b0fb941caf47e20b53f8ef11f9d86ad9054c3d0",
        ),
        (
            "e2e_secret",
            "abc123",
            "d71ae47993fef02dd2ed9f04df735099bf099851a8ff6246e45674e2c565fe2d",
        ),
        (
            "change-me-please",
            "abc123",
            "255e12f98c5e35c3190912037781ab895658bee2bda81e932bc960222e444672",
        ),
        (
            "e2e_secret",
            "",
            "7a45c467705e6b9b0a4352194a4d315a2458f1f07a453836754b07da64d38317",
        ),
    ];

    #[test]
    fn session_token_matches_go_golden_vectors() {
        for (psk, sid, want) in KAT {
            let got = compute_session_token(psk, sid);
            assert_eq!(
                &got, want,
                "compute_session_token(psk={}, sid={:?}) 与 Go 端不一致",
                psk, sid
            );
            assert_eq!(got.len(), 64, "令牌必须是 64 位 hex");
        }
    }

    #[test]
    fn session_token_is_deterministic_and_psk_bound() {
        // 同一 (psk, sessionID) 必须稳定：客户端与服务端各自独立算出同一个值
        let a = compute_session_token("rotate_me_please", "sid-1");
        let b = compute_session_token("rotate_me_please", "sid-1");
        assert_eq!(a, b, "令牌必须是 (psk, sessionID) 的纯函数");
        // sessionID 变了令牌就变（不同会话互不通用）
        assert_ne!(a, compute_session_token("rotate_me_please", "sid-2"));
        // PSK 轮换后旧令牌失效
        assert_ne!(a, compute_session_token("another_psk", "sid-1"));
        // 密钥材料必须是 sha256(psk) 而不是 psk 本身
        assert_ne!(
            psk_key("e2e_secret"),
            compute_session_token("e2e_secret", "abc123").as_bytes()
        );
    }

    #[test]
    fn verify_session_token_accepts_valid_rejects_invalid() {
        for (psk, sid, tok) in KAT {
            assert!(
                verify_session_token(psk, sid, tok),
                "合法令牌校验必须通过 (psk={}, sid={:?})",
                psk,
                sid
            );
        }
    }

    #[test]
    fn verify_session_token_failure_conditions() {
        let (psk, sid, tok) = KAT[0];
        // 会话 ID 被换（冒充别人的会话）
        assert!(
            !verify_session_token(psk, "00000000-0000-0000-0000-000000000000", tok),
            "不同会话 ID 必须失败"
        );
        // PSK 被换（轮换后旧令牌）
        assert!(
            !verify_session_token("another_psk", sid, tok),
            "不同 PSK 必须失败"
        );
        // 空令牌（旧版客户端）——默认关闭该特性时不应误判为合法
        assert!(!verify_session_token(psk, sid, ""), "空令牌必须失败");
        // 非 hex 垃圾串
        assert!(
            !verify_session_token(psk, sid, "garbage"),
            "非 hex 必须失败"
        );
        // 长度不对（63/65 位 hex）
        assert!(
            !verify_session_token(psk, sid, &tok[..63]),
            "长度不足的 hex 必须失败"
        );
        assert!(
            !verify_session_token(psk, sid, &format!("{}f", tok)),
            "长度过长的 hex 必须失败"
        );
        // 64 位 hex 但内容错误
        let mut bad = tok.as_bytes().to_vec();
        bad[0] = if bad[0] == b'0' { b'1' } else { b'0' };
        assert!(
            !verify_session_token(psk, sid, std::str::from_utf8(&bad).unwrap()),
            "改一比特必须失败"
        );
        // 全零标签
        assert!(
            !verify_session_token(psk, sid, &"0".repeat(64)),
            "全零标签必须失败"
        );
    }

    // ---------- 混淆填充策略（档 C） ----------
    //
    // 入参是线路负载长度（明文 + GCM 标签），不是明文长度。
    // 阈值与桶边界逐个对齐 Go 的 TestPadModeOff / TestPadModeBucket / TestPadModeFallback。

    /// 串行执行一次改 pad_mode 全局的用例，结束后恢复原值。
    fn with_pad_mode(mode: &str, f: impl FnOnce()) {
        let _g = PAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = pad_mode_name();
        let _ = set_pad_mode(mode);
        f();
        let _ = set_pad_mode(&prev);
    }

    #[test]
    fn pad_off_never_pads() {
        with_pad_mode("off", || {
            for &n in &[0usize, 1, 100, 200, 1500, 70000] {
                assert_eq!(pad_length(n), 0, "off 模式下 wire_len={} 的填充应为 0", n);
            }
            assert_eq!(pad_mode_name(), "off", "pad_mode_name 应反映实际生效值");
        });
    }

    #[test]
    fn pad_bucket_fills_exactly_to_boundary() {
        with_pad_mode("bucket", || {
            // pad_length 入参不含 10B 头；完整记录碰到桶边界时必须推进到
            // 下一个桶，保证 bucket 模式从不产生零填充。
            for &b in PAD_BUCKETS.iter() {
                let wire = b.saturating_sub(10);
                let got = pad_length(wire);
                assert!(got > 0, "完整记录 {}B 也必须有正填充", b);
            }
            // Go 用例里的精确期望值
            for &(wire_len, want) in &[
                (0usize, 118usize),
                (1, 117),
                (118, 128),
                (128, 118),
                (129, 117),
                (1500, 90),
                (1514, 76),
            ] {
                assert_eq!(
                    pad_length(wire_len),
                    want,
                    "bucket 模式 wire_len={} 应填 {}",
                    wire_len,
                    want
                );
            }
            // 超出最大桶的 jumbo 帧只加小额随机填充
            for _ in 0..100 {
                let got = pad_length(4090);
                assert!(
                    (1..=100).contains(&got),
                    "jumbo 帧填充应为 [1,100]，实际 {}",
                    got
                );
            }
            assert_eq!(pad_mode_name(), "bucket");
        });
    }

    #[test]
    fn bucket_padding_covers_every_normal_ip_packet_length() {
        with_pad_mode("bucket", || {
            for wire_len in 1usize..=(1514 + GCM_TAG_SIZE) {
                let pad = pad_length(wire_len);
                assert!(pad > 0, "wire_len={} was emitted without padding", wire_len);
                let record_len = 10 + wire_len + pad;
                assert!(
                    PAD_BUCKETS.contains(&record_len),
                    "wire_len={} produced non-bucket record length {}",
                    wire_len,
                    record_len
                );
            }
        });
    }

    #[test]
    fn random_session_tokens_are_unique_and_exact() {
        let a = new_session_token().unwrap();
        let b = new_session_token().unwrap();
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert_eq!(b.len(), 64);
        assert!(verify_random_session_token(&a, &a));
        assert!(!verify_random_session_token(&a, &b));
        assert!(!verify_random_session_token(&a, ""));
    }

    #[test]
    fn pad_mode_invalid_falls_back_to_bucket() {
        with_pad_mode("bucket", || {
            for bad in ["bogus", "", "offf", "LEGACY", "legacy", "bucket ", "0"] {
                let got = set_pad_mode(bad);
                assert_eq!(got, "bucket", "非法 pad_mode {:?} 应回落 bucket", bad);
                assert_eq!(
                    pad_mode_name(),
                    "bucket",
                    "非法 pad_mode 后生效值应为 bucket"
                );
            }
        });
    }

    #[test]
    fn pad_mode_valid_accepts_the_two_plus_empty() {
        assert!(pad_mode_valid(""));
        assert!(pad_mode_valid("off"));
        assert!(pad_mode_valid("bucket"));
        for bad in ["bogus", "offf", "LEGACY", "legacy", "bucket ", "1"] {
            assert!(!pad_mode_valid(bad), "配置层应拒绝 {:?}", bad);
        }
        assert_eq!(
            pad_mode_invalid_error("bogus"),
            "invalid pad_mode \"bogus\" (want off or bucket)"
        );
    }

    // ---------- 加密强度下限（档 D） ----------

    /// Go 端 server.go 的拒连条件，逐字复现以便矩阵化测试。
    fn server_rejects_min_enc(encrypt: bool, min_enc: i64, declared_algo: i64) -> bool {
        encrypt && min_enc > 0 && declared_algo != ENC_ALGO_GCM
    }

    /// Go 端 client.go 的拒连条件：不看 encrypt（协商结果已是最终值），
    /// 低于本地下限即视为握手失败并触发重连。
    fn client_rejects_min_enc(min_enc: i64, negotiated_algo: i64) -> bool {
        min_enc > 0 && negotiated_algo != ENC_ALGO_GCM
    }

    #[test]
    fn min_enc_rank_parses_case_insensitively() {
        assert_eq!(min_enc_rank(""), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("any"), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("gcm"), ENC_RANK_GCM);
        // 解析层宽容（大小写/空白），校验层严格 —— 见 validate_args
        for v in ["GCM", "Gcm", "ANY"] {
            assert_eq!(
                min_enc_rank(v),
                min_enc_rank(&v.to_ascii_lowercase()),
                "min_enc 解析不区分大小写：{:?}",
                v
            );
        }
        assert_eq!(min_enc_rank("  gcm  "), ENC_RANK_GCM, "必须 trim");
        assert_eq!(min_enc_rank("bogus"), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("gc"), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("ctr"), ENC_RANK_NONE, "ctr 已随旧协议移除");
        assert_eq!(
            min_enc_invalid_error("bogus"),
            "invalid min_enc \"bogus\" (want gcm, any or empty)"
        );
    }

    #[test]
    fn enc_algo_supported_is_exact_not_magnitude() {
        assert!(enc_algo_supported(ENC_ALGO_GCM, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(ENC_ALGO_NONE, ENC_ALGO_GCM));
        // 关键：算法号不相等就一律视为不支持，不能按数值大小推断能力。
        assert!(!enc_algo_supported(3, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(99, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(ENC_ALGO_GCM, ENC_ALGO_NONE));
    }

    #[test]
    fn gcm_roundtrip_and_key_derivation() {
        let salt = new_random_salt();
        let pt = b"hello gcm payload!";
        let wire = (pt.len() + GCM_TAG_SIZE) as u32;
        // 往返成功（region = 明文 + 标签空间）
        let tx = InnerCipher::gcm("gcm_psk", &salt).unwrap();
        let rx = InnerCipher::gcm("gcm_psk", &salt).unwrap();
        let mut buf = vec![0u8; pt.len() + GCM_TAG_SIZE];
        buf[..pt.len()].copy_from_slice(pt);
        tx.seal_in_place(&mut buf, pt.len(), 42, wire);
        let plain = rx.open_in_place(&mut buf, 42, wire).expect("gcm open");
        assert_eq!(&plain[..pt.len()], pt);

        // 密钥只与 psk 绑定：不同 psk 打开不了彼此的密文
        let wrong = InnerCipher::gcm("other_psk", &salt).unwrap();
        assert!(wrong.open_in_place(&mut buf, 42, wire).is_err());

        // 标签派生必须与 Go 的 gcmKeyLabel 逐字节一致，否则两端无法互通；
        // data 与 fec 两个域也必须用不同密钥
        let data_key = derive_key_labeled("gcm_psk", GCM_KEY_LABEL);
        let fec_key = derive_key_labeled("gcm_psk", "_enc_key_fec");
        assert_ne!(data_key, fec_key, "data 与 fec 域必须用不同密钥");

        // 盐长度非法、未知密钥域均拒绝构造
        assert!(InnerCipher::gcm("x", &[1, 2, 3]).is_err());
        assert!(InnerCipher::gcm_domain("x", &salt, "bogus").is_err());
    }

    #[test]
    fn gcm_data_and_fec_domains_never_share_ciphertext() {
        let salt = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let data = InnerCipher::gcm_domain("domain_psk", &salt, "data").unwrap();
        let fec = InnerCipher::gcm_domain("domain_psk", &salt, "fec").unwrap();
        let plain = b"same plaintext and sequence";
        let wire_len = (plain.len() + GCM_TAG_SIZE) as u32;
        let mut data_wire = vec![0u8; wire_len as usize];
        let mut fec_wire = vec![0u8; wire_len as usize];
        data_wire[..plain.len()].copy_from_slice(plain);
        fec_wire[..plain.len()].copy_from_slice(plain);
        data.seal_in_place(&mut data_wire, plain.len(), 77, wire_len);
        fec.seal_in_place(&mut fec_wire, plain.len(), 77, wire_len);
        assert_ne!(data_wire, fec_wire);
        assert!(data.open_in_place(&mut fec_wire, 77, wire_len).is_err());
    }

    #[test]
    fn min_enc_floor_matrix() {
        // 无下限：任何算法都放行
        assert!(!server_rejects_min_enc(true, ENC_RANK_NONE, ENC_ALGO_NONE));
        assert!(!server_rejects_min_enc(true, ENC_RANK_NONE, ENC_ALGO_GCM));
        // 下限 GCM：未声明 GCM 能力的客户端被拒，GCM 放行
        assert!(
            server_rejects_min_enc(true, ENC_RANK_GCM, ENC_ALGO_NONE),
            "GCM 下限必须拒绝未声明 GCM 能力的客户端"
        );
        assert!(!server_rejects_min_enc(true, ENC_RANK_GCM, ENC_ALGO_GCM));
        // encrypt=false 时下限失效（此时本不该配置 min_enc，校验层已拦）
        assert!(!server_rejects_min_enc(false, ENC_RANK_GCM, ENC_ALGO_NONE));
        // 未知算法 ID 必须被 GCM 下限拦下——用 >= 比较会让它漏过去
        assert!(
            server_rejects_min_enc(true, ENC_RANK_GCM, 3),
            "未知算法 ID 不得被当成 GCM"
        );
    }

    #[test]
    fn client_floor_rejects_downgrade_without_encrypt_guard() {
        // 客户端侧不判断 encrypt：协商结果已经是最终值，低于本地下限就是失败。
        // 缺这一层就会出现"静默降级"——用户明明要求 GCM，实际跑的是明文。
        assert!(!client_rejects_min_enc(ENC_RANK_NONE, ENC_ALGO_NONE));
        assert!(
            client_rejects_min_enc(ENC_RANK_GCM, ENC_ALGO_NONE),
            "服务端降级到明文时必须判定握手失败并重连"
        );
        assert!(!client_rejects_min_enc(ENC_RANK_GCM, ENC_ALGO_GCM));
        assert!(
            client_rejects_min_enc(ENC_RANK_GCM, 3),
            "未知算法 ID 的协商结果不得被当成 GCM"
        );
    }
}
