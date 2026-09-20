use aes::Aes256;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU8, Ordering};

use crate::utils::*;

// 与 Go 端 crypto.go 对齐的算法常量
pub const ENC_ALGO_LEGACY_CTR: i64 = 0;
pub const ENC_ALGO_GCM: i64 = 2;
/// 协商式 GCM 密钥分离（对齐 Go encAlgoGCMV2）：算法语义与 2 完全一致，仅密钥
/// 改为独立标签派生，消除"同一 AES 密钥同时充当 GCM 的 GHASH 子密钥与 legacy
/// CTR 密钥流"的分层混用。必须走协商：直接改 2 的派生会让"新服务端+旧客户端"
/// 在双方都声明支持 GCM 的情况下静默黑洞（协商成功、标签全败）；改为新算法值
/// 后旧对端自动回退 CTR。新客户端声明 3，新服务端按 3 用 v2 密钥、按 2 用旧密钥。
pub const ENC_ALGO_GCM_V2: i64 = 3;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_NONCE_SIZE: usize = 12;
pub const ENC_SALT_SIZE: usize = 8;

// 客户端握手请求里声明的本端最高算法支持（对齐 Go clientEncAlgoSupport）。
// 声明 v2(3)：新服务端按 3 协商 v2 密钥；旧服务端精确匹配 2 失败会回退
// legacy CTR（安全降级，绝不静默黑洞）——两端都升级后 GCM 恢复。
pub const CLIENT_ENC_ALGO_SUPPORT: i64 = ENC_ALGO_GCM_V2;

/// 把协商出的内层算法号归一化成面板固定的三个值：
/// 0=无内层加密，1=legacy CTR，2=GCM（v1/v2 密钥派生不同，语义一致）。
///
/// 不能直接下发原始算法号：ENC_ALGO_LEGACY_CTR 的值是 0，与"未加密"撞号；
/// 而面板只认识 2，GCM-v2=3 会落进"明文"兜底分支。对齐 Go encAlgoForDisplay。
pub fn enc_algo_for_display(enc_algo: i64, encrypt: bool) -> i64 {
    if !encrypt {
        return 0;
    }
    if enc_algo == ENC_ALGO_GCM || enc_algo == ENC_ALGO_GCM_V2 {
        return 2;
    }
    1
}

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
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&psk_key(psk))
        .expect("HMAC accepts any key length");
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

pub fn generate_padding(min: usize, max: usize) -> String {
    let len = RNG.with(|rng| rng.borrow_mut().gen_range(min, max + 1));
    let mut buf = vec![0u8; len];
    RNG.with(|rng| rng.borrow_mut().fill(&mut buf));
    hex::encode(buf)
}

/// 混淆填充策略（对齐 Go frame.go 的 padModeCode）。
/// 发送路径按整数码分派，接收路径完全不看它——pad_len 在帧头里自带。
pub const PAD_OFF: u8 = 0;
pub const PAD_LEGACY: u8 = 1;
pub const PAD_BUCKET: u8 = 2;

pub const PAD_MODE_OFF: &str = "off";
pub const PAD_MODE_LEGACY: &str = "legacy";
pub const PAD_MODE_BUCKET: &str = "bucket";

/// 默认与进程初值都是 legacy（对齐 Go 的 init()），
/// 但配置层的空串会在应用前被改写成 bucket。
static PAD_MODE_CODE: AtomicU8 = AtomicU8::new(PAD_LEGACY);

// pad_mode 是进程级全局状态。Rust 测试默认并行，改它的用例必须串行；
// 这里只放锁，策略分派不持锁，避免发送热路径出现同步开销。
#[cfg(test)]
pub static PAD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 小帧填充目标桶（覆盖 MTU 1500 常见帧及其含标签长度）
const PAD_BUCKETS: [usize; 8] = [128, 256, 384, 512, 768, 1024, 1280, 1514];

/// 切换填充策略（非法值回落 legacy），返回实际生效的策略名。
/// 空串也算非法 → legacy；配置层的"空串即 bucket"改写必须在此之前完成。
pub fn set_pad_mode(mode: &str) -> String {
    match mode {
        PAD_MODE_OFF => PAD_MODE_CODE.store(PAD_OFF, Ordering::Relaxed),
        PAD_MODE_BUCKET => PAD_MODE_CODE.store(PAD_BUCKET, Ordering::Relaxed),
        _ => {
            PAD_MODE_CODE.store(PAD_LEGACY, Ordering::Relaxed);
            return PAD_MODE_LEGACY.to_string();
        }
    }
    mode.to_string()
}

pub fn pad_mode_name() -> String {
    match PAD_MODE_CODE.load(Ordering::Relaxed) {
        PAD_OFF => PAD_MODE_OFF.to_string(),
        PAD_BUCKET => PAD_MODE_BUCKET.to_string(),
        _ => PAD_MODE_LEGACY.to_string(),
    }
}

/// 当前策略下该线路长度应加多少填充。
/// wire_len 必须是线路长度（明文 + GCM 标签），不是明文长度。
pub fn pad_length(wire_len: usize) -> usize {
    match PAD_MODE_CODE.load(Ordering::Relaxed) {
        PAD_OFF => 0,
        PAD_BUCKET => pad_bucket(wire_len),
        _ => pad_legacy(wire_len),
    }
}

/// 旧版随机填充（阈值语义不变，入参改为线路长度）
pub fn pad_legacy(wire_len: usize) -> usize {
    RNG.with(|rng| {
        let mut r = rng.borrow_mut();
        if wire_len == 0 {
            100 + r.gen_range(0, 201)
        } else if wire_len < 200 {
            300 + r.gen_range(0, 200)
        } else if wire_len < 800 {
            100 + r.gen_range(0, 200)
        } else {
            r.gen_range(0, 100)
        }
    })
}

/// 填充到固定长度桶；超出最大桶的 jumbo 帧只加小额随机填充，
/// 不为抗流量分析付过大带宽代价。
pub fn pad_bucket(wire_len: usize) -> usize {
    if wire_len == 0 {
        return 0;
    }
    for &b in PAD_BUCKETS.iter() {
        if wire_len <= b {
            return b - wire_len;
        }
    }
    RNG.with(|rng| rng.borrow_mut().gen_range(0, 100))
}

/// 校验 pad_mode 取值（配置加载层，对齐 Go Config.Validate）。
/// 空串合法：等价于默认 bucket。
pub fn pad_mode_valid(mode: &str) -> bool {
    mode.is_empty()
        || mode == PAD_MODE_OFF
        || mode == PAD_MODE_LEGACY
        || mode == PAD_MODE_BUCKET
}

/// 配置加载层的错误文案，与 Go Validate 逐字一致
pub fn pad_mode_invalid_error(mode: &str) -> String {
    format!(
        "invalid pad_mode {:?} (want {}, {} or {})",
        mode, PAD_MODE_OFF, PAD_MODE_LEGACY, PAD_MODE_BUCKET
    )
}

// ======================= 加密强度下限（min_enc） =======================
//
// 旧实现里"是否加密"是布尔开关：一端把 encrypt 关掉，整条链路（含 FEC 校验帧）
// 就只剩 TLS 一层。min_enc 把开关换成强度下限，允许运维强制"低于 GCM 一律拒连"。
//
// 取值："" 或 "any"（无下限，保持旧行为）、"ctr"/"legacy"、"gcm"

// 强度排序（数值越大越强），与算法 ID 是两套编码。
// 注意：ENC_ALGO_LEGACY_CTR 的值恰为 0，若直接拿算法 ID 当强度用，
// "最低要求 CTR" 会被解析成"不设下限"。
pub const ENC_RANK_NONE: i64 = 0;
pub const ENC_RANK_CTR: i64 = 1;
pub const ENC_RANK_GCM: i64 = 2;

pub const MIN_ENC_CTR: &str = "ctr";
pub const MIN_ENC_LEGACY: &str = "legacy";
pub const MIN_ENC_GCM: &str = "gcm";

/// 算法强度排序；未知算法视为最弱（CTR 档）。
/// 0 / 1 / 任何其它值都算 CTR——只有恰好等于 ENC_ALGO_GCM/V2 才算 GCM。
pub fn enc_algo_rank(algo: i64) -> i64 {
    if algo == ENC_ALGO_GCM || algo == ENC_ALGO_GCM_V2 {
        ENC_RANK_GCM
    } else {
        ENC_RANK_CTR
    }
}

/// 解析最低强度配置；0 表示不设下限
pub fn min_enc_rank(mode: &str) -> i64 {
    match mode.trim().to_ascii_lowercase().as_str() {
        MIN_ENC_GCM => ENC_RANK_GCM,
        MIN_ENC_CTR | MIN_ENC_LEGACY => ENC_RANK_CTR,
        _ => ENC_RANK_NONE,
    }
}

/// 对端声明的算法位集是否恰好等于某算法。
/// 刻意用精确比较而非 >=：Go 侧正是因为 >= 比出了 bug——未知算法值
/// 会被误判为"满足 GCM 下限"。未来若定义算法 3，旧实现对端不该被放过。
pub fn enc_algo_supported(declared: i64, want: i64) -> bool {
    declared == want
}

/// 配置加载层的错误文案，与 Go Validate 逐字一致
pub fn min_enc_invalid_error(mode: &str) -> String {
    format!(
        "invalid min_enc {:?} (want {}, {} or empty)",
        mode, MIN_ENC_CTR, MIN_ENC_GCM
    )
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

// 生成本端导出的 AES-256 key（legacy CTR 与 GCM-v1 共用，历史原因）
fn derive_key(psk: &str) -> [u8; 32] {
    derive_key_labeled(psk, "_enc_key")
}

/// 按标签派生 AES-256 key（对齐 Go gcmKeyLabel：GCM-v2 用独立标签实现
/// GCM/CTR 密钥分离）
fn derive_key_labeled(psk: &str, label: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}{}", psk, label).as_bytes());
    let out = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

/// 各 GCM 算法值的密钥派生标签。算法 2 保留旧标签以兼容既有实现；
/// 算法 3 用独立标签实现 GCM/CTR 密钥分离（对齐 Go gcmKeyLabel）。
fn gcm_key_label(algo: i64) -> &'static str {
    if algo == ENC_ALGO_GCM_V2 {
        "_enc_key_gcm_v2"
    } else {
        "_enc_key"
    }
}

/// 每会话随机的方向盐（crypto/rand 等价物，对齐 Go newRandomSalt）
pub fn new_random_salt() -> [u8; ENC_SALT_SIZE] {
    let mut s = [0u8; ENC_SALT_SIZE];
    getrandom::getrandom(&mut s).expect("Failed to generate encryption salt");
    s
}

/// 内层载荷加密器，对齐 Go 的 innerCipher 两种算法：
/// - Legacy：AES-256-CTR 异或，帧长不变，密钥调度一次构建、每帧复用；
/// - GCM：AES-256-GCM，nonce = seq(4BE) || salt(8B)，AAD = wireLen(4BE) || seq(4BE)，
///   密文后附 16B 标签（线路 dataLen = 明文长 + 16）。
pub enum InnerCipher {
    Legacy {
        block: Aes256,
        base_iv: [u8; 16],
    },
    Gcm {
        aead: Aes256Gcm,
        salt: [u8; ENC_SALT_SIZE],
    },
}

type GcmNonce = aes_gcm::Nonce<aes_gcm::aead::consts::U12>;

impl InnerCipher {
    pub fn legacy(psk: &str) -> InnerCipher {
        let key = derive_key(psk);
        let block = Aes256::new((&key).into());
        let mut i_hasher = Sha256::new();
        i_hasher.update(format!("{}_enc_iv", psk).as_bytes());
        let iv_full = i_hasher.finalize();
        let mut base_iv = [0u8; 16];
        base_iv.copy_from_slice(&iv_full[..16]);
        InnerCipher::Legacy { block, base_iv }
    }

    pub fn gcm(psk: &str, salt: &[u8]) -> Result<InnerCipher, String> {
        Self::gcm_algo(psk, salt, ENC_ALGO_GCM)
    }

    /// 按协商出的算法值构造 GCM 加密器（2 或 3；二者仅密钥派生标签不同）
    pub fn gcm_algo(psk: &str, salt: &[u8], algo: i64) -> Result<InnerCipher, String> {
        if algo != ENC_ALGO_GCM && algo != ENC_ALGO_GCM_V2 {
            return Err(format!("unknown GCM algo {}", algo));
        }
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!(
                "encryption salt must be {} bytes, got {}",
                ENC_SALT_SIZE,
                salt.len()
            ));
        }
        let key = derive_key_labeled(psk, gcm_key_label(algo));
        let aead = Aes256Gcm::new((&key).into());
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
            InnerCipher::Legacy { .. } => 0,
        }
    }

    fn gcm_nonce(&self, seq: u32) -> GcmNonce {
        match self {
            InnerCipher::Gcm { salt, .. } => {
                let mut nonce = [0u8; GCM_NONCE_SIZE];
                nonce[0..4].copy_from_slice(&seq.to_be_bytes());
                nonce[4..].copy_from_slice(salt);
                *Nonce::from_slice(&nonce)
            }
            _ => unreachable!(),
        }
    }
}

fn gcm_aad(wire_len: u32, seq: u32) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[0..4].copy_from_slice(&wire_len.to_be_bytes());
    aad[4..8].copy_from_slice(&seq.to_be_bytes());
    aad
}

/// 手写 AES-CTR（大端 128 位计数器），密钥调度复用 `block`，与
/// `ctr::Ctr128BE<Aes256>`（及 Go cipher.NewCTR）输出逐字节一致。
/// 8 块栈上批处理走 AES-NI 交错路径，比逐块 `encrypt_block` 快 2-4 倍。
fn ctr_apply(block: &Aes256, base_iv: &[u8; 16], seq: u32, data: &mut [u8]) {
    use aes::cipher::BlockEncrypt;
    let mut iv = *base_iv;
    iv[12..16].copy_from_slice(&seq.to_be_bytes());
    let mut counter = u128::from_be_bytes(iv);

    const PAR: usize = 8;
    let full = data.len() / 16;
    let mut done = 0usize;
    while done + PAR <= full {
        let mut ks: [aes::Block; PAR] = Default::default();
        for b in ks.iter_mut() {
            *b = aes::Block::from(counter.to_be_bytes());
            counter = counter.wrapping_add(1);
        }
        block.encrypt_blocks(&mut ks);
        let seg = &mut data[done * 16..(done + PAR) * 16];
        for (i, blk) in ks.iter().enumerate() {
            for (b, k) in seg[i * 16..(i + 1) * 16].iter_mut().zip(blk.iter()) {
                *b ^= k;
            }
        }
        done += PAR;
    }
    while done < full {
        let mut ks = aes::Block::from(counter.to_be_bytes());
        counter = counter.wrapping_add(1);
        block.encrypt_block(&mut ks);
        for (b, k) in data[done * 16..done * 16 + 16].iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        done += 1;
    }
    // 尾部非对齐字节复用最后一块密钥流（CTR 语义）
    let tail_start = full * 16;
    if tail_start < data.len() {
        let mut ks = aes::Block::from(counter.to_be_bytes());
        block.encrypt_block(&mut ks);
        for (b, k) in data[tail_start..].iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
    }
}

impl InnerCipher {
    /// 就地加密 region 的前 pt_len 字节；region 必须预留 tag_len() 空间。
    /// 对齐 Go sealInPlace：region = [明文 pt_len][标签空间]。
    pub fn seal_in_place(&self, region: &mut [u8], pt_len: usize, seq: u32, wire_len: u32) {
        if pt_len == 0 {
            return;
        }
        match self {
            InnerCipher::Legacy { block, base_iv } => {
                ctr_apply(block, base_iv, seq, &mut region[..pt_len]);
            }
            InnerCipher::Gcm { aead, .. } => {
                let (ct, tag_space) = region.split_at_mut(pt_len);
                let tag = aead
                    .encrypt_in_place_detached(&self.gcm_nonce(seq), &gcm_aad(wire_len, seq), ct)
                    .expect("GCM encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_slice());
            }
        }
    }

    /// 就地解密并校验，成功后 data 截断为明文。legacy 恒成功；
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
            InnerCipher::Legacy { block, base_iv } => {
                ctr_apply(block, base_iv, seq, data);
                Ok(data)
            }
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
            InnerCipher::Legacy { block, base_iv } => {
                let n = src.len().min(dst.len());
                dst[..n].copy_from_slice(&src[..n]);
                ctr_apply(block, base_iv, seq, &mut dst[..n]);
                Ok(&mut dst[..n])
            }
        }
    }
}

/// 计算任一 seq 的 legacy 密钥流应用（供黄金向量测试等独立场景使用）
pub fn xor_crypt_in_place(data: &mut [u8], seq: u32, key: &[u8], base_iv: &[u8]) {
    if data.is_empty() || key.is_empty() {
        return;
    }
    let block = Aes256::new(key.into());
    let mut iv = [0u8; 16];
    iv.copy_from_slice(&base_iv[..16]);
    ctr_apply(&block, &iv, seq, data);
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
        ("e2e_secret", "", "7a45c467705e6b9b0a4352194a4d315a2458f1f07a453836754b07da64d38317"),
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
        assert_ne!(psk_key("e2e_secret"), compute_session_token("e2e_secret", "abc123").as_bytes());
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
        assert!(!verify_session_token(psk, sid, "garbage"), "非 hex 必须失败");
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
    // 阈值与桶边界逐个对齐 Go 的 TestPadModeLegacyRanges / Off / Bucket / Fallback。

    /// 串行执行一次改 pad_mode 全局的用例，结束后恢复原值。
    fn with_pad_mode(mode: &str, f: impl FnOnce()) {
        let _g = PAD_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let prev = pad_mode_name();
        let _ = set_pad_mode(mode);
        f();
        let _ = set_pad_mode(&prev);
    }

    #[test]
    fn pad_legacy_ranges_match_go() {
        with_pad_mode("legacy", || {
            for &(wire_len, (min, max)) in &[
                (0usize, (100usize, 300usize)),
                (1, (300, 499)),
                (199, (300, 499)),
                (200, (100, 299)),
                (799, (100, 299)),
                (800, (0, 99)),
                (1400, (0, 99)),
            ] {
                for _ in 0..200 {
                    let got = pad_length(wire_len);
                    assert!(
                        got >= min && got <= max,
                        "legacy 模式 wire_len={} 的填充 {} 超出预期范围 [{},{}]",
                        wire_len,
                        got,
                        min,
                        max
                    );
                }
            }
        });
    }

    #[test]
    fn pad_off_never_pads() {
        with_pad_mode("off", || {
            for &n in &[0usize, 1, 100, 200, 1500, 70000] {
                assert_eq!(
                    pad_length(n),
                    0,
                    "off 模式下 wire_len={} 的填充应为 0",
                    n
                );
            }
            assert_eq!(pad_mode_name(), "off", "pad_mode_name 应反映实际生效值");
        });
    }

    #[test]
    fn pad_bucket_fills_exactly_to_boundary() {
        with_pad_mode("bucket", || {
            // 逐个桶核对：桶边界本身不填，边界前一字节恰好填 1
            for &b in PAD_BUCKETS.iter() {
                assert_eq!(
                    pad_length(b),
                    0,
                    "bucket 模式 wire_len={}（正好在桶边界）应填 0",
                    b
                );
                assert_eq!(
                    pad_length(b - 1),
                    1,
                    "bucket 模式 wire_len={} 应填 1 到 {} 桶",
                    b - 1,
                    b
                );
            }
            // Go 用例里的精确期望值
            for &(wire_len, want) in &[
                (0usize, 0usize),
                (1, 127),
                (128, 0),
                (129, 127),
                (1500, 14),
                (1514, 0),
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
                let got = pad_length(1515);
                assert!(
                    got <= 99,
                    "jumbo 帧填充应为 [0,99]，实际 {}",
                    got
                );
            }
            assert_eq!(pad_mode_name(), "bucket");
        });
    }

    #[test]
    fn pad_mode_invalid_falls_back_to_legacy() {
        with_pad_mode("legacy", || {
            for bad in ["bogus", "", "offf", "LEGACY", "bucket ", "0"] {
                let got = set_pad_mode(bad);
                assert_eq!(
                    got, "legacy",
                    "非法 pad_mode {:?} 应回落 legacy",
                    bad
                );
                assert_eq!(
                    pad_mode_name(),
                    "legacy",
                    "非法 pad_mode 后生效值应为 legacy"
                );
            }
        });
    }

    #[test]
    fn pad_mode_valid_accepts_the_three_plus_empty() {
        assert!(pad_mode_valid(""));
        assert!(pad_mode_valid("off"));
        assert!(pad_mode_valid("legacy"));
        assert!(pad_mode_valid("bucket"));
        for bad in ["bogus", "offf", "LEGACY", "bucket ", "1"] {
            assert!(!pad_mode_valid(bad), "配置层应拒绝 {:?}", bad);
        }
        assert_eq!(
            pad_mode_invalid_error("bogus"),
            "invalid pad_mode \"bogus\" (want off, legacy or bucket)"
        );
    }

    // ---------- 加密强度下限（档 D） ----------

    /// Go 端 server.go 的拒连条件，逐字复现以便矩阵化测试。
    fn server_rejects_min_enc(encrypt: bool, min_enc: i64, declared_algo: i64) -> bool {
        encrypt && min_enc > 0 && enc_algo_rank(declared_algo) < min_enc
    }

    /// Go 端 client.go 的拒连条件：不看 encrypt（协商结果已是最终值），
    /// 低于本地下限即视为握手失败并触发重连。
    fn client_rejects_min_enc(min_enc: i64, negotiated_algo: i64) -> bool {
        min_enc > 0 && enc_algo_rank(negotiated_algo) < min_enc
    }

    #[test]
    fn enc_algo_rank_treats_unknown_as_weakest() {
        // 回归锁：只有恰好等于 ENC_ALGO_GCM/GCM_V2 才算 GCM。未知算法必须落到
        // CTR 档，绝不能因为"数值更大"就算满足 GCM 下限。
        assert_eq!(enc_algo_rank(ENC_ALGO_GCM), ENC_RANK_GCM);
        assert_eq!(enc_algo_rank(ENC_ALGO_GCM_V2), ENC_RANK_GCM);
        for algo in [0i64, 1, 4, 7, 99, -1, i64::MAX] {
            assert_eq!(
                enc_algo_rank(algo),
                ENC_RANK_CTR,
                "算法 ID {} 应被视为 CTR 档（未知算法算最弱）",
                algo
            );
        }
    }

    #[test]
    fn min_enc_rank_parses_case_insensitively() {
        assert_eq!(min_enc_rank(""), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("any"), ENC_RANK_NONE);
        assert_eq!(min_enc_rank("ctr"), ENC_RANK_CTR);
        assert_eq!(min_enc_rank("legacy"), ENC_RANK_CTR);
        assert_eq!(min_enc_rank("gcm"), ENC_RANK_GCM);
        // 解析层宽容（大小写/空白），校验层严格 —— 见 validate_args
        for v in ["GCM", "Ctr", "LEGACY", "ANY"] {
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
        assert_eq!(
            min_enc_invalid_error("bogus"),
            "invalid min_enc \"bogus\" (want ctr, gcm or empty)"
        );
    }

    #[test]
    fn enc_algo_supported_is_exact_not_magnitude() {
        assert!(enc_algo_supported(ENC_ALGO_GCM, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(ENC_ALGO_LEGACY_CTR, ENC_ALGO_GCM));
        // 关键：算法号不相等就一律视为不支持，不能按数值大小推断能力。
        // GCM-v2=3 语义上确实是 GCM，但只声明 2 的旧对端不得被当成支持 v2。
        assert!(!enc_algo_supported(ENC_ALGO_GCM_V2, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(99, ENC_ALGO_GCM));
        assert!(!enc_algo_supported(ENC_ALGO_GCM, ENC_ALGO_LEGACY_CTR));
    }

    #[test]
    fn enc_algo_for_display_covers_the_ambiguity() {
        // 0 号歧义：legacy CTR 的算法号就是 0，必须靠 encrypt 区分"未加密"
        assert_eq!(enc_algo_for_display(ENC_ALGO_LEGACY_CTR, false), 0);
        assert_eq!(enc_algo_for_display(ENC_ALGO_LEGACY_CTR, true), 1);
        // GCM v1 与 v2 密钥派生不同，但对面板是同一种内层加密
        assert_eq!(enc_algo_for_display(ENC_ALGO_GCM, true), 2);
        assert_eq!(enc_algo_for_display(ENC_ALGO_GCM_V2, true), 2);
        // 未加密时任何算法号都是 0——否则面板会把明文会话标成 CTR
        assert_eq!(enc_algo_for_display(ENC_ALGO_GCM_V2, false), 0);
        // 未知算法号 + encrypt 一律归为 CTR，不产生面板不认识的 3
        assert_eq!(enc_algo_for_display(99, true), 1);
    }

    #[test]
    fn gcm_v2_roundtrip_and_key_separation() {
        let salt = new_random_salt();
        let wire = (16 + GCM_TAG_SIZE) as u32;
        // 同算法往返成功（region = 明文 16B + 标签空间 16B）
        let tx = InnerCipher::gcm_algo("v2_psk", &salt, ENC_ALGO_GCM_V2).unwrap();
        let rx = InnerCipher::gcm_algo("v2_psk", &salt, ENC_ALGO_GCM_V2).unwrap();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(b"hello gcm v2 pay");
        tx.seal_in_place(&mut buf, 16, 42, wire);
        let plain = rx.open_in_place(&mut buf, 42, wire).expect("v2 open");
        assert_eq!(&plain[..16], b"hello gcm v2 pay");

        // 密钥分离：v1 密文必须不能用 v2 密钥打开——
        // 这是把 GCM/CTR 密钥混用问题做成分离协商值的全部意义
        let tx1 = InnerCipher::gcm("sep_psk", &salt).unwrap();
        let rx2 = InnerCipher::gcm_algo("sep_psk", &salt, ENC_ALGO_GCM_V2).unwrap();
        let mut buf1 = [0u8; 32];
        buf1[..16].copy_from_slice(b"cross-label pay!");
        tx1.seal_in_place(&mut buf1, 16, 7, wire);
        assert!(
            rx2.open_in_place(&mut buf1, 7, wire).is_err(),
            "v1 密文不得被 v2 密钥打开"
        );

        // 未知算法值拒绝构造
        assert!(InnerCipher::gcm_algo("x", &salt, 99).is_err());

        // v2 与 v1 同强度档（min_enc=gcm 必须同时接受 2 与 3）
        assert_eq!(enc_algo_rank(ENC_ALGO_GCM_V2), ENC_RANK_GCM);
    }

    #[test]
    fn min_enc_floor_matrix() {
        // 无下限：任何算法都放行
        assert!(!server_rejects_min_enc(true, ENC_RANK_NONE, ENC_ALGO_LEGACY_CTR));
        assert!(!server_rejects_min_enc(true, ENC_RANK_NONE, ENC_ALGO_GCM));
        // 下限 CTR：legacy CTR 与 GCM 都够
        assert!(!server_rejects_min_enc(true, ENC_RANK_CTR, ENC_ALGO_LEGACY_CTR));
        assert!(!server_rejects_min_enc(true, ENC_RANK_CTR, ENC_ALGO_GCM));
        // 下限 GCM：CTR 客户端被拒，GCM 放行
        assert!(
            server_rejects_min_enc(true, ENC_RANK_GCM, ENC_ALGO_LEGACY_CTR),
            "GCM 下限必须拒绝 CTR 客户端"
        );
        assert!(!server_rejects_min_enc(true, ENC_RANK_GCM, ENC_ALGO_GCM));
        // GCM-v2(3) 与 v1 同强度档
        assert!(!server_rejects_min_enc(true, ENC_RANK_GCM, ENC_ALGO_GCM_V2));
        // encrypt=false 时下限失效（此时本不该配置 min_enc，校验层已拦）
        assert!(!server_rejects_min_enc(false, ENC_RANK_GCM, ENC_ALGO_LEGACY_CTR));
        // 未知算法 ID 必须被 GCM 下限拦下——用 >= 比较会让它漏过去
        assert!(
            server_rejects_min_enc(true, ENC_RANK_GCM, 4),
            "未知算法 ID 必须算 CTR 档并被 GCM 下限拒绝"
        );
    }

    #[test]
    fn client_floor_rejects_downgrade_without_encrypt_guard() {
        // 客户端侧不判断 encrypt：协商结果已经是最终值，低于本地下限就是失败。
        // 缺这一层就会出现"静默降级"——用户明明要求 GCM，实际跑的是 CTR。
        assert!(!client_rejects_min_enc(ENC_RANK_NONE, ENC_ALGO_LEGACY_CTR));
        assert!(!client_rejects_min_enc(ENC_RANK_CTR, ENC_ALGO_LEGACY_CTR));
        assert!(
            client_rejects_min_enc(ENC_RANK_GCM, ENC_ALGO_LEGACY_CTR),
            "服务端降级到 CTR 时必须判定握手失败并重连"
        );
        assert!(!client_rejects_min_enc(ENC_RANK_GCM, ENC_ALGO_GCM));
        // GCM-v2(3) 与 v1 同强度档，不得拒
        assert!(!client_rejects_min_enc(ENC_RANK_GCM, ENC_ALGO_GCM_V2));
        assert!(
            client_rejects_min_enc(ENC_RANK_GCM, 4),
            "未知算法 ID 的协商结果不得被当成 GCM"
        );
    }
}
