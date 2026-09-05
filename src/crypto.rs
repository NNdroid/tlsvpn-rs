use aes::Aes256;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};

use crate::utils::*;

// 与 Go 端 crypto.go 对齐的算法常量
pub const ENC_ALGO_LEGACY_CTR: i64 = 0;
pub const ENC_ALGO_GCM: i64 = 2;
pub const GCM_TAG_SIZE: usize = 16;
pub const GCM_NONCE_SIZE: usize = 12;
pub const ENC_SALT_SIZE: usize = 8;

// 客户端握手请求里声明的本端最高算法支持（对齐 Go clientEncAlgoSupport）
pub const CLIENT_ENC_ALGO_SUPPORT: i64 = ENC_ALGO_GCM;

pub fn hash_psk(psk: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(psk.as_bytes());
    hex::encode(hasher.finalize())
}

pub fn generate_padding(min: usize, max: usize) -> String {
    let len = RNG.with(|rng| rng.borrow_mut().gen_range(min, max + 1));
    let mut buf = vec![0u8; len];
    RNG.with(|rng| rng.borrow_mut().fill(&mut buf));
    hex::encode(buf)
}

/// 填充长度策略（对齐 Go getPaddingLength）：
/// 0 → [100,300]，<200 → [300,499]，<800 → [100,299]，其余 → [0,99]
pub fn get_padding_length(data_len: usize) -> usize {
    RNG.with(|rng| {
        let mut r = rng.borrow_mut();
        if data_len == 0 {
            100 + r.gen_range(0, 201)
        } else if data_len < 200 {
            300 + r.gen_range(0, 200)
        } else if data_len < 800 {
            100 + r.gen_range(0, 200)
        } else {
            r.gen_range(0, 100)
        }
    })
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

// 生成本端导出的 AES-256 key（legacy CTR 与 GCM 共用）
fn derive_key(psk: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(format!("{}_enc_key", psk).as_bytes());
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
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!(
                "encryption salt must be {} bytes, got {}",
                ENC_SALT_SIZE,
                salt.len()
            ));
        }
        let key = derive_key(psk);
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
