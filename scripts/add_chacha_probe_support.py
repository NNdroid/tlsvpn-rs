#!/usr/bin/env python3
from pathlib import Path
p = Path('examples/interop_client.rs')
s = p.read_text()
s = s.replace('use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};', 'use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce as AesNonce, Tag as AesTag};\nuse chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag, XChaCha20Poly1305, XNonce};', 1)
start = s.index('struct ProbeCipher {')
end = s.index('/// 从 TLS 流读取一帧', start)
block = r'''enum ProbeCipher {
    Aes256 { aead: Aes256Gcm, salt: [u8; ENC_SALT_SIZE] },
    Aes128 { aead: Aes128Gcm, salt: [u8; ENC_SALT_SIZE] },
    ChaCha20 { aead: ChaCha20Poly1305, salt: [u8; ENC_SALT_SIZE] },
    XChaCha20 { aead: XChaCha20Poly1305, nonce_prefix: [u8; 20] },
}

impl ProbeCipher {
    fn new(psk: &str, salt: &[u8], algo: i64) -> Result<Self, String> {
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!("bad salt len {}", salt.len()));
        }
        let label = match algo {
            2 => "_enc_key",
            4 => "_enc_key128",
            5 => "_enc_chacha20",
            6 => "_enc_xchacha20",
            _ => return Err(format!("unsupported inner cipher {}", algo)),
        };
        let mut h = Sha256::new();
        h.update(psk.as_bytes());
        h.update(label.as_bytes());
        let key = h.finalize();
        let mut salt8 = [0u8; ENC_SALT_SIZE];
        salt8.copy_from_slice(salt);
        match algo {
            2 => Ok(Self::Aes256 { aead: Aes256Gcm::new_from_slice(&key).map_err(|_| "bad aes256 key")?, salt: salt8 }),
            4 => Ok(Self::Aes128 { aead: Aes128Gcm::new_from_slice(&key[..16]).map_err(|_| "bad aes128 key")?, salt: salt8 }),
            5 => Ok(Self::ChaCha20 { aead: ChaCha20Poly1305::new_from_slice(&key).map_err(|_| "bad chacha key")?, salt: salt8 }),
            6 => {
                let aead = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| "bad xchacha key")?;
                let mut nh = Sha256::new();
                nh.update(b"tlsvpn-xchacha20-nonce-v1");
                nh.update(salt);
                let digest = nh.finalize();
                let mut prefix = [0u8; 20];
                prefix.copy_from_slice(&digest[..20]);
                Ok(Self::XChaCha20 { aead, nonce_prefix: prefix })
            }
            _ => unreachable!(),
        }
    }

    fn nonce12(salt: &[u8; ENC_SALT_SIZE], seq: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&seq.to_be_bytes());
        n[4..].copy_from_slice(salt);
        n
    }
    fn nonce24(prefix: &[u8; 20], seq: u32) -> [u8; 24] {
        let mut n = [0u8; 24];
        n[..20].copy_from_slice(prefix);
        n[20..].copy_from_slice(&seq.to_be_bytes());
        n
    }
    fn aad(wire_len: u32, seq: u32) -> [u8; 8] {
        let mut a = [0u8; 8];
        a[0..4].copy_from_slice(&wire_len.to_be_bytes());
        a[4..8].copy_from_slice(&seq.to_be_bytes());
        a
    }

    fn seal(&self, region: &mut [u8], pt_len: usize, seq: u32) {
        let wire_len = region.len() as u32;
        let aad = Self::aad(wire_len, seq);
        let (ct, tag_space) = region.split_at_mut(pt_len);
        let tag = match self {
            Self::Aes256 { aead, salt } => aead.encrypt_in_place_detached(AesNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct).expect("aes256 seal").to_vec(),
            Self::Aes128 { aead, salt } => aead.encrypt_in_place_detached(AesNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct).expect("aes128 seal").to_vec(),
            Self::ChaCha20 { aead, salt } => aead.encrypt_in_place_detached(ChaChaNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct).expect("chacha seal").to_vec(),
            Self::XChaCha20 { aead, nonce_prefix } => aead.encrypt_in_place_detached(XNonce::from_slice(&Self::nonce24(nonce_prefix, seq)), &aad, ct).expect("xchacha seal").to_vec(),
        };
        tag_space[..GCM_TAG_SIZE].copy_from_slice(&tag);
    }

    fn open<'a>(&self, data: &'a mut [u8], seq: u32) -> Result<&'a mut [u8], ()> {
        if data.len() < GCM_TAG_SIZE { return Err(()); }
        let wire_len = data.len() as u32;
        let aad = Self::aad(wire_len, seq);
        let (ct, tag) = data.split_at_mut(data.len() - GCM_TAG_SIZE);
        match self {
            Self::Aes256 { aead, salt } => aead.decrypt_in_place_detached(AesNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct, AesTag::from_slice(tag)).map_err(|_| ())?,
            Self::Aes128 { aead, salt } => aead.decrypt_in_place_detached(AesNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct, AesTag::from_slice(tag)).map_err(|_| ())?,
            Self::ChaCha20 { aead, salt } => aead.decrypt_in_place_detached(ChaChaNonce::from_slice(&Self::nonce12(salt, seq)), &aad, ct, ChaChaTag::from_slice(tag)).map_err(|_| ())?,
            Self::XChaCha20 { aead, nonce_prefix } => aead.decrypt_in_place_detached(XNonce::from_slice(&Self::nonce24(nonce_prefix, seq)), &aad, ct, ChaChaTag::from_slice(tag)).map_err(|_| ())?,
        }
        Ok(ct)
    }
}

'''
s = s[:start] + block + s[end:]
s = s.replace('// 声明的内层加密能力：0 = legacy CTR，2 = GCM。', '// 声明的内层加密算法：2=AES-256-GCM, 4=AES-128-GCM, 5=ChaCha20, 6=XChaCha20。')
old = '''        // 精确比较而非 >=：enc_algo 是枚举不是强度量级，未知算法 ID 不得被
        // 当成 GCM 能力（与 crypto::enc_algo_supported 一致）。fec_group 那边
        // 用 >= 是对的——K 单调递增，K=3 严格强于 K=2。
        // 现在唯一合格值是 2：服务端声明不了 GCM 说明不再受支持，直接失败。
        if algo == 2 {
            let stx = hex::decode(resp.enc_salt.as_deref().unwrap_or("")).unwrap_or_default();
            let srx = hex::decode(resp.enc_salt2.as_deref().unwrap_or("")).unwrap_or_default();
            ic_tx = Some(ProbeCipher::new(&psk, &stx).unwrap_or_else(|e| fail(&e)));
            ic_rx = Some(ProbeCipher::new(&psk, &srx).unwrap_or_else(|e| fail(&e)));
            println!("NEGOTIATED: GCM (per-session bidirectional salts)");
        } else {
            println!("NEGOTIATED: algo={} (plaintext or unknown)", algo);
            println!("FAIL: expected GCM negotiation with modern server");
            std::process::exit(1);
        }
'''
new = '''        // enc_algo 是枚举，必须与探针请求精确一致，不能按数值大小推断能力。
        if algo == enc_algo && matches!(algo, 2 | 4 | 5 | 6) {
            let stx = hex::decode(resp.enc_salt.as_deref().unwrap_or("")).unwrap_or_default();
            let srx = hex::decode(resp.enc_salt2.as_deref().unwrap_or("")).unwrap_or_default();
            ic_tx = Some(ProbeCipher::new(&psk, &stx, algo).unwrap_or_else(|e| fail(&e)));
            ic_rx = Some(ProbeCipher::new(&psk, &srx, algo).unwrap_or_else(|e| fail(&e)));
            println!("NEGOTIATED: inner AEAD algo={} (per-session bidirectional salts)", algo);
        } else {
            println!("NEGOTIATED: algo={} (plaintext or unknown)", algo);
            println!("FAIL: expected requested authenticated inner AEAD");
            std::process::exit(1);
        }
'''
if old not in s: raise SystemExit('negotiation block not found')
s = s.replace(old, new, 1)
s = s.replace('FAIL: GCM OPEN FAILED', 'FAIL: AEAD OPEN FAILED')
p.write_text(s)
