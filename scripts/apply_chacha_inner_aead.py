#!/usr/bin/env python3
from pathlib import Path

# Cargo dependency (one crypto implementation for ChaCha20 and XChaCha20).
p = Path('Cargo.toml'); s = p.read_text()
if 'chacha20poly1305 = ' not in s:
    s = s.replace('ring = "0.17"\n', 'ring = "0.17"\nchacha20poly1305 = "0.10"\n', 1)
p.write_text(s)

# Config surface: reuse enc_algo, add no fields. Legacy min_enc="gcm" now means authenticated AEAD floor.
p = Path('src/main.rs'); s = p.read_text()
s = s.replace('pub enc_algo: String, // gcm256（默认）| gcm128（显式性能模式）', 'pub enc_algo: String, // gcm256（默认）| gcm128 | chacha20 | xchacha20')
s = s.replace('"" | "gcm256" | "gcm128" => {}', '"" | "gcm256" | "gcm128" | "chacha20" | "xchacha20" => {}')
s = s.replace('invalid enc_algo {:?} (want gcm256 or gcm128)', 'invalid enc_algo {:?} (want gcm256, gcm128, chacha20 or xchacha20)')
p.write_text(s)

p = Path('src/crypto.rs'); s = p.read_text()
if 'chacha20poly1305::' not in s:
    s = s.replace('use ring::aead::{self, Aad, LessSafeKey, Nonce, Tag, UnboundKey};\n', 'use ring::aead::{self, Aad, LessSafeKey, Nonce as RingNonce, Tag as RingTag, UnboundKey};\nuse chacha20poly1305::{\n    aead::{AeadInPlace as _, KeyInit as _},\n    ChaCha20Poly1305, Nonce as ChaChaNonce, Tag as ChaChaTag, XChaCha20Poly1305, XNonce,\n};\n', 1)
s = s.replace('pub const ENC_ALGO_GCM128: i64 = 4;\n', 'pub const ENC_ALGO_GCM128: i64 = 4;\npub const ENC_ALGO_CHACHA20: i64 = 5;\npub const ENC_ALGO_XCHACHA20: i64 = 6;\n', 1)
s = s.replace('pub const GCM_NONCE_SIZE: usize = 12;\n', 'pub const GCM_NONCE_SIZE: usize = 12;\npub const XCHACHA_NONCE_SIZE: usize = 24;\n', 1)
s = s.replace('pub const GCM128_KEY_LABEL: &str = "_enc_key128";\n', 'pub const GCM128_KEY_LABEL: &str = "_enc_key128";\npub const CHACHA_KEY_LABEL: &str = "_enc_chacha20";\npub const XCHACHA_KEY_LABEL: &str = "_enc_xchacha20";\npub const XCHACHA_NONCE_LABEL: &str = "tlsvpn-xchacha20-nonce-v1";\n', 1)
old = '''pub fn enc_algo_from_config(mode: &str) -> i64 {\n    if mode.trim().eq_ignore_ascii_case("gcm128") {\n        ENC_ALGO_GCM128\n    } else {\n        ENC_ALGO_GCM\n    }\n}\n\npub fn enc_algo_label(algo: i64) -> &'static str {\n    match algo {\n        ENC_ALGO_GCM128 => "gcm128",\n        ENC_ALGO_GCM => "gcm256",\n        _ => "none",\n    }\n}\n\npub fn is_gcm_algo(algo: i64) -> bool {\n    algo == ENC_ALGO_GCM || algo == ENC_ALGO_GCM128\n}\n'''
new = '''pub fn enc_algo_from_config(mode: &str) -> i64 {\n    match mode.trim().to_ascii_lowercase().as_str() {\n        "gcm128" => ENC_ALGO_GCM128,\n        "chacha20" => ENC_ALGO_CHACHA20,\n        "xchacha20" => ENC_ALGO_XCHACHA20,\n        _ => ENC_ALGO_GCM,\n    }\n}\n\npub fn enc_algo_label(algo: i64) -> &'static str {\n    match algo {\n        ENC_ALGO_GCM128 => "gcm128",\n        ENC_ALGO_CHACHA20 => "chacha20",\n        ENC_ALGO_XCHACHA20 => "xchacha20",\n        ENC_ALGO_GCM => "gcm256",\n        _ => "none",\n    }\n}\n\npub fn is_gcm_algo(algo: i64) -> bool {\n    algo == ENC_ALGO_GCM || algo == ENC_ALGO_GCM128\n}\n\npub fn is_inner_aead_algo(algo: i64) -> bool {\n    is_gcm_algo(algo) || algo == ENC_ALGO_CHACHA20 || algo == ENC_ALGO_XCHACHA20\n}\n'''
if old not in s: raise SystemExit('enc algo helper block not found')
s = s.replace(old, new, 1)

start = s.index('/// 内层载荷 AES-GCM。')
end = s.index('pub fn gen_session_id()', start)
block = r'''/// 统一内层 AEAD。AES-GCM 与 ChaCha20-Poly1305 使用 12B nonce = seq(4BE)||salt(8B)。
/// XChaCha20-Poly1305 复用握手已有的 8B salt，确定性派生 20B prefix，再追加 seq(4BE)，
/// 因此无需新增配置项、握手字段或修改 frame wire format；全部算法 tag 都是 16B。
pub enum InnerCipher {
    Gcm256 { aead: LessSafeKey, salt: [u8; ENC_SALT_SIZE] },
    Gcm128 { aead: LessSafeKey, salt: [u8; ENC_SALT_SIZE] },
    ChaCha20 { aead: ChaCha20Poly1305, salt: [u8; ENC_SALT_SIZE] },
    XChaCha20 { aead: XChaCha20Poly1305, nonce_prefix: [u8; 20] },
}

impl InnerCipher {
    pub fn gcm(psk: &str, salt: &[u8]) -> Result<InnerCipher, String> {
        Self::for_algo(psk, salt, ENC_ALGO_GCM)
    }
    pub fn gcm_for_algo(psk: &str, salt: &[u8], algo: i64) -> Result<InnerCipher, String> {
        Self::for_algo(psk, salt, algo)
    }
    pub fn gcm_domain(psk: &str, salt: &[u8], domain: &str) -> Result<InnerCipher, String> {
        Self::domain_for_algo(psk, salt, domain, ENC_ALGO_GCM)
    }
    pub fn gcm_domain_for_algo(psk: &str, salt: &[u8], domain: &str, algo: i64) -> Result<InnerCipher, String> {
        Self::domain_for_algo(psk, salt, domain, algo)
    }

    pub fn for_algo(psk: &str, salt: &[u8], algo: i64) -> Result<InnerCipher, String> {
        Self::domain_for_algo(psk, salt, "data", algo)
    }

    pub fn domain_for_algo(psk: &str, salt: &[u8], domain: &str, algo: i64) -> Result<InnerCipher, String> {
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!("encryption salt must be {} bytes, got {}", ENC_SALT_SIZE, salt.len()));
        }
        if domain != "data" && domain != "fec" {
            return Err(format!("unknown AEAD domain {:?}", domain));
        }
        let base = match algo {
            ENC_ALGO_GCM => GCM_KEY_LABEL,
            ENC_ALGO_GCM128 => GCM128_KEY_LABEL,
            ENC_ALGO_CHACHA20 => CHACHA_KEY_LABEL,
            ENC_ALGO_XCHACHA20 => XCHACHA_KEY_LABEL,
            _ => return Err(format!("unsupported inner AEAD algorithm {}", algo)),
        };
        let label = if domain == "fec" { format!("{}_fec", base) } else { base.to_string() };
        let key = derive_key_labeled(psk, &label);
        let mut salt8 = [0u8; ENC_SALT_SIZE];
        salt8.copy_from_slice(salt);

        match algo {
            ENC_ALGO_GCM => {
                let key = UnboundKey::new(&aead::AES_256_GCM, &key)
                    .map_err(|_| "invalid AES-256-GCM key".to_string())?;
                Ok(InnerCipher::Gcm256 { aead: LessSafeKey::new(key), salt: salt8 })
            }
            ENC_ALGO_GCM128 => {
                let key = UnboundKey::new(&aead::AES_128_GCM, &key[..16])
                    .map_err(|_| "invalid AES-128-GCM key".to_string())?;
                Ok(InnerCipher::Gcm128 { aead: LessSafeKey::new(key), salt: salt8 })
            }
            ENC_ALGO_CHACHA20 => {
                let aead = ChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| "invalid ChaCha20-Poly1305 key".to_string())?;
                Ok(InnerCipher::ChaCha20 { aead, salt: salt8 })
            }
            ENC_ALGO_XCHACHA20 => {
                let aead = XChaCha20Poly1305::new_from_slice(&key)
                    .map_err(|_| "invalid XChaCha20-Poly1305 key".to_string())?;
                let mut h = Sha256::new();
                h.update(XCHACHA_NONCE_LABEL.as_bytes());
                h.update(salt);
                let digest = h.finalize();
                let mut prefix = [0u8; 20];
                prefix.copy_from_slice(&digest[..20]);
                Ok(InnerCipher::XChaCha20 { aead, nonce_prefix: prefix })
            }
            _ => unreachable!(),
        }
    }

    pub fn is_gcm(&self) -> bool {
        matches!(self, InnerCipher::Gcm256 { .. } | InnerCipher::Gcm128 { .. })
    }

    pub fn tag_len(&self) -> usize { GCM_TAG_SIZE }

    fn standard_nonce(salt: &[u8; ENC_SALT_SIZE], seq: u32) -> [u8; GCM_NONCE_SIZE] {
        let mut nonce = [0u8; GCM_NONCE_SIZE];
        nonce[..4].copy_from_slice(&seq.to_be_bytes());
        nonce[4..].copy_from_slice(salt);
        nonce
    }

    fn xchacha_nonce(prefix: &[u8; 20], seq: u32) -> [u8; XCHACHA_NONCE_SIZE] {
        let mut nonce = [0u8; XCHACHA_NONCE_SIZE];
        nonce[..20].copy_from_slice(prefix);
        nonce[20..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    pub fn seal_in_place(&self, region: &mut [u8], pt_len: usize, seq: u32, wire_len: u32) {
        if pt_len == 0 { return; }
        let aad = gcm_aad(wire_len, seq);
        let (ct, tag_space) = region.split_at_mut(pt_len);
        match self {
            InnerCipher::Gcm256 { aead, salt } | InnerCipher::Gcm128 { aead, salt } => {
                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = aead.seal_in_place_separate_tag(nonce, Aad::from(aad), ct)
                    .expect("AES-GCM encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_ref());
            }
            InnerCipher::ChaCha20 { aead, salt } => {
                let nonce = Self::standard_nonce(salt, seq);
                let tag = aead.encrypt_in_place_detached(ChaChaNonce::from_slice(&nonce), &aad, ct)
                    .expect("ChaCha20-Poly1305 encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_slice());
            }
            InnerCipher::XChaCha20 { aead, nonce_prefix } => {
                let nonce = Self::xchacha_nonce(nonce_prefix, seq);
                let tag = aead.encrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, ct)
                    .expect("XChaCha20-Poly1305 encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_slice());
            }
        }
    }

    pub fn open_in_place<'a>(&self, data: &'a mut [u8], seq: u32, wire_len: u32) -> Result<&'a mut [u8], ()> {
        if data.is_empty() { return Ok(data); }
        if data.len() < GCM_TAG_SIZE { return Err(()); }
        let aad = gcm_aad(wire_len, seq);
        let (ct, tag_bytes) = data.split_at_mut(data.len() - GCM_TAG_SIZE);
        match self {
            InnerCipher::Gcm256 { aead, salt } | InnerCipher::Gcm128 { aead, salt } => {
                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = RingTag::try_from(&tag_bytes[..]).map_err(|_| ())?;
                aead.open_in_place_separate_tag(nonce, Aad::from(aad), tag, ct, 0..).map_err(|_| ())?;
            }
            InnerCipher::ChaCha20 { aead, salt } => {
                let nonce = Self::standard_nonce(salt, seq);
                let tag = ChaChaTag::from_slice(tag_bytes);
                aead.decrypt_in_place_detached(ChaChaNonce::from_slice(&nonce), &aad, ct, tag).map_err(|_| ())?;
            }
            InnerCipher::XChaCha20 { aead, nonce_prefix } => {
                let nonce = Self::xchacha_nonce(nonce_prefix, seq);
                let tag = ChaChaTag::from_slice(tag_bytes);
                aead.decrypt_in_place_detached(XNonce::from_slice(&nonce), &aad, ct, tag).map_err(|_| ())?;
            }
        }
        Ok(ct)
    }

    pub fn open_to<'a>(&self, dst: &'a mut [u8], src: &[u8], seq: u32, aad: &[u8]) -> Result<&'a mut [u8], ()> {
        if src.len() < GCM_TAG_SIZE { return Err(()); }
        let (ct, tag_bytes) = src.split_at(src.len() - GCM_TAG_SIZE);
        if dst.len() < ct.len() { return Err(()); }
        let out = &mut dst[..ct.len()];
        out.copy_from_slice(ct);
        match self {
            InnerCipher::Gcm256 { aead, salt } | InnerCipher::Gcm128 { aead, salt } => {
                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = RingTag::try_from(tag_bytes).map_err(|_| ())?;
                aead.open_in_place_separate_tag(nonce, Aad::from(aad), tag, out, 0..).map_err(|_| ())?;
            }
            InnerCipher::ChaCha20 { aead, salt } => {
                let nonce = Self::standard_nonce(salt, seq);
                let tag = ChaChaTag::from_slice(tag_bytes);
                aead.decrypt_in_place_detached(ChaChaNonce::from_slice(&nonce), aad, out, tag).map_err(|_| ())?;
            }
            InnerCipher::XChaCha20 { aead, nonce_prefix } => {
                let nonce = Self::xchacha_nonce(nonce_prefix, seq);
                let tag = ChaChaTag::from_slice(tag_bytes);
                aead.decrypt_in_place_detached(XNonce::from_slice(&nonce), aad, out, tag).map_err(|_| ())?;
            }
        }
        Ok(out)
    }
}

fn gcm_aad(wire_len: u32, seq: u32) -> [u8; 8] {
    let mut aad = [0u8; 8];
    aad[0..4].copy_from_slice(&wire_len.to_be_bytes());
    aad[4..8].copy_from_slice(&seq.to_be_bytes());
    aad
}

'''
s = s[:start] + block + s[end:]
# min_enc legacy floor should accept any authenticated AEAD.
s = s.replace('只有一种内层算法，下限只剩"是否必须有\n// GCM"这一种语义。', '历史值 "gcm" 现在保留为“必须启用受支持的认证内层 AEAD”这一语义，\n// 不新增配置值；具体算法继续由 enc_algo 精确匹配。')
p.write_text(s)

for name in ['src/client.rs', 'src/server.rs']:
    p = Path(name); s = p.read_text()
    s = s.replace('InnerCipher::gcm_for_algo', 'InnerCipher::for_algo')
    s = s.replace('InnerCipher::gcm_domain_for_algo', 'InnerCipher::domain_for_algo')
    s = s.replace('is_gcm_algo(', 'is_inner_aead_algo(')
    s = s.replace('任一种认证 GCM', '任一种认证内层 AEAD')
    p.write_text(s)

# Unit tests exercise production InnerCipher directly.
p = Path('src/crypto.rs'); s = p.read_text()
s += r'''

#[cfg(test)]
mod chacha_inner_tests {
    use super::*;

    #[test]
    fn chacha_roundtrip_and_tamper() {
        let salt = [0u8,1,2,3,4,5,6,7];
        for algo in [ENC_ALGO_CHACHA20, ENC_ALGO_XCHACHA20] {
            let tx = InnerCipher::for_algo("chacha-test-psk", &salt, algo).unwrap();
            let rx = InnerCipher::for_algo("chacha-test-psk", &salt, algo).unwrap();
            let pt = b"chacha inner payload";
            let mut buf = vec![0u8; pt.len() + GCM_TAG_SIZE];
            buf[..pt.len()].copy_from_slice(pt);
            let wire_len = buf.len() as u32;
            tx.seal_in_place(&mut buf, pt.len(), 0x10203040, wire_len);
            let out = rx.open_in_place(&mut buf, 0x10203040, wire_len).unwrap();
            assert_eq!(out, pt);

            let mut bad = vec![0u8; pt.len() + GCM_TAG_SIZE];
            bad[..pt.len()].copy_from_slice(pt);
            let bad_wire = bad.len() as u32;
            tx.seal_in_place(&mut bad, pt.len(), 7, bad_wire);
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(rx.open_in_place(&mut bad, 7, bad_wire).is_err());
        }
    }

    #[test]
    fn xchacha_nonce_reuses_existing_salt_without_new_wire_field() {
        let salt = [0u8,1,2,3,4,5,6,7];
        let a = InnerCipher::for_algo("xnonce-psk", &salt, ENC_ALGO_XCHACHA20).unwrap();
        let b = InnerCipher::for_algo("xnonce-psk", &salt, ENC_ALGO_XCHACHA20).unwrap();
        let prefix_a = match a { InnerCipher::XChaCha20 { nonce_prefix, .. } => nonce_prefix, _ => unreachable!() };
        let prefix_b = match b { InnerCipher::XChaCha20 { nonce_prefix, .. } => nonce_prefix, _ => unreachable!() };
        assert_eq!(prefix_a, prefix_b);
        let n1 = InnerCipher::xchacha_nonce(&prefix_a, 1);
        let n2 = InnerCipher::xchacha_nonce(&prefix_a, 2);
        assert_eq!(&n1[20..], &1u32.to_be_bytes());
        assert_ne!(n1, n2);
    }

    #[test]
    fn config_names_map_to_stable_algorithm_ids() {
        for (name, id) in [
            ("gcm256", ENC_ALGO_GCM),
            ("gcm128", ENC_ALGO_GCM128),
            ("chacha20", ENC_ALGO_CHACHA20),
            ("xchacha20", ENC_ALGO_XCHACHA20),
        ] {
            assert_eq!(enc_algo_from_config(name), id);
            assert_eq!(enc_algo_label(id), name);
            assert!(is_inner_aead_algo(id));
        }
    }
}
'''
p.write_text(s)
