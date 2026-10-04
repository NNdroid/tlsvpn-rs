#!/usr/bin/env python3
from pathlib import Path

cargo = Path('Cargo.toml')
s = cargo.read_text()
s = s.replace('[features]\n# Diagnostic builds only: release dataplane has no allocator counter overhead.\nalloc-profile = []', '''[features]
default = ["crypto-ring"]
# Compile-time crypto backend A/B. Exactly one must be enabled.
crypto-ring = ["dep:ring", "rustls/ring"]
crypto-aws-lc = ["dep:aws-lc-rs", "rustls/aws_lc_rs"]
# Diagnostic builds only: release dataplane has no allocator counter overhead.
alloc-profile = []''')
s = s.replace('rustls = { version = "0.23", default-features = false, features = ["ring", "std", "tls12"] }', 'rustls = { version = "0.23", default-features = false, features = ["std", "tls12"] }')
s = s.replace('ring = "0.17"', 'ring = { version = "0.17", optional = true }\naws-lc-rs = { version = "1", optional = true }')
cargo.write_text(s)

p = Path('src/crypto.rs')
s = p.read_text()
old = 'use ring::aead::{self, Aad, LessSafeKey, Nonce as RingNonce, Tag as RingTag, UnboundKey};\n'
new = r'''#[cfg(all(feature = "crypto-ring", feature = "crypto-aws-lc"))]
compile_error!("crypto-ring and crypto-aws-lc are mutually exclusive");
#[cfg(not(any(feature = "crypto-ring", feature = "crypto-aws-lc")))]
compile_error!("enable exactly one crypto backend: crypto-ring or crypto-aws-lc");

#[cfg(feature = "crypto-ring")]
mod aes_backend {
    use ring::aead::{self, Aad, LessSafeKey, Nonce, Tag, UnboundKey};

    pub type AesKey = LessSafeKey;

    pub fn new_key(key: &[u8], bits: usize) -> Result<AesKey, String> {
        let alg = match bits {
            128 => &aead::AES_128_GCM,
            256 => &aead::AES_256_GCM,
            _ => return Err(format!("unsupported AES-GCM key size {bits}")),
        };
        let key = UnboundKey::new(alg, key).map_err(|_| format!("invalid AES-{bits}-GCM key"))?;
        Ok(LessSafeKey::new(key))
    }

    #[inline]
    pub fn seal(
        key: &AesKey,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; 16], ()> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), data)
            .map_err(|_| ())?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    #[inline]
    pub fn open(
        key: &AesKey,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        tag_bytes: &[u8],
        data: &mut [u8],
    ) -> Result<(), ()> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let tag = Tag::try_from(tag_bytes).map_err(|_| ())?;
        key.open_in_place_separate_tag(nonce, Aad::from(aad), tag, data, 0..)
            .map_err(|_| ())?;
        Ok(())
    }
}

#[cfg(feature = "crypto-aws-lc")]
mod aes_backend {
    use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};

    pub type AesKey = LessSafeKey;

    pub fn new_key(key: &[u8], bits: usize) -> Result<AesKey, String> {
        let alg = match bits {
            128 => &aead::AES_128_GCM,
            256 => &aead::AES_256_GCM,
            _ => return Err(format!("unsupported AES-GCM key size {bits}")),
        };
        let key = UnboundKey::new(alg, key).map_err(|_| format!("invalid AES-{bits}-GCM key"))?;
        Ok(LessSafeKey::new(key))
    }

    #[inline]
    pub fn seal(
        key: &AesKey,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        data: &mut [u8],
    ) -> Result<[u8; 16], ()> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let tag = key
            .seal_in_place_separate_tag(nonce, Aad::from(aad), data)
            .map_err(|_| ())?;
        let mut out = [0u8; 16];
        out.copy_from_slice(tag.as_ref());
        Ok(out)
    }

    #[inline]
    pub fn open(
        key: &AesKey,
        nonce_bytes: [u8; 12],
        aad: &[u8],
        tag_bytes: &[u8],
        data: &mut [u8],
    ) -> Result<(), ()> {
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        key.open_in_place_separate_tag(nonce, Aad::from(aad), tag_bytes, data)
            .map_err(|_| ())?;
        Ok(())
    }
}

use aes_backend::AesKey;
'''
if old not in s:
    raise SystemExit('ring aead import anchor not found')
s = s.replace(old, new, 1)
s = s.replace('aead: LessSafeKey,', 'aead: AesKey,')
s = s.replace('''                let key = UnboundKey::new(&aead::AES_256_GCM, &key)
                    .map_err(|_| "invalid AES-256-GCM key".to_string())?;
                Ok(InnerCipher::Gcm256 {
                    aead: LessSafeKey::new(key),
                    salt: salt8,
                })''', '''                Ok(InnerCipher::Gcm256 {
                    aead: aes_backend::new_key(&key, 256)?,
                    salt: salt8,
                })''')
s = s.replace('''                let key = UnboundKey::new(&aead::AES_128_GCM, &key[..16])
                    .map_err(|_| "invalid AES-128-GCM key".to_string())?;
                Ok(InnerCipher::Gcm128 {
                    aead: LessSafeKey::new(key),
                    salt: salt8,
                })''', '''                Ok(InnerCipher::Gcm128 {
                    aead: aes_backend::new_key(&key[..16], 128)?,
                    salt: salt8,
                })''')
s = s.replace('''                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = aead
                    .seal_in_place_separate_tag(nonce, Aad::from(aad), ct)
                    .expect("AES-GCM encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_ref());''', '''                let tag = aes_backend::seal(aead, Self::standard_nonce(salt, seq), &aad, ct)
                    .expect("AES-GCM encryption cannot fail");
                tag_space[..GCM_TAG_SIZE].copy_from_slice(&tag);''')
s = s.replace('''                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = RingTag::try_from(&tag_bytes[..]).map_err(|_| ())?;
                aead.open_in_place_separate_tag(nonce, Aad::from(aad), tag, ct, 0..)
                    .map_err(|_| ())?;''', '''                aes_backend::open(
                    aead,
                    Self::standard_nonce(salt, seq),
                    &aad,
                    tag_bytes,
                    ct,
                )?;''')
s = s.replace('''                let nonce = RingNonce::assume_unique_for_key(Self::standard_nonce(salt, seq));
                let tag = RingTag::try_from(tag_bytes).map_err(|_| ())?;
                aead.open_in_place_separate_tag(nonce, Aad::from(aad), tag, out, 0..)
                    .map_err(|_| ())?;''', '''                aes_backend::open(
                    aead,
                    Self::standard_nonce(salt, seq),
                    aad,
                    tag_bytes,
                    out,
                )?;''')
if 'ring::aead' in s or 'RingNonce' in s or 'RingTag' in s or 'UnboundKey::new(&aead::' in s:
    raise SystemExit('stale ring-specific AES-GCM use remains')
p.write_text(s)
