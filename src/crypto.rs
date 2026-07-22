use aes::Aes256;
use byteorder::{BigEndian, ByteOrder};
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::utils::*;

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

pub fn get_cipher_context(psk: &str) -> (Vec<u8>, Vec<u8>) {
    let mut k_hasher = Sha256::new();
    k_hasher.update(format!("{}_enc_key", psk).as_bytes());
    let key = k_hasher.finalize().to_vec();

    let mut i_hasher = Sha256::new();
    i_hasher.update(format!("{}_enc_iv", psk).as_bytes());
    let iv = i_hasher.finalize()[..16].to_vec();

    (key, iv)
}

pub fn xor_crypt_in_place(data: &mut [u8], seq: u32, key: &[u8], base_iv: &[u8]) {
    if data.is_empty() || key.is_empty() {
        return;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(base_iv);
    BigEndian::write_u32(&mut iv[12..16], seq);
    let mut cipher = Aes256Ctr::new_from_slices(key, &iv).unwrap();
    cipher.apply_keystream(data);
}

pub fn get_padding_length(data_len: usize) -> usize {
    RNG.with(|rng| {
        let mut r = rng.borrow_mut();
        if data_len == 0 {
            return 100 + r.gen_range(0, 201);
        }
        if data_len < 200 {
            return 300 + r.gen_range(0, 200);
        }
        if data_len < 800 {
            return 100 + r.gen_range(0, 200);
        }
        r.gen_range(0, 100)
    })
}

pub fn gen_session_id() -> String {
    let mut buf = [0u8; 16];
    RNG.with(|rng| rng.borrow_mut().fill(&mut buf));
    hex::encode(buf)
}
