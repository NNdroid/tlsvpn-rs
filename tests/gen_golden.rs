// ============================================================
// 由 Rust 侧生成黄金向量（用于在无 Go 环境时自举）
// ============================================================
//
// 正常流程下黄金向量应由 Go 侧生成（Go 是协议基准实现）。
// 但当手边只有 Rust 工具链时，可用本工具先生成一份，
// 之后在有 Go 的环境里运行 `go test -run TestGenerateGoldenVectors`
// 校验两者是否一致 —— 若不一致即说明存在协议分歧。
//
// 运行：
//   TLSVPN_GOLDEN_OUT=path/to/protocol_golden.json cargo test --test gen_golden -- --ignored --nocapture

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use sha2::{Digest, Sha256};

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

fn hash_psk(psk: &str) -> String {
    let mut h = Sha256::new();
    h.update(psk.as_bytes());
    hex::encode(h.finalize())
}

fn get_cipher_context(psk: &str) -> (Vec<u8>, Vec<u8>) {
    let mut kh = Sha256::new();
    kh.update(format!("{}_enc_key", psk).as_bytes());
    let key = kh.finalize().to_vec();
    let mut ih = Sha256::new();
    ih.update(format!("{}_enc_iv", psk).as_bytes());
    let iv = ih.finalize()[..16].to_vec();
    (key, iv)
}

fn xor_crypt(data: &mut [u8], seq: u32, key: &[u8], base_iv: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(base_iv);
    iv[12..16].copy_from_slice(&seq.to_be_bytes());
    let mut c = Aes256Ctr::new_from_slices(key, &iv).unwrap();
    c.apply_keystream(data);
}

#[test]
#[ignore = "工具：手动运行以生成黄金向量"]
fn generate_golden_vectors() {
    use serde_json::json;

    let psks = ["", "test_psk", "my_super_secret_test_key", "中文密钥🔑", "a"];

    let mut cipher_contexts = Vec::new();
    let mut psk_hashes = Vec::new();
    for psk in psks {
        let (key, iv) = get_cipher_context(psk);
        cipher_contexts.push(json!({
            "psk": psk,
            "key_hex": hex::encode(&key),
            "iv_hex": hex::encode(&iv),
        }));
        psk_hashes.push(json!({ "psk": psk, "hash": hash_psk(psk) }));
    }

    let cases: Vec<(&str, u32, Vec<u8>)> = vec![
        ("test_psk", 0, b"hello".to_vec()),
        ("test_psk", 1, b"hello".to_vec()),
        (
            "test_psk",
            42,
            b"The quick brown fox jumps over the lazy dog".to_vec(),
        ),
        ("test_psk", 4294967295, vec![0x00, 0xFF, 0x7F, 0x80]),
        ("my_super_secret_test_key", 12345, vec![0xAB; 64]),
        (
            "中文密钥🔑",
            7,
            "多字节 PSK 派生必须一致".as_bytes().to_vec(),
        ),
    ];

    let mut xor_vectors = Vec::new();
    for (psk, seq, data) in &cases {
        let (key, iv) = get_cipher_context(psk);
        let mut buf = data.clone();
        xor_crypt(&mut buf, *seq, &key, &iv);
        xor_vectors.push(json!({
            "psk": psk,
            "seq": seq,
            "plaintext_hex": hex::encode(data),
            "ciphertext_hex": hex::encode(&buf),
        }));
    }

    let headers: [(u32, u16, u32); 4] = [
        (0, 0, 0),
        (1, 2, 3),
        (1400, 100, 65536),
        (65535, 65535, 4294967295),
    ];
    let mut frame_headers = Vec::new();
    for (dl, pl, sq) in headers {
        let mut h = [0u8; 10];
        h[0..4].copy_from_slice(&dl.to_be_bytes());
        h[4..6].copy_from_slice(&pl.to_be_bytes());
        h[6..10].copy_from_slice(&sq.to_be_bytes());
        frame_headers.push(json!({
            "data_len": dl, "pad_len": pl, "seq": sq,
            "header_hex": hex::encode(h),
        }));
    }

    let out = json!({
        "version": 1,
        "cipher_contexts": cipher_contexts,
        "xor_vectors": xor_vectors,
        "psk_hashes": psk_hashes,
        "frame_headers": frame_headers,
        "handshake_req_keys": [
            "brutal_rx","brutal_tx","client_id","encrypt","fec",
            "ipv4","ipv6","mac","padding","psk"
        ],
        "handshake_resp_keys": [
            "brutal_rx","brutal_tx","client_id","encrypt","fec",
            "gw_v4","gw_v6","ipv4","ipv6","message","padding",
            "session_id","success"
        ],
    });

    let text = serde_json::to_string_pretty(&out).unwrap();
    let path = std::env::var("TLSVPN_GOLDEN_OUT")
        .unwrap_or_else(|_| "protocol_golden.rust.json".to_string());
    std::fs::write(&path, format!("{}\n", text)).expect("写入失败");
    println!("已生成: {}", path);
    println!("{}", text);
}
