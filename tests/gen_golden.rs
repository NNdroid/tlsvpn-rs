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
//
// 注意：字段集合必须与 Go 的 testdata/protocol_golden.json 保持同构，
// 否则 protocol_conformance.rs 会因缺字段而解析失败、整组静默跳过。

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

fn hash_psk(psk: &str) -> String {
    let mut h = Sha256::new();
    h.update(psk.as_bytes());
    hex::encode(h.finalize())
}

/// 密钥标签与 Go `gcmKeyLabel` 逐字一致：HKDF-SHA256(ikm=psk, salt=encSalt,
/// info=label)，FEC 面再拼一个 "_fec" 后缀，实现两个域之间的密钥分离。自 Go
/// commit 68ae122 起 KDF 为带盐 HKDF（数据面不兼容变更），此处必须同步。
fn gcm_key(psk: &str, salt: &[u8], domain: &str) -> Vec<u8> {
    let label: &[u8] = if domain == "fec" {
        b"_enc_key_fec"
    } else {
        b"_enc_key"
    };
    let hk = Hkdf::<Sha256>::new(Some(salt), psk.as_bytes());
    let mut key = [0u8; 32];
    hk.expand(label, &mut key).unwrap();
    key.to_vec()
}

/// 与 src/crypto.rs::InnerCipher::gcm_domain 同构：nonce = seq‖salt，
/// AAD = wireLen‖padLen(0)‖seq（v4 起绑定帧头 padLen）。
fn gcm_domain_ciphertext(
    psk: &str,
    domain: &str,
    salt_hex: &str,
    seq: u32,
    plaintext: &[u8],
) -> String {
    let salt = hex::decode(salt_hex).unwrap();
    let cipher = Aes256Gcm::new_from_slice(&gcm_key(psk, &salt, domain)).unwrap();
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&seq.to_be_bytes());
    nonce[4..].copy_from_slice(&salt);
    let wire_len = (plaintext.len() + 16) as u32;
    // v4 起 AAD 绑定帧头 padLen：golden 域向量经 Go sealInPlace（cold path,
    // padLen=0）生成，padLen 字节为 0x0000（对齐 Go crypto.go nonceAAD）。
    let mut aad = [0u8; 10];
    aad[..4].copy_from_slice(&wire_len.to_be_bytes());
    aad[4..6].copy_from_slice(&0u16.to_be_bytes());
    aad[6..].copy_from_slice(&seq.to_be_bytes());
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut buf)
        .unwrap();
    buf.extend_from_slice(&tag);
    hex::encode(buf)
}

#[test]
#[ignore = "工具：手动运行以生成黄金向量"]
fn generate_golden_vectors() {
    use serde_json::json;

    let psks = [
        "",
        "test_psk",
        "my_super_secret_test_key",
        "中文密钥🔑",
        "a",
    ];
    let psk_hashes: Vec<_> = psks
        .iter()
        .map(|psk| json!({ "psk": psk, "hash": hash_psk(psk) }))
        .collect();

    // 与 Go 侧固定的跨语言向量完全一致（盐、序号、明文都不随机），
    // 所以两份文件可以直接逐字节比对。
    let domain_cases: [(&str, &str, &str, u32, &str); 2] = [
        (
            "cross-language-domain-vector",
            "0011223344556677",
            "data",
            16909060,
            "65746865726e65742d7061796c6f6164",
        ),
        (
            "cross-language-domain-vector",
            "0011223344556677",
            "fec",
            16909060,
            "65746865726e65742d7061796c6f6164",
        ),
    ];
    let gcm_domain_vectors: Vec<_> = domain_cases
        .iter()
        .map(|(psk, salt, domain, seq, pt_hex)| {
            let pt = hex::decode(pt_hex).unwrap();
            json!({
                "psk": psk,
                "salt_hex": salt,
                "domain": domain,
                "seq": seq,
                "plaintext_hex": pt_hex,
                "ciphertext_hex": gcm_domain_ciphertext(psk, domain, salt, *seq, &pt),
            })
        })
        .collect();

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
        "psk_hashes": psk_hashes,
        "gcm_domain_vectors": gcm_domain_vectors,
        "frame_headers": frame_headers,
        "handshake_req_keys": [
            "brutal_conn_index","brutal_conns","brutal_groups","brutal_total_rx","brutal_total_tx",
            "client_id","client_instance","enc_algo","encrypt","fec",
            "fec_group","ipv4","ipv6","mac","padding","protocol_version","psk","session_token"
        ],
        "handshake_resp_keys": [
            "brutal_groups","brutal_total_rx","brutal_total_tx","client_id","enc_algo",
            "enc_salt","enc_salt2","encrypt","fec",
            "fec_group","gw_v4","gw_v6","ipv4","ipv6","message","padding","protocol_version",
            "session_epoch","session_id","session_token","success"
        ],
    });

    let text = serde_json::to_string_pretty(&out).unwrap();
    let path = std::env::var("TLSVPN_GOLDEN_OUT")
        .unwrap_or_else(|_| "protocol_golden.rust.json".to_string());
    std::fs::write(&path, format!("{}\n", text)).expect("写入失败");
    println!("已生成: {}", path);
    println!("{}", text);
}
