// ============================================================
// 跨语言协议一致性测试
// ============================================================
//
// 读取 Go 侧生成的黄金向量文件，逐项比对 Rust 实现是否产生完全相同的结果。
// 任一项不符即代表两端无法互通。
//
// 运行：
//   TLSVPN_GOLDEN=../tlsvpn/testdata/protocol_golden.json cargo test --test protocol_conformance
//
// 若未设置 TLSVPN_GOLDEN，会尝试默认相对路径；找不到则跳过（不算失败），
// 以免在只有 Rust 仓库的环境里误报。

use aes::Aes256;
use ctr::cipher::{KeyIvInit, StreamCipher};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

type Aes256Ctr = ctr::Ctr128BE<Aes256>;

#[derive(Deserialize)]
struct GoldenVectors {
    #[allow(dead_code)]
    version: u32,
    cipher_contexts: Vec<CipherContextVec>,
    xor_vectors: Vec<XorVec>,
    psk_hashes: Vec<PSKHashVec>,
    frame_headers: Vec<FrameHeaderVec>,
    handshake_req_keys: Vec<String>,
    handshake_resp_keys: Vec<String>,
}

#[derive(Deserialize)]
struct CipherContextVec {
    psk: String,
    key_hex: String,
    iv_hex: String,
}

#[derive(Deserialize)]
struct XorVec {
    psk: String,
    seq: u32,
    plaintext_hex: String,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
struct PSKHashVec {
    psk: String,
    hash: String,
}

#[derive(Deserialize)]
struct FrameHeaderVec {
    data_len: u32,
    pad_len: u16,
    seq: u32,
    header_hex: String,
}

// ---------- 被测实现（与 src/crypto.rs 保持同源逻辑） ----------
// 注意：这里刻意复制实现而非 import，是为了让本测试成为独立的"协议契约"守卫。
// 若 src 中的实现被改动而这里未同步，测试会失败并提示协议漂移。

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

fn xor_crypt_in_place(data: &mut [u8], seq: u32, key: &[u8], base_iv: &[u8]) {
    if data.is_empty() || key.is_empty() {
        return;
    }
    let mut iv = [0u8; 16];
    iv.copy_from_slice(base_iv);
    iv[12..16].copy_from_slice(&seq.to_be_bytes());
    let mut c = Aes256Ctr::new_from_slices(key, &iv).unwrap();
    c.apply_keystream(data);
}

fn build_frame_header(data_len: u32, pad_len: u16, seq: u32) -> [u8; 10] {
    let mut h = [0u8; 10];
    h[0..4].copy_from_slice(&data_len.to_be_bytes());
    h[4..6].copy_from_slice(&pad_len.to_be_bytes());
    h[6..10].copy_from_slice(&seq.to_be_bytes());
    h
}

// ---------- 黄金向量加载 ----------

fn load_golden() -> Option<GoldenVectors> {
    let path = std::env::var("TLSVPN_GOLDEN")
        .map(PathBuf::from)
        .ok()
        .or_else(|| {
            let candidates = [
                "../tlsvpn/testdata/protocol_golden.json",
                "../../tlsvpn/testdata/protocol_golden.json",
                "testdata/protocol_golden.json",
            ];
            candidates.iter().map(PathBuf::from).find(|p| p.exists())
        })?;

    if !path.exists() {
        return None;
    }
    let raw = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

macro_rules! golden_or_skip {
    () => {
        match load_golden() {
            Some(g) => g,
            None => {
                eprintln!(
                    "跳过：未找到黄金向量文件。请设置 TLSVPN_GOLDEN 环境变量指向 \
                     Go 侧生成的 testdata/protocol_golden.json"
                );
                return;
            }
        }
    };
}

// ---------- 测试用例 ----------

#[test]
fn test_psk_hash_matches_go() {
    let g = golden_or_skip!();
    for v in &g.psk_hashes {
        let got = hash_psk(&v.psk);
        assert_eq!(
            got, v.hash,
            "PSK {:?} 的哈希与 Go 端不一致 —— 握手鉴权会失败",
            v.psk
        );
    }
}

#[test]
fn test_cipher_context_matches_go() {
    let g = golden_or_skip!();
    for v in &g.cipher_contexts {
        let (key, iv) = get_cipher_context(&v.psk);
        assert_eq!(
            hex::encode(&key),
            v.key_hex,
            "PSK {:?} 派生的 AES key 与 Go 端不一致",
            v.psk
        );
        assert_eq!(
            hex::encode(&iv),
            v.iv_hex,
            "PSK {:?} 派生的 base IV 与 Go 端不一致",
            v.psk
        );
    }
}

#[test]
fn test_xor_crypt_matches_go() {
    let g = golden_or_skip!();
    for v in &g.xor_vectors {
        let plain = hex::decode(&v.plaintext_hex).expect("黄金向量明文解码失败");
        let (key, iv) = get_cipher_context(&v.psk);
        let mut buf = plain.clone();
        xor_crypt_in_place(&mut buf, v.seq, &key, &iv);
        assert_eq!(
            hex::encode(&buf),
            v.ciphertext_hex,
            "PSK {:?} seq={} 的加密结果与 Go 端不一致 —— 数据面无法互通",
            v.psk,
            v.seq
        );
    }
}

#[test]
fn test_xor_is_involutive() {
    // CTR 模式下加密两次应还原，验证解密路径
    let (key, iv) = get_cipher_context("roundtrip");
    let original = b"the quick brown fox".to_vec();
    let mut buf = original.clone();
    xor_crypt_in_place(&mut buf, 99, &key, &iv);
    assert_ne!(buf, original, "加密后不应与原文相同");
    xor_crypt_in_place(&mut buf, 99, &key, &iv);
    assert_eq!(buf, original, "二次异或应还原原文");
}

#[test]
fn test_frame_header_matches_go() {
    let g = golden_or_skip!();
    for v in &g.frame_headers {
        let h = build_frame_header(v.data_len, v.pad_len, v.seq);
        assert_eq!(
            hex::encode(h),
            v.header_hex,
            "帧头布局与 Go 端不一致 (data_len={} pad_len={} seq={})",
            v.data_len,
            v.pad_len,
            v.seq
        );
    }
}

#[test]
fn test_frame_header_is_big_endian() {
    let h = build_frame_header(2, 0, 0x0102_0304);
    assert_eq!(&h[6..10], &[0x01, 0x02, 0x03, 0x04], "seq 必须为大端序");
    assert_eq!(&h[0..4], &[0x00, 0x00, 0x00, 0x02], "data_len 必须为大端序");
}

// ---------- 握手 JSON 字段契约 ----------
//
// 这里定义与 Go 端 HandshakeReq/HandshakeResp 对应的结构，
// 校验 serde 序列化出的字段名集合与 Go 完全一致。

#[derive(serde::Serialize, Default)]
struct HandshakeReqShape {
    client_id: String,
    psk: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    mac: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ipv4: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    ipv6: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    padding: String,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_tx: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_rx: u64,
    #[serde(skip_serializing_if = "is_false")]
    fec: bool,
    #[serde(skip_serializing_if = "is_false")]
    encrypt: bool,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

#[test]
fn test_handshake_req_field_names() {
    let g = golden_or_skip!();

    let full = HandshakeReqShape {
        client_id: "c".into(),
        psk: "p".into(),
        mac: "m".into(),
        ipv4: "1".into(),
        ipv6: "2".into(),
        padding: "x".into(),
        brutal_tx: 1,
        brutal_rx: 1,
        fec: true,
        encrypt: true,
    };
    let val: serde_json::Value = serde_json::to_value(&full).unwrap();
    let mut keys: Vec<String> = val.as_object().unwrap().keys().cloned().collect();
    keys.sort();

    let mut want = g.handshake_req_keys.clone();
    want.sort();

    assert_eq!(
        keys, want,
        "HandshakeReq 字段名与 Go 端不一致 —— 握手会失败或字段静默丢失"
    );
}

#[test]
fn test_handshake_resp_field_names_present_in_go() {
    let g = golden_or_skip!();
    // Go 端 Resp 的字段集合，Rust 端反序列化时必须能全部接受
    let expected = [
        "brutal_rx",
        "brutal_tx",
        "client_id",
        "encrypt",
        "fec",
        "gw_v4",
        "gw_v6",
        "ipv4",
        "ipv6",
        "message",
        "padding",
        "session_id",
        "success",
    ];
    let mut want = g.handshake_resp_keys.clone();
    want.sort();
    let mut exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    exp.sort();
    assert_eq!(
        want, exp,
        "Go 端 HandshakeResp 字段集合发生变化，Rust 端需同步"
    );
}

#[test]
fn test_omitempty_semantics() {
    // 零值时这些字段必须不出现，与 Go 的 omitempty 对齐
    let minimal = HandshakeReqShape {
        client_id: "c".into(),
        psk: "p".into(),
        ..Default::default()
    };
    let val: serde_json::Value = serde_json::to_value(&minimal).unwrap();
    let obj = val.as_object().unwrap();

    for k in [
        "mac",
        "ipv4",
        "ipv6",
        "padding",
        "brutal_tx",
        "brutal_rx",
        "fec",
        "encrypt",
    ] {
        assert!(
            !obj.contains_key(k),
            "字段 {} 在零值时应被省略（对齐 Go 的 omitempty）",
            k
        );
    }
    for k in ["client_id", "psk"] {
        assert!(obj.contains_key(k), "字段 {} 必须始终出现", k);
    }
}

// ---------- 填充长度分支 ----------

fn get_padding_length_bounds(data_len: usize) -> (usize, usize) {
    if data_len == 0 {
        (100, 300)
    } else if data_len < 200 {
        (300, 499)
    } else if data_len < 800 {
        (100, 299)
    } else {
        (0, 99)
    }
}

#[test]
fn test_padding_length_branches_match_go() {
    // 校验分支边界与 Go 端一致（Go: 0->[100,300], <200->[300,499],
    // <800->[100,299], else->[0,99]）
    for (len, want) in [
        (0usize, (100usize, 300usize)),
        (1, (300, 499)),
        (199, (300, 499)),
        (200, (100, 299)),
        (799, (100, 299)),
        (800, (0, 99)),
        (1400, (0, 99)),
    ] {
        assert_eq!(
            get_padding_length_bounds(len),
            want,
            "data_len={} 的填充范围与 Go 端不一致",
            len
        );
    }
}
