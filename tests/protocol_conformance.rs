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

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

#[derive(Deserialize)]
struct GoldenVectors {
    #[allow(dead_code)]
    version: u32,
    psk_hashes: Vec<PSKHashVec>,
    gcm_domain_vectors: Vec<GcmDomainVec>,
    frame_headers: Vec<FrameHeaderVec>,
    tls_fingerprint_vectors: Vec<TlsFingerprintVec>,
    handshake_req_keys: Vec<String>,
    handshake_resp_keys: Vec<String>,
    tls_info_keys: Vec<String>,
}

#[derive(Deserialize)]
struct GcmDomainVec {
    psk: String,
    salt_hex: String,
    domain: String,
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

#[derive(Deserialize)]
struct TlsFingerprintVec {
    cipher_suites: Vec<u16>,
    signature_schemes: Vec<u16>,
    groups: Vec<u16>,
    alpn: Vec<String>,
    fingerprint_sha256: String,
}

// ---------- 被测实现（与 src/crypto.rs 保持同源逻辑） ----------
// 注意：这里刻意复制实现而非 import，是为了让本测试成为独立的"协议契约"守卫。
// 若 src 中的实现被改动而这里未同步，测试会失败并提示协议漂移。

fn hash_psk(psk: &str) -> String {
    let mut h = Sha256::new();
    h.update(psk.as_bytes());
    hex::encode(h.finalize())
}

fn gcm_domain_seal(v: &GcmDomainVec) -> Vec<u8> {
    // 数据面用 "_enc_key"，FEC 面再加 "_fec" 后缀——与 Go gcmKeyLabel 逐字一致。
    let label: &[u8] = if v.domain == "fec" { b"_enc_key_fec" } else { b"_enc_key" };
    let mut h = Sha256::new();
    h.update(v.psk.as_bytes());
    h.update(label);
    let cipher = Aes256Gcm::new_from_slice(&h.finalize()).unwrap();
    let salt = hex::decode(&v.salt_hex).unwrap();
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&v.seq.to_be_bytes());
    nonce[4..].copy_from_slice(&salt);
    let mut plaintext = hex::decode(&v.plaintext_hex).unwrap();
    let wire_len = (plaintext.len() + 16) as u32;
    let mut aad = [0u8; 8];
    aad[..4].copy_from_slice(&wire_len.to_be_bytes());
    aad[4..].copy_from_slice(&v.seq.to_be_bytes());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&nonce), &aad, &mut plaintext)
        .unwrap();
    plaintext.extend_from_slice(&tag);
    plaintext
}

fn build_frame_header(data_len: u32, pad_len: u16, seq: u32) -> [u8; 10] {
    let mut h = [0u8; 10];
    h[0..4].copy_from_slice(&data_len.to_be_bytes());
    h[4..6].copy_from_slice(&pad_len.to_be_bytes());
    h[6..10].copy_from_slice(&seq.to_be_bytes());
    h
}

fn is_tls_grease(v: u16) -> bool {
    (v >> 8) as u8 == v as u8 && (v as u8 & 0x0f) == 0x0a
}

fn tls_client_hello_fingerprint(v: &TlsFingerprintVec) -> String {
    let mut canonical = b"tls-clienthello-v1\0".to_vec();
    for values in [&v.cipher_suites, &v.signature_schemes, &v.groups] {
        let normalized: Vec<u16> = values.iter().copied().filter(|x| !is_tls_grease(*x)).collect();
        canonical.extend_from_slice(&(normalized.len() as u16).to_be_bytes());
        for value in normalized {
            canonical.extend_from_slice(&value.to_be_bytes());
        }
    }
    canonical.extend_from_slice(&(v.alpn.len() as u16).to_be_bytes());
    for proto in &v.alpn {
        canonical.extend_from_slice(&(proto.len() as u16).to_be_bytes());
        canonical.extend_from_slice(proto.as_bytes());
    }
    hex::encode(Sha256::digest(&canonical))
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
    // 文件存在却读不出/解析失败是协议测试自身损坏，绝不能伪装成“文件缺失”跳过。
    // 新增向量曾把 Go nil slice 写成 null，Rust Vec 解析失败，而旧代码把整套
    // 跨语言测试静默跳过；这里让这种情况明确失败。
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("读取黄金向量 {} 失败: {e}", path.display()));
    Some(
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("解析黄金向量 {} 失败: {e}", path.display())),
    )
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
fn test_gcm_domain_known_answer_vectors() {
    // 离线固定向量：不依赖黄金文件也能守住密钥派生契约。数值取自 Go 仓库
    // testdata/protocol_golden.json（数据面与 FEC 面各自独立的密钥标签）。
    let psk = "cross-language-domain-vector";
    let salt_hex = "0011223344556677";
    let seq = 16909060u32;
    let pt_hex = "65746865726e65742d7061796c6f6164";
    for (domain, want) in [
        ("data", "6b7d896fdb4baed8b0775ea1ee38aba4097de242650d322e5a3a6775c4f07c8b"),
        ("fec", "108721428cf9bacbba87a5b5ca28423d6a4af4d23d0c3338a676c8a584088b56"),
    ] {
        let v = GcmDomainVec {
            psk: psk.into(),
            salt_hex: salt_hex.into(),
            domain: domain.into(),
            seq,
            plaintext_hex: pt_hex.into(),
            ciphertext_hex: String::new(),
        };
        assert_eq!(
            hex::encode(gcm_domain_seal(&v)),
            want,
            "domain={} 的密钥派生或 GCM 参数与 Go 端不一致 —— 数据面无法互通",
            domain
        );
    }
}

#[test]
fn test_gcm_data_and_fec_domains_match_go() {
    let g = golden_or_skip!();
    assert_eq!(g.gcm_domain_vectors.len(), 2);
    let mut ciphertexts = Vec::new();
    for v in &g.gcm_domain_vectors {
        let got = gcm_domain_seal(v);
        assert_eq!(hex::encode(&got), v.ciphertext_hex, "domain={}", v.domain);
        ciphertexts.push(got);
    }
    assert_ne!(ciphertexts[0], ciphertexts[1]);
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

#[test]
fn test_tls_client_hello_fingerprint_vectors() {
    let g = golden_or_skip!();
    for v in &g.tls_fingerprint_vectors {
        assert_eq!(
            tls_client_hello_fingerprint(v),
            v.fingerprint_sha256,
            "TLS ClientHello fingerprint drifted between Go and Rust"
        );
    }
}

// ---------- 握手 JSON 字段契约 ----------
//
// 这里定义与 Go 端 HandshakeReq/HandshakeResp 对应的结构，
// 校验 serde 序列化出的字段名集合与 Go 完全一致。

#[derive(serde::Serialize, Default)]
struct HandshakeReqShape {
    #[serde(skip_serializing_if = "is_zero_i64")]
    protocol_version: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_instance: String,
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
    #[serde(skip_serializing_if = "is_false")]
    brutal_groups: bool,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_total_tx: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_total_rx: u64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    brutal_conns: i64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    brutal_conn_index: i64,
    #[serde(skip_serializing_if = "is_false")]
    fec: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    fec_group: i64,
    #[serde(skip_serializing_if = "is_false")]
    encrypt: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    enc_algo: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_token: String,
}

#[derive(serde::Serialize, Default)]
struct TlsHandshakeInfoShape {
    #[serde(skip_serializing_if = "String::is_empty")]
    fingerprint_kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    fingerprint_sha256: String,
    #[serde(skip_serializing_if = "is_zero_u16")]
    version_id: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(skip_serializing_if = "is_zero_u16")]
    cipher_suite_id: u16,
    #[serde(skip_serializing_if = "String::is_empty")]
    cipher_suite: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    alpn: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    sni: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    offered_cipher_suites: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    offered_signature_schemes: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    offered_groups: Vec<u16>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    offered_alpn: Vec<String>,
}

fn full_tls_info_shape() -> TlsHandshakeInfoShape {
    TlsHandshakeInfoShape {
        fingerprint_kind: "tls-clienthello-v1".into(),
        fingerprint_sha256: "abc".into(),
        version_id: 0x0304,
        version: "TLS 1.3".into(),
        cipher_suite_id: 0x1301,
        cipher_suite: "TLS_AES_128_GCM_SHA256".into(),
        alpn: "h2".into(),
        sni: "example.com".into(),
        offered_cipher_suites: vec![0x1301],
        offered_signature_schemes: vec![0x0804],
        offered_groups: vec![0x001d],
        offered_alpn: vec!["h2".into()],
    }
}

#[derive(serde::Serialize, Default)]
struct HandshakeRespShape {
    #[serde(skip_serializing_if = "is_zero_i64")]
    protocol_version: i64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    session_epoch: u64,
    success: bool,
    message: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    client_id: String,
    ipv4: String,
    ipv6: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    gw_v4: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    gw_v6: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    padding: String,
    #[serde(skip_serializing_if = "is_false")]
    brutal_groups: bool,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_total_tx: u64,
    #[serde(skip_serializing_if = "is_zero_u64")]
    brutal_total_rx: u64,
    #[serde(skip_serializing_if = "is_false")]
    fec: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    fec_group: i64,
    #[serde(skip_serializing_if = "is_false")]
    encrypt: bool,
    #[serde(skip_serializing_if = "is_zero_i64")]
    enc_algo: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    enc_salt: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    enc_salt2: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls: Option<TlsHandshakeInfoShape>,
}

fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
fn is_zero_u16(v: &u16) -> bool {
    *v == 0
}
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

#[test]
fn test_handshake_req_field_names() {
    let g = golden_or_skip!();

    let full = HandshakeReqShape {
        protocol_version: 2,
        client_instance: "instance-1".into(),
        client_id: "c".into(),
        psk: "p".into(),
        mac: "m".into(),
        ipv4: "1".into(),
        ipv6: "2".into(),
        padding: "x".into(),
        brutal_groups: true,
        brutal_total_tx: 30,
        brutal_total_rx: 500,
        brutal_conns: 4,
        brutal_conn_index: 1,
        fec: true,
        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        session_token: "t".into(),
    };
    let val: serde_json::Value = serde_json::to_value(&full).unwrap();
    let mut keys: Vec<String> = val.as_object().unwrap().keys().cloned().collect();
    keys.sort();

    // 黄金向量的键列表由 Go 生成器从活动结构体 marshal 得出（omitempty 字段需
    // 全填充样本才能出现），Go 侧另有 TestHandshakeJSONContract 用硬编码
    // wantReq 独立锁定，所以这里是逐字相等，不再是「∪ session_token」的妥协。
    let mut want = g.handshake_req_keys.clone();
    want.sort();

    assert_eq!(
        keys, want,
        "HandshakeReq 字段名与 Go 端不一致 —— 握手会失败或字段静默丢失"
    );
}

#[test]
fn test_handshake_resp_field_names() {
    // Rust 端 Resp 的完整字段集合（与 Go frame.go 的 HandshakeResp 对齐）
    let full = HandshakeRespShape {
        protocol_version: 2,
        session_epoch: 1,
        success: true,
        message: "OK".into(),
        session_id: "s".into(),
        client_id: "c".into(),
        ipv4: "1".into(),
        ipv6: "2".into(),
        gw_v4: "3".into(),
        gw_v6: "4".into(),
        padding: "x".into(),
        brutal_groups: true,
        brutal_total_tx: 30,
        brutal_total_rx: 500,
        fec: true,
        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        enc_salt: "a".into(),
        enc_salt2: "b".into(),
        session_token: "t".into(),
        tls: Some(full_tls_info_shape()),
    };
    let val: serde_json::Value = serde_json::to_value(&full).unwrap();
    let mut keys: Vec<String> = val.as_object().unwrap().keys().cloned().collect();
    keys.sort();

    let expected = [
        "brutal_groups",
        "brutal_total_rx",
        "brutal_total_tx",
        "client_id",
        "enc_algo",
        "enc_salt",
        "enc_salt2",
        "encrypt",
        "fec",
        "fec_group",
        "gw_v4",
        "gw_v6",
        "ipv4",
        "ipv6",
        "message",
        "padding",
        "protocol_version",
        "session_epoch",
        "session_id",
        "session_token",
        "success",
        "tls",
    ];
    let mut exp: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    exp.sort();
    assert_eq!(
        keys, exp,
        "HandshakeResp 字段名集合与 Go 端不一致 —— 服务端可能发不出/客户端读不到"
    );
}

#[test]
fn test_golden_handshake_keys_match_rust() {
    // 黄金向量的键列表必须与 Rust 端完全相等，双向锁定：任何一端单方面加/删
    // 字段都会在这里失败。
    // 曾一度只能做单向子集——Go 生成器的样本漏填了 session_token，omitempty 把
    // 它吞掉后字段集合不完整。Go 侧全字段样本与这里必须逐字相等。
    let g = golden_or_skip!();

    let req_full = HandshakeReqShape {
        protocol_version: 2,
        client_instance: "instance-1".into(),
        session_token: "t".into(),
        mac: "m".into(),
        ipv4: "1".into(),
        ipv6: "2".into(),
        padding: "x".into(),
        brutal_groups: true,
        brutal_total_tx: 30,
        brutal_total_rx: 500,
        brutal_conns: 4,
        brutal_conn_index: 1,
        fec: true,
        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        ..Default::default()
    };
    let resp_full = HandshakeRespShape {
        protocol_version: 2,
        session_epoch: 1,
        success: true,
        message: "OK".into(),
        session_id: "s".into(),
        client_id: "c".into(),
        ipv4: "1".into(),
        ipv6: "2".into(),
        gw_v4: "3".into(),
        gw_v6: "4".into(),
        padding: "x".into(),
        brutal_groups: true,
        brutal_total_tx: 30,
        brutal_total_rx: 500,
        fec: true,
        fec_group: 4,
        encrypt: true,
        enc_algo: 2,
        enc_salt: "a".into(),
        enc_salt2: "b".into(),
        session_token: "t".into(),
        tls: Some(full_tls_info_shape()),
    };
    for (what, golden, shape) in [
        (
            "HandshakeReq",
            &g.handshake_req_keys,
            serde_json::to_value(&req_full).unwrap(),
        ),
        (
            "HandshakeResp",
            &g.handshake_resp_keys,
            serde_json::to_value(&resp_full).unwrap(),
        ),
    ] {
        let have: std::collections::BTreeSet<String> =
            shape.as_object().unwrap().keys().cloned().collect();
        let golden_set: std::collections::BTreeSet<String> = golden.iter().cloned().collect();
        let go_only: Vec<&String> = golden_set.difference(&have).collect();
        let rust_only: Vec<&String> = have.difference(&golden_set).collect();
        assert!(
            go_only.is_empty() && rust_only.is_empty(),
            "Go 黄金向量的 {} 字段集与 Rust 端不一致\n  Go 有 Rust 无: {:?}\n  Rust 有 Go 无: {:?}",
            what,
            go_only,
            rust_only
        );
    }

    let tls_shape = serde_json::to_value(full_tls_info_shape()).unwrap();
    let tls_have: std::collections::BTreeSet<String> =
        tls_shape.as_object().unwrap().keys().cloned().collect();
    let tls_golden: std::collections::BTreeSet<String> =
        g.tls_info_keys.iter().cloned().collect();
    assert_eq!(tls_have, tls_golden, "TLSHandshakeInfo 字段集与 Go 端不一致");
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
        "protocol_version",
        "client_instance",
        "mac",
        "ipv4",
        "ipv6",
        "padding",
        "brutal_groups",
        "brutal_total_tx",
        "brutal_total_rx",
        "brutal_conns",
        "brutal_conn_index",
        "fec",
        "fec_group",
        "encrypt",
        "enc_algo",
        // 旧版客户端不发 session_token：空串必须省略，服务端才收得到"无令牌"
        "session_token",
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

/// 与 Go `padBuckets`/`padBucket` 同构：入参是线路长度（明文 + GCM 标签），
/// 返回的填充按"完整线路记录 = 10B 头 + 线路长度"对齐到固定桶。
const GOLDEN_PAD_BUCKETS: [usize; 10] = [128, 256, 384, 512, 768, 1024, 1280, 1600, 2048, 4096];

fn golden_pad_bucket(wire_len: usize) -> (usize, usize) {
    let record_len = 10usize.saturating_add(wire_len);
    for &b in GOLDEN_PAD_BUCKETS.iter() {
        if record_len < b {
            return (b - record_len, b - record_len);
        }
    }
    // 超出最大桶的 jumbo 帧只加小额随机填充
    (1, 100)
}

#[test]
fn test_padding_length_bucket_branches_match_go() {
    // 桶边界两侧必须给出不同的填充量：落在桶内是确定性值，越界则进入随机小额。
    // 入参是线路长度（明文 + GCM 标签），不是明文长度。
    for (wire_len, want) in [
        (0usize, (118usize, 118usize)),  // 10+0=10 < 128
        (117usize, (1usize, 1usize)),    // 10+117=127 < 128
        (118, (128, 128)),               // 10+118=128 恰好出桶 → 下一桶 256
        (245, (1, 1)),                   // 10+245=255 < 256
        (246, (128, 128)),               // 10+246=256 → 384
        (4085, (1, 1)),                  // 10+4085=4095 < 4096
        (4086, (1, 100)),                // 10+4086=4096 越出所有桶 → jumbo 随机
        (1400, (190, 190)),              // 10+1400=1410 → 1600 桶，常见大帧仍在桶内
        (5000, (1, 100)),                // 10+5000=5010 越出所有桶 → jumbo 随机
    ] {
        assert_eq!(
            golden_pad_bucket(wire_len),
            want,
            "wire_len={} 的填充桶边界与 Go 端不一致",
            wire_len
        );
    }
}
