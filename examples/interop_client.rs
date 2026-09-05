//! 互操作探针（e2e 用）：与 interop/probe.go 等价的 Rust 实现。
//!
//! 用自包含协议栈连到服务端（Go 或 Rust 皆可），完成握手 + GCM 数据帧
//! 交换，用于验证跨实现互通。
//!
//! 运行：cargo run --release --example interop_client -- --addr 127.0.0.1:2443 --psk e2e_secret

use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, Tag};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const ENC_SALT_SIZE: usize = 8;
const GCM_TAG_SIZE: usize = 16;
const FEC_MAGIC: u8 = 0xFE;

#[derive(serde::Serialize)]
struct HandshakeReq {
    client_id: String,
    psk: String,
    mac: String,
    ipv4: String,
    #[serde(skip_serializing_if = "is_false")]
    fec: bool,
    #[serde(skip_serializing_if = "is_zero")]
    fec_group: i64,
    encrypt: bool,
    enc_algo: i64,
    brutal_tx: u64,
    brutal_rx: u64,
}

#[derive(serde::Deserialize, Debug)]
struct HandshakeResp {
    success: bool,
    #[allow(dead_code)]
    message: String,
    #[allow(dead_code)]
    session_id: Option<String>,
    #[allow(dead_code)]
    ipv4: String,
    #[allow(dead_code)]
    ipv6: String,
    fec_group: Option<i64>,
    encrypt: Option<bool>,
    enc_algo: Option<i64>,
    enc_salt: Option<String>,
    enc_salt2: Option<String>,
}

fn is_false(v: &bool) -> bool {
    !*v
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

fn hash_psk(psk: &str) -> String {
    let mut h = Sha256::new();
    h.update(psk.as_bytes());
    hex::encode(h.finalize())
}

fn append_padded_frame(buf: &mut Vec<u8>, seq: u32, data: &[u8], ic: Option<&ProbeCipher>) {
    let enc_tag = match ic {
        Some(_) if seq != 0 && !data.is_empty() => GCM_TAG_SIZE,
        _ => 0,
    };
    let pad_len = 100;
    let start = buf.len();
    buf.resize(start + 10 + data.len() + enc_tag + pad_len, 0);
    buf[start..start + 4].copy_from_slice(&((data.len() + enc_tag) as u32).to_be_bytes());
    buf[start + 4..start + 6].copy_from_slice(&(pad_len as u16).to_be_bytes());
    buf[start + 6..start + 10].copy_from_slice(&seq.to_be_bytes());
    if !data.is_empty() {
        buf[start + 10..start + 10 + data.len()].copy_from_slice(data);
        if let Some(c) = ic {
            if seq != 0 {
                c.seal(
                    &mut buf[start + 10..start + 10 + data.len() + enc_tag],
                    data.len(),
                    seq,
                );
            }
        }
    }
    for (i, b) in buf[start + 10 + data.len() + enc_tag..]
        .iter_mut()
        .enumerate()
    {
        *b = i as u8;
    }
}

struct ProbeCipher {
    aead: Aes256Gcm,
    salt: [u8; ENC_SALT_SIZE],
}

impl ProbeCipher {
    fn new(psk: &str, salt: &[u8]) -> Result<Self, String> {
        if salt.len() != ENC_SALT_SIZE {
            return Err(format!("bad salt len {}", salt.len()));
        }
        let mut h = Sha256::new();
        h.update(format!("{}_enc_key", psk).as_bytes());
        let key = h.finalize();
        let aead = Aes256Gcm::new((&key).into());
        let mut s = [0u8; ENC_SALT_SIZE];
        s.copy_from_slice(salt);
        Ok(Self { aead, salt: s })
    }

    fn nonce(&self, seq: u32) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&seq.to_be_bytes());
        n[4..].copy_from_slice(&self.salt);
        n
    }

    fn aad(&self, wire_len: u32, seq: u32) -> [u8; 8] {
        let mut a = [0u8; 8];
        a[0..4].copy_from_slice(&wire_len.to_be_bytes());
        a[4..8].copy_from_slice(&seq.to_be_bytes());
        a
    }

    fn seal(&self, region: &mut [u8], pt_len: usize, seq: u32) {
        let wire_len = region.len() as u32;
        let (ct, tag_space) = region.split_at_mut(pt_len);
        let tag = self
            .aead
            .encrypt_in_place_detached(
                Nonce::from_slice(&self.nonce(seq)),
                &self.aad(wire_len, seq),
                ct,
            )
            .expect("gcm seal");
        tag_space[..GCM_TAG_SIZE].copy_from_slice(tag.as_slice());
    }

    fn open<'a>(&self, data: &'a mut [u8], seq: u32) -> Result<&'a mut [u8], ()> {
        if data.len() < GCM_TAG_SIZE {
            return Err(());
        }
        let wire_len = data.len() as u32;
        let (ct, tag) = data.split_at_mut(data.len() - GCM_TAG_SIZE);
        self.aead
            .decrypt_in_place_detached(
                Nonce::from_slice(&self.nonce(seq)),
                &self.aad(wire_len, seq),
                ct,
                Tag::from_slice(tag),
            )
            .map_err(|_| ())?;
        Ok(ct)
    }
}

/// 从 TLS 流读取一帧（持久缓冲 + 正确跳过填充，防流错位）
struct ProbeScanner {
    buf: Vec<u8>,
}

impl ProbeScanner {
    fn new() -> Self {
        Self {
            buf: Vec::with_capacity(70 * 1024),
        }
    }

    fn read_frame(
        &mut self,
        reader: &mut rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
        deadline: Instant,
    ) -> std::io::Result<Option<(Vec<u8>, u32)>> {
        let mut tmp = [0u8; 16384];
        loop {
            if self.buf.len() >= 10 {
                let data_len =
                    u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]])
                        as usize;
                let pad_len = u16::from_be_bytes([self.buf[4], self.buf[5]]) as usize;
                let seq = u32::from_be_bytes([self.buf[6], self.buf[7], self.buf[8], self.buf[9]]);
                if self.buf.len() >= 10 + data_len + pad_len {
                    let data = self.buf[10..10 + data_len].to_vec();
                    self.buf.drain(..10 + data_len + pad_len);
                    return Ok(Some((data, seq)));
                }
            }
            if Instant::now() > deadline {
                return Ok(None);
            }
            match reader.read(&mut tmp) {
                Ok(0) => return Ok(None),
                Ok(n) => self.buf.extend_from_slice(&tmp[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

fn main() {
    let mut addr = String::from("127.0.0.1:4400");
    let mut psk = String::from("e2e_secret");
    let mut encrypt = true;
    let mut fec = false;
    let mut fec_group: i64 = 0;
    let mut send_frames = 8usize;
    let mut expect_frames = 1usize;
    let mut socks5_addr = String::new();
    let mut timeout_sec: u64 = 10;
    let mut mac = String::from("aa:bb:cc:dd:ee:ff");
    let mut stay_sec: u64 = 0;
    let mut bcast = false;
    let mut parity_test = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--addr" => {
                addr = args[i + 1].clone();
                i += 1;
            }
            "--psk" => {
                psk = args[i + 1].clone();
                i += 1;
            }
            "--encrypt" => encrypt = true,
            "--fec" => {
                fec = true;
                fec_group = args[i + 1].parse().unwrap_or(0);
                i += 1;
            }
            "--send" => {
                send_frames = args[i + 1].parse().unwrap_or(8);
                i += 1;
            }
            "--expect-frames" => {
                expect_frames = args[i + 1].parse().unwrap_or(1);
                i += 1;
            }
            "--mac" => {
                mac = args[i + 1].clone();
                i += 1;
            }
            "--stay" => {
                stay_sec = args[i + 1].parse().unwrap_or(0);
                i += 1;
            }
            "--bcast" => {
                bcast = true;
            }
            "--parity-test" => {
                bcast = true; // parity-test 即广播模式（多发等长帧）
                parity_test = true;
                send_frames = 10;
            }
            "--socks5" => {
                socks5_addr = args[i + 1].clone();
                i += 1;
            }
            "--timeout" => {
                timeout_sec = args[i + 1].parse().unwrap_or(10);
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    let fail = |msg: &str| -> ! {
        println!("FAIL: {}", msg);
        std::process::exit(1);
    };

    // 1. 建连（可选 SOCKS5）
    let tcp = if socks5_addr.is_empty() {
        TcpStream::connect(&addr).unwrap_or_else(|e| fail(&format!("dial: {}", e)))
    } else {
        // 极简 SOCKS5 CONNECT（无认证）
        let mut parts = addr.rsplitn(2, ':');
        let port: u16 = parts
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| fail("bad addr port"));
        let host = parts.next().unwrap_or_else(|| fail("bad addr host"));
        let mut pp = socks5_addr.rsplitn(2, ':');
        let pport: u16 = pp
            .next()
            .unwrap()
            .parse()
            .unwrap_or_else(|_| fail("bad socks5 port"));
        let phost = pp.next().unwrap().to_string();
        let mut s = TcpStream::connect((phost.as_str(), pport))
            .unwrap_or_else(|e| fail(&format!("socks5 dial: {}", e)));
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut req = vec![5u8, 1, 0];
        s.write_all(&req)
            .unwrap_or_else(|e| fail(&format!("socks5 greet: {}", e)));
        let mut resp = [0u8; 2];
        s.read_exact(&mut resp)
            .unwrap_or_else(|e| fail(&format!("socks5 greet resp: {}", e)));
        if resp != [5, 0] {
            fail("socks5: no acceptable auth");
        }
        req = vec![5u8, 1, 0, 3, host.len() as u8];
        req.extend_from_slice(host.as_bytes());
        req.extend_from_slice(&port.to_be_bytes());
        s.write_all(&req)
            .unwrap_or_else(|e| fail(&format!("socks5 connect: {}", e)));
        let mut head = [0u8; 4];
        s.read_exact(&mut head)
            .unwrap_or_else(|e| fail(&format!("socks5 reply: {}", e)));
        if head[1] != 0 {
            fail("socks5: CONNECT refused");
        }
        match head[3] {
            1 => {
                let mut junk = [0u8; 6];
                let _ = s.read_exact(&mut junk);
            }
            4 => {
                let mut junk = [0u8; 18];
                let _ = s.read_exact(&mut junk);
            }
            3 => {
                let mut l = [0u8; 1];
                s.read_exact(&mut l).ok();
                {
                    let mut junk = vec![0u8; l[0] as usize + 2];
                    let _ = s.read_exact(&mut junk);
                }
            }
            _ => {}
        }
        s.set_read_timeout(None).ok();
        s
    };
    tcp.set_nodelay(true).ok();

    // 2. TLS（rustls 0.23）
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    #[derive(Debug)]
    struct NoVerify;
    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _e: &CertificateDer<'_>,
            _i: &[CertificateDer<'_>],
            _s: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _m: &[u8],
            _c: &CertificateDer<'_>,
            _d: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(std::sync::Arc::new(NoVerify));
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let config = std::sync::Arc::new(config);
    let server_name = ServerName::try_from(addr.split(':').next().unwrap().to_string())
        .unwrap_or_else(|_| fail("bad server name"));
    let conn = rustls::ClientConnection::new(config, server_name)
        .unwrap_or_else(|e| fail(&format!("tls init: {}", e)));
    let mut tls = rustls::StreamOwned::new(conn, tcp);

    // 3. 握手
    let client_id = {
        let mut h = Sha256::new();
        h.update(format!("{}{}", mac, psk).as_bytes());
        hex::encode(&h.finalize()[..16])
    };
    let req = HandshakeReq {
        client_id: client_id.clone(),
        psk: hash_psk(&psk),
        mac: mac.clone(),
        ipv4: "10.7.0.77".into(),
        fec,
        fec_group,
        encrypt,
        enc_algo: 2,
        brutal_tx: 100,
        brutal_rx: 500,
    };
    let req_json = serde_json::to_vec(&req).unwrap();
    let mut out = Vec::new();
    append_padded_frame(&mut out, 0, &req_json, None);
    tls.write_all(&out)
        .unwrap_or_else(|e| fail(&format!("write req: {}", e)));

    let mut scanner = ProbeScanner::new();
    let resp_data = scanner
        .read_frame(&mut tls, Instant::now() + Duration::from_secs(5))
        .unwrap_or_else(|e| fail(&format!("read resp: {}", e)))
        .unwrap_or_else(|| fail("handshake timeout"));
    let resp: HandshakeResp = serde_json::from_slice(&resp_data.0)
        .unwrap_or_else(|e| fail(&format!("bad resp json: {}", e)));
    if !resp.success {
        fail(&format!("handshake rejected: {}", resp.message));
    }
    println!(
        "RESP: success={} enc_algo={:?} enc_salt={} enc_salt2={} fec_group={:?} session={:?} ipv4={}",
        resp.success, resp.enc_algo, resp.enc_salt.as_deref().unwrap_or(""), resp.enc_salt2.as_deref().unwrap_or(""),
        resp.fec_group, resp.session_id, resp.ipv4
    );

    if resp.encrypt != Some(encrypt) {
        fail(&format!("server encrypt mismatch: {:?}", resp.encrypt));
    }

    // 4. 协商
    let mut ic_tx: Option<ProbeCipher> = None;
    let mut ic_rx: Option<ProbeCipher> = None;
    if encrypt {
        if resp.enc_algo.unwrap_or(0) >= 2 {
            let stx = hex::decode(resp.enc_salt.as_deref().unwrap_or("")).unwrap_or_default();
            let srx = hex::decode(resp.enc_salt2.as_deref().unwrap_or("")).unwrap_or_default();
            ic_tx = Some(ProbeCipher::new(&psk, &stx).unwrap_or_else(|e| fail(&e)));
            ic_rx = Some(ProbeCipher::new(&psk, &srx).unwrap_or_else(|e| fail(&e)));
            println!("NEGOTIATED: GCM (per-session bidirectional salts)");
        } else {
            println!("FAIL: expected GCM negotiation with modern server");
            std::process::exit(1);
        }
    }
    if fec {
        if resp.fec_group.unwrap_or(0) >= 2 {
            println!("NEGOTIATED: XOR FEC K={}", resp.fec_group.unwrap());
        } else if fec_group >= 2 {
            println!("FAIL: expected XOR FEC negotiation");
            std::process::exit(1);
        } else {
            println!("NEGOTIATED: dup fallback");
        }
    }

    // 5. 发送加密数据帧（parity-test 模式跳过，由 bcast 块发送等长帧）
    if !parity_test {
        {
            let payload_seed = b"PROBE-DATA-RS";
            for i in 0..send_frames {
                let mut payload = payload_seed.to_vec();
                payload.extend_from_slice(format!("-{:04}", i).as_bytes());
                let mut fb = Vec::new();
                append_padded_frame(&mut fb, (i + 1) as u32, &payload, ic_tx.as_ref());
                tls.write_all(&fb)
                    .unwrap_or_else(|e| fail(&format!("write data: {}", e)));
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    // 双客户端模式：发广播帧后驻留接收（验证 c2s+s2c 全双工）
    if stay_sec > 0 {
        if bcast {
            let n = if parity_test { send_frames } else { 1 };
            for i in 0..n {
                let mut frame = vec![0xffu8; 6];
                frame.extend_from_slice(&hex::decode(mac.replace(':', "")).unwrap_or_default());
                frame.extend_from_slice(format!("BCAST-FROM-RS-{}-idx{:03}", mac, i).as_bytes());
                // 等长帧（固定 60 字节）确保每组校验帧长度一致
                frame.resize(60, 0);
                let mut fb = Vec::new();
                append_padded_frame(&mut fb, (i + 1) as u32, &frame, ic_tx.as_ref());
                tls.write_all(&fb).ok();
                std::thread::sleep(Duration::from_millis(250));
            }
            println!("SENT: {} broadcast frames", n);
        }
        let stay_deadline = Instant::now() + Duration::from_secs(stay_sec);
        let mut last_ka = Instant::now();
        let mut rx_count = 0usize;
        let mut parity_ok = false;
        while Instant::now() < stay_deadline {
            match scanner.read_frame(
                &mut tls,
                stay_deadline.min(Instant::now() + Duration::from_millis(500)),
            ) {
                Ok(Some((mut body, seq))) => {
                    if seq == 0 {
                        if body.len() >= 7 && body[0] == FEC_MAGIC {
                            // 校验帧：解析描述符并用 s2c 盐以 groupStart 解密
                            let start = u32::from_be_bytes([body[1], body[2], body[3], body[4]]);
                            let k = body[5] as usize;
                            let desc_len = 6 + 4 * k;
                            let tag_len = if ic_rx.is_some() { GCM_TAG_SIZE } else { 0 };
                            let mut max_len = 0usize;
                            for i in 0..k {
                                let off = 6 + 4 * i;
                                if off + 4 > body.len() {
                                    break;
                                }
                                let l = u32::from_be_bytes([
                                    body[off],
                                    body[off + 1],
                                    body[off + 2],
                                    body[off + 3],
                                ]) as usize;
                                if l > max_len {
                                    max_len = l;
                                }
                            }
                            let mut ok = false;
                            if let Some(ic) = &ic_rx {
                                if body.len() >= desc_len + tag_len {
                                    let mut region = vec![0u8; max_len + tag_len];
                                    region.copy_from_slice(
                                        &body[desc_len..desc_len + max_len + tag_len],
                                    );
                                    if ic.open(&mut region, start).is_ok() {
                                        ok = true;
                                    }
                                }
                            }
                            println!(
                                "RX-PARITY-{}: start={} K={} len={}",
                                if ok { "OK" } else { "BAD" },
                                start,
                                k,
                                body.len()
                            );
                            parity_ok = ok;
                        }
                        continue;
                    }
                    if let Some(ic) = &ic_rx {
                        match ic.open(&mut body, seq) {
                            Ok(plain) => {
                                let n = plain.len().min(60);
                                println!(
                                    "RX-DECRYPTED: seq={} {:?}",
                                    seq,
                                    String::from_utf8_lossy(&plain[..n])
                                );
                            }
                            Err(_) => {
                                println!("FAIL: GCM OPEN FAILED (seq={})", seq);
                                std::process::exit(1);
                            }
                        }
                    } else {
                        println!("RX: seq={} len={}", seq, body.len());
                    }
                    rx_count += 1;
                }
                Ok(None) => {
                    if Instant::now() > stay_deadline {
                        break;
                    }
                }
                Err(_) => break,
            }
            if last_ka.elapsed() > Duration::from_secs(2) {
                let mut kb = Vec::new();
                append_padded_frame(&mut kb, 0, &[], None);
                tls.write_all(&kb).ok();
                last_ka = Instant::now();
            }
        }
        println!("SUMMARY: stay-frames={} parity-ok={}", rx_count, parity_ok);
        if fec && !parity_ok {
            println!("FAIL: expected a verifiable parity frame (did receiver negotiate --fec?)");
            std::process::exit(1);
        }
        println!("PASS");
        return;
    }

    // 6. 收帧循环
    let deadline = Instant::now() + Duration::from_secs(timeout_sec);
    let mut got_frames = 0usize;
    let mut got_parity = 0usize;
    let mut heartbeats = 0usize;
    let mut last_keepalive = Instant::now();
    while (got_frames < expect_frames || heartbeats < 1) && Instant::now() < deadline {
        match scanner.read_frame(
            &mut tls,
            deadline.min(Instant::now() + Duration::from_secs(2)),
        ) {
            Ok(Some((mut body, seq))) => {
                if seq == 0 {
                    if body.len() >= 7 && body[0] == FEC_MAGIC {
                        got_parity += 1;
                        println!("RX: parity frame (len={})", body.len());
                    } else if body.is_empty() {
                        heartbeats += 1; // 服务端下行链路存活证明
                    }
                    continue;
                }
                if let Some(ic) = &ic_rx {
                    match ic.open(&mut body, seq) {
                        Ok(plain) => {
                            let n = plain.len().min(40);
                            println!(
                                "RX: seq={} plain={:?}",
                                seq,
                                String::from_utf8_lossy(&plain[..n])
                            );
                        }
                        Err(_) => {
                            println!("FAIL: GCM OPEN FAILED (seq={})", seq);
                            std::process::exit(1);
                        }
                    }
                } else {
                    println!("RX: seq={} len={}", seq, body.len());
                }
                got_frames += 1;
            }
            Ok(None) => {
                if Instant::now() > deadline {
                    break;
                }
            }
            Err(e) => fail(&format!("read loop: {}", e)),
        }
        if last_keepalive.elapsed() > Duration::from_secs(2) {
            let mut kb = Vec::new();
            append_padded_frame(&mut kb, 0, &[], None);
            tls.write_all(&kb).ok();
            last_keepalive = Instant::now();
        }
    }
    println!(
        "SUMMARY: frames={} parity={} heartbeats={}",
        got_frames, got_parity, heartbeats
    );
    // 单客户端模式：收到心跳即证明下行链路存活（服务端不回显数据帧）
    if got_frames < expect_frames && heartbeats == 0 {
        fail("expected more frames");
    }
    println!("PASS");
}
