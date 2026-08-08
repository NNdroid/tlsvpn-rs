#[cfg(not(target_os = "linux"))]
pub trait AsRawFd {}
#[cfg(not(target_os = "linux"))]
impl<T> AsRawFd for T {}

use crate::Args;
use aes::Aes256;
use crossbeam_channel::bounded;
use parking_lot::{Mutex, RwLock};
use rustls::{ClientConfig, ClientConnection};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info};

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::frame::*;
use crate::net::*;
use crate::socks5::{split_host_port, Socks5Proxy};

// 自定义验证器，用于对齐 Go 客户端的 SHA256 哈希证书校验功能
struct CertHashVerifier {
    expected_hash: String,
}
impl rustls::client::ServerCertVerifier for CertHashVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(&end_entity.0);
        let hash_str = hex::encode(hasher.finalize());
        if hash_str == self.expected_hash {
            Ok(rustls::client::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "cert SHA-256 mismatch: expected {}",
                self.expected_hash
            )))
        }
    }
}

pub fn start_client(args: &Args) {
    info!("Starting Client Mode towards {}...", args.addr);
    let psk_hash = hash_psk(&args.psk);
    let (cipher_key, cipher_iv) = if args.encrypt {
        get_cipher_context(&args.psk)
    } else {
        (vec![], vec![])
    };

    let actual_mac = if args.mac.is_empty() {
        // 尝试从 Linux sysfs 读取真实 MAC 地址，如果失败再 fallback
        std::fs::read_to_string(format!("/sys/class/net/{}/address", args.tap))
            .unwrap_or_else(|_| "00:00:00:00:00:00".to_string())
            .trim()
            .to_string()
    } else {
        args.mac.clone()
    };
    let ns = uuid::Uuid::new_v3(&uuid::Uuid::NAMESPACE_URL, b"my_vpn_tunnel");
    let client_id =
        uuid::Uuid::new_v5(&ns, format!("{}{}", actual_mac, args.psk).as_bytes()).to_string();

    let my_stat = Arc::new(ClientStat::new(
        client_id.clone(),
        args.req_v4.clone(),
        args.req_v6.clone(),
        actual_mac.clone(),
    ));
    let stats_registry = Arc::new(RwLock::new(HashMap::new()));
    stats_registry
        .write()
        .insert("local".into(), my_stat.clone());

    if !args.web.is_empty() {
        start_web_server(
            args.web.clone(),
            "client".to_string(),
            stats_registry.clone(),
        );
    }

    let (tap_tx, tap_rx) = bounded::<Vec<u8>>(4096);
    let tx_port = Arc::new(AsyncPort::new("CLIENT_UPLINK".to_string(), args.fec));
    let reorder_buf = Arc::new(Mutex::new(ReorderBuffer::new()));
    let reorder_clone_for_timeout = reorder_buf.clone();
    let tx_clone = tap_tx.clone();

    std::thread::spawn(move || loop {
        std::thread::sleep(Duration::from_millis(5));
        let ready_frames = reorder_clone_for_timeout.lock().flush_timeout();
        for ordered_data in ready_frames {
            let _ = tx_clone.try_send(ordered_data);
        }
    });
    let dedup = Arc::new(Mutex::new(DeDuplicator::new())); // 客户端也增加去重器

    let device = tun_rs::DeviceBuilder::new()
        .name(&args.tap)
        .layer(tun_rs::Layer::L2)
        .mtu(1500)
        .build_sync()
        .unwrap();
    let dev_writer = Arc::new(device);
    let dev_reader = dev_writer.clone();

    std::thread::spawn(move || {
        while let Ok(data) = tap_rx.recv() {
            let _ = dev_writer.send(&data);
        }
    });

    let port_clone = tx_port.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if let Ok(n) = dev_reader.recv(&mut buf) {
                if n > 0 {
                    let mut frame = get_frame();
                    frame.clear();
                    frame.extend_from_slice(&buf[..n]);
                    port_clone.write_frame(frame);
                }
            }
        }
    });

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let mut config = ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    if args.insecure {
        struct DummyVerifier;
        impl rustls::client::ServerCertVerifier for DummyVerifier {
            fn verify_server_cert(
                &self,
                _e: &rustls::Certificate,
                _i: &[rustls::Certificate],
                _s: &rustls::ServerName,
                _scts: &mut dyn Iterator<Item = &[u8]>,
                _ocsp: &[u8],
                _now: std::time::SystemTime,
            ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::ServerCertVerified::assertion())
            }
        }
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(DummyVerifier));
    } else if !args.cert_sha256.is_empty() {
        // 装配指定的 Hash Verification 对齐 Go 版本逻辑
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(CertHashVerifier {
                expected_hash: args.cert_sha256.clone(),
            }));
    }

    let client_config = Arc::new(config);

    // 客戶端保存服務端的 SessionID 狀態
    let server_session_id = Arc::new(Mutex::new(String::new()));

    // SOCKS5 is a client-only feature: when set, the outbound connection to the
    // server is established through the proxy. The server is unaware of it.
    let socks5_proxy: Option<Socks5Proxy> = if args.socks5.is_empty() {
        None
    } else {
        match Socks5Proxy::parse(&args.socks5) {
            Some(p) => Some(p),
            None => {
                error!("Invalid SOCKS5 proxy spec: {}", args.socks5);
                return;
            }
        }
    };
    let (target_host, target_port) = split_host_port(&args.addr);

    for i in 0..args.conns {
        let addr = args.addr.clone();
        let sni = args.sni.clone();
        let cid = client_id.clone();
        let p_hash = psk_hash.clone();
        let port = tx_port.clone();
        let c_key = cipher_key.clone();
        let c_iv = cipher_iv.clone();
        let encrypt = args.encrypt;
        let fec = args.fec;
        let t_tx = tap_tx.clone();
        let brutal = args.brutal;
        let brutal_up = args.brutal_up;
        let brutal_down = args.brutal_down;
        let config_clone = client_config.clone();
        let tap_name = args.tap.clone();

        let mac_arg = if actual_mac.is_empty() {
            None
        } else {
            Some(actual_mac.clone())
        };
        let v4_arg = if args.req_v4.is_empty() {
            None
        } else {
            Some(args.req_v4.clone())
        };
        let v6_arg = if args.req_v6.is_empty() {
            None
        } else {
            Some(args.req_v6.clone())
        };

        let local_stat = my_stat.clone();
        let reorder_clone = reorder_buf.clone();
        let dedup_clone = dedup.clone();
        let conns_count = args.conns as u64;
        let sid_clone = server_session_id.clone();
        let socks5_proxy = socks5_proxy.clone();
        let target_host = target_host.clone();
        let proxied = socks5_proxy.is_some();

        std::thread::spawn(move || {
            loop {
                info!("[Conn {}] Connecting...", i);
                let mut socket = match &socks5_proxy {
                    Some(p) => match p.connect(&target_host, target_port) {
                        Ok(s) => s,
                        Err(e) => {
                            error!("[Conn {}] SOCKS5 connect failed: {}", i, e);
                            std::thread::sleep(Duration::from_secs(3));
                            continue;
                        }
                    },
                    None => match std::net::TcpStream::connect(&addr) {
                        Ok(s) => s,
                        Err(_) => {
                            std::thread::sleep(Duration::from_secs(3));
                            continue;
                        }
                    },
                };

                socket.set_nodelay(true).unwrap();
                socket.set_nonblocking(true).unwrap();
                apply_tcp_keepalive(&socket);

                let server_name = sni.as_str().try_into().unwrap();
                let mut tls = ClientConnection::new(config_clone.clone(), server_name).unwrap();

                let client_tx_rate = if brutal_up > 0 {
                    std::cmp::max(1, brutal_up / conns_count)
                } else {
                    0
                };
                let client_rx_rate = if brutal_down > 0 {
                    std::cmp::max(1, brutal_down / conns_count)
                } else {
                    0
                };

                let req = HandshakeReq {
                    client_id: cid.clone(),
                    psk: p_hash.clone(),
                    mac: mac_arg.clone(),
                    ipv4: v4_arg.clone(),
                    ipv6: v6_arg.clone(),
                    padding: Some(generate_padding(100, 500)),
                    brutal_tx: if brutal { Some(client_tx_rate) } else { None },
                    brutal_rx: if brutal { Some(client_rx_rate) } else { None },
                    fec: Some(fec),
                    encrypt: Some(encrypt),
                };
                let req_json = serde_json::to_vec(&req).unwrap();

                let mut send_buf = Vec::with_capacity(65536 * 4);
                append_tls_frame(&mut send_buf, 0, &req_json, &[], &[]);
                let _ = tls.writer().write_all(&send_buf);

                let mut scanner = FrameScanner::new();
                let mut handshake_ok = false;
                let start_time = Instant::now();

                while start_time.elapsed() < Duration::from_secs(5) {
                    while tls.wants_write() {
                        match tls.write_tls(&mut socket) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => break,
                        }
                    }
                    match tls.read_tls(&mut socket) {
                        Ok(0) => break,
                        Ok(_) => {
                            if tls.process_new_packets().is_ok() {
                                while let Ok(Some((data, seq))) =
                                    scanner.read_frame(&mut tls.reader())
                                {
                                    if seq == 0 {
                                        if let Ok(resp) =
                                            serde_json::from_slice::<HandshakeResp>(&data)
                                        {
                                            if resp.success && resp.encrypt == Some(encrypt) {
                                                // 智能比對並重置緩衝區
                                                let mut current_sid = sid_clone.lock();
                                                let new_sid =
                                                    resp.session_id.clone().unwrap_or_default();
                                                if *current_sid != new_sid {
                                                    info!(
                                                        "[Conn {}] 🔄 检测到服务端重置了会话，正在清理本地旧的接收缓冲池...",
                                                        i
                                                    );
                                                    *current_sid = new_sid;
                                                    reorder_clone.lock().reset();
                                                    dedup_clone.lock().reset();
                                                }

                                                handshake_ok = true;
                                                if !proxied && brutal && resp.brutal_rx.unwrap_or(0) > 0 {
                                                    apply_tcp_brutal(
                                                        &socket,
                                                        resp.brutal_rx.unwrap(),
                                                    );
                                                }
                                                if i == 0 {
                                                    Command::new("ip")
                                                        .args([
                                                            "addr", "add", &resp.ipv4, "dev",
                                                            &tap_name,
                                                        ])
                                                        .output()
                                                        .ok();
                                                    Command::new("ip")
                                                        .args([
                                                            "-6", "addr", "add", &resp.ipv6, "dev",
                                                            &tap_name,
                                                        ])
                                                        .output()
                                                        .ok();
                                                    Command::new("ip")
                                                        .args([
                                                            "link", "set", "dev", &tap_name, "up",
                                                        ])
                                                        .output()
                                                        .ok();
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => break,
                    }
                    if handshake_ok {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }

                if !handshake_ok {
                    std::thread::sleep(Duration::from_secs(3));
                    continue;
                }

                local_stat.active_conns.fetch_add(1, Ordering::Relaxed);
                let (tx, rx) = bounded(4096);
                let rtt = Arc::new(AtomicU32::new(50000));
                port.register_backend(Arc::new(Backend {
                    ch: tx.clone(),
                    rtt_cache: rtt.clone(),
                }));

                let mut last_keepalive = Instant::now();
                let mut last_rx = Instant::now();
                let mut rtt_timer = Instant::now();

                loop {
                    let mut is_active = false;
                    let idle_time = last_rx.elapsed().as_secs();

                    if idle_time > 15 {
                        break;
                    }
                    if idle_time >= 5 {
                        rtt.store(100000, Ordering::Relaxed);
                    } else if rtt_timer.elapsed() > Duration::from_millis(200) {
                        // For proxied sockets the RTT we could read is to the
                        // proxy, not the server; keep the default and avoid
                        // touching the tunnel (matches Go's nil-TCPConn path).
                        rtt.store(
                            if proxied { 50000 } else { get_tcp_rtt(&socket) },
                            Ordering::Relaxed,
                        );
                        rtt_timer = Instant::now();
                    }

                    let mut close = false;

                    while tls.wants_write() {
                        is_active = true;
                        match tls.write_tls(&mut socket) {
                            Ok(0) => {
                                close = true;
                                break;
                            }
                            Ok(_) => {}
                            Err(e)
                                if e.kind() == ErrorKind::WouldBlock
                                    || e.kind() == ErrorKind::TimedOut =>
                            {
                                break;
                            }
                            Err(_) => {
                                close = true;
                                break;
                            }
                        }
                    }
                    if close {
                        break;
                    }

                    if !tls.wants_write() {
                        let mut pulled = 0;
                        send_buf.clear();
                        while let Ok(frames) = rx.try_recv() {
                            is_active = true;
                            for f in frames {
                                append_tls_frame(&mut send_buf, f.seq, &f.data, &c_key, &c_iv);
                                local_stat.tx_packets.fetch_add(1, Ordering::Relaxed);
                                if !f.data.is_empty() {
                                    put_frame(f.data);
                                }
                            }
                            pulled += 1;
                            if send_buf.len() >= 32768 {
                                if tls.writer().write_all(&send_buf).is_ok() {
                                    local_stat
                                        .tx_bytes
                                        .fetch_add(send_buf.len() as u64, Ordering::Relaxed);
                                }
                                send_buf.clear();
                                while tls.wants_write() {
                                    match tls.write_tls(&mut socket) {
                                        Ok(0) => {
                                            close = true;
                                            break;
                                        }
                                        Ok(_) => {}
                                        Err(e)
                                            if e.kind() == ErrorKind::WouldBlock
                                                || e.kind() == ErrorKind::TimedOut =>
                                        {
                                            break;
                                        }
                                        Err(_) => {
                                            close = true;
                                            break;
                                        }
                                    }
                                }
                                if tls.wants_write() || close {
                                    break;
                                }
                            }
                            if pulled >= 1024 {
                                break;
                            }
                        }

                        if !send_buf.is_empty() && !close {
                            if tls.writer().write_all(&send_buf).is_ok() {
                                local_stat
                                    .tx_bytes
                                    .fetch_add(send_buf.len() as u64, Ordering::Relaxed);
                            }
                            while tls.wants_write() {
                                match tls.write_tls(&mut socket) {
                                    Ok(0) => {
                                        close = true;
                                        break;
                                    }
                                    Ok(_) => {}
                                    Err(e)
                                        if e.kind() == ErrorKind::WouldBlock
                                            || e.kind() == ErrorKind::TimedOut =>
                                    {
                                        break;
                                    }
                                    Err(_) => {
                                        close = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if close {
                        break;
                    }

                    if last_keepalive.elapsed() > Duration::from_secs(4) {
                        send_buf.clear();
                        append_tls_frame(&mut send_buf, 0, &[], &[], &[]);
                        let _ = tls.writer().write_all(&send_buf);
                        last_keepalive = Instant::now();
                    }

                    loop {
                        match tls.read_tls(&mut socket) {
                            Ok(0) => {
                                close = true;
                                break;
                            }
                            Ok(_) => {
                                is_active = true;
                                last_rx = Instant::now();
                            }
                            Err(e)
                                if e.kind() == ErrorKind::WouldBlock
                                    || e.kind() == ErrorKind::TimedOut =>
                            {
                                break;
                            }
                            Err(_) => {
                                close = true;
                                break;
                            }
                        }
                    }

                    if is_active && !close {
                        if tls.process_new_packets().is_ok() {
                            while let Ok(Some((mut data, seq))) =
                                scanner.read_frame(&mut tls.reader())
                            {
                                local_stat
                                    .rx_bytes
                                    .fetch_add((data.len() + 10) as u64, Ordering::Relaxed);
                                local_stat.rx_packets.fetch_add(1, Ordering::Relaxed);

                                if data.is_empty() {
                                    continue;
                                }
                                if encrypt && seq != 0 {
                                    xor_crypt_in_place(&mut data, seq, &c_key, &c_iv);
                                }

                                if !dedup_clone.lock().is_duplicate(seq) {
                                    let ready_frames = reorder_clone.lock().insert(seq, data);
                                    for ordered_data in ready_frames {
                                        let _ = t_tx.try_send(ordered_data);
                                    }
                                }
                            }
                        } else {
                            close = true;
                        }
                    }

                    if close {
                        break;
                    }
                    if !is_active {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }

                port.unregister_backend(&tx);
                local_stat.active_conns.fetch_sub(1, Ordering::Relaxed);
                std::thread::sleep(Duration::from_secs(3));
            }
        });
    }

    if args.fwmark > 0 {
        setup_policy_routing(&args.tap, args.fwmark, "10.0.0.1", "fd00::1");
    }
    loop {
        std::thread::sleep(Duration::from_secs(60));
    }
}
