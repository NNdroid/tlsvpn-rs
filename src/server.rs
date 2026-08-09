#[cfg(not(target_os = "linux"))]
pub trait AsRawFd {}
#[cfg(not(target_os = "linux"))]
impl<T> AsRawFd for T {}

use crate::Args;
use aes::Aes256;
use crossbeam_channel::{bounded, Receiver};
use mio::net::{TcpListener, TcpStream as MioTcpStream};
use mio::{Events, Interest, Poll, Token};
use parking_lot::{Mutex, RwLock};
use rustls::{ServerConfig, ServerConnection};
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Write};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::api::*;
use crate::buffer::*;
use crate::crypto::*;
use crate::frame::*;
use crate::net::*;
use crate::tap::{MemTap, TapDevice};
use crate::utils::*;

pub fn start_server(args: &Args) {
    info!("Starting Server Mode on {}...", args.addr);
    let psk_hash = hash_psk(&args.psk);
    let (cipher_key, cipher_iv) = if args.encrypt {
        get_cipher_context(&args.psk)
    } else {
        (vec![], vec![])
    };

    let v4_gw = args
        .v4cidr
        .split('/')
        .next()
        .unwrap_or("10.0.0.1")
        .to_string();
    let v6_gw = args
        .v6cidr
        .split('/')
        .next()
        .unwrap_or("fd00::1")
        .to_string();
    let v4_mask = args.v4cidr.split('/').nth(1).unwrap_or("24").to_string();
    let v6_mask = args.v6cidr.split('/').nth(1).unwrap_or("64").to_string();

    let mut v4_counter = ip4_to_u32(&v4_gw) + 1;
    let v4_prefix_len: u32 = v4_mask.parse().unwrap_or(24);
    // 计算IPv4的最大可用IP边界
    let v4_max_ip = (ip4_to_u32(&v4_gw)
        & !(1u32
            .checked_shl(32 - v4_prefix_len)
            .unwrap_or(0)
            .wrapping_sub(1)))
        | (1u32
            .checked_shl(32 - v4_prefix_len)
            .unwrap_or(0)
            .wrapping_sub(1));
    let mut v6_counter = ip6_to_u128(&v6_gw) + 1;
    // 计算 IPv6 的最大可用 IP 边界
    let v6_prefix_len: u32 = v6_mask.parse().unwrap_or(64);
    let v6_shift = 128u32.saturating_sub(v6_prefix_len);
    // 防止 << 128 导致 Rust 运行时 panic
    let v6_wildcard = if v6_shift >= 128 {
        u128::MAX
    } else {
        (1u128 << v6_shift) - 1
    };
    let v6_max_ip = (ip6_to_u128(&v6_gw) & !v6_wildcard) | v6_wildcard;

    let ip_bindings: Arc<RwLock<HashMap<String, (String, String)>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let used_ips: Arc<RwLock<HashSet<String>>> = Arc::new(RwLock::new(HashSet::new()));
    used_ips.write().insert(v4_gw.clone());
    used_ips.write().insert(v6_gw.clone());

    let vswitch = VSwitch::new();
    let (tap_tx, tap_rx) = bounded::<Vec<VPNFrame>>(4096);
    let tap_port = Arc::new(AsyncPort::new("TAP_LOCAL".to_string(), args.fec));
    vswitch.add_port("TAP_LOCAL".to_string(), tap_port.clone());

    let device: Arc<dyn TapDevice> = if args.tap == "mem" {
        info!("Using in-memory TAP backend (no real device)");
        Arc::new(MemTap)
    } else {
        let dev = tun_rs::DeviceBuilder::new()
            .name(&args.tap)
            .layer(tun_rs::Layer::L2)
            .mtu(1500)
            .build_sync()
            .unwrap();

        info!("Configuring Server TAP Interface IP...");
        Command::new("ip")
            .args(["addr", "add", &args.v4cidr, "dev", &args.tap])
            .output()
            .ok();
        Command::new("ip")
            .args(["-6", "addr", "add", &args.v6cidr, "dev", &args.tap])
            .output()
            .ok();
        Command::new("ip")
            .args(["link", "set", "dev", &args.tap, "up"])
            .output()
            .ok();
        Arc::new(dev)
    };

    let stats_registry = Arc::new(RwLock::new(HashMap::new()));
    if !args.web.is_empty() {
        start_web_server(
            args.web.clone(),
            "server".to_string(),
            stats_registry.clone(),
        );
    }

    let dev_writer = device.clone();
    let dev_reader = dev_writer.clone();

    let tap_tx_backend = Arc::new(Backend {
        ch: tap_tx,
        rtt_cache: Arc::new(AtomicU32::new(0)),
    });
    tap_port.register_backend(tap_tx_backend);
    std::thread::spawn(move || {
        while let Ok(frames) = tap_rx.recv() {
            for f in frames {
                if !f.data.is_empty() {
                    let _ = dev_writer.send(&f.data);
                }
            }
        }
    });

    let vswitch_clone = vswitch.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 65536];
        loop {
            if let Ok(n) = dev_reader.recv(&mut buf) {
                if n > 0 {
                    vswitch_clone.process_frame("TAP_LOCAL", buf[..n].to_vec());
                }
            }
        }
    });

    let cert_file = std::fs::File::open(&args.cert).expect("Cannot open cert");
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .unwrap()
        .into_iter()
        .map(rustls::Certificate)
        .collect();

    let key = {
        let load_key = || -> Option<rustls::PrivateKey> {
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::pkcs8_private_keys(&mut reader) {
                if !keys.is_empty() {
                    return Some(rustls::PrivateKey(keys.remove(0)));
                }
            }
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::rsa_private_keys(&mut reader) {
                if !keys.is_empty() {
                    return Some(rustls::PrivateKey(keys.remove(0)));
                }
            }
            let mut reader = std::io::BufReader::new(std::fs::File::open(&args.key).ok()?);
            if let Ok(mut keys) = rustls_pemfile::ec_private_keys(&mut reader) {
                if !keys.is_empty() {
                    return Some(rustls::PrivateKey(keys.remove(0)));
                }
            }
            None
        };
        load_key().expect("Failed to load private key.")
    };

    let mut tls_config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_config = Arc::new(tls_config);

    let mut poll = Poll::new().unwrap();
    let mut events = Events::with_capacity(4096);
    let mut server = TcpListener::bind(args.addr.parse().unwrap()).unwrap();
    poll.registry()
        .register(&mut server, Token(0), Interest::READABLE)
        .unwrap();

    struct MioSession {
        socket: MioTcpStream,
        tls: ServerConnection,
        scanner: FrameScanner,
        rx: Receiver<Vec<VPNFrame>>,
        handshake_done: bool,
        sniffed: bool, // 新增前置嗅探标志
        client_session: Option<Arc<ClientSession>>,
        tx_backend: Option<Arc<Backend>>,
        last_keepalive: Instant,
        last_rx: Instant,
        send_buf: Vec<u8>,
    }

    let mut mio_sessions: HashMap<Token, MioSession> = HashMap::new();
    let active_client_sessions: Arc<RwLock<HashMap<String, Arc<ClientSession>>>> =
        Arc::new(RwLock::new(HashMap::new()));
    let mut unique_token = 1;

    info!("✅ Server listening for TLS connections.");

    loop {
        poll.poll(&mut events, Some(Duration::from_millis(2)))
            .unwrap();
        let mut closed_tokens = Vec::new();

        for (token, sess) in mio_sessions.iter_mut() {
            let idle_time = sess.last_rx.elapsed().as_secs();

            if idle_time > 15 {
                closed_tokens.push(*token);
                continue;
            }

            if idle_time >= 5 {
                if let Some(backend) = &sess.tx_backend {
                    backend.rtt_cache.store(100000, Ordering::Relaxed);
                }
            }

            if sess.handshake_done && sess.last_keepalive.elapsed() > Duration::from_secs(4) {
                sess.send_buf.clear();
                append_tls_frame(&mut sess.send_buf, 0, &[], &[], &[]);
                let _ = sess.tls.writer().write_all(&sess.send_buf);
                sess.last_keepalive = Instant::now();
            }

            if let Some(c_sess) = &sess.client_session {
                if c_sess.stat.force_disconnect.load(Ordering::Relaxed) {
                    closed_tokens.push(*token);
                    continue;
                }
            }

            if sess.handshake_done {
                while sess.tls.wants_write() {
                    match sess.tls.write_tls(&mut sess.socket) {
                        Ok(0) => {
                            closed_tokens.push(*token);
                            break;
                        }
                        Ok(_) => {}
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(_) => {
                            closed_tokens.push(*token);
                            break;
                        }
                    }
                }

                if !sess.tls.wants_write() {
                    let mut pulled = 0;
                    sess.send_buf.clear();

                    while let Ok(frames) = sess.rx.try_recv() {
                        for f in frames {
                            append_tls_frame(
                                &mut sess.send_buf,
                                f.seq,
                                &f.data,
                                &cipher_key,
                                &cipher_iv,
                            );
                            if let Some(s) = &sess.client_session {
                                s.stat.tx_packets.fetch_add(1, Ordering::Relaxed);
                            }
                            if !f.data.is_empty() {
                                put_frame(f.data);
                            }
                        }
                        pulled += 1;

                        if sess.send_buf.len() >= 32768 {
                            if let Some(s) = &sess.client_session {
                                s.stat
                                    .tx_bytes
                                    .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);
                            }
                            let _ = sess.tls.writer().write_all(&sess.send_buf);
                            sess.send_buf.clear();

                            while sess.tls.wants_write() {
                                match sess.tls.write_tls(&mut sess.socket) {
                                    Ok(0) => {
                                        closed_tokens.push(*token);
                                        break;
                                    }
                                    Ok(_) => {}
                                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                    Err(_) => {
                                        closed_tokens.push(*token);
                                        break;
                                    }
                                }
                            }
                            if sess.tls.wants_write() || closed_tokens.contains(token) {
                                break;
                            }
                        }
                        if pulled >= 1024 {
                            break;
                        }
                    }

                    if !sess.send_buf.is_empty() && !closed_tokens.contains(token) {
                        if let Some(s) = &sess.client_session {
                            s.stat
                                .tx_bytes
                                .fetch_add(sess.send_buf.len() as u64, Ordering::Relaxed);
                        }
                        let _ = sess.tls.writer().write_all(&sess.send_buf);
                        while sess.tls.wants_write() {
                            match sess.tls.write_tls(&mut sess.socket) {
                                Ok(0) => {
                                    closed_tokens.push(*token);
                                    break;
                                }
                                Ok(_) => {}
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(_) => {
                                    closed_tokens.push(*token);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        closed_tokens.sort();
        closed_tokens.dedup();
        for t in closed_tokens {
            if let Some(mut s) = mio_sessions.remove(&t) {
                let _ = poll.registry().deregister(&mut s.socket);
                if let (Some(c_sess), Some(backend)) = (s.client_session, s.tx_backend) {
                    c_sess.port.unregister_backend(&backend.ch);
                    if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
                        let cid = c_sess.stat.client_id.clone();

                        // 递增并捕获当前的断线事件版本号
                        let current_version = c_sess
                            .stat
                            .disconnect_version
                            .fetch_add(1, Ordering::Relaxed)
                            + 1;

                        let act_clone = active_client_sessions.clone();
                        let vs_clone = vswitch.clone(); // 注意：如果你已经改用 DashMap，这里直接 clone 即可
                        let sr_clone = stats_registry.clone();
                        let stat_clone = c_sess.stat.clone();

                        info!(
                            "[{}] ⚠️ 客户端所有物理连接已断开，会话进入 120 秒保留期 (版本: {})...",
                            cid, current_version
                        );
                        std::thread::spawn(move || {
                            std::thread::sleep(Duration::from_secs(120));

                            // 双重校验：连接数必须为 0，且版本号必须与 120 秒前一致
                            let current_conns = stat_clone.active_conns.load(Ordering::Relaxed);
                            let latest_version =
                                stat_clone.disconnect_version.load(Ordering::Relaxed);

                            if current_conns == 0 && latest_version == current_version {
                                act_clone.write().remove(&cid);
                                vs_clone.remove_port(&cid); // DashMap 版本直接 remove_port
                                sr_clone.write().remove(&cid);
                                info!("[{}] 💀 会话超时彻底销毁，释放 IP 及内存资源", cid);
                            } else {
                                // 如果版本号不一致，说明这 120 秒内发生过重连并产生了新的断线事件，当前线程是过期的废弃任务
                                info!(
                                    "[{}] ⚡ 发现较新的重连事件 (当前版本: {})，取消本次销毁动作",
                                    cid, latest_version
                                );
                            }
                        });
                    }
                }
            }
        }

        for event in events.iter() {
            let token = event.token();
            if token == Token(0) {
                while let Ok((mut socket, _)) = server.accept() {
                    socket.set_nodelay(true).unwrap();
                    apply_tcp_keepalive(&socket);
                    let t = Token(unique_token);
                    unique_token += 1;
                    poll.registry()
                        .register(&mut socket, t, Interest::READABLE | Interest::WRITABLE)
                        .unwrap();

                    let (tx, rx) = bounded(4096);
                    mio_sessions.insert(
                        t,
                        MioSession {
                            socket,
                            tls: ServerConnection::new(tls_config.clone()).unwrap(),
                            scanner: FrameScanner::new(),
                            rx,
                            handshake_done: false,
                            sniffed: false,
                            client_session: None,
                            tx_backend: Some(Arc::new(Backend {
                                ch: tx,
                                rtt_cache: Arc::new(AtomicU32::new(50000)),
                            })),
                            last_keepalive: Instant::now(),
                            last_rx: Instant::now(),
                            send_buf: Vec::with_capacity(65536 * 4),
                        },
                    );
                }
            } else if let Some(sess) = mio_sessions.get_mut(&token) {
                let mut close = false;
                let mut tarpit = false;

                if event.is_readable() {
                    // 读取前嗅探首字节，若不是 0x16 则返回 HTTP 403 后断开
                    if !sess.sniffed {
                        let mut peek_buf = [0u8; 1];
                        match sess.socket.peek(&mut peek_buf) {
                            Ok(1) => {
                                sess.sniffed = true;
                                if peek_buf[0] != 0x16 {
                                    serve_fallback_http(&mut sess.socket, false);
                                    close = true;
                                }
                            }
                            _ => {} // 如果 Peek 失败等待下一次事件
                        }
                    }

                    if !close {
                        let mut progress = false;
                        loop {
                            match sess.tls.read_tls(&mut sess.socket) {
                                Ok(0) => {
                                    close = true;
                                    break;
                                }
                                Ok(_) => {
                                    progress = true;
                                }
                                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                                Err(_) => {
                                    close = true;
                                    break;
                                }
                            }
                        }
                        if progress {
                            sess.last_rx = Instant::now();
                        }

                        if progress && !close {
                            if sess.tls.process_new_packets().is_ok() {
                                loop {
                                    match sess.scanner.read_frame(&mut sess.tls.reader()) {
                                        Ok(Some((mut data, seq))) => {
                                            if let Some(s) = &sess.client_session {
                                                s.stat.rx_bytes.fetch_add(
                                                    (data.len() + 10) as u64,
                                                    Ordering::Relaxed,
                                                );
                                                s.stat.rx_packets.fetch_add(1, Ordering::Relaxed);
                                            }

                                            if seq == 0 && !sess.handshake_done {
                                                if let Ok(req) =
                                                    serde_json::from_slice::<HandshakeReq>(&data)
                                                {
                                                    if req.psk == psk_hash {
                                                        sess.handshake_done = true;
                                                        let assigned_v4;
                                                        let assigned_v6;
                                                        let c_sess = {
                                                            let mut sessions_lock =
                                                                active_client_sessions.write();
                                                            if let Some(exist) =
                                                                sessions_lock.get(&req.client_id)
                                                            {
                                                                info!("[{}] ⚡ 會話在銷毀倒計時內成功復活！(無縫接續)", req.client_id);
                                                                assigned_v4 =
                                                                    exist.stat.ipv4.clone();
                                                                assigned_v6 =
                                                                    exist.stat.ipv6.clone();
                                                                exist.clone()
                                                            } else {
                                                                let mut bindings =
                                                                    ip_bindings.write();
                                                                let mut used = used_ips.write();

                                                                let (v4, v6) = if let Some(
                                                                    existing,
                                                                ) =
                                                                    bindings.get(&req.client_id)
                                                                {
                                                                    existing.clone()
                                                                } else {
                                                                    let v4 = if let Some(req_ip) =
                                                                        req.ipv4.filter(|s| {
                                                                            !s.is_empty()
                                                                        }) {
                                                                        let just_ip = req_ip
                                                                            .split('/')
                                                                            .next()
                                                                            .unwrap_or(&req_ip)
                                                                            .to_string();
                                                                        if used.contains(&just_ip) {
                                                                            // 請求的 IP 被佔用，進入安全分配迴圈
                                                                            loop {
                                                                                if v4_counter
                                                                                    >= v4_max_ip - 1
                                                                                {
                                                                                    v4_counter =
                                                                                        ip4_to_u32(
                                                                                            &v4_gw,
                                                                                        ) + 1;
                                                                                }
                                                                                let fallback_ip =
                                                                                    u32_to_ip4(
                                                                                        v4_counter,
                                                                                    );
                                                                                v4_counter += 1;
                                                                                if !used.contains(
                                                                                    &fallback_ip,
                                                                                ) {
                                                                                    break format!(
                                                                                        "{}/{}",
                                                                                        fallback_ip,
                                                                                        v4_mask
                                                                                    );
                                                                                }
                                                                            }
                                                                        } else {
                                                                            if req_ip.contains('/')
                                                                            {
                                                                                req_ip
                                                                            } else {
                                                                                format!(
                                                                                    "{}/{}",
                                                                                    req_ip, v4_mask
                                                                                )
                                                                            }
                                                                        }
                                                                    } else {
                                                                        // 循环寻找一个没有被占用的 IP
                                                                        loop {
                                                                            // 如果计数器快要触达广播地址，则重置回网关后的第一个 IP
                                                                            if v4_counter
                                                                                >= v4_max_ip - 1
                                                                            {
                                                                                v4_counter =
                                                                                    ip4_to_u32(
                                                                                        &v4_gw,
                                                                                    ) + 1;
                                                                            }
                                                                            let just_ip =
                                                                                u32_to_ip4(
                                                                                    v4_counter,
                                                                                );
                                                                            v4_counter += 1;
                                                                            // 检查这个 IP 是否在 used 集合里，不在就 break 并返回
                                                                            if !used
                                                                                .contains(&just_ip)
                                                                            {
                                                                                break format!(
                                                                                    "{}/{}",
                                                                                    just_ip,
                                                                                    v4_mask
                                                                                );
                                                                            }
                                                                        }
                                                                    };

                                                                    let v6 = if let Some(req_ip) =
                                                                        req.ipv6.filter(|s| {
                                                                            !s.is_empty()
                                                                        }) {
                                                                        let just_ip = req_ip
                                                                            .split('/')
                                                                            .next()
                                                                            .unwrap_or(&req_ip)
                                                                            .to_string();
                                                                        if used.contains(&just_ip) {
                                                                            // 請求的 IPv6 被佔用，進入安全分配迴圈
                                                                            loop {
                                                                                if v6_counter
                                                                                    >= v6_max_ip
                                                                                {
                                                                                    v6_counter =
                                                                                        ip6_to_u128(
                                                                                            &v6_gw,
                                                                                        ) + 1;
                                                                                }
                                                                                let fallback_ip =
                                                                                    u128_to_ip6(
                                                                                        v6_counter,
                                                                                    );
                                                                                v6_counter += 1;
                                                                                if !used.contains(
                                                                                    &fallback_ip,
                                                                                ) {
                                                                                    break format!(
                                                                                        "{}/{}",
                                                                                        fallback_ip,
                                                                                        v6_mask
                                                                                    );
                                                                                }
                                                                            }
                                                                        } else {
                                                                            if req_ip.contains('/')
                                                                            {
                                                                                req_ip
                                                                            } else {
                                                                                format!(
                                                                                    "{}/{}",
                                                                                    req_ip, v6_mask
                                                                                )
                                                                            }
                                                                        }
                                                                    } else {
                                                                        // 循环寻找一个没有被占用的 IPv6
                                                                        loop {
                                                                            // 如果计数器快要触达边界，则重置回网关后的第一个 IP
                                                                            if v6_counter
                                                                                >= v6_max_ip
                                                                            {
                                                                                v6_counter =
                                                                                    ip6_to_u128(
                                                                                        &v6_gw,
                                                                                    ) + 1;
                                                                            }
                                                                            let just_ip =
                                                                                u128_to_ip6(
                                                                                    v6_counter,
                                                                                );
                                                                            v6_counter += 1;
                                                                            // 检查这个 IPv6 是否在 used 集合里
                                                                            if !used
                                                                                .contains(&just_ip)
                                                                            {
                                                                                break format!(
                                                                                    "{}/{}",
                                                                                    just_ip,
                                                                                    v6_mask
                                                                                );
                                                                            }
                                                                        }
                                                                    };

                                                                    bindings.insert(
                                                                        req.client_id.clone(),
                                                                        (v4.clone(), v6.clone()),
                                                                    );
                                                                    used.insert(
                                                                        v4.split('/')
                                                                            .next()
                                                                            .unwrap_or(&v4)
                                                                            .to_string(),
                                                                    );
                                                                    used.insert(
                                                                        v6.split('/')
                                                                            .next()
                                                                            .unwrap_or(&v6)
                                                                            .to_string(),
                                                                    );
                                                                    (v4, v6)
                                                                };
                                                                assigned_v4 = v4;
                                                                assigned_v6 = v6;

                                                                let stat =
                                                                    Arc::new(ClientStat::new(
                                                                        req.client_id.clone(),
                                                                        assigned_v4.clone(),
                                                                        assigned_v6.clone(),
                                                                        req.mac
                                                                            .clone()
                                                                            .unwrap_or_default(),
                                                                    ));
                                                                stats_registry.write().insert(
                                                                    req.client_id.clone(),
                                                                    stat.clone(),
                                                                );

                                                                let port =
                                                                    Arc::new(AsyncPort::new(
                                                                        req.client_id.clone(),
                                                                        req.fec.unwrap_or(false),
                                                                    ));
                                                                vswitch.add_port(
                                                                    req.client_id.clone(),
                                                                    port.clone(),
                                                                );

                                                                let new_sess =
                                                                    Arc::new(ClientSession {
                                                                        session_id: gen_session_id(
                                                                        ),
                                                                        stat,
                                                                        port,
                                                                        reorder_buf: Arc::new(
                                                                            Mutex::new(
                                                                                ReorderBuffer::new(
                                                                                ),
                                                                            ),
                                                                        ),
                                                                        dedup: Arc::new(
                                                                            Mutex::new(
                                                                                DeDuplicator::new(),
                                                                            ),
                                                                        ),
                                                                    });
                                                                let c_sess_clone = new_sess.clone();
                                                                let vs_clone = vswitch.clone();
                                                                let cid_clone =
                                                                    req.client_id.clone();

                                                                std::thread::spawn(move || {
                                                                    // 每 5ms 巡检一次，与 Go 版本的 timeoutWorker 对齐
                                                                    loop {
                                                                        std::thread::sleep(
                                                                            Duration::from_millis(
                                                                                5,
                                                                            ),
                                                                        );

                                                                        // 如果会话已经被销毁（连接数归零且版本号变化），则退出巡检协程
                                                                        if c_sess_clone
                                                                            .stat
                                                                            .active_conns
                                                                            .load(Ordering::Relaxed)
                                                                            == 0
                                                                        {
                                                                            // 延迟一点退出，防止刚好在重连间隙
                                                                            std::thread::sleep(
                                                                                Duration::from_secs(
                                                                                    2,
                                                                                ),
                                                                            );
                                                                            if c_sess_clone
                                        .stat
                                        .active_conns
                                        .load(Ordering::Relaxed)
                                        == 0
                                      {
                                        break;
                                      }
                                                                        }

                                                                        let ready_frames =
                                                                            c_sess_clone
                                                                                .reorder_buf
                                                                                .lock()
                                                                                .flush_timeout();
                                                                        for ordered_data in
                                                                            ready_frames
                                                                        {
                                                                            vs_clone.process_frame(
                                                                                &cid_clone,
                                                                                ordered_data,
                                                                            );
                                                                        }
                                                                    }
                                                                });
                                                                sessions_lock.insert(
                                                                    req.client_id.clone(),
                                                                    new_sess.clone(),
                                                                );
                                                                new_sess
                                                            }
                                                        };

                                                        c_sess
                                                            .stat
                                                            .active_conns
                                                            .fetch_add(1, Ordering::Relaxed);
                                                        if let Some(b) = &sess.tx_backend {
                                                            b.rtt_cache
                                                                .store(50000, Ordering::Relaxed);
                                                        }
                                                        c_sess.port.register_backend(
                                                            sess.tx_backend.clone().unwrap(),
                                                        );
                                                        sess.client_session = Some(c_sess.clone());

                                                        let server_tx_rate =
                                                            if req.brutal_rx.unwrap_or(0) > 0
                                                                && (args.brutal_up == 0
                                                                    || req.brutal_rx.unwrap()
                                                                        < args.brutal_up)
                                                            {
                                                                req.brutal_rx.unwrap()
                                                            } else {
                                                                args.brutal_up
                                                            };
                                                        let client_tx_rate =
                                                            if req.brutal_tx.unwrap_or(0) > 0
                                                                && (args.brutal_down == 0
                                                                    || req.brutal_tx.unwrap()
                                                                        < args.brutal_down)
                                                            {
                                                                req.brutal_tx.unwrap()
                                                            } else {
                                                                args.brutal_down
                                                            };

                                                        if args.brutal && server_tx_rate > 0 {
                                                            apply_tcp_brutal(
                                                                &sess.socket,
                                                                server_tx_rate,
                                                            );
                                                        }

                                                        let resp = HandshakeResp {
                                                            success: true,
                                                            message: "OK".into(),
                                                            client_id: req.client_id,
                                                            session_id: Some(
                                                                c_sess.session_id.clone(),
                                                            ),
                                                            ipv4: assigned_v4,
                                                            ipv6: assigned_v6,
                                                            gw_v4: Some(v4_gw.clone()),
                                                            gw_v6: Some(v6_gw.clone()),
                                                            padding: None,
                                                            brutal_tx: Some(server_tx_rate),
                                                            brutal_rx: Some(client_tx_rate),
                                                            fec: req.fec,
                                                            encrypt: Some(args.encrypt),
                                                        };
                                                        let resp_json =
                                                            serde_json::to_vec(&resp).unwrap();
                                                        sess.send_buf.clear();
                                                        append_tls_frame(
                                                            &mut sess.send_buf,
                                                            0,
                                                            &resp_json,
                                                            &[],
                                                            &[],
                                                        );
                                                        let _ = sess
                                                            .tls
                                                            .writer()
                                                            .write_all(&sess.send_buf);

                                                        while sess.tls.wants_write() {
                                                            match sess.tls.write_tls(&mut sess.socket) {
                                Ok(0) => {
                                  close = true;
                                  break;
                                }
                                Ok(_) => {}
                                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                  break
                                }
                                Err(_) => {
                                  close = true;
                                  break;
                                }
                              }
                                                        }
                                                    } else {
                                                        // PSK 不匹配，触发混淆探测阻力(焦油坑)
                                                        warn!("PSK 验证失败，将连接送入焦油坑");
                                                        tarpit = true;
                                                        close = true;
                                                        break;
                                                    }
                                                } else {
                                                    warn!("非法协议格式，将连接送入焦油坑");
                                                    tarpit = true;
                                                    close = true;
                                                    break; // 解析失败，当成扫描器送入焦油坑
                                                }
                                            } else if sess.handshake_done {
                                                if data.is_empty() {
                                                    continue;
                                                }
                                                if let Some(c_sess) = &sess.client_session {
                                                    if args.encrypt && seq != 0 {
                                                        xor_crypt_in_place(
                                                            &mut data,
                                                            seq,
                                                            &cipher_key,
                                                            &cipher_iv,
                                                        );
                                                    }

                                                    // 对齐去重判断
                                                    if !c_sess.dedup.lock().is_duplicate(seq) {
                                                        let ready_frames = c_sess
                                                            .reorder_buf
                                                            .lock()
                                                            .insert(seq, data);
                                                        for ordered_data in ready_frames {
                                                            vswitch.process_frame(
                                                                &c_sess.stat.client_id,
                                                                ordered_data,
                                                            );
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                        Ok(None) => break,
                                        Err(_) => {
                                            if !sess.handshake_done {
                                                let is_h2 = sess.tls.alpn_protocol() == Some(b"h2");
                                                serve_fallback_http(&mut sess.tls.writer(), is_h2);
                                                while sess.tls.wants_write() {
                                                    let _ = sess.tls.write_tls(&mut sess.socket);
                                                }
                                            }
                                            close = true;
                                            break;
                                        }
                                    }
                                }
                            } else {
                                if !sess.handshake_done {
                                    serve_fallback_http(&mut sess.socket, false);
                                }
                                close = true;
                            }
                        }
                    }
                }

                if event.is_writable() && !close {
                    while sess.tls.wants_write() {
                        match sess.tls.write_tls(&mut sess.socket) {
                            Ok(0) => {
                                close = true;
                                break;
                            }
                            Ok(_) => {}
                            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                            Err(_) => {
                                close = true;
                                break;
                            }
                        }
                    }
                }

                if close {
                    let mut s = mio_sessions.remove(&token).unwrap();
                    let _ = poll.registry().deregister(&mut s.socket);

                    if tarpit {
                        // 剥离 Mio，将 Socket 丢给单独的线程执行慢速伪装
                        let socket = s.socket;
                        std::thread::spawn(move || {
                            camouflage_probe(socket);
                        });
                    }

                    if let (Some(c_sess), Some(backend)) = (s.client_session, s.tx_backend) {
                        c_sess.port.unregister_backend(&backend.ch);
                        if c_sess.stat.active_conns.fetch_sub(1, Ordering::Relaxed) <= 1 {
                            let cid = c_sess.stat.client_id.clone();

                            // 递增并捕获当前的断线事件版本号
                            let current_version = c_sess
                                .stat
                                .disconnect_version
                                .fetch_add(1, Ordering::Relaxed)
                                + 1;

                            let act_clone = active_client_sessions.clone();
                            let vs_clone = vswitch.clone(); // 注意：如果你已经改用 DashMap，这里直接 clone 即可
                            let sr_clone = stats_registry.clone();
                            let stat_clone = c_sess.stat.clone();

                            info!(
                                "[{}] ⚠️ 客户端所有物理连接已断开，会话进入 120 秒保留期 (版本: {})...",
                                cid, current_version
                            );
                            std::thread::spawn(move || {
                                std::thread::sleep(Duration::from_secs(120));

                                // 双重校验：连接数必须为 0，且版本号必须与 120 秒前一致
                                let current_conns = stat_clone.active_conns.load(Ordering::Relaxed);
                                let latest_version =
                                    stat_clone.disconnect_version.load(Ordering::Relaxed);

                                if current_conns == 0 && latest_version == current_version {
                                    act_clone.write().remove(&cid);
                                    vs_clone.remove_port(&cid); // DashMap 版本直接 remove_port
                                    sr_clone.write().remove(&cid);
                                    info!("[{}] 💀 会话超时彻底销毁，释放 IP 及内存资源", cid);
                                } else {
                                    // 如果版本号不一致，说明这 120 秒内发生过重连并产生了新的断线事件，当前线程是过期的废弃任务
                                    info!(
                                        "[{}] ⚡ 发现较新的重连事件 (当前版本: {})，取消本次销毁动作",
                                        cid, latest_version
                                    );
                                }
                            });
                        }
                    }
                }
            }
        }
    }
}
