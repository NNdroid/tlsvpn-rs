use aes::Aes256;
use ctr::cipher::KeyIvInit;
use parking_lot::{Mutex, RwLock};
use sha2::Digest;
use std::collections::HashMap;
use std::io::Read;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tiny_http::{Header, Method, Response, Server as HttpServer};
use tracing::info;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::buffer::*;
use crate::net::*;

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct HandshakeReq {
    pub client_id: String,
    pub psk: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_tx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_rx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<bool>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct HandshakeResp {
    pub success: bool,
    pub message: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw_v4: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw_v6: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub padding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_tx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub brutal_rx: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fec: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encrypt: Option<bool>,
}

pub struct ClientStat {
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub mac: String,
    pub active_conns: AtomicU32,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub force_disconnect: AtomicBool,
    pub disconnect_version: AtomicU64,
}

impl ClientStat {
    pub fn new(id: String, ipv4: String, ipv6: String, mac: String) -> Self {
        Self {
            client_id: id,
            ipv4,
            ipv6,
            mac,
            active_conns: AtomicU32::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            force_disconnect: AtomicBool::new(false),
            disconnect_version: AtomicU64::new(0),
        }
    }
}

type StatRegistry = Arc<RwLock<HashMap<String, Arc<ClientStat>>>>;

pub struct ClientSession {
    pub session_id: String,
    pub stat: Arc<ClientStat>,
    pub port: Arc<AsyncPort>,
    pub reorder_buf: Arc<Mutex<ReorderBuffer>>,
    pub dedup: Arc<Mutex<DeDuplicator>>,
}

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>VPN Dashboard (Rust Edition)</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #121212; color: #e0e0e0; margin: 0; padding: 20px; }
        .card { background: #1e1e1e; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); margin-bottom: 20px; }
        h1, h2 { margin-top: 0; color: #bb86fc; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #333; }
        th { background-color: #2c2c2c; }
        .btn { padding: 6px 12px; background-color: #cf6679; color: white; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #ff7597; }
        .speed { color: #03dac6; font-weight: bold; } 
    </style>
</head>
<body>
    <h1>🚀 VPN Dashboard (<span id="mode">加载中...</span>)</h1>
    <div class="card">
        <h2>系统状态</h2>
        <p>活跃连接数/设备: <strong id="active-clients">0</strong></p>
        <p>总发送: <strong id="total-tx">0 B</strong> | 总接收: <strong id="total-rx">0 B</strong></p>
        <p>总上传速率: <strong id="total-tx-speed" class="speed">0 B/s</strong> | 总下载速率: <strong id="total-rx-speed" class="speed">0 B/s</strong></p>
    </div>
    <div class="card" id="clients-container">
        <h2>客户端列表 / 本机详情</h2>
        <table>
            <thead>
                <tr>
                    <th>ID / Name</th>
                    <th>IPv4</th>
                    <th>MAC</th>
                    <th>TCP连接数</th>
                    <th>TX (发)</th>
                    <th>RX (收)</th>
                    <th>↑ 上传速率</th>
                    <th>↓ 下载速率</th>
                    <th>操作</th>
                </tr>
            </thead>
            <tbody id="clients-body">
            </tbody>
        </table>
    </div>

    <script>
        function formatBytes(bytes, isSpeed = false) {
            if (bytes === 0 || isNaN(bytes)) return '0 ' + (isSpeed ? 'B/s' : 'B');
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            const unit = sizes[i] + (isSpeed ? '/s' : '');
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + unit;
        }

        let previousClients = {};
        let lastFetchTime = 0;

        async function fetchStats() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();
                const now = performance.now();
                let timeDelta = lastFetchTime ? (now - lastFetchTime) / 1000 : 2; 
                lastFetchTime = now;

                document.getElementById('mode').innerText = data.mode.toUpperCase();
                document.getElementById('active-clients').innerText = data.active_clients;
                
                let tbody = '';
                let totalTx = 0, totalRx = 0;
                let totalTxSpeed = 0, totalRxSpeed = 0;
                const currentClientsState = {};

                const processClient = (id, c) => {
                    totalTx += c.tx_bytes;
                    totalRx += c.rx_bytes;
                    let txSpeed = 0;
                    let rxSpeed = 0;
                    
                    if (previousClients[id]) {
                        txSpeed = Math.max(0, (c.tx_bytes - previousClients[id].tx_bytes) / timeDelta);
                        rxSpeed = Math.max(0, (c.rx_bytes - previousClients[id].rx_bytes) / timeDelta);
                    }
                    
                    currentClientsState[id] = { tx_bytes: c.tx_bytes, rx_bytes: c.rx_bytes };
                    totalTxSpeed += txSpeed;
                    totalRxSpeed += rxSpeed;

                    return '<tr>' +
                        '<td>' + (id.length > 8 ? id.substring(0,8) + '...' : id) + '</td>' +
                        '<td>' + c.ipv4 + '</td>' +
                        '<td>' + c.mac + '</td>' +
                        '<td>' + c.active_conns + '</td>' +
                        '<td>' + formatBytes(c.tx_bytes) + '</td>' +
                        '<td>' + formatBytes(c.rx_bytes) + '</td>' +
                        '<td class="speed">' + formatBytes(txSpeed, true) + '</td>' +
                        '<td class="speed">' + formatBytes(rxSpeed, true) + '</td>' +
                        '<td>' + (data.mode === 'server' ? '<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>' : '-') + '</td>' +
                    '</tr>';
                };

                for (const [id, c] of Object.entries(data.clients)) {
                    tbody += processClient(id, c);
                }

                previousClients = currentClientsState;
                document.getElementById('clients-body').innerHTML = tbody;
                document.getElementById('total-tx').innerText = formatBytes(totalTx);
                document.getElementById('total-rx').innerText = formatBytes(totalRx);
                document.getElementById('total-tx-speed').innerText = formatBytes(totalTxSpeed, true);
                document.getElementById('total-rx-speed').innerText = formatBytes(totalRxSpeed, true);

            } catch (err) { console.error("API Error", err); }
        }

        async function kickClient(id) {
            if(!confirm("确定要强制断开该客户端吗？")) return;
            await fetch('/api/control', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({ action: 'kick', client_id: id })
            });
            fetchStats();
        }

        setInterval(fetchStats, 2000);
        fetchStats();
    </script>
</body>
</html>"#;

pub fn start_web_server(addr: String, mode: String, registry: StatRegistry) {
    std::thread::spawn(move || {
        let server = HttpServer::http(&addr).expect("Web Server bind failed");
        info!("🚀 Web Dashboard started at http://{}", addr);

        #[allow(unused_mut)]
        for mut request in server.incoming_requests() {
            match (request.method(), request.url()) {
                (&Method::Get, "/") => {
                    let response = Response::from_string(DASHBOARD_HTML).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
                            .unwrap(),
                    );
                    let _ = request.respond(response);
                }
                (&Method::Get, "/api/stats") => {
                    let lock = registry.read();
                    let mut views = HashMap::new();
                    for (k, v) in lock.iter() {
                        views.insert(k.clone(), serde_json::json!({
                            "client_id": v.client_id, "ipv4": v.ipv4, "mac": v.mac,
                            "active_conns": v.active_conns.load(Ordering::Relaxed),
                            "tx_bytes": v.tx_bytes.load(Ordering::Relaxed), "rx_bytes": v.rx_bytes.load(Ordering::Relaxed),
                        }));
                    }
                    let json = serde_json::json!({ "mode": mode, "active_clients": views.len(), "clients": views }).to_string();
                    let response = Response::from_string(json).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    );
                    let _ = request.respond(response);
                }
                (&Method::Post, "/api/control") => {
                    let mut content = String::new();
                    request.as_reader().read_to_string(&mut content).unwrap();
                    #[derive(serde::Deserialize)]
                    struct ControlReq {
                        action: String,
                        client_id: String,
                    }

                    if let Ok(req) = serde_json::from_str::<ControlReq>(&content) {
                        if req.action == "kick" && mode == "server" {
                            if let Some(client) = registry.read().get(&req.client_id) {
                                client.force_disconnect.store(true, Ordering::Relaxed);
                                info!("[WebUI] Force kicked client: {}", req.client_id);
                            }
                        }
                    }
                    let response = Response::from_string(r#"{"status":"ok"}"#).with_header(
                        Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
                    );
                    let _ = request.respond(response);
                }
                _ => {
                    let _ =
                        request.respond(Response::from_string("Not Found").with_status_code(404));
                }
            }
        }
    });
}
