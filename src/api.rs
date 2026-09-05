use base64ct::{Base64, Encoding};
use parking_lot::Mutex;
use serde_json::json;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Instant;
use tiny_http::{Header, Method, Response, Server as HttpServer};
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// ======================= 握手协议结构（与 Go frame.go 契约一致） =======================
//
// 黄金向量锁定的字段名集合：
//   req : client_id, psk, mac, ipv4, ipv6, padding, brutal_tx, brutal_rx,
//         fec, fec_group, encrypt, enc_algo
//   resp: success, message, session_id, client_id, ipv4, ipv6, gw_v4, gw_v6,
//         padding, brutal_tx, brutal_rx, fec, fec_group, encrypt, enc_algo,
//         enc_salt, enc_salt2
// 除 client_id/psk（req）与 success/message/client_id/ipv4/ipv6（resp）外
// 全部对齐 Go 的 omitempty：零值不出现在线路上。

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct HandshakeReq {
    pub client_id: String,
    pub psk: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub mac: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv4: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_tx: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_rx: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fec: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub fec_group: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub enc_algo: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone, Default)]
pub struct HandshakeResp {
    pub success: bool,
    pub message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gw_v4: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub gw_v6: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub padding: String,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_tx: u64,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub brutal_rx: u64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub fec: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub fec_group: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub encrypt: bool,
    #[serde(default, skip_serializing_if = "is_zero_i64")]
    pub enc_algo: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enc_salt: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub enc_salt2: String,
}

pub fn is_zero_u64(v: &u64) -> bool {
    *v == 0
}
pub fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
pub fn is_false(v: &bool) -> bool {
    !*v
}

// ======================= 运行时统计（面板/指标用） =======================

#[derive(Debug)]
pub struct ClientStat {
    pub client_id: String,
    pub ipv4: String,
    pub ipv6: String,
    pub mac: String,
    pub active_conns: std::sync::atomic::AtomicU32,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
    pub force_disconnect: std::sync::atomic::AtomicBool,
    pub disconnect_version: AtomicU64,
    pub fec_mode: Mutex<String>,
    pub enc_algo: std::sync::atomic::AtomicI64,
    pub created_at: Instant,
}

impl ClientStat {
    pub fn new(id: String, ipv4: String, ipv6: String, mac: String) -> Self {
        Self {
            client_id: id,
            ipv4,
            ipv6,
            mac,
            active_conns: std::sync::atomic::AtomicU32::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            force_disconnect: std::sync::atomic::AtomicBool::new(false),
            disconnect_version: AtomicU64::new(0),
            fec_mode: Mutex::new("off".into()),
            enc_algo: std::sync::atomic::AtomicI64::new(0),
            created_at: Instant::now(),
        }
    }
}

pub type StatRegistry =
    Arc<parking_lot::RwLock<std::collections::HashMap<String, Arc<ClientStat>>>>;

/// 封禁表：clientID → 封禁到期 unix 毫秒（0=永久），对齐 Go Server.banned
pub struct BanList {
    inner: Mutex<std::collections::HashMap<String, i64>>,
}

impl BanList {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(std::collections::HashMap::new()),
        }
    }

    pub fn ban(&self, client_id: &str, ttl_minutes: i64) -> bool {
        if client_id.is_empty() {
            return false;
        }
        let exp = if ttl_minutes <= 0 {
            0
        } else {
            now_unix_ms() + ttl_minutes * 60 * 1000
        };
        self.inner.lock().insert(client_id.to_string(), exp);
        true
    }

    pub fn unban(&self, client_id: &str) {
        self.inner.lock().remove(client_id);
    }

    pub fn is_banned(&self, client_id: &str) -> bool {
        if client_id.is_empty() {
            return false;
        }
        let mut map = self.inner.lock();
        match map.get(client_id) {
            None => false,
            Some(&exp) => {
                if exp > 0 && now_unix_ms() >= exp {
                    map.remove(client_id);
                    false
                } else {
                    true
                }
            }
        }
    }

    /// 返回 clientID → 剩余秒（0=永久），自动清理过期项
    pub fn snapshot(&self) -> std::collections::HashMap<String, i64> {
        let mut map = self.inner.lock();
        let now = now_unix_ms();
        map.retain(|_, exp| *exp == 0 || *exp > now);
        map.iter()
            .map(|(k, exp)| (k.clone(), if *exp == 0 { 0 } else { (*exp - now) / 1000 }))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

impl Default for BanList {
    fn default() -> Self {
        Self::new()
    }
}

pub fn now_unix_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ======================= 日志环形缓冲 + 运行时级别 =======================

pub struct LogLine {
    pub seq: u64,
    pub level: String,
    pub time: String,
    pub msg: String,
}

lazy_static::lazy_static! {
    static ref LOG_RING: Mutex<LogRing> = Mutex::new(LogRing::new(500));
    pub static ref LOG_LEVEL_HANDLE: std::sync::OnceLock<tracing_subscriber::reload::Handle<EnvFilter, tracing_subscriber::Registry>> = std::sync::OnceLock::new();
    static ref LOG_LEVEL_NAME: Mutex<String> = Mutex::new("info".into());
}

struct LogRing {
    seq: u64,
    lines: Vec<LogLine>,
    cap: usize,
}

impl LogRing {
    fn new(cap: usize) -> Self {
        Self {
            seq: 0,
            lines: Vec::new(),
            cap,
        }
    }
    fn add(&mut self, level: &str, msg: &str) {
        self.seq += 1;
        self.lines.push(LogLine {
            seq: self.seq,
            level: level.to_string(),
            time: wall_clock_hms(),
            msg: msg.to_string(),
        });
        if self.lines.len() > self.cap {
            let drop = self.lines.len() - self.cap;
            self.lines.drain(..drop);
        }
    }
    fn snapshot(&self, after: u64) -> Vec<&LogLine> {
        self.lines.iter().filter(|l| l.seq > after).collect()
    }
}

// 当地时间不可用时以 UTC 呈现（仅面板展示用途）
fn wall_clock_hms() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86400;
    let ms = now.subsec_millis();
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        ms
    )
}

struct LogRingLayer;

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for LogRingLayer {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);
        let level = match *event.metadata().level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };
        LOG_RING.lock().add(level, &visitor.0);
    }
}

struct MessageVisitor(String);

impl tracing::field::Visit for MessageVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value);
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        }
    }
}

/// 初始化日志系统：终端输出 + 环形缓冲 + 可热更级别
pub fn init_logging(level: &str) {
    let filter = EnvFilter::new(level);
    let (filter, handle) = tracing_subscriber::reload::Layer::new(filter);
    let _ = LOG_LEVEL_HANDLE.set(handle);
    *LOG_LEVEL_NAME.lock() = level.to_lowercase();

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(LogRingLayer)
        .init();
}

pub fn current_log_level_name() -> String {
    LOG_LEVEL_NAME.lock().clone()
}

pub fn set_runtime_log_level(level: &str) -> Result<(), String> {
    let level = level.trim();
    if matches!(
        level.to_lowercase().as_str(),
        "trace" | "debug" | "info" | "warn" | "error"
    ) {
        if let Some(h) = LOG_LEVEL_HANDLE.get() {
            h.modify(|f| *f = EnvFilter::new(level))
                .map_err(|e| e.to_string())?;
        }
        *LOG_LEVEL_NAME.lock() = level.to_lowercase();
        Ok(())
    } else {
        Err(format!("invalid log level {:?}", level))
    }
}

pub fn log_ring_snapshot(after: u64) -> Vec<serde_json::Value> {
    let ring = LOG_RING.lock();
    ring.snapshot(after)
        .into_iter()
        .map(|l| {
            json!({
                "seq": l.seq,
                "level": l.level,
                "time": l.time,
                "msg": l.msg,
            })
        })
        .collect()
}

// ======================= 进程级指标辅助 =======================

pub fn thread_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("Threads:") {
                    return rest.trim().parse().unwrap_or(0);
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// 进程 RSS（MB）。heap_alloc_mb 以 RSS 近似呈现（Rust 无 Go 式堆统计）。
pub fn rss_mb() -> f64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = std::fs::read_to_string("/proc/self/statm") {
            if let Some(pages) = s.split_whitespace().nth(1) {
                if let Ok(pages) = pages.parse::<u64>() {
                    return pages as f64 * 4096.0 / 1024.0 / 1024.0;
                }
            }
        }
        0.0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0.0
    }
}

// ======================= 面板（与 Go dashboardHTML 逐字一致） =======================

const DASHBOARD_HTML: &str = r##"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>tlsvpn Dashboard</title>
<style>
body { font-family:'Segoe UI',Tahoma,sans-serif; background:#121212; color:#e0e0e0; margin:0; padding:20px; }
.wrap { max-width:1200px; margin:0 auto; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(230px,1fr)); gap:14px; }
.card { background:#1e1e1e; border-radius:8px; padding:14px 18px; box-shadow:0 4px 6px rgba(0,0,0,.3); margin-bottom:14px; }
.card.wide { grid-column:1/-1; }
h1 { color:#bb86fc; margin:0 0 12px; font-size:1.35em; }
h1 small { color:#888; font-weight:normal; font-size:.55em; margin-left:8px; }
h2 { margin:0 0 10px; color:#bb86fc; font-size:1.02em; }
.kpi { font-size:1.5em; font-weight:bold; color:#03dac6; }
.sub { color:#999; font-size:.84em; margin-top:3px; }
table { width:100%; border-collapse:collapse; margin-top:8px; }
th,td { padding:7px 9px; text-align:left; border-bottom:1px solid #333; font-size:.88em; white-space:nowrap; }
th { background:#2c2c2c; color:#bbb; }
.speed { color:#03dac6; font-weight:bold; }
.badge { display:inline-block; padding:2px 8px; border-radius:10px; font-size:.78em; font-weight:600; }
.b-on { background:#1b3a2f; color:#4ee1a0; } .b-dup { background:#3a341b; color:#e1c94e; } .b-off { background:#333; color:#888; }
.btn { padding:3px 10px; background:#cf6679; color:white; border:none; border-radius:4px; cursor:pointer; font-size:.82em; margin-right:4px; }
.btn:hover { background:#ff7597; }
.btn.blue { background:#3d5a80; } .btn.blue:hover { background:#5b84b1; }
.btn.gray { background:#444; } .btn.gray:hover { background:#666; }
#chart { width:100%; height:170px; display:block; }
.legend { font-size:.8em; color:#999; margin-top:6px; }
.legend span { margin-right:14px; }
.dot { display:inline-block; width:9px; height:9px; border-radius:50%; margin-right:4px; }
#logbox { background:#0d0d0d; border-radius:6px; padding:10px; height:220px; overflow-y:auto; font:12px/1.5 Consolas,monospace; }
#logbox .lv-WARN { color:#e1c94e; } #logbox .lv-ERROR,#logbox .lv-PANIC { color:#ff7597; } #logbox .lv-DEBUG { color:#666; }
.logbar { display:flex; gap:8px; align-items:center; margin-top:8px; flex-wrap:wrap; }
.logbar select,.logbar input { background:#2a2a2a; color:#ddd; border:1px solid #444; border-radius:4px; padding:4px 8px; font-size:.85em; }
.logbar input { width:110px; }
.tabs { display:flex; gap:6px; margin-bottom:10px; flex-wrap:wrap; }
.tabs button { background:#2a2a2a; color:#bbb; border:none; border-radius:4px 4px 0 0; padding:6px 14px; cursor:pointer; font-size:.88em; }
.tabs button.on { background:#bb86fc; color:#121212; font-weight:600; }
.pane { display:none; } .pane.on { display:block; }
footer { text-align:center; color:#666; font-size:.78em; margin-top:16px; }
@media (max-width:640px){ th,td{padding:5px;} .hide-sm{display:none;} }
</style>
</head>
<body>
<div class="wrap">
<h1>🚀 tlsvpn <span id="mode">…</span><small id="meta"></small></h1>
<div class="grid">
  <div class="card"><div class="sub">活跃客户端/设备</div><div class="kpi" id="active-clients">0</div><div class="sub" id="conns-sub">TCP 连接: -</div></div>
  <div class="card"><div class="sub">总发送</div><div class="kpi" id="total-tx">0 B</div><div class="sub">↑ <span id="total-tx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">总接收</div><div class="kpi" id="total-rx">0 B</div><div class="sub">↓ <span id="total-rx-speed" class="speed">0 B/s</span></div></div>
  <div class="card"><div class="sub">运行时长</div><div class="kpi" id="uptime">-</div><div class="sub">版本 <span id="ver">-</span> · GC <a href="#" onclick="doAction('gc');return false;" style="color:#5b84b1">立即回收</a></div></div>
  <div class="card"><div class="sub">FEC 恢复 / 确认丢失</div><div class="kpi" id="fec-kpi">-</div><div class="sub">校验帧 <span id="parity">-</span> · 丢帧(队列) <span id="dropped">-</span></div></div>
  <div class="card"><div class="sub">内存 / 协程</div><div class="kpi" id="mem">-</div><div class="sub">Goroutines: <span id="goroutines">-</span></div></div>
  <div class="card" id="ippool-card" style="display:none"><div class="sub">IPv4 地址池</div><div class="kpi" id="ippool-kpi">-</div><div class="sub">IPv6 已分配: <span id="v6used">-</span></div></div>
</div>
<div class="card wide"><h2>吞吐趋势 <span style="font-size:.7em;color:#888">(近 120 秒)</span></h2>
  <canvas id="chart" width="1160" height="170"></canvas>
  <div class="legend"><span><i class="dot" style="background:#03dac6"></i>上行</span><span><i class="dot" style="background:#bb86fc"></i>下行</span></div></div>

<div class="card wide">
  <div class="tabs">
    <button class="on" data-pane="clients" onclick="showPane(this)">客户端</button>
    <button data-pane="conns" onclick="showPane(this)">连接明细</button>
    <button data-pane="macs" id="macs-tab" onclick="showPane(this)">MAC 表</button>
    <button data-pane="bans" id="bans-tab" onclick="showPane(this)">封禁</button>
    <button data-pane="logs" onclick="showPane(this)">日志</button>
  </div>

  <div class="pane on" id="pane-clients">
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ID</th><th>IPv4</th><th class="hide-sm">IPv6</th><th class="hide-sm">MAC</th><th>TCP</th><th>TX (发)</th><th>RX (收)</th><th>↑ 速率</th><th>↓ 速率</th><th class="hide-sm">FEC</th><th class="hide-sm">加密</th><th>操作</th></tr></thead>
      <tbody id="clients-body"></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-conns"><div style="overflow-x:auto"><table>
    <thead><tr><th>#</th><th>目标</th><th>对端</th><th>状态</th><th>RTT</th><th>TX</th><th>RX</th><th class="hide-sm">重试</th><th class="hide-sm">在线</th><th class="hide-sm">最近错误</th><th>操作</th></tr></thead>
    <tbody id="conns-body"><tr><td colspan="11" style="color:#777">仅客户端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-macs"><div style="overflow-x:auto"><table>
    <thead><tr><th>MAC</th><th>端口</th><th>最近活跃</th></tr></thead>
    <tbody id="macs-body"><tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr></tbody>
  </table></div></div>

  <div class="pane" id="pane-bans">
    <div class="logbar"><input id="ban-id" placeholder="ClientID（可短前缀）"><input id="ban-min" placeholder="分钟（留空=永久）" style="width:150px">
    <button class="btn blue" onclick="addBan()">封禁</button><button class="btn gray" onclick="loadBans()">刷新</button></div>
    <div style="overflow-x:auto"><table>
      <thead><tr><th>ClientID</th><th>剩余</th><th>操作</th></tr></thead>
      <tbody id="bans-body"><tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr></tbody>
    </table></div>
  </div>

  <div class="pane" id="pane-logs">
    <div id="logbox"></div>
    <div class="logbar">
      <label style="font-size:.85em;color:#999">级别
        <select id="loglevel" onchange="setLogLevel(this.value)">
          <option value="debug">debug</option><option value="info">info</option>
          <option value="warn">warn</option><option value="error">error</option>
        </select>
      </label>
      <label style="font-size:.85em;color:#999"><input type="checkbox" id="autoscroll" checked> 自动滚动</label>
      <button class="btn gray" onclick="logSeq=0;document.getElementById('logbox').innerHTML=''">清屏</button>
    </div>
  </div>
</div>
<footer>tlsvpn dashboard · 数据每 2 秒刷新 · <span id="tls-flag"></span></footer>
</div>
<script>
const MAXPTS=60;let prev={},lastT=0;const txHist=[],rxHist=[];
let logSeq=0,logTimer=null;

function fmtBytes(b,s=false){
  if(!isFinite(b)||b<=0)return '0 '+(s?'B/s':'B');
  const u=['B','KB','MB','GB','TB'],i=Math.min(Math.floor(Math.log(b)/Math.log(1024)),4);
  return parseFloat((b/Math.pow(1024,i)).toFixed(2))+' '+u[i]+(s?'/s':'');
}
function fmtDur(s){s=Math.floor(s);const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  if(d>0)return d+'天'+h+'时';if(h>0)return h+'时'+m+'分';if(m>0)return m+'分'+(s%60)+'秒';return s+'秒';}
function badge(f){if(!f||f==='off')return '<span class="badge b-off">关闭</span>';
  if(f==='dup')return '<span class="badge b-dup">复制</span>';return '<span class="badge b-on">'+f+'</span>';}
function encBadge(a){if(a===2)return '<span class="badge b-on">GCM</span>';
  if(a===1)return '<span class="badge b-dup">CTR</span>';return '<span class="badge b-off">明文</span>';}
function showPane(btn){document.querySelectorAll('.tabs button').forEach(b=>b.classList.remove('on'));
  document.querySelectorAll('.pane').forEach(p=>p.classList.remove('on'));
  btn.classList.add('on');document.getElementById('pane-'+btn.dataset.pane).classList.add('on');
  if(btn.dataset.pane==='logs')startLogPoll();else stopLogPoll();}

function drawChart(){
  const c=document.getElementById('chart'),ctx=c.getContext('2d'),W=c.width,H=c.height;
  ctx.clearRect(0,0,W,H);ctx.strokeStyle='#2a2a2a';
  for(let i=1;i<4;i++){ctx.beginPath();ctx.moveTo(0,H*i/4);ctx.lineTo(W,H*i/4);ctx.stroke();}
  if(txHist.length<2)return;
  const max=Math.max(...txHist,...rxHist,1);
  const plot=(h,col)=>{ctx.strokeStyle=col;ctx.lineWidth=2;ctx.beginPath();
    h.forEach((v,i)=>{const x=i/(MAXPTS-1)*W,y=H-6-(v/max)*(H-20);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();};
  plot(txHist,'#03dac6');plot(rxHist,'#bb86fc');
  ctx.fillStyle='#888';ctx.font='11px sans-serif';ctx.fillText(fmtBytes(max),4,12);
}

async function api(path,opts){opts=opts||{};opts.headers=Object.assign({'X-Requested-With':'tlsvpn'},opts.headers||{});return fetch(path,opts);}

async function fetchStats(){
  try{
    const res=await fetch('/api/stats');
    if(res.status===401){document.body.innerHTML='<div class="card"><h2>401</h2><p>需要认证：请用 <code>-web-auth user:pass</code> 配置的凭据登录。</p></div>';return;}
    const data=await res.json();
    const now=performance.now();const dt=lastT?(now-lastT)/1000:2;lastT=now;

    document.getElementById('mode').innerText=data.mode.toUpperCase();
    document.getElementById('ver').innerText=data.version||'-';
    document.getElementById('uptime').innerText=fmtDur(data.uptime_sec||0);
    document.getElementById('loglevel').value=data.log_level||'info';
    document.getElementById('tls-flag').innerText=location.protocol==='https:'?'HTTPS':'HTTP（建议 -web-cert 启用 HTTPS）';

    let tbody='',tTx=0,tRx=0,tTxS=0,tRxS=0,cur={},tConns=0;
    const proc=(id,c)=>{
      tTx+=c.tx_bytes;tRx+=c.rx_bytes;tConns+=c.active_conns||0;
      let sx=0,sr=0;
      if(prev[id]){sx=Math.max(0,(c.tx_bytes-prev[id].tx_bytes)/dt);sr=Math.max(0,(c.rx_bytes-prev[id].rx_bytes)/dt);}
      cur[id]={tx_bytes:c.tx_bytes,rx_bytes:c.rx_bytes};tTxS+=sx;tRxS+=sr;
      const sid=id.length>10?id.slice(0,10)+'…':id;
      tbody+='<tr><td title="'+id+'">'+sid+'</td><td>'+(c.ipv4||'-')+'</td><td class="hide-sm">'+(c.ipv6||'-')+'</td>'+
        '<td class="hide-sm">'+(c.mac||'-')+'</td><td>'+c.active_conns+'</td>'+
        '<td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
        '<td class="speed">'+fmtBytes(sx,true)+'</td><td class="speed">'+fmtBytes(sr,true)+'</td>'+
        '<td class="hide-sm">'+badge(c.fec)+'</td><td class="hide-sm">'+encBadge(c.enc_algo)+'</td>'+
        '<td>'+(data.mode==='server'?'<button class="btn" onclick="kickClient(\''+id+'\')">踢出</button>'+
          '<button class="btn blue" onclick="banClient(\''+id+'\',0)">封禁</button>':'-')+'</td></tr>';
    };
    if(data.mode==='server'){for(const [id,c] of Object.entries(data.clients||{}))proc(id,c);}
    else if(data.clients&&data.clients.local)proc('local',data.clients.local);
    prev=cur;txHist.push(tTxS);rxHist.push(tRxS);
    if(txHist.length>MAXPTS){txHist.shift();rxHist.shift();}
    drawChart();

    document.getElementById('active-clients').innerText=data.active_clients;
    document.getElementById('conns-sub').innerText='TCP 连接: '+tConns+(data.mode==='client'?' / '+((data.conns||[]).length):'');
    document.getElementById('total-tx').innerText=fmtBytes(tTx);
    document.getElementById('total-rx').innerText=fmtBytes(tRx);
    document.getElementById('total-tx-speed').innerText=fmtBytes(tTxS,true);
    document.getElementById('total-rx-speed').innerText=fmtBytes(tRxS,true);
    document.getElementById('clients-body').innerHTML=tbody||'<tr><td colspan="12" style="color:#777">暂无客户端</td></tr>';

    const f=data.fec||{};
    document.getElementById('fec-kpi').innerHTML=(f.recovered||0)+' <small style="font-size:.6em;color:#888">/</small> '+(f.lost||0);
    document.getElementById('parity').innerText=f.parity_tx||0;
    document.getElementById('dropped').innerText=data.dropped_frames||0;
    const m=data.mem||{};
    document.getElementById('mem').innerHTML=(m.heap_alloc_mb||0).toFixed(1)+'<small style="font-size:.55em;color:#888"> MB</small>';
    document.getElementById('goroutines').innerText=m.num_goroutine||0;

    if(data.ip_pool){document.getElementById('ippool-card').style.display='';
      document.getElementById('ippool-kpi').innerHTML=data.ip_pool.v4_used+'<small style="font-size:.55em;color:#888"> / '+data.ip_pool.v4_total+'</small>';
      document.getElementById('v6used').innerText=data.ip_pool.v6_used;}

    const meta=[];if(data.enc_algo===2)meta.push('GCM 加密');else if(data.enc_algo===1)meta.push('CTR 加密(旧)');
    if(data.fec_mode&&data.fec_mode!=='off')meta.push('FEC '+data.fec_mode);
    document.getElementById('meta').innerText=meta.join(' · ');

    renderConns(data);renderMacs(data);renderBans(data);
  }catch(e){console.error('获取统计数据失败',e);}
}

function renderConns(data){
  const list=data.conns||[];
  if(data.mode!=='client'){document.getElementById('conns-body').innerHTML='<tr><td colspan="11" style="color:#777">仅客户端模式提供</td></tr>';return;}
  document.getElementById('conns-body').innerHTML=list.map(c=>'<tr><td>'+c.index+'</td><td>'+c.target+'</td><td>'+(c.remote||'-')+'</td>'+
    '<td>'+(c.state==='up'?'<span class="badge b-on">up</span>':c.state==='connecting'?'<span class="badge b-dup">connecting</span>':'<span class="badge b-off">'+c.state+'</span>')+'</td>'+
    '<td>'+(c.rtt_ms>=100000?'-':c.rtt_ms+' ms')+'</td><td>'+fmtBytes(c.tx_bytes)+'</td><td>'+fmtBytes(c.rx_bytes)+'</td>'+
    '<td class="hide-sm">'+c.retries+'</td><td class="hide-sm">'+(c.age_sec?fmtDur(c.age_sec):'-')+'</td>'+
    '<td class="hide-sm" style="color:#c66" title="'+(c.last_error||'')+'">'+((c.last_error||'').slice(0,40))+'</td>'+
    '<td><button class="btn gray" onclick="doAction(\'reconnect\')">重连</button></td></tr>').join('')||
    '<tr><td colspan="11" style="color:#777">无连接</td></tr>';
}
function renderMacs(data){
  const t=document.getElementById('macs-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr>';return;}
  const list=data.mac_table||[];
  t.innerHTML=list.map(e=>'<tr><td>'+e.mac+'</td><td>'+e.port+'</td><td>'+e.age_sec+' 秒前</td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">尚未学习到 MAC</td></tr>';
}
function renderBans(data){
  const t=document.getElementById('bans-body');
  if(data.mode!=='server'){t.innerHTML='<tr><td colspan="3" style="color:#777">仅服务端模式提供</td></tr>';return;}
  const bans=data.banned||{};
  t.innerHTML=Object.entries(bans).map(([id,left])=>'<tr><td title="'+id+'">'+(id.length>18?id.slice(0,18)+'…':id)+'</td>'+
    '<td>'+(left===0?'<span class="badge b-dup">永久</span>':fmtDur(left))+'</td>'+
    '<td><button class="btn gray" onclick="unban(\''+id+'\')">解封</button></td></tr>').join('')||
    '<tr><td colspan="3" style="color:#777">无封禁记录</td></tr>';
}

async function kickClient(id){if(!confirm('确定要强制断开该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'kick',client_id:id})});fetchStats();}
async function banClient(id,minutes){if(!confirm('确定封禁该客户端吗？'))return;await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:minutes})});fetchStats();}
async function addBan(){const id=document.getElementById('ban-id').value.trim();if(!id)return alert('请输入 ClientID');
  const m=parseInt(document.getElementById('ban-min').value,10);await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'ban',client_id:id,ttl_minutes:isNaN(m)?0:m})});
  document.getElementById('ban-id').value='';document.getElementById('ban-min').value='';fetchStats();}
async function unban(id){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'unban',client_id:id})});fetchStats();}
async function doAction(action,extra){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({action:action},extra||{}))});fetchStats();}
async function setLogLevel(v){await api('/api/control',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'loglevel',level:v})});}

function startLogPoll(){
  stopLogPoll();pollLogs();logTimer=setInterval(pollLogs,2000);
}
function stopLogPoll(){if(logTimer){clearInterval(logTimer);logTimer=null;}}
async function pollLogs(){
  try{
    const res=await fetch('/api/logs?after='+logSeq);
    if(!res.ok)return;
    const lines=await res.json();
    if(!lines.length)return;
    const box=document.getElementById('logbox');
    box.innerHTML+=lines.map(l=>'<div class="lv-'+l.level+'">['+l.time+'] '+l.level+' '+l.msg.replace(/</g,'&lt;')+'</div>').join('');
    logSeq=lines[lines.length-1].seq;
    if(document.getElementById('autoscroll').checked)box.scrollTop=box.scrollHeight;
  }catch(e){}
}

setInterval(fetchStats,2000);fetchStats();
</script>
</body>
</html>"##;

// ======================= Web 服务（Basic Auth + CSRF + API） =======================

pub const APP_VERSION: &str = "1.1.0-rs";

/// 模式相关的统计/控制由 server/client 各自实现
pub trait WebStatsProvider: Send + Sync {
    fn stats_json(&self) -> serde_json::Value;
    /// Prometheus 文本格式指标
    fn metrics_text(&self) -> String;
    /// 执行管理动作；返回 Err 时以 400 回应
    fn control(
        &self,
        action: &str,
        client_id: &str,
        level: &str,
        ttl_minutes: i64,
    ) -> Result<(), String>;
}

fn http_header(name: &str, value: &str) -> Header {
    Header::from_bytes(name.as_bytes(), value.as_bytes()).unwrap()
}

fn respond_json(req: tiny_http::Request, body: String, status: u16) {
    let resp = Response::from_string(body)
        .with_status_code(status)
        .with_header(http_header("Content-Type", "application/json"));
    let _ = req.respond(resp);
}

/// 常量时间比较，避免时序侧信道
fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn check_basic_auth(auth_spec: &str, req: &tiny_http::Request) -> bool {
    if auth_spec.is_empty() {
        return true;
    }
    let header = req
        .headers()
        .iter()
        .find(|h| h.field.equiv("Authorization"))
        .map(|h| h.value.as_str().to_string())
        .unwrap_or_default();
    let Some(encoded) = header.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = Base64::decode_vec(encoded.trim()) else {
        return false;
    };
    let Ok(cred) = String::from_utf8(decoded) else {
        return false;
    };
    ct_eq(&cred, auth_spec)
}

pub fn start_web_server(addr: String, auth: String, provider: Arc<dyn WebStatsProvider>) {
    std::thread::spawn(move || {
        let server = match HttpServer::http(&addr) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Web Server bind failed: {}", e);
                return;
            }
        };
        info!("🚀 Web Dashboard started at http://{}", addr);
        for mut request in server.incoming_requests() {
            let url = request.url().split('?').next().unwrap_or("").to_string();

            // 仪表盘页面与 API 一致地受认证保护
            if !check_basic_auth(&auth, &request) {
                let resp = Response::from_string("Unauthorized")
                    .with_status_code(401)
                    .with_header(http_header(
                        "WWW-Authenticate",
                        r#"Basic realm="tlsvpn dashboard""#,
                    ));
                let _ = request.respond(resp);
                continue;
            }

            match (request.method(), url.as_str()) {
                (&Method::Get, "/") => {
                    let response = Response::from_string(DASHBOARD_HTML)
                        .with_header(http_header("Content-Type", "text/html; charset=utf-8"));
                    let _ = request.respond(response);
                }
                (&Method::Get, "/api/stats") => {
                    respond_json(request, provider.stats_json().to_string(), 200);
                }
                (&Method::Get, "/api/logs") => {
                    let after: u64 = request
                        .url()
                        .split_once('?')
                        .and_then(|(_, q)| {
                            q.split('&')
                                .find_map(|kv| kv.strip_prefix("after=")?.parse().ok())
                        })
                        .unwrap_or(0);
                    respond_json(request, json!(log_ring_snapshot(after)).to_string(), 200);
                }
                (&Method::Get, "/metrics") => {
                    let resp = Response::from_string(provider.metrics_text())
                        .with_header(http_header("Content-Type", "text/plain; version=0.0.4"));
                    let _ = request.respond(resp);
                }
                (&Method::Post, "/api/control") => {
                    // 管理动作统一走 CSRF 头防护（对齐 Go csrfGuard）
                    let has_csrf = request
                        .headers()
                        .iter()
                        .any(|h| h.field.equiv("X-Requested-With") && h.value.as_str() == "tlsvpn");
                    if !has_csrf {
                        let _ = request.respond(
                            Response::from_string(
                                "Missing X-Requested-With header (CSRF protection)",
                            )
                            .with_status_code(403),
                        );
                        continue;
                    }
                    let mut content = String::new();
                    if std::io::Read::read_to_string(request.as_reader(), &mut content).is_err() {
                        respond_json(request, json!({"error": "invalid body"}).to_string(), 400);
                        continue;
                    }
                    #[derive(serde::Deserialize)]
                    struct ControlReq {
                        action: String,
                        #[serde(default)]
                        client_id: String,
                        #[serde(default)]
                        level: String,
                        #[serde(default)]
                        ttl_minutes: i64,
                    }
                    let Ok(creq) = serde_json::from_str::<ControlReq>(&content) else {
                        respond_json(request, json!({"error": "bad json"}).to_string(), 400);
                        continue;
                    };
                    match provider.control(
                        &creq.action,
                        &creq.client_id,
                        &creq.level,
                        creq.ttl_minutes,
                    ) {
                        Ok(()) => respond_json(request, r#"{"status": "ok"}"#.to_string(), 200),
                        Err(e) => respond_json(request, json!({"error": e}).to_string(), 400),
                    }
                }
                _ => {
                    let _ =
                        request.respond(Response::from_string("Not Found").with_status_code(404));
                }
            }
        }
    });
}
