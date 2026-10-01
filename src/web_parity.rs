use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

const EVENT_CAP: usize = 500;
const TREND_RECENT_CAP: usize = 120;
const TREND_MINUTE_CAP: usize = 1440;
const DEFAULT_TRAFFIC_DAYS: usize = 30;
const MAX_TRAFFIC_DAYS: usize = 3650;
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const TRAFFIC_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Debug, Clone)]
struct WebSession {
    expires: Instant,
    auth_hash: [u8; 32],
}

#[derive(Debug, Default)]
struct SessionStore {
    sessions: Mutex<HashMap<String, WebSession>>,
}

fn auth_hash(auth: &str) -> [u8; 32] {
    Sha256::digest(auth.as_bytes()).into()
}

impl SessionStore {
    fn create(&self, auth: &str) -> Result<String, String> {
        let mut raw = [0u8; 32];
        getrandom::getrandom(&mut raw).map_err(|e| format!("session random: {e}"))?;
        let token = hex::encode(raw);
        let now = Instant::now();
        let mut sessions = self.sessions.lock();
        sessions.retain(|_, s| s.expires > now);
        sessions.insert(
            token.clone(),
            WebSession {
                expires: now + SESSION_TTL,
                auth_hash: auth_hash(auth),
            },
        );
        Ok(token)
    }

    fn valid(&self, token: &str, auth: &str) -> bool {
        if token.is_empty() || auth.is_empty() {
            return false;
        }
        let now = Instant::now();
        let wanted = auth_hash(auth);
        let mut sessions = self.sessions.lock();
        let Some(session) = sessions.get_mut(token) else {
            return false;
        };
        if session.expires <= now || !constant_time_32(&session.auth_hash, &wanted) {
            sessions.remove(token);
            return false;
        }
        session.expires = now + SESSION_TTL;
        true
    }

    fn revoke(&self, token: &str) {
        if !token.is_empty() {
            self.sessions.lock().remove(token);
        }
    }
}

fn constant_time_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize)]
pub struct DashboardEvent {
    pub seq: u64,
    pub time: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub level: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client: String,
    pub msg: String,
}

#[derive(Debug, Default)]
struct EventInner {
    seq: u64,
    ring: VecDeque<DashboardEvent>,
    subscribers: Vec<Sender<DashboardEvent>>,
}

#[derive(Debug, Default)]
pub struct EventHub {
    inner: Mutex<EventInner>,
}

impl EventHub {
    pub fn emit(&self, kind: &str, level: &str, client: &str, msg: &str) {
        let mut inner = self.inner.lock();
        inner.seq += 1;
        let event = DashboardEvent {
            seq: inner.seq,
            time: wall_clock_hms(),
            kind: kind.to_string(),
            level: level.to_string(),
            client: client.to_string(),
            msg: msg.to_string(),
        };
        inner.ring.push_back(event.clone());
        while inner.ring.len() > EVENT_CAP {
            inner.ring.pop_front();
        }
        inner
            .subscribers
            .retain(|tx| match tx.try_send(event.clone()) {
                Ok(()) | Err(TrySendError::Full(_)) => true,
                Err(TrySendError::Disconnected(_)) => false,
            });
    }

    pub fn snapshot(&self, after: u64) -> Vec<DashboardEvent> {
        self.inner
            .lock()
            .ring
            .iter()
            .filter(|e| e.seq > after)
            .cloned()
            .collect()
    }

    pub fn stream(&self, after: u64) -> EventStream {
        let (tx, rx) = bounded(256);
        let mut inner = self.inner.lock();
        let backlog = inner
            .ring
            .iter()
            .filter(|e| e.seq > after)
            .cloned()
            .collect();
        inner.subscribers.push(tx);
        EventStream {
            backlog,
            rx,
            pending: Vec::new(),
            offset: 0,
        }
    }
}

pub struct EventStream {
    backlog: VecDeque<DashboardEvent>,
    rx: Receiver<DashboardEvent>,
    pending: Vec<u8>,
    offset: usize,
}

impl EventStream {
    fn refill(&mut self) -> io::Result<()> {
        self.pending.clear();
        self.offset = 0;
        let next = if let Some(e) = self.backlog.pop_front() {
            Some(e)
        } else {
            match self.rx.recv_timeout(Duration::from_secs(25)) {
                Ok(e) => Some(e),
                Err(crossbeam_channel::RecvTimeoutError::Timeout) => {
                    self.pending.extend_from_slice(b": ping\n\n");
                    None
                }
                Err(crossbeam_channel::RecvTimeoutError::Disconnected) => return Ok(()),
            }
        };
        if let Some(e) = next {
            let data = serde_json::to_vec(&e).map_err(io::Error::other)?;
            self.pending.extend_from_slice(b"data: ");
            self.pending.extend_from_slice(&data);
            self.pending.extend_from_slice(b"\n\n");
        }
        Ok(())
    }
}

impl Read for EventStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.offset >= self.pending.len() {
            self.refill()?;
            if self.pending.is_empty() {
                return Ok(0);
            }
        }
        let n = (self.pending.len() - self.offset).min(buf.len());
        buf[..n].copy_from_slice(&self.pending[self.offset..self.offset + n]);
        self.offset += n;
        Ok(n)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TrendPoint {
    #[serde(rename = "t")]
    pub unix: i64,
    #[serde(rename = "up")]
    pub up_bps: f64,
    #[serde(rename = "down")]
    pub down_bps: f64,
}

#[derive(Debug, Default)]
struct TrendState {
    last_at: Option<Instant>,
    last_up: u64,
    last_down: u64,
    minute_at: Option<Instant>,
    minute_up: u64,
    minute_down: u64,
    recent: VecDeque<TrendPoint>,
    minutes: VecDeque<TrendPoint>,
}

impl TrendState {
    fn observe(&mut self, up: u64, down: u64) {
        let now = Instant::now();
        let Some(last_at) = self.last_at else {
            self.last_at = Some(now);
            self.last_up = up;
            self.last_down = down;
            self.minute_at = Some(now);
            self.minute_up = up;
            self.minute_down = down;
            return;
        };
        let elapsed = now.duration_since(last_at).as_secs_f64();
        if elapsed < 0.5 {
            return;
        }
        let up_delta = up.saturating_sub(self.last_up);
        let down_delta = down.saturating_sub(self.last_down);
        self.last_at = Some(now);
        self.last_up = up;
        self.last_down = down;
        self.recent.push_back(TrendPoint {
            unix: unix_seconds(),
            up_bps: up_delta as f64 / elapsed,
            down_bps: down_delta as f64 / elapsed,
        });
        while self.recent.len() > TREND_RECENT_CAP {
            self.recent.pop_front();
        }

        let minute_at = self.minute_at.unwrap_or(now);
        let minute_elapsed = now.duration_since(minute_at).as_secs_f64();
        if minute_elapsed >= 60.0 {
            let minute_up = up.saturating_sub(self.minute_up);
            let minute_down = down.saturating_sub(self.minute_down);
            self.minutes.push_back(TrendPoint {
                unix: (unix_seconds() / 60) * 60,
                up_bps: minute_up as f64 / minute_elapsed,
                down_bps: minute_down as f64 / minute_elapsed,
            });
            self.minute_at = Some(now);
            self.minute_up = up;
            self.minute_down = down;
            while self.minutes.len() > TREND_MINUTE_CAP {
                self.minutes.pop_front();
            }
        }
    }

    fn snapshot(&self, range: &str) -> Value {
        match range {
            "1h" => {
                let start = self.minutes.len().saturating_sub(60);
                let points: Vec<TrendPoint> = self.minutes.iter().skip(start).cloned().collect();
                json!({"step_sec": 60, "points": points})
            }
            "24h" => {
                let all: Vec<TrendPoint> = self.minutes.iter().cloned().collect();
                let mut points = Vec::new();
                for chunk in all.chunks(5) {
                    if chunk.is_empty() {
                        continue;
                    }
                    let n = chunk.len() as f64;
                    points.push(TrendPoint {
                        unix: chunk.last().map(|p| p.unix).unwrap_or(0),
                        up_bps: chunk.iter().map(|p| p.up_bps).sum::<f64>() / n,
                        down_bps: chunk.iter().map(|p| p.down_bps).sum::<f64>() / n,
                    });
                }
                json!({"step_sec": 300, "points": points})
            }
            _ => {
                let points: Vec<TrendPoint> = self.recent.iter().cloned().collect();
                json!({"step_sec": 1, "points": points})
            }
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct TrafficDay {
    up: u64,
    down: u64,
}

#[derive(Debug, Default, Deserialize)]
struct TrafficFile {
    #[allow(dead_code)]
    today: String,
    #[serde(default)]
    days: BTreeMap<String, TrafficDay>,
}

#[derive(Debug, Default, Deserialize)]
struct ClientTrafficFile {
    #[allow(dead_code)]
    today: String,
    #[serde(default)]
    days: BTreeMap<String, BTreeMap<String, TrafficDay>>,
}

#[derive(Debug)]
struct TrafficState {
    days: usize,
    file: PathBuf,
    client_file: PathBuf,
    today: String,
    buckets: BTreeMap<String, TrafficDay>,
    client_buckets: BTreeMap<String, BTreeMap<String, TrafficDay>>,
    last_up: u64,
    last_down: u64,
    client_last: HashMap<String, (u64, u64)>,
    last_flush: Instant,
}

impl TrafficState {
    fn new(config_path: &Path, cfg: &Value) -> Self {
        let days = cfg
            .get("traffic_days")
            .and_then(Value::as_u64)
            .unwrap_or(DEFAULT_TRAFFIC_DAYS as u64)
            .clamp(1, MAX_TRAFFIC_DAYS as u64) as usize;
        let file = configured_traffic_file(config_path, cfg);
        let client_file = client_traffic_file(&file);
        let buckets = read_json::<TrafficFile>(&file)
            .map(|v| v.days)
            .unwrap_or_default();
        let client_buckets = read_json::<ClientTrafficFile>(&client_file)
            .map(|v| v.days)
            .unwrap_or_default();
        let mut out = Self {
            days,
            file,
            client_file,
            today: local_day(),
            buckets,
            client_buckets,
            last_up: 0,
            last_down: 0,
            client_last: HashMap::new(),
            last_flush: Instant::now(),
        };
        out.trim();
        out
    }

    fn apply_config(&mut self, days: i64, file: &str) {
        self.days = days.clamp(1, MAX_TRAFFIC_DAYS as i64) as usize;
        if !file.is_empty() {
            self.file = PathBuf::from(file);
            self.client_file = client_traffic_file(&self.file);
        }
        self.trim();
    }

    fn observe(&mut self, stats: &Value) {
        let today = local_day();
        self.today = today.clone();
        let (up, down) = aggregate_bytes(stats);
        let up_delta = up.saturating_sub(self.last_up);
        let down_delta = down.saturating_sub(self.last_down);
        self.last_up = up;
        self.last_down = down;
        let bucket = self.buckets.entry(today.clone()).or_default();
        bucket.up = bucket.up.saturating_add(up_delta);
        bucket.down = bucket.down.saturating_add(down_delta);

        if stats.get("mode").and_then(Value::as_str) == Some("server") {
            if let Some(clients) = stats.get("clients").and_then(Value::as_object) {
                for (id, client) in clients {
                    let rx = client.get("rx_bytes").and_then(Value::as_u64).unwrap_or(0);
                    let tx = client.get("tx_bytes").and_then(Value::as_u64).unwrap_or(0);
                    let prev = self.client_last.get(id).copied().unwrap_or((0, 0));
                    let entry = self
                        .client_buckets
                        .entry(today.clone())
                        .or_default()
                        .entry(id.clone())
                        .or_default();
                    entry.up = entry.up.saturating_add(rx.saturating_sub(prev.0));
                    entry.down = entry.down.saturating_add(tx.saturating_sub(prev.1));
                    self.client_last.insert(id.clone(), (rx, tx));
                }
            }
        }

        self.trim();
        if self.last_flush.elapsed() >= TRAFFIC_FLUSH_INTERVAL {
            self.persist();
            self.last_flush = Instant::now();
        }
    }

    fn trim(&mut self) {
        while self.buckets.len() > self.days {
            let Some(first) = self.buckets.keys().next().cloned() else {
                break;
            };
            self.buckets.remove(&first);
            self.client_buckets.remove(&first);
        }
        while self.client_buckets.len() > self.days {
            let Some(first) = self.client_buckets.keys().next().cloned() else {
                break;
            };
            self.client_buckets.remove(&first);
        }
    }

    fn snapshot(&self) -> Value {
        let daily: Vec<Value> = self
            .buckets
            .iter()
            .map(|(date, day)| json!({"date":date,"up":day.up,"down":day.down}))
            .collect();
        let today = self.buckets.get(&self.today).cloned().unwrap_or_default();
        json!({
            "days": self.days,
            "today": self.today,
            "up": today.up,
            "down": today.down,
            "daily": daily,
        })
    }

    fn client_snapshot(&self) -> Value {
        let mut by_client: BTreeMap<String, Vec<Value>> = BTreeMap::new();
        for (date, clients) in &self.client_buckets {
            for (id, day) in clients {
                by_client
                    .entry(id.clone())
                    .or_default()
                    .push(json!({"date":date,"up":day.up,"down":day.down}));
            }
        }
        Value::Array(
            by_client
                .into_iter()
                .map(|(id, daily)| json!({"id":id,"daily":daily}))
                .collect(),
        )
    }

    fn persist(&self) {
        if self.file.as_os_str().is_empty() {
            return;
        }
        let aggregate = json!({"today":self.today,"days":self.buckets});
        if let Err(e) = atomic_write_json(&self.file, &aggregate) {
            warn!("daily traffic persistence failed: {}", e);
        }
        let clients = json!({"today":self.today,"days":self.client_buckets});
        if let Err(e) = atomic_write_json(&self.client_file, &clients) {
            warn!("client traffic persistence failed: {}", e);
        }
    }
}

#[derive(Debug)]
pub struct WebParityState {
    config_path: PathBuf,
    source_config: RwLock<Value>,
    needs_restart: RwLock<Vec<String>>,
    trend: Mutex<TrendState>,
    traffic: Mutex<TrafficState>,
    last_clients: Mutex<HashSet<String>>,
    sampler_started: AtomicBool,
    pub events: EventHub,
    sessions: SessionStore,
}

impl WebParityState {
    pub fn new(config_path: &str) -> Self {
        let config_path = PathBuf::from(config_path);
        let source_config = std::fs::read_to_string(&config_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or_else(|| json!({}));
        let traffic = TrafficState::new(&config_path, &source_config);
        Self {
            config_path,
            source_config: RwLock::new(source_config),
            needs_restart: RwLock::new(Vec::new()),
            trend: Mutex::new(TrendState::default()),
            traffic: Mutex::new(traffic),
            last_clients: Mutex::new(HashSet::new()),
            sampler_started: AtomicBool::new(false),
            events: EventHub::default(),
            sessions: SessionStore::default(),
        }
    }

    pub fn config_path(&self) -> &Path {
        &self.config_path
    }

    pub fn current_config(&self) -> Value {
        self.source_config.read().clone()
    }

    pub fn current_auth(&self) -> String {
        self.source_config
            .read()
            .pointer("/web/auth")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    }

    pub fn redacted_config(&self) -> Value {
        let mut cfg = self.current_config();
        set_pointer_string(&mut cfg, &["psk"], "");
        set_pointer_string(&mut cfg, &["socks5"], "");
        set_pointer_string(&mut cfg, &["web", "auth"], "");
        cfg
    }

    pub fn merge_preserving_secrets(&self, mut candidate: Value) -> Value {
        let current = self.source_config.read();
        preserve_empty_string(&mut candidate, &current, &["psk"]);
        preserve_empty_string(&mut candidate, &current, &["socks5"]);
        preserve_empty_string(&mut candidate, &current, &["web", "auth"]);
        candidate
    }

    pub fn replace_config(&self, value: Value) {
        *self.source_config.write() = value;
    }

    pub fn set_needs_restart(&self, value: Vec<String>) {
        *self.needs_restart.write() = value;
    }

    pub fn needs_restart(&self) -> Vec<String> {
        self.needs_restart.read().clone()
    }

    pub fn try_start_sampler(&self) -> bool {
        self.sampler_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub fn observe_stats(&self, stats: &Value) {
        let (up, down) = aggregate_bytes(stats);
        self.trend.lock().observe(up, down);
        self.traffic.lock().observe(stats);
        self.observe_client_events(stats);
    }

    pub fn trend_json(&self, range: &str) -> Value {
        self.trend.lock().snapshot(range)
    }

    pub fn traffic_json(&self) -> Value {
        self.traffic.lock().snapshot()
    }

    pub fn client_traffic_json(&self) -> Value {
        self.traffic.lock().client_snapshot()
    }

    pub fn apply_traffic_config(&self, days: i64, file: &str) {
        self.traffic.lock().apply_config(days, file);
    }

    pub fn create_session(&self, auth: &str) -> Result<String, String> {
        self.sessions.create(auth)
    }

    pub fn session_valid(&self, token: &str, auth: &str) -> bool {
        self.sessions.valid(token, auth)
    }

    pub fn revoke_session(&self, token: &str) {
        self.sessions.revoke(token)
    }

    fn observe_client_events(&self, stats: &Value) {
        let current: HashSet<String> = stats
            .get("clients")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let mut previous = self.last_clients.lock();
        for id in current.difference(&previous) {
            self.events.emit("connect", "info", id, "Client connected");
        }
        for id in previous.difference(&current) {
            self.events
                .emit("disconnect", "warn", id, "Client disconnected");
        }
        *previous = current;
    }
}

pub fn atomic_write_json(path: &Path, value: &Value) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create parent directory: {e}"))?;
        }
    }
    let mut data = serde_json::to_vec_pretty(value).map_err(|e| format!("marshal json: {e}"))?;
    data.push(b'\n');
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, data).map_err(|e| format!("write temp file: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod temp file: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("replace file: {e}")
    })?;
    Ok(())
}

pub fn diff_paths(old: &Value, new: &Value) -> Vec<String> {
    let mut out = Vec::new();
    diff_value("", old, new, &mut out);
    out.sort();
    out.dedup();
    out
}

fn diff_value(prefix: &str, old: &Value, new: &Value, out: &mut Vec<String>) {
    match (old, new) {
        (Value::Object(a), Value::Object(b)) => {
            let mut keys: Vec<&String> = a.keys().chain(b.keys()).collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let next = if prefix.is_empty() {
                    key.to_string()
                } else {
                    format!("{prefix}.{key}")
                };
                match (a.get(key), b.get(key)) {
                    (Some(x), Some(y)) => diff_value(&next, x, y, out),
                    _ => out.push(next),
                }
            }
        }
        _ if old != new => out.push(prefix.to_string()),
        _ => {}
    }
}

fn aggregate_bytes(stats: &Value) -> (u64, u64) {
    let mode = stats.get("mode").and_then(Value::as_str).unwrap_or("");
    let tx = stats
        .get("global_tx_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let rx = stats
        .get("global_rx_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if mode == "server" {
        (rx, tx)
    } else {
        (tx, rx)
    }
}

fn configured_traffic_file(config_path: &Path, cfg: &Value) -> PathBuf {
    if let Some(file) = cfg.get("traffic_file").and_then(Value::as_str) {
        if !file.is_empty() {
            return PathBuf::from(file);
        }
    }
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("tlsvpn-traffic.json")
}

fn client_traffic_file(file: &Path) -> PathBuf {
    if file.as_os_str().is_empty() {
        return PathBuf::new();
    }
    let parent = file.parent().unwrap_or_else(|| Path::new("."));
    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("tlsvpn-traffic");
    let ext = file.extension().and_then(|s| s.to_str()).unwrap_or("json");
    parent.join(format!("{stem}-clients.{ext}"))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    if path.as_os_str().is_empty() {
        return None;
    }
    std::fs::read_to_string(path)
        .ok()
        .and_then(|raw| serde_json::from_str(&raw).ok())
}

fn preserve_empty_string(candidate: &mut Value, current: &Value, path: &[&str]) {
    let candidate_value = get_path(candidate, path).and_then(Value::as_str);
    if candidate_value.map_or(true, str::is_empty) {
        if let Some(existing) = get_path(current, path).and_then(Value::as_str) {
            set_pointer_string(candidate, path, existing);
        }
    }
}

fn get_path<'a>(mut value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    for part in path {
        value = value.get(*part)?;
    }
    Some(value)
}

fn set_pointer_string(value: &mut Value, path: &[&str], text: &str) {
    if path.is_empty() {
        return;
    }
    let mut cur = value;
    for part in &path[..path.len() - 1] {
        if !cur.get(*part).map(Value::is_object).unwrap_or(false) {
            cur[*part] = json!({});
        }
        cur = &mut cur[*part];
    }
    cur[path[path.len() - 1]] = Value::String(text.to_string());
}

fn wall_clock_hms() -> String {
    #[cfg(target_os = "linux")]
    {
        let mut raw: libc::time_t = 0;
        unsafe {
            libc::time(&mut raw as *mut _);
            let mut tm: libc::tm = std::mem::zeroed();
            if !libc::localtime_r(&raw as *const _, &mut tm as *mut _).is_null() {
                return format!(
                    "{:02}:{:02}:{:02}.{:03}",
                    tm.tm_hour,
                    tm.tm_min,
                    tm.tm_sec,
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_millis()
                );
            }
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs() % 86_400;
    format!(
        "{:02}:{:02}:{:02}.{:03}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60,
        now.subsec_millis()
    )
}

fn local_day() -> String {
    #[cfg(target_os = "linux")]
    {
        let mut raw: libc::time_t = 0;
        unsafe {
            libc::time(&mut raw as *mut _);
            let mut tm: libc::tm = std::mem::zeroed();
            if !libc::localtime_r(&raw as *const _, &mut tm as *mut _).is_null() {
                return format!(
                    "{:04}-{:02}-{:02}",
                    tm.tm_year + 1900,
                    tm.tm_mon + 1,
                    tm.tm_mday
                );
            }
        }
    }
    utc_day(unix_seconds())
}

fn utc_day(unix: i64) -> String {
    let z = unix.div_euclid(86_400) + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096).div_euclid(365);
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2).div_euclid(153);
    let day = doy - (153 * mp + 2).div_euclid(5) + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += if month <= 2 { 1 } else { 0 };
    format!("{year:04}-{month:02}-{day:02}")
}

fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_and_secret_merge_match_go_contract() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("tlsvpn-web-state-{}.json", std::process::id()));
        std::fs::write(
            &path,
            r#"{"psk":"secret","socks5":"u:p@127.0.0.1:1080","web":{"auth":"admin:pw"}}"#,
        )
        .unwrap();
        let state = WebParityState::new(path.to_str().unwrap());
        let redacted = state.redacted_config();
        assert_eq!(redacted["psk"], "");
        assert_eq!(redacted["socks5"], "");
        assert_eq!(redacted["web"]["auth"], "");
        let merged = state.merge_preserving_secrets(redacted);
        assert_eq!(merged["psk"], "secret");
        assert_eq!(merged["socks5"], "u:p@127.0.0.1:1080");
        assert_eq!(merged["web"]["auth"], "admin:pw");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn session_is_invalidated_when_web_auth_changes() {
        let state = WebParityState::new("/definitely/missing/config.json");
        let token = state.create_session("admin:old").unwrap();
        assert!(state.session_valid(&token, "admin:old"));
        assert!(!state.session_valid(&token, "admin:new"));
    }

    #[test]
    fn diff_paths_is_stable_and_nested() {
        let a = json!({"log_level":"info","web":{"addr":":8080"}});
        let b = json!({"log_level":"debug","web":{"addr":":8081"}});
        assert_eq!(diff_paths(&a, &b), vec!["log_level", "web.addr"]);
    }

    #[test]
    fn traffic_snapshot_matches_go_shape_and_direction() {
        let dir = std::env::temp_dir();
        let config = dir.join(format!("tlsvpn-traffic-test-{}.json", std::process::id()));
        let file = dir.join(format!("tlsvpn-traffic-data-{}.json", std::process::id()));
        std::fs::write(
            &config,
            serde_json::to_vec(&json!({"traffic_days":7,"traffic_file":file})).unwrap(),
        )
        .unwrap();
        let state = WebParityState::new(config.to_str().unwrap());
        state.observe_stats(&json!({
            "mode":"client","global_tx_bytes":1000,"global_rx_bytes":400,
            "clients":{"local":{"tx_bytes":1000,"rx_bytes":400}}
        }));
        let tr = state.traffic_json();
        assert_eq!(tr["days"], 7);
        assert_eq!(tr["up"], 1000);
        assert_eq!(tr["down"], 400);
        assert!(tr["daily"].as_array().unwrap().len() >= 1);
        let _ = std::fs::remove_file(config);
        let _ = std::fs::remove_file(file);
    }

    #[test]
    fn trend_ranges_have_go_compatible_step_sizes() {
        let state = WebParityState::new("/definitely/missing/config.json");
        assert_eq!(state.trend_json("2m")["step_sec"], 1);
        assert_eq!(state.trend_json("1h")["step_sec"], 60);
        assert_eq!(state.trend_json("24h")["step_sec"], 300);
    }
}
