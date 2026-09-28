use crossbeam_channel::{bounded, Receiver, Sender, TrySendError};
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const EVENT_CAP: usize = 500;
const TREND_CAP: usize = 120;
const SESSION_TTL: Duration = Duration::from_secs(24 * 60 * 60);

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
    points: VecDeque<TrendPoint>,
}

impl TrendState {
    fn observe(&mut self, up: u64, down: u64) {
        let now = Instant::now();
        let Some(last_at) = self.last_at else {
            self.last_at = Some(now);
            self.last_up = up;
            self.last_down = down;
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
        self.points.push_back(TrendPoint {
            unix: unix_seconds(),
            up_bps: up_delta as f64 / elapsed,
            down_bps: down_delta as f64 / elapsed,
        });
        while self.points.len() > TREND_CAP {
            self.points.pop_front();
        }
    }
}

#[derive(Debug)]
pub struct WebParityState {
    config_path: PathBuf,
    source_config: RwLock<Value>,
    needs_restart: RwLock<Vec<String>>,
    trend: Mutex<TrendState>,
    pub events: EventHub,
    sessions: SessionStore,
}

impl WebParityState {
    pub fn new(config_path: &str) -> Self {
        let source_config = std::fs::read_to_string(config_path)
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .unwrap_or_else(|| json!({}));
        Self {
            config_path: PathBuf::from(config_path),
            source_config: RwLock::new(source_config),
            needs_restart: RwLock::new(Vec::new()),
            trend: Mutex::new(TrendState::default()),
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

    pub fn observe_stats(&self, stats: &Value) {
        let up = stats
            .get("global_tx_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let down = stats
            .get("global_rx_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        self.trend.lock().observe(up, down);
    }

    pub fn trend_json(&self) -> Value {
        let points: Vec<TrendPoint> = self.trend.lock().points.iter().cloned().collect();
        json!({"step_sec": 1, "points": points})
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
}

pub fn atomic_write_json(path: &Path, value: &Value) -> Result<(), String> {
    let mut data = serde_json::to_vec_pretty(value).map_err(|e| format!("marshal config: {e}"))?;
    data.push(b'\n');
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&tmp, data).map_err(|e| format!("write temp config: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("chmod temp config: {e}"))?;
    }
    std::fs::rename(&tmp, path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("replace config: {e}")
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
}
