//! 诊断中心（对齐 Go web_diagnostics.go）。
//!
//! 消费 WebStatsProvider 的 stats_json（serde_json::Value），按基线差分计算速率
//! 指标，按三级桶（recent 2 分钟 / minutes 逐分钟 / bucket 聚合）保留历史，
//! 供 `/api/diagnostics` 与 SSE `diagnostics` 事件消费。
//!
//! 与 Go 一致：读图不创建样本、不改变其他浏览器的基线；保留有界，不持久化。
//! 每指标只对真实观测求均值；连接身份不跨重连合并；缺失或未测指标保留 gap。

use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const DIAGNOSTIC_CONNECTION_LIMIT: usize = 32;
const DIAGNOSTIC_RECENT_CAP: usize = 60;
const DIAGNOSTIC_MINUTE_CAP: usize = 1440;
const DIAGNOSTIC_VALID_WINDOW_SECS: f64 = 10.0;

#[derive(Clone, Debug, Default)]
pub struct DiagnosticConn {
    pub id: String,
    pub client: String,
    pub label: String,
    pub metrics: HashMap<String, Option<f64>>,
}

#[derive(Clone, Debug, Default)]
pub struct DiagnosticPoint {
    pub seconds: f64,
    pub t: i64,
    pub metrics: HashMap<String, Option<f64>>,
    pub conns: Vec<DiagnosticConn>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct DiagnosticSnapshot {
    pub instance: String,
    pub step: i64,
    pub points: Vec<DiagnosticPoint>,
}

#[derive(Debug, Default)]
struct Baseline {
    instance: String,
    t: i64,
    counters: HashMap<String, u64>,
    conns: HashMap<String, HashMap<String, u64>>,
    pad_epoch: u64,
}

#[derive(Debug, Default)]
pub struct DiagnosticHistory {
    inner: Mutex<DiagState>,
}

#[derive(Debug)]
struct DiagState {
    prev: Baseline,
    recent: Vec<DiagnosticPoint>,
    minutes: Vec<DiagnosticPoint>,
    bucket: Vec<DiagnosticPoint>,
}

impl Default for DiagState {
    fn default() -> Self {
        Self {
            prev: Baseline::default(),
            recent: Vec::new(),
            minutes: Vec::new(),
            bucket: Vec::new(),
        }
    }
}

impl DiagnosticHistory {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DiagState::default()),
        }
    }

    /// 记录一次采样（stats_json 输出；对齐 Go record）。线程安全。
    pub fn record(&self, stats: &Value) {
        let mut st = self.inner.lock().unwrap();
        let mode = stats["mode"].as_str().unwrap_or("");
        let instance = stats["instance_id"].as_str().unwrap_or("").to_string();
        let sample_ms = sample_time_ms(stats);
        if sample_ms <= st.prev.t {
            return;
        }
        if !st.prev.instance.is_empty() && st.prev.instance != instance {
            *st = DiagState::default();
        }
        let seconds = (sample_ms - st.prev.t) as f64 / 1000.0;
        let valid = st.prev.t != 0 && seconds <= DIAGNOSTIC_VALID_WINDOW_SECS;

        // 计数器：fec_data/fec_parity/recovered/lost/reconnect/drop/tap_error。
        let mut counters: HashMap<String, u64> = HashMap::new();
        counters.insert("fec_data".into(), u64_at(stats, &["fec", "data_wire_bytes"]));
        counters.insert("fec_parity".into(), u64_at(stats, &["fec", "parity_wire_bytes"]));
        counters.insert("recovered".into(), u64_at(stats, &["fec", "recovered"]));
        counters.insert("lost".into(), u64_at(stats, &["fec", "lost"]));
        counters.insert("drop".into(), u64_at(stats, &["dropped_frames"]));
        // 对齐 Go WebStats.TapErrors（json: tap_write_errors）。
        counters.insert("tap_error".into(), u64_at(stats, &["tap_write_errors"]));
        if mode == "client" {
            // 对齐 Go WebStats.ReconnectAttempts（json: reconnect_attempts）。
            counters.insert("reconnect".into(), u64_at(stats, &["reconnect_attempts"]));
        }
        let mut has_pad = false;
        let mut pad_epoch = 0u64;
        if let Some(_pad) = stats["padding"].as_object() {
            has_pad = true;
            counters.insert("pad".into(), u64_at(stats, &["padding", "pad_bytes"]));
            counters.insert("pad_wire".into(), u64_at(stats, &["padding", "wire_bytes"]));
            pad_epoch = u64_at(stats, &["padding", "epoch"]);
        }

        let weight = if valid { seconds } else { 2.0 };
        let mut metrics: HashMap<String, Option<f64>> = HashMap::new();
        metrics.insert("online".into(), Some(u64_at(stats, &["active_clients"]) as f64));
        for (k, v) in &counters {
            let old = st.prev.counters.get(k).copied();
            metrics.insert(
                k.clone(),
                rate(*v, old, seconds, valid && old.is_some()),
            );
        }
        if has_pad && pad_epoch != st.prev.pad_epoch {
            metrics.insert("pad".into(), None);
            metrics.insert("pad_wire".into(), None);
        }
        // 比率基于平均字节速率，绝非百分比平均。
        metrics.insert(
            "fec_pct".into(),
            ratio(metrics.get("fec_parity").copied().flatten(), metrics.get("fec_data").copied().flatten()),
        );
        metrics.insert(
            "pad_pct".into(),
            ratio(metrics.get("pad").copied().flatten(), metrics.get("pad_wire").copied().flatten()),
        );

        let mut next: HashMap<String, HashMap<String, u64>> = HashMap::new();
        let mut conns: Vec<DiagnosticConn> = Vec::new();
        let conn_arrays: &[&str] = if mode == "server" {
            &["server_conns"]
        } else {
            &["conns"]
        };
        for arr in conn_arrays {
            if let Some(items) = stats[arr].as_array() {
                for c in items {
                    let id = c["conn_id"].as_str().unwrap_or("").to_string();
                    if id.is_empty() {
                        continue;
                    }
                    let client = if mode == "server" {
                        c["client_id"].as_str().unwrap_or("").to_string()
                    } else {
                        "local".to_string()
                    };
                    let label = if mode == "server" {
                        c["remote"].as_str().unwrap_or("").to_string()
                    } else {
                        c["target"].as_str().unwrap_or("").to_string()
                    };
                    let mut tx = u64_at(c, &["tx_bytes"]);
                    let mut rx = u64_at(c, &["rx_bytes"]);
                    if mode == "server" {
                        std::mem::swap(&mut tx, &mut rx);
                    }
                    let mut current: HashMap<String, u64> = HashMap::new();
                    current.insert("up".into(), tx);
                    current.insert("down".into(), rx);
                    current.insert(
                        "assigned".into(),
                        u64_at(c, &["scheduler", "assigned_bytes"]),
                    );
                    let old = st.prev.conns.get(&id);
                    let mut m: HashMap<String, Option<f64>> = HashMap::new();
                    m.insert(
                        "queue".into(),
                        Some(u64_at(c, &["scheduler", "queued_bytes"]) as f64),
                    );
                    m.insert("rtt".into(), None);
                    for (k, v) in &current {
                        let oldv = old.and_then(|o| o.get(k)).copied();
                        m.insert(k.clone(), rate(*v, oldv, seconds, valid && oldv.is_some()));
                    }
                    let rtt = u64_at(c, &["rtt_ms"]);
                    if rtt > 0 {
                        m.insert("rtt".into(), Some(rtt as f64));
                    }
                    // 去程/回程单向时延（µs→ms）。0=未收敛，留 gap。
                    let fwd = u64_at(c, &["scheduler", "fwd_oneway_us"]);
                    if fwd > 0 {
                        m.insert("fwd".into(), Some(fwd as f64 / 1000.0));
                    }
                    let ret = u64_at(c, &["scheduler", "ret_oneway_us"]);
                    if ret > 0 {
                        m.insert("ret".into(), Some(ret as f64 / 1000.0));
                    }
                    // 时钟偏移 θ 与不确定度 U（ns→ms）。纯观测值。
                    if bool_at(c, &["scheduler", "clock_offset_converged"]) {
                        m.insert("clk_sync".into(), Some(1.0));
                        m.insert(
                            "clk_off".into(),
                            Some(i64_at(c, &["scheduler", "clock_offset_ns"]) as f64 / 1_000_000.0),
                        );
                        m.insert(
                            "clk_unc".into(),
                            Some(u64_at(c, &["scheduler", "clock_offset_unc_us"]) as f64 / 1000.0),
                        );
                    }
                    conns.push(DiagnosticConn {
                        id: id.clone(),
                        client,
                        label,
                        metrics: m,
                    });
                    next.insert(id, current);
                }
            }
        }
        conns.sort_by(|a, b| a.id.cmp(&b.id));
        let mut truncated = false;
        if conns.len() > DIAGNOSTIC_CONNECTION_LIMIT {
            truncated = true;
            conns.truncate(DIAGNOSTIC_CONNECTION_LIMIT);
            let keep: std::collections::HashSet<&str> = conns.iter().map(|c| c.id.as_str()).collect();
            next.retain(|id, _| keep.contains(id.as_str()));
        }

        let p = DiagnosticPoint {
            seconds: weight,
            t: sample_ms,
            metrics,
            conns,
            truncated,
        };
        st.recent.push(p.clone());
        if st.recent.len() > DIAGNOSTIC_RECENT_CAP {
            st.recent.remove(0);
        }
        // 跨分钟边界：把 bucket 聚合进 minutes。
        if !st.bucket.is_empty()
            && (st.bucket[0].t / 60_000) != (p.t / 60_000)
        {
            let agg = aggregate_diagnostics(&st.bucket);
            st.bucket.clear();
            st.minutes.push(agg);
            if st.minutes.len() > DIAGNOSTIC_MINUTE_CAP {
                st.minutes.remove(0);
            }
        }
        st.bucket.push(p);

        st.prev = Baseline {
            instance,
            t: sample_ms,
            counters,
            conns: next,
            pad_epoch,
        };
    }

    /// 取快照（对齐 Go snapshot；range: 2m/1h/24h）。
    pub fn snapshot(&self, range: &str) -> DiagnosticSnapshot {
        let st = self.inner.lock().unwrap();
        let mut out = DiagnosticSnapshot {
            instance: st.prev.instance.clone(),
            step: 2,
            points: Vec::new(),
        };
        if range == "2m" {
            let cutoff = st.prev.t - 120_000;
            out.points.extend(st.recent.iter().filter(|p| p.t >= cutoff).cloned());
            return out;
        }
        let mut raw: Vec<DiagnosticPoint> = st.minutes.clone();
        if !st.bucket.is_empty() {
            raw.push(aggregate_diagnostics(&st.bucket));
        }
        let cutoff = st.prev.t - 3_600_000; // 1h
        out.step = 60;
        if range == "24h" {
            out.step = 300;
        }
        let cutoff = if range == "24h" {
            st.prev.t - 24 * 3_600_000
        } else {
            cutoff
        };
        let mut selected: Vec<DiagnosticPoint> = raw
            .into_iter()
            .filter(|p| p.t >= cutoff)
            .collect();
        let mut points = Vec::new();
        let mut i = 0;
        // 桶宽（ms）= step(秒) * 1000。注意 out.step 是秒（1h=60/24h=300），
        // 而 Go 的 step 变量是分钟（1/5）；两者换算后桶宽一致（1h=1min、24h=5min）。
        // 曾误用 out.step * 60_000 导致 24h 桶宽变成 5 小时、1h 变成 1 小时。
        while i < selected.len() {
            let mut end = i + 1;
            while end < selected.len()
                && selected[end].t / (out.step * 1000) == selected[i].t / (out.step * 1000)
            {
                end += 1;
            }
            points.push(aggregate_diagnostics(&selected[i..end]));
            i = end;
        }
        selected.clear();
        out.points = points;
        out
    }
}

/// 聚合一组点：每指标按权重求均值（只对真实观测），连接按 id 合并。
fn aggregate_diagnostics(points: &[DiagnosticPoint]) -> DiagnosticPoint {
    let mut out = DiagnosticPoint {
        t: points.last().map(|p| p.t).unwrap_or(0),
        metrics: HashMap::new(),
        conns: Vec::new(),
        truncated: points.iter().any(|p| p.truncated),
        ..Default::default()
    };
    let mut sums: HashMap<String, f64> = HashMap::new();
    let mut counts: HashMap<String, f64> = HashMap::new();
    let mut by_id: HashMap<String, DiagnosticConn> = HashMap::new();
    let mut cs: HashMap<String, HashMap<String, f64>> = HashMap::new();
    let mut cn: HashMap<String, HashMap<String, f64>> = HashMap::new();

    for p in points {
        let weight = if p.seconds > 0.0 { p.seconds } else { 2.0 };
        out.seconds += weight;
        for (k, v) in &p.metrics {
            if let Some(v) = v {
                *sums.entry(k.clone()).or_insert(0.0) += v * weight;
                *counts.entry(k.clone()).or_insert(0.0) += weight;
            }
        }
        for c in &p.conns {
            if !by_id.contains_key(&c.id) {
                if by_id.len() >= DIAGNOSTIC_CONNECTION_LIMIT {
                    out.truncated = true;
                    continue;
                }
                by_id.insert(c.id.clone(), c.clone());
                cs.insert(c.id.clone(), HashMap::new());
                cn.insert(c.id.clone(), HashMap::new());
            }
            for (k, v) in &c.metrics {
                if let Some(v) = v {
                    *cs.get_mut(&c.id).unwrap().entry(k.clone()).or_insert(0.0) += v * weight;
                    *cn.get_mut(&c.id).unwrap().entry(k.clone()).or_insert(0.0) += weight;
                }
            }
        }
    }
    for (k, n) in &counts {
        out.metrics.insert(k.clone(), Some(sums[k] / *n));
    }
    for (id, c) in &mut by_id {
        let mut m = HashMap::new();
        if let Some(cns) = cn.get(id) {
            for (k, n) in cns {
                m.insert(k.clone(), Some(cs[id][k] / *n));
            }
        }
        c.metrics = m;
        out.conns.push(c.clone());
    }
    out.conns.sort_by(|a, b| a.id.cmp(&b.id));
    // 比率基于平均字节速率。
    for (key, a_key, b_key) in [
        ("fec_pct", "fec_parity", "fec_data"),
        ("pad_pct", "pad", "pad_wire"),
    ] {
        let a = out.metrics.get(a_key).copied().flatten();
        let b = out.metrics.get(b_key).copied().flatten();
        out.metrics.insert(key.into(), ratio(a, b));
    }
    out
}

#[inline]
fn sample_time_ms(stats: &Value) -> i64 {
    // 优先读 stats 的显式 sample_time_ms（对齐 Go WebStats.SampleTimeMs，json
    // 字段 sample_time_ms；测试可注入精确时间戳）。stats_json 不产出该字段时
    // 回退真实时钟（采样由调用方周期驱动，差分只依赖相对时间，与 Go 语义一致）。
    if let Some(ms) = stats["sample_time_ms"].as_i64() {
        return ms;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    now
}

#[inline]
fn rate(now: u64, old: Option<u64>, seconds: f64, valid: bool) -> Option<f64> {
    if !valid || seconds <= 0.0 {
        return None;
    }
    let old = old?;
    if now < old {
        return None;
    }
    Some((now - old) as f64 / seconds)
}

#[inline]
fn ratio(a: Option<f64>, b: Option<f64>) -> Option<f64> {
    match (a, b) {
        (Some(a), Some(b)) if b > 0.0 => Some(100.0 * a / b),
        _ => None,
    }
}

#[inline]
fn u64_at(v: &Value, path: &[&str]) -> u64 {
    let mut cur = v;
    for key in path {
        cur = &cur[key];
    }
    cur.as_u64().unwrap_or(0)
}

#[inline]
fn i64_at(v: &Value, path: &[&str]) -> i64 {
    let mut cur = v;
    for key in path {
        cur = &cur[key];
    }
    cur.as_i64().unwrap_or(0)
}

#[inline]
fn bool_at(v: &Value, path: &[&str]) -> bool {
    let mut cur = v;
    for key in path {
        cur = &cur[key];
    }
    cur.as_bool().unwrap_or(false)
}

// serde_json::Value → DiagnosticSnapshot 序列化（供 /api/diagnostics 输出）。
impl DiagnosticSnapshot {
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("instance_id".into(), Value::String(self.instance.clone()));
        m.insert("step_sec".into(), Value::Number(self.step.into()));
        let points: Vec<Value> = self.points.iter().map(point_to_value).collect();
        m.insert("points".into(), Value::Array(points));
        Value::Object(m)
    }
}

fn point_to_value(p: &DiagnosticPoint) -> Value {
    let mut m = Map::new();
    m.insert(
        "seconds".into(),
        Value::Number(serde_json::Number::from_f64(p.seconds).unwrap_or(0.into())),
    );
    m.insert("t".into(), Value::Number(p.t.into()));
    m.insert("metrics".into(), metrics_to_value(&p.metrics));
    let conns: Vec<Value> = p.conns.iter().map(conn_to_value).collect();
    m.insert("conns".into(), Value::Array(conns));
    m.insert("truncated".into(), Value::Bool(p.truncated));
    Value::Object(m)
}

fn conn_to_value(c: &DiagnosticConn) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), Value::String(c.id.clone()));
    m.insert("client".into(), Value::String(c.client.clone()));
    m.insert("label".into(), Value::String(c.label.clone()));
    m.insert("metrics".into(), metrics_to_value(&c.metrics));
    Value::Object(m)
}

fn metrics_to_value(metrics: &HashMap<String, Option<f64>>) -> Value {
    let mut m = Map::new();
    for (k, v) in metrics {
        m.insert(
            k.clone(),
            match v {
                Some(v) => Value::Number(
                    serde_json::Number::from_f64(*v).unwrap_or(0.into()),
                ),
                None => Value::Null,
            },
        );
    }
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(up: u64, down: u64) -> Value {
        serde_json::json!({
            "mode": "client",
            "instance_id": "i1",
            "active_clients": 1,
            "conns": [{
                "conn_id": "c1",
                "target": "t",
                "tx_bytes": up,
                "rx_bytes": down,
                "rtt_ms": 5,
                "scheduler": {
                    "assigned_bytes": 100,
                    "queued_bytes": 10,
                    "fwd_oneway_us": 1000,
                    "ret_oneway_us": 2000,
                    "clock_offset_ns": 500000,
                    "clock_offset_unc_us": 100,
                    "clock_offset_converged": true,
                }
            }],
        })
    }

    /// 对齐 Go diagnosticFixture(at, n)：可注入 sample_time_ms 以复现精确速率断言。
    fn diag_fixture(at: i64, n: u64) -> Value {
        serde_json::json!({
            "mode": "client",
            "instance_id": "process-a",
            "sample_time_ms": at,
            "active_clients": 1,
            "reconnect_attempts": n,
            "dropped_frames": n * 2,
            "tap_write_errors": n,
            "fec": {
                "data_wire_bytes": n * 1000,
                "parity_wire_bytes": n * 250,
                "recovered": n * 2,
                "lost": n,
            },
            "padding": {"epoch": 1, "wire_bytes": n * 1000, "pad_bytes": n * 100},
            "conns": [{
                "conn_id": "physical-a",
                "target": "peer",
                "tx_bytes": n * 1000,
                "rx_bytes": n * 2000,
                "scheduler": {
                    "assigned_bytes": n * 800,
                    "queued_bytes": 128,
                    "fwd_oneway_us": 15000,
                    "ret_oneway_us": 25000,
                }
            }],
        })
    }

    #[test]
    fn record_produces_rate_metrics() {
        let h = DiagnosticHistory::new();
        h.record(&sample(1000, 500));
        // 第二个样本 2 秒后：需要真实时钟，这里直接验证结构存在且无 panic。
        h.record(&sample(3000, 1500));
        let snap = h.snapshot("2m");
        assert_eq!(snap.instance, "i1");
        assert!(!snap.points.is_empty());
        let last = snap.points.last().unwrap();
        assert!(last.metrics.contains_key("online"));
        assert!(last.metrics.contains_key("fec_data"));
        // conns 应包含 c1 且含 fwd/ret/clk。
        let c1 = last.conns.iter().find(|c| c.id == "c1").expect("c1 present");
        assert!(c1.metrics.contains_key("fwd"));
        assert!(c1.metrics.contains_key("ret"));
        assert!(c1.metrics.contains_key("clk_sync"));
    }

    #[test]
    fn aggregate_merges_conns_and_averages() {
        let mut p1 = DiagnosticPoint {
            seconds: 1.0,
            t: 1000,
            metrics: HashMap::from([("online".into(), Some(1.0))]),
            conns: vec![DiagnosticConn {
                id: "c1".into(),
                client: "local".into(),
                label: "t".into(),
                metrics: HashMap::from([("rtt".into(), Some(5.0))]),
            }],
            truncated: false,
        };
        let mut p2 = p1.clone();
        p2.t = 2000;
        p2.conns[0].metrics = HashMap::from([("rtt".into(), Some(7.0))]);
        let agg = aggregate_diagnostics(&[p1, p2]);
        assert_eq!(agg.seconds, 2.0);
        assert_eq!(agg.conns.len(), 1);
        assert_eq!(agg.conns[0].metrics["rtt"], Some(6.0));
        assert_eq!(agg.metrics["online"], Some(1.0));
    }

    /// 对齐 Go TestWebDiagnosticsRatesDirectionsAndBoundaries：速率方向、
    /// 重连/padding epoch 交叉、计数器回滚、instance 变更、server 模式交换。
    #[test]
    fn rates_directions_and_boundaries() {
        let h = DiagnosticHistory::new();
        h.record(&diag_fixture(60_000, 10));
        h.record(&diag_fixture(64_000, 12));
        let points = h.snapshot("2m").points;
        let p = &points[1];
        // 第一帧不伪造速率。
        assert!(points[0].conns[0].metrics["up"].is_none());
        // 第二帧 4 秒后：Δ=2000/4=500 up，Δ=4000/4=1000 down，Δ=1600/4=400 assigned。
        let c = &p.conns[0];
        assert_eq!(c.metrics["up"], Some(500.0));
        assert_eq!(c.metrics["down"], Some(1000.0));
        assert_eq!(c.metrics["assigned"], Some(400.0));
        assert_eq!(c.metrics["queue"], Some(128.0));
        // 未测 RTT 不伪造。
        assert!(c.metrics["rtt"].is_none());
        assert_eq!(c.metrics["fwd"], Some(15.0));
        assert_eq!(c.metrics["ret"], Some(25.0));
        assert_eq!(p.metrics["fec_pct"], Some(25.0));
        assert_eq!(p.metrics["pad_pct"], Some(10.0));
        assert_eq!(p.metrics["recovered"], Some(1.0));
        // tap_error = n：10→12，Δ=2/4s = 0.5。
        assert_eq!(p.metrics["tap_error"], Some(0.5));

        // 换物理连接 + padding epoch 变化：速率与 pad 留 gap，不跨基线。
        let mut s = diag_fixture(66_000, 13);
        s["conns"][0]["conn_id"] = serde_json::json!("physical-b");
        s["padding"]["epoch"] = serde_json::json!(2);
        h.record(&s);
        let p = &h.snapshot("2m").points[2];
        assert!(p.conns[0].metrics["up"].is_none());
        assert!(p.metrics["pad"].is_none());

        // 计数器回滚（n=13→1）：underflow 留 gap。
        let mut s = diag_fixture(68_000, 1);
        s["conns"][0]["conn_id"] = serde_json::json!("physical-b");
        h.record(&s);
        assert!(h.snapshot("2m").points[3].metrics["fec_data"].is_none());

        // instance 变更：历史重置，只保留新 instance 的一帧。
        let mut s = diag_fixture(70_000, 1);
        s["instance_id"] = serde_json::json!("process-b");
        h.record(&s);
        let snap = h.snapshot("24h");
        assert_eq!(snap.points.len(), 1);
        assert_eq!(snap.instance, "process-b");

        // server 模式：up/down 交换 + rtt 实测 + 未收敛 fwd/ret 留 gap。
        let server = DiagnosticHistory::new();
        let mut a = diag_fixture(60_000, 10);
        a["mode"] = serde_json::json!("server");
        a["conns"] = serde_json::json!([]);
        a["server_conns"] = serde_json::json!([{
            "conn_id": "server-a", "client_id": "client-a",
            "tx_bytes": 1000, "rx_bytes": 2000, "rtt_ms": 22,
        }]);
        server.record(&a);
        let mut b = a.clone();
        b["sample_time_ms"] = serde_json::json!(62_000);
        b["server_conns"][0]["tx_bytes"] = serde_json::json!(1400);
        b["server_conns"][0]["rx_bytes"] = serde_json::json!(2600);
        server.record(&b);
        let c = &server.snapshot("2m").points[1].conns[0];
        // server 无 reconnect 指标（键缺失 = 无该指标）。
        assert!(server.snapshot("2m").points[1].metrics.get("reconnect").is_none());
        // server 模式交换：rx=Δ600/2=300 up（client→server 视角），tx=Δ400/2=200 down。
        assert_eq!(c.metrics["up"], Some(300.0));
        assert_eq!(c.metrics["down"], Some(200.0));
        assert_eq!(c.metrics["rtt"], Some(22.0));
        assert!(c.metrics.get("fwd").is_none() && c.metrics.get("ret").is_none());

        // 连接退役：下一帧 conns 为空。
        let mut b = b.clone();
        b["sample_time_ms"] = serde_json::json!(64_000);
        b["server_conns"] = serde_json::json!([]);
        b["active_clients"] = serde_json::json!(0);
        server.record(&b);
        assert!(server.snapshot("2m").points[2].conns.is_empty());
    }

    /// 对齐 Go TestWebDiagnosticsSamplingGapsAndAlignedBuckets：长 gap 不产生
    /// 速率、跨分钟桶聚合、重复时间戳去重。
    #[test]
    fn sampling_gaps_and_aligned_buckets() {
        let h = DiagnosticHistory::new();
        h.record(&diag_fixture(60_000, 1));
        h.record(&diag_fixture(62_000, 2));
        h.record(&diag_fixture(660_000, 20));
        h.record(&diag_fixture(662_000, 21));
        // 跨 5 分钟 outage：两段不应被合并成一个桶。
        let got = h.snapshot("24h");
        assert_eq!(got.points.len(), 2, "distinct buckets merged across outage");
        // 长 gap 内的速率留 gap（第一帧 60s→660s 无效）。
        assert!(h.snapshot("2m").points[0].conns[0].metrics["up"].is_none());
        // 重复时间戳不产生样本。
        let before = h.snapshot("2m").points.len();
        h.record(&diag_fixture(662_000, 22));
        assert_eq!(h.snapshot("2m").points.len(), before);
    }

    /// 对齐 Go TestWebDiagnosticsAggregationRetentionAndConcurrency 的关键断言：
    /// 聚合用总字节/总时间（加权均值），连接数截断保留上限。
    #[test]
    fn aggregation_uses_weighted_mean_and_truncates_conns() {
        let h = DiagnosticHistory::new();
        h.record(&diag_fixture(60_000, 0));
        h.record(&diag_fixture(62_000, 2));
        h.record(&diag_fixture(68_000, 3));
        let snap = h.snapshot("1h");
        let p = &snap.points[0];
        // 3000 字节 over 8 秒 = 375/s（加权，而非未加权速率平均）。
        assert_eq!(p.conns[0].metrics["up"], Some(375.0));
        assert_eq!(p.metrics["fec_pct"], Some(25.0));

        // 40 条连接：截断到 32，标记 truncated，prev 也保留 32。
        let mut s = diag_fixture(100_000, 1);
        s["conns"] = serde_json::json!(
            (0..40).map(|i| serde_json::json!({"conn_id": format!("conn-{:02}", i), "target": "p"})).collect::<Vec<_>>()
        );
        h.record(&s);
        let snap2m = h.snapshot("2m");
        let last = snap2m.points.last().unwrap();
        assert!(last.truncated);
        assert_eq!(last.conns.len(), 32);
    }
}
