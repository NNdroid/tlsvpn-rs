//! 跨路径 RTT 探针 + 双向时钟偏移探针的调度器（对齐 Go rtt_probe.go /
//! clock_offset.go 的调度器部分）。
//!
//! 每侧各一个调度器线程：客户端挂 Client、服务端每会话挂 ClientSession。同一
//! 结构既发起探针（initiator）也响应回包（responder），两侧对称。probeCh（cap 8）
//! 由发送循环持有，探针/回包经它投递到物理连接写路径（与 keepalive 同路），
//! 读循环把探针帧前置拦截后经 on_frame 投递回来。
//!
//! 并发纪律（对齐 Go）：
//! - pending/decay/nonce 等调度状态由 run 线程独占，无锁。
//! - enable/kick/on_frame 由其他线程经通道/原子调用，跨线程安全。
//! - 时钟估计器的 θ/不确定度结果经原子发布，快照读取方无锁读取。
//!
//! 定时器用 crossbeam `select!` + `after(d)` 复刻 Go 的 select+timer：每次循环
//! 生成一个新的抖动间隔，天然实现"每周期重置定时器"，且与 kick/replies 等
//! 就绪分支随机选择，与 Go select 语义一致。

use crate::clock_offset as co;
use crate::protocol::{CONTROL_KIND_CLOCK_PROBE, CONTROL_KIND_RTT_PROBE};
use crate::rtt_probe as rp;
use crate::routing_policy::one_way_rank_encode;
use crossbeam_channel::{after, bounded, select, Sender};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// ======================= 探测节奏与估算参数（对齐 Go 常量） =======================

/// 探测基准周期（ms）；实际间隔均匀抖动 ±RTT_PROBE_JITTER_MS。
const RTT_PROBE_BASE_INTERVAL_MS: u64 = 500;
const RTT_PROBE_JITTER_MS: u64 = 250;

/// decayed-min 的慢升速率：每秒钟最小值允许抬升的纳秒数（0.5ms/s）。
const RTT_PROBE_DECAY_PER_SEC_NS: u64 = 500_000;

/// 未回包探针的过期时间（ms）。
const RTT_PROBE_PENDING_TIMEOUT_MS: u64 = 2000;

/// 未回包探针上限（防泄漏）。
const RTT_PROBE_PENDING_MAX: usize = 256;

/// 每周期发全生成集（更快收敛、更多填充帧）；false=每周期 2 个探针轮转。
const RTT_PROBE_FAST_MODE_ALL: bool = false;

const CLOCK_OFFSET_BASE_INTERVAL_MS: u64 = 500;
const CLOCK_OFFSET_JITTER_MS: u64 = 250;

/// 判 θ 可信所需最少样本数。
const CLOCK_OFFSET_MIN_SAMPLES: usize = 8;
/// 样本环形缓冲容量上限。
const CLOCK_OFFSET_SAMPLE_CAP: usize = 256;
/// MAD→标准差的正态一致性常数（1/0.6745）。
const CLOCK_OFFSET_MAD_SCALE: f64 = 1.4826;
/// 判 θ 可用的残余不确定度上限（µs）。
const CLOCK_OFFSET_UNCERTAINTY_MAX_US: u64 = 2000;

/// 选路层编码零点（µs）——与 routing_policy::ONE_WAY_RANK_ZERO_US 一致，此处
/// 仅作发布层编码复用的引用（见 one_way_rank_encode）。
// 显示层 δ 抬升：所有有测量方向的最小值抬到 1µs 所需的公共偏移。

// ======================= 探针目标抽象 =======================

/// 调度器与物理连接（Backend）的解耦接口。Backend 在 net.rs 中实现本 trait，
/// 避免 probe_scheduler 反向依赖 net。
pub trait ProbeTarget: Send + Sync + 'static {
    /// 非阻塞投递探针帧载荷到该连接的 probe_ch。返回是否投递成功（false = 通道满，
    /// 调用方移除 pending，对齐 Go 的 select-default-delete）。
    fn push_probe(&self, payload: Vec<u8>) -> bool;
    /// 发布 RTT 探针分解结果到 Backend 原子。fwd/ret 为 None 表示该方向本轮
    /// 无测量（不覆盖旧值，对齐 Go recomputeAll 的 `if f, ok := fwdRaw[i]`）。
    fn publish_one_way(
        &self,
        fwd: Option<(u64, u64)>, // (选路 rank 编码, 显示 µs)
        ret: Option<(u64, u64)>,
        updated_ms: u64,
    );
}

// ======================= 通用工具 =======================

#[inline]
fn unix_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[inline]
fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// 从 OS 随机源取 u64（抖动用；getrandom 已是依赖）。
fn rand_u64() -> u64 {
    let mut b = [0u8; 8];
    // getrandom 失败（极罕见）退化为时间种子，不影响安全性。
    if getrandom::getrandom(&mut b).is_err() {
        return unix_ns() ^ (SystemTime::now().elapsed().map(|e| e.as_nanos() as u64).unwrap_or(0));
    }
    u64::from_le_bytes(b)
}

/// 以 base 为均值、±jitter 均匀抖动的间隔，下限 50ms（对齐 Go resetTimer）。
fn jittered_delay(base_ms: u64, jitter_ms: u64) -> Duration {
    let span = 2 * jitter_ms + 1;
    let off = rand_u64() % span;
    let ms = (base_ms + off).saturating_sub(jitter_ms).max(50);
    Duration::from_millis(ms)
}

#[inline]
fn one_way_us(sample_ns: u64) -> u64 {
    sample_ns / 1000
}

/// 显示层 δ 抬升量：所有有测量方向（fwd/ret 联合）的最小值抬到 1µs 所需的
/// 公共偏移。仅用于显示发布，选路层不得使用（对齐 Go displayDeltaUS）。
fn display_delta_us(fwd_raw: &HashMap<usize, i64>, ret_raw: &HashMap<usize, i64>) -> i64 {
    let mut min = i64::MAX;
    for &v in fwd_raw.values() {
        if v < min {
            min = v;
        }
    }
    for &v in ret_raw.values() {
        if v < min {
            min = v;
        }
    }
    if min == i64::MAX || min >= 1 {
        return 0;
    }
    1 - min
}

// ======================= RTT 探针调度器 =======================

struct PendingProbe {
    src_conn: usize,
    reply_on: usize,
    issued: Instant,
}

struct RttFrame {
    kind: u8,
    nonce: u32,
    reply_on: u32,
    send_ts: u64,
    recv_at_ns: u64,
}

/// 调度器句柄（Arc 共享）：线程安全入口。
pub struct RttProbeScheduler {
    resolve: Box<dyn Fn(usize) -> Option<Arc<dyn ProbeTarget>> + Send + Sync>,
    active_conns: Box<dyn Fn() -> Vec<usize> + Send + Sync>,
    min_half_ref_us: Box<dyn Fn() -> u64 + Send + Sync>,
    enabled: AtomicBool,
    kick_tx: Sender<()>,
    replies_tx: Sender<RttFrame>,
    stop_tx: Sender<()>,
}

/// run 线程独占的调度状态。
struct RttState {
    pending: HashMap<u32, PendingProbe>,
    decay: HashMap<(u32, u32), u64>,      // decayed-min per (src,dst)，ns
    last_decay: HashMap<(u32, u32), Instant>, // 每 key 独立的慢升计时
    nonce: u32,
    rotate: usize,
    ref_conn: usize,
    active: Vec<usize>,
}

impl RttProbeScheduler {
    /// 创建调度器（不启动探测；enabled 由握手协商后置 true）。
    pub fn new(
        resolve: Box<dyn Fn(usize) -> Option<Arc<dyn ProbeTarget>> + Send + Sync>,
        active_conns: Box<dyn Fn() -> Vec<usize> + Send + Sync>,
        min_half_ref_us: Box<dyn Fn() -> u64 + Send + Sync>,
    ) -> Arc<Self> {
        let (kick_tx, kick_rx) = bounded(1);
        let (replies_tx, replies_rx) = bounded(64);
        let (stop_tx, stop_rx) = bounded(1);
        let s = RttProbeScheduler {
            resolve,
            active_conns,
            min_half_ref_us,
            enabled: AtomicBool::new(false),
            kick_tx,
            replies_tx,
            stop_tx,
        };
        // run 线程拥有调度状态；句柄经 Arc 共享。
        let state = RttState {
            pending: HashMap::with_capacity(16),
            decay: HashMap::with_capacity(32),
            last_decay: HashMap::with_capacity(32),
            nonce: 0,
            rotate: 0,
            ref_conn: 0,
            active: Vec::new(),
        };
        let arc = Arc::new(s);
        {
            let s = arc.clone();
            let _ = std::thread::Builder::new()
                .name("rtt-probe-sched".into())
                .spawn(move || s.run(state, kick_rx, replies_rx, stop_rx));
        }
        // 调用方持有句柄 Arc；run 线程持有一份克隆，stop() 后线程退出并释放其克隆。
        arc
    }

    /// 握手协商成功后开启探测（幂等）。
    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    /// 事件驱动：后端注册/stall 恢复时立即发起一轮。
    pub fn kick(&self) {
        let _ = self.kick_tx.try_send(());
    }

    /// 终止调度线程。
    pub fn stop(&self) {
        let _ = self.stop_tx.try_send(());
    }

    /// 读循环回调（在物理连接读 goroutine 内调用，必须非阻塞）。
    pub fn on_frame(&self, payload: &[u8], _src_conn: usize) {
        if !rp::is_rtt_probe_frame(payload) {
            return;
        }
        let Ok((kind, nonce, reply_on, send_ts)) = rp::parse_rtt_probe_frame(payload) else {
            return;
        };
        let _ = self.replies_tx.try_send(RttFrame {
            kind,
            nonce,
            reply_on,
            send_ts,
            recv_at_ns: unix_ns(),
        });
    }

    fn run(
        self: Arc<Self>,
        mut state: RttState,
        kick_rx: crossbeam_channel::Receiver<()>,
        replies_rx: crossbeam_channel::Receiver<RttFrame>,
        stop_rx: crossbeam_channel::Receiver<()>,
    ) {
        loop {
            select! {
                recv(kick_rx) -> _ => {
                    if self.enabled.load(Ordering::Relaxed) {
                        self.issue_round(&mut state);
                    }
                }
                recv(replies_rx) -> fr => {
                    if let Ok(fr) = fr {
                        if fr.kind == CONTROL_KIND_RTT_PROBE {
                            self.respond(&mut state, fr);
                        } else {
                            self.absorb(&mut state, fr);
                        }
                    }
                }
                recv(stop_rx) -> _ => return,
                recv(after(jittered_delay(
                    RTT_PROBE_BASE_INTERVAL_MS,
                    RTT_PROBE_JITTER_MS,
                ))) -> _ => {
                    if self.enabled.load(Ordering::Relaxed) {
                        self.issue_round(&mut state);
                    }
                }
            }
        }
    }

    fn issue_round(&self, state: &mut RttState) {
        let active = (self.active_conns)();
        if active.len() < 2 {
            // 少于 2 条连接时无跨路径可言，仅需 ref 基线（若存在）以维持锚定。
            if active.len() == 1 {
                self.emit_probe(state, active[0], active[0]);
            }
            state.active = active;
            return;
        }
        let ref_c = active[0];
        state.ref_conn = ref_c;
        state.active = active.clone();

        // 生成集：row = {(i,ref) | i≠ref}，col = {(ref,j) | j≠ref}。
        let mut row = Vec::with_capacity(active.len() - 1);
        let mut col = Vec::with_capacity(active.len() - 1);
        for &idx in &active {
            if idx == ref_c {
                continue;
            }
            row.push(idx);
            col.push(idx);
        }

        if RTT_PROBE_FAST_MODE_ALL {
            for &i in &row {
                self.emit_probe(state, i, ref_c);
            }
            for &j in &col {
                self.emit_probe(state, ref_c, j);
            }
            self.emit_probe(state, ref_c, ref_c);
            return;
        }

        // 轮转：每周期一对 (row[k], col[k])；k==0 时附加 ref 基线。
        let n = row.len();
        if n == 0 {
            return;
        }
        let k = state.rotate % n;
        state.rotate = (k + 1) % n;
        self.emit_probe(state, row[k], ref_c);
        self.emit_probe(state, ref_c, col[k]);
        if k == 0 {
            self.emit_probe(state, ref_c, ref_c);
        }
    }

    /// 在 src 连接上发起一个"对端回包到 reply_on"的探针。
    fn emit_probe(&self, state: &mut RttState, src_conn: usize, reply_on: usize) {
        let Some(b) = (self.resolve)(src_conn) else {
            return;
        };
        state.nonce = state.nonce.wrapping_add(1);
        if state.nonce == 0 {
            state.nonce = state.nonce.wrapping_add(1);
        }
        let nonce = state.nonce;
        state.pending.insert(
            nonce,
            PendingProbe {
                src_conn,
                reply_on,
                issued: Instant::now(),
            },
        );
        Self::sweep_pending(state);
        let mut payload = Vec::new();
        rp::append_rtt_probe_frame(&mut payload, nonce, reply_on as u32);
        if !b.push_probe(payload) {
            // 通道满：放弃本次探针，移除 pending。
            state.pending.remove(&nonce);
        }
    }

    fn sweep_pending(state: &mut RttState) {
        let now = Instant::now();
        let keys: Vec<u32> = state
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.issued)
                    > Duration::from_millis(RTT_PROBE_PENDING_TIMEOUT_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            state.pending.remove(&k);
        }
        while state.pending.len() > RTT_PROBE_PENDING_MAX {
            // 保守裁剪：先删最旧的若干（HashMap 无插入序，删任意即可对齐"超量
            // 裁剪"语义；非确定序不影响正确性，仅影响被裁的是哪一帧）。
            let key = state.pending.keys().next().copied();
            match key {
                Some(k) => {
                    state.pending.remove(&k);
                }
                None => break,
            }
        }
    }

    /// 收到对端探针请求：按 reply_on 把回包注入目标连接。
    fn respond(&self, _state: &mut RttState, fr: RttFrame) {
        let Some(b) = (self.resolve)(fr.reply_on as usize) else {
            return;
        };
        let mut payload = Vec::new();
        rp::append_rtt_reply_frame(&mut payload, fr.nonce, fr.send_ts);
        let _ = b.push_probe(payload);
    }

    /// 收到回包：查 nonce、算 RTT、更新 decayed-min、重算 fwd/ret。
    fn absorb(&self, state: &mut RttState, fr: RttFrame) {
        let Some(p) = state.pending.remove(&fr.nonce) else {
            return;
        };
        let recv_ns = fr.recv_at_ns;
        if fr.send_ts == 0 || fr.send_ts > recv_ns {
            return; // 无有效 send_ts 或时钟异常，丢弃
        }
        let mut rtt = recv_ns - fr.send_ts;
        if rtt == 0 {
            rtt = 1; // 同机回环/同纳秒收发：clamp 到 1ns，防止 decay 存 0 与"未测量"哨兵混淆
        }
        Self::update_decay(state, p.src_conn as u32, p.reply_on as u32, rtt);
        self.recompute_all(state);
    }

    /// 慢升快降的 decayed-min。慢升量按 (src,dst) 独立累积。
    fn update_decay(state: &mut RttState, src: u32, dst: u32, sample_ns: u64) {
        let sample_ns = if sample_ns == 0 { 1 } else { sample_ns };
        let key = (src, dst);
        let now = Instant::now();
        let elapsed = now
            .saturating_duration_since(state.last_decay.get(&key).copied().unwrap_or(now));
        state.last_decay.insert(key, now);
        let cur = state.decay.get(&key).copied().unwrap_or(0);
        if cur == 0 {
            state.decay.insert(key, sample_ns);
            return;
        }
        // 时钟回拨（Instant 单调不会发生，但保留 saturating 语义）不做慢升。
        let mut cur = cur;
        if !elapsed.is_zero() {
            cur = cur.saturating_add(
                (elapsed.as_nanos() as u64) / 1_000_000_000 * RTT_PROBE_DECAY_PER_SEC_NS,
            );
        }
        if sample_ns < cur {
            cur = sample_ns;
        }
        state.decay.insert(key, cur);
    }

    /// 用当前锚定重算各连接 fwd/ret 并发布到 Backend 原子。
    fn recompute_all(&self, state: &mut RttState) {
        if state.active.is_empty() {
            return;
        }
        let ref_c = state.ref_conn;
        let half_ref = self.anchor_half_ref(state, ref_c);
        if half_ref == 0 {
            return; // 锚定尚未建立
        }
        let now_ms = unix_ms();

        let (fwd_raw, ret_raw) = decompose_one_way(&state.decay, &state.active, ref_c, half_ref);
        let delta = display_delta_us(&fwd_raw, &ret_raw);
        for &i in &state.active {
            let Some(b) = (self.resolve)(i) else {
                continue;
            };
            let fwd = fwd_raw.get(&i).map(|&f| (one_way_rank_encode(f), (f + delta) as u64));
            let ret = ret_raw.get(&i).map(|&r| (one_way_rank_encode(r), (r + delta) as u64));
            b.publish_one_way(fwd, ret, now_ms);
        }
    }

    /// 锚定：只用参考连接的探针自回包基线 (ref,ref)/2，抬升到 minHalfRefUS。
    fn anchor_half_ref(&self, state: &RttState, ref_c: usize) -> u64 {
        if let Some(&v) = state.decay.get(&(ref_c as u32, ref_c as u32)) {
            if v > 0 {
                let mut h = one_way_us(v) / 2;
                if h < 1 {
                    h = 1;
                }
                let mn = (self.min_half_ref_us)();
                if h < mn {
                    h = mn;
                }
                return h;
            }
        }
        0
    }
}

/// 核心分解：由 decay 矩阵 + 锚定计算每条连接有测量方向的原始有符号相对量
/// （µs，可负）。以 ref 对称基准（halfRef）锚定：
///
/// fwd_i = decay[(i,ref)] - halfRef；ret_i = decay[(ref,i)] - halfRef；ref 自身 = halfRef。
///
/// 仅包含"该方向已有探针测量"的连接。返回值直接供选路（有符号）与显示
/// （+δ）两路消费，不做任何非负化（对齐 Go decomposeOneWay）。
fn decompose_one_way(
    decay: &HashMap<(u32, u32), u64>,
    active: &[usize],
    ref_c: usize,
    half_ref: u64,
) -> (HashMap<usize, i64>, HashMap<usize, i64>) {
    let mut fwd_x = HashMap::with_capacity(active.len());
    let mut ret_x = HashMap::with_capacity(active.len());
    for &i in active {
        if i == ref_c {
            fwd_x.insert(i, half_ref as i64);
            ret_x.insert(i, half_ref as i64);
            continue;
        }
        if let Some(&v) = decay.get(&(i as u32, ref_c as u32)) {
            fwd_x.insert(i, one_way_us(v) as i64 - half_ref as i64);
        }
        if let Some(&v) = decay.get(&(ref_c as u32, i as u32)) {
            ret_x.insert(i, one_way_us(v) as i64 - half_ref as i64);
        }
    }
    (fwd_x, ret_x)
}

// ======================= 时钟偏移估计器 =======================

struct OffsetSample {
    t1: u64, // A 发送
    t2: u64, // B 接收
    t3: u64, // B 发送（回包注入时刻，对端显式回填，非 issued 近似）
    t4: u64, // A 接收
    _conn: usize,
}

/// 原子发布通道：快照读取不抢调度 goroutine 的锁。
pub struct ClockPublish {
    pub theta_ns: AtomicI64,
    pub unc_us: AtomicU64,
    pub converged: AtomicBool,
}

/// 维护样本缓冲，线性最小化估计 θ（ns，A 相对 B）+ 不确定度 U（µs）。
struct ClockEstimator {
    samples: Vec<OffsetSample>,
    head: usize, // 环形游标
    full: bool,
    est_theta_ns: i64,
    est_unc_us: u64,
    converged: bool,
    dirty: bool,
    publish: Arc<ClockPublish>,
}

impl ClockEstimator {
    fn new(publish: Arc<ClockPublish>) -> Self {
        ClockEstimator {
            samples: Vec::with_capacity(CLOCK_OFFSET_SAMPLE_CAP),
            head: 0,
            full: false,
            est_theta_ns: 0,
            est_unc_us: 0,
            converged: false,
            dirty: true,
            publish,
        }
    }

    fn add(&mut self, s: OffsetSample) {
        if self.samples.len() < CLOCK_OFFSET_SAMPLE_CAP {
            self.samples.push(s);
            self.head = 0;
            return;
        }
        self.samples[self.head] = s;
        self.head = (self.head + 1) % CLOCK_OFFSET_SAMPLE_CAP;
        self.full = true;
        self.dirty = true;
    }

    fn count(&self) -> usize {
        if self.full {
            CLOCK_OFFSET_SAMPLE_CAP
        } else {
            self.samples.len()
        }
    }

    fn refresh(&mut self) {
        if self.dirty {
            self.solve();
        }
    }

    fn solve(&mut self) {
        self.dirty = false;
        self.converged = false;
        self.est_theta_ns = 0;
        self.est_unc_us = 0;

        let n = self.count();
        if n < CLOCK_OFFSET_MIN_SAMPLES {
            return;
        }
        // 每个往返给出一个 θ 约束：θ_i = ((t2-t1) - (t4-t3))/2 = (B-F)/2。
        let mut est: Vec<i64> = Vec::with_capacity(n);
        for s in &self.samples {
            if s.t1 == 0 || s.t2 < s.t1 || s.t3 == 0 || s.t4 < s.t3 {
                continue; // 时钟异常样本丢弃
            }
            let f = (s.t2 - s.t1) as i64; // 去程分量 F + θ
            let b = (s.t4 - s.t3) as i64; // 回程分量 B - θ
            est.push((f - b) / 2);
        }
        if est.len() < CLOCK_OFFSET_MIN_SAMPLES {
            return;
        }
        est.sort_unstable();

        let med = median(&est);
        // MAD：到中位数绝对偏差的中位数，×1.4826 得一致性标准差估计。
        let mut dev: Vec<i64> = est.iter().map(|&v| (v - med).abs()).collect();
        dev.sort_unstable();
        let mad = median(&dev);
        let unc_ns = (mad as f64 * CLOCK_OFFSET_MAD_SCALE).max(0.0) as i64;
        let unc_us = (unc_ns as u64) / 1000;

        self.est_theta_ns = med;
        self.est_unc_us = unc_us;
        if unc_us <= CLOCK_OFFSET_UNCERTAINTY_MAX_US {
            self.converged = true;
        }
        self.publish.theta_ns.store(self.est_theta_ns, Ordering::Relaxed);
        self.publish.unc_us.store(self.est_unc_us, Ordering::Relaxed);
        self.publish.converged.store(self.converged, Ordering::Relaxed);
    }
}

fn median(sorted: &[i64]) -> i64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2
    }
}

// ======================= 时钟偏移调度器 =======================

struct PendingClockProbe {
    target_conn: usize,
    issued: Instant,
}

struct ClockFrame {
    kind: u8,
    nonce: u32,
    conn: u32,
    send_ts: u64,
    recv_ts: u64,
    tx_ts: u32,
    recv_at_ns: u64,
}

/// 调度器句柄（Arc 共享）。
pub struct ClockOffsetScheduler {
    resolve: Box<dyn Fn(usize) -> Option<Arc<dyn ProbeTarget>> + Send + Sync>,
    active_conns: Box<dyn Fn() -> Vec<usize> + Send + Sync>,
    enabled: AtomicBool,
    kick_tx: Sender<()>,
    replies_tx: Sender<ClockFrame>,
    stop_tx: Sender<()>,
    publish: Arc<ClockPublish>,
}

struct ClockState {
    pending: HashMap<u32, PendingClockProbe>,
    est: ClockEstimator,
    nonce: u32,
    target: usize,
}

impl ClockOffsetScheduler {
    pub fn new(
        resolve: Box<dyn Fn(usize) -> Option<Arc<dyn ProbeTarget>> + Send + Sync>,
        active_conns: Box<dyn Fn() -> Vec<usize> + Send + Sync>,
    ) -> Arc<Self> {
        let (kick_tx, kick_rx) = bounded(1);
        let (replies_tx, replies_rx) = bounded(64);
        let (stop_tx, stop_rx) = bounded(1);
        let publish = Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        });
        let s = ClockOffsetScheduler {
            resolve,
            active_conns,
            enabled: AtomicBool::new(false),
            kick_tx,
            replies_tx,
            stop_tx,
            publish: publish.clone(),
        };
        let state = ClockState {
            pending: HashMap::with_capacity(16),
            est: ClockEstimator::new(publish),
            nonce: 0,
            target: 0,
        };
        let arc = Arc::new(s);
        {
            let s = arc.clone();
            let _ = std::thread::Builder::new()
                .name("clock-probe-sched".into())
                .spawn(move || s.run(state, kick_rx, replies_rx, stop_rx));
        }
        arc
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub fn kick(&self) {
        let _ = self.kick_tx.try_send(());
    }

    pub fn stop(&self) {
        let _ = self.stop_tx.try_send(());
    }

    /// 当前估计：θ(ns)、不确定度 U(µs)、是否可信。
    pub fn theta_ns(&self) -> (i64, u64, bool) {
        if !self.publish.converged.load(Ordering::Relaxed) {
            return (0, 0, false);
        }
        (
            self.publish.theta_ns.load(Ordering::Relaxed),
            self.publish.unc_us.load(Ordering::Relaxed),
            true,
        )
    }

    pub fn on_frame(&self, payload: &[u8], _src_conn: usize) {
        if !co::is_clock_offset_frame(payload) {
            return;
        }
        let Ok((kind, nonce, conn, send_ts, recv_ts, tx_ts)) =
            co::parse_clock_offset_frame(payload)
        else {
            return;
        };
        let _ = self.replies_tx.try_send(ClockFrame {
            kind,
            nonce,
            conn,
            send_ts,
            recv_ts,
            tx_ts,
            recv_at_ns: unix_ns(),
        });
    }

    fn run(
        self: Arc<Self>,
        mut state: ClockState,
        kick_rx: crossbeam_channel::Receiver<()>,
        replies_rx: crossbeam_channel::Receiver<ClockFrame>,
        stop_rx: crossbeam_channel::Receiver<()>,
    ) {
        loop {
            select! {
                recv(kick_rx) -> _ => {
                    if self.enabled.load(Ordering::Relaxed) {
                        self.issue_round(&mut state);
                    }
                }
                recv(replies_rx) -> fr => {
                    if let Ok(fr) = fr {
                        if fr.kind == CONTROL_KIND_CLOCK_PROBE {
                            self.respond(&mut state, fr);
                        } else {
                            self.absorb(&mut state, fr);
                        }
                    }
                }
                recv(stop_rx) -> _ => return,
                recv(after(jittered_delay(
                    CLOCK_OFFSET_BASE_INTERVAL_MS,
                    CLOCK_OFFSET_JITTER_MS,
                ))) -> _ => {
                    if self.enabled.load(Ordering::Relaxed) {
                        self.issue_round(&mut state);
                    }
                }
            }
        }
    }

    fn issue_round(&self, state: &mut ClockState) {
        let active = (self.active_conns)();
        if active.is_empty() {
            return;
        }
        // 偏移估计针对 ref 连接（index 最小者），与 rttProbe 的 ref 选法一致。
        let ref_c = active[0];
        state.target = ref_c;
        self.emit_probe(state, ref_c);
    }

    fn emit_probe(&self, state: &mut ClockState, conn_index: usize) {
        let Some(b) = (self.resolve)(conn_index) else {
            return;
        };
        state.nonce = state.nonce.wrapping_add(1);
        if state.nonce == 0 {
            state.nonce = state.nonce.wrapping_add(1);
        }
        let nonce = state.nonce;
        state.pending.insert(
            nonce,
            PendingClockProbe {
                target_conn: conn_index,
                issued: Instant::now(),
            },
        );
        Self::sweep_pending(state);
        let mut payload = Vec::new();
        co::append_clock_offset_probe_frame(&mut payload, nonce, conn_index as u32);
        if !b.push_probe(payload) {
            state.pending.remove(&nonce);
        }
    }

    fn sweep_pending(state: &mut ClockState) {
        let now = Instant::now();
        let keys: Vec<u32> = state
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.issued)
                    > Duration::from_millis(RTT_PROBE_PENDING_TIMEOUT_MS)
            })
            .map(|(k, _)| *k)
            .collect();
        for k in keys {
            state.pending.remove(&k);
        }
        while state.pending.len() > RTT_PROBE_PENDING_MAX {
            match state.pending.keys().next().copied() {
                Some(k) => {
                    state.pending.remove(&k);
                }
                None => break,
            }
        }
    }

    /// 收到对端探针请求：记接收时刻 t2（recv_ts），并把回包注入时刻 t3（off_ts）
    /// 显式写入帧，供对端精确解出回程分量，不用 issued 时刻近似。
    fn respond(&self, _state: &mut ClockState, fr: ClockFrame) {
        let Some(b) = (self.resolve)(fr.conn as usize) else {
            return;
        };
        let now_ns = unix_ns();
        let now_ms = unix_ms();
        let recv_ts = now_ns;
        let tx_ts = (now_ms & 0xFFFF_FFFF) as u32; // UnixMilli 低 32 位
        let mut payload = Vec::new();
        co::append_clock_offset_reply_frame(&mut payload, fr.nonce, fr.send_ts, recv_ts, tx_ts);
        let _ = b.push_probe(payload);
    }

    /// 收到回包：查 nonce、凑齐四时间戳、喂估计器。
    fn absorb(&self, state: &mut ClockState, fr: ClockFrame) {
        let Some(p) = state.pending.remove(&fr.nonce) else {
            return;
        };
        if fr.send_ts == 0 || fr.recv_ts == 0 || fr.tx_ts == 0 {
            return; // 缺时间戳（含对端未填 off_ts）：丢弃该样本
        }
        let recv_ns = fr.recv_at_ns;
        let t3_ns = (fr.tx_ts as u64) * 1_000_000; // off_ts（UnixMilli）→ ns
        if fr.send_ts > recv_ns || fr.recv_ts > recv_ns || t3_ns > recv_ns {
            return; // 时钟异常，丢弃
        }
        state.est.add(OffsetSample {
            t1: fr.send_ts,
            t2: fr.recv_ts,
            t3: t3_ns,
            t4: recv_ns,
            _conn: p.target_conn,
        });
        state.est.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jittered_delay_stays_within_bounds() {
        for _ in 0..200 {
            let d = jittered_delay(500, 250);
            assert!(d >= Duration::from_millis(50), "下限 50ms");
            assert!(d <= Duration::from_millis(750), "上限 base+jitter");
        }
    }

    #[test]
    fn decompose_matches_go_semantics() {
        // 构造：ref=0, active=[0,1]。decay[(0,0)]=2ms（基线）→halfRef=1000µs。
        // decay[(1,0)]=4ms → fwd_1 = 4000µs - 1000µs = 3000µs。
        // decay[(0,1)]=1ms → ret_1 = 1000µs - 1000µs = 0µs。
        let mut decay = HashMap::new();
        decay.insert((0u32, 0u32), 2_000_000u64);
        decay.insert((1u32, 0u32), 4_000_000u64);
        decay.insert((0u32, 1u32), 1_000_000u64);
        let (fwd, ret) = decompose_one_way(&decay, &[0, 1], 0, 1000);
        assert_eq!(fwd[&0], 1000, "ref 自身 = halfRef");
        assert_eq!(ret[&0], 1000, "ref 自身 = halfRef");
        assert_eq!(fwd[&1], 3000, "fwd_1 = 4ms(µs) - 1ms(µs)");
        assert_eq!(ret[&1], 0, "ret_1 = 1ms(µs) - 1ms(µs) = 0");
    }

    #[test]
    fn display_delta_raises_min_to_one() {
        let mut fwd = HashMap::new();
        let mut ret = HashMap::new();
        fwd.insert(1, -500);
        ret.insert(1, -200);
        assert_eq!(display_delta_us(&fwd, &ret), 501, "δ = 1 - min = 1-(-500)");

        // 全非负：δ=0
        let mut fwd2 = HashMap::new();
        let mut ret2 = HashMap::new();
        fwd2.insert(1, 100);
        ret2.insert(1, 200);
        assert_eq!(display_delta_us(&fwd2, &ret2), 0);

        // 空：δ=0
        assert_eq!(display_delta_us(&HashMap::new(), &HashMap::new()), 0);
    }

    #[test]
    fn estimator_converges_on_consistent_samples() {
        // 对称往返，θ 恒为 0：t1=1000,t2=6000,t3=6000,t4=11000 → θ=0
        let mut est = ClockEstimator::new(Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        }));
        for i in 0..CLOCK_OFFSET_MIN_SAMPLES + 2 {
            let base = 1000u64 + (i as u64) * 10;
            est.add(OffsetSample {
                t1: base,
                t2: base + 5000,
                t3: base + 5000,
                t4: base + 10000,
                _conn: 0,
            });
        }
        est.refresh();
        assert!(est.publish.converged.load(Ordering::Relaxed));
        assert_eq!(est.publish.theta_ns.load(Ordering::Relaxed), 0);
        assert_eq!(est.publish.unc_us.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn estimator_reports_unconverged_with_few_samples() {
        let mut est = ClockEstimator::new(Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        }));
        est.add(OffsetSample {
            t1: 1000,
            t2: 6000,
            t3: 6000,
            t4: 11000,
            _conn: 0,
        });
        est.refresh();
        assert!(!est.publish.converged.load(Ordering::Relaxed));
    }

    #[test]
    fn estimator_estimates_constant_offset() {
        // 时钟偏移 θ = +1000ns：F-θ 与 B+θ 不对称。
        let mut est = ClockEstimator::new(Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        }));
        for i in 0..CLOCK_OFFSET_MIN_SAMPLES + 4 {
            let base = 1000u64 + (i as u64) * 10;
            est.add(OffsetSample {
                t1: base,
                t2: base + 5000,  // 去程含 +θ
                t3: base + 5000,
                t4: base + 11000, // 回程含 -θ
                _conn: 0,
            });
        }
        est.refresh();
        assert!(est.publish.converged.load(Ordering::Relaxed));
        // θ = ((t2-t1) - (t4-t3))/2 = (5000 - 6000)/2 = -500。绝对值 < 5000（容差）。
        let theta = est.publish.theta_ns.load(Ordering::Relaxed);
        assert_eq!(theta, -500, "θ 应为 -500ns");
    }

    #[test]
    fn median_works_for_odd_and_even() {
        assert_eq!(median(&[1, 2, 3]), 2);
        assert_eq!(median(&[1, 2, 3, 4]), 2);
        assert_eq!(median(&[]), 0);
    }
}
