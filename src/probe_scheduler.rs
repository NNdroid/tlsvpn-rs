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
/// 稳态轮转不受影响——拓扑变化后的收敛爆发（RTT_PROBE_BURST_ROUNDS）与其独立叠加。
const RTT_PROBE_FAST_MODE_ALL: bool = false;

/// 拓扑变化（kick / 连接重拨）后的收敛爆发轮数（对齐 Go rttProbeBurstRounds）。
/// 轮转模式每轮只测一对 (row[k],ref)+(ref,col[k])，n 条连接要 n 轮（~2.5s）才
/// 覆盖全生成集，期间 fwd 门宽松放行、near 窗口 lenient、排名走 min_rtt/2 回退。
/// 爆发期每轮发全生成集，bootstrap 从 ~2.5s 缩到 ~500ms；爆发结束回到轮转稳态。
/// 每轮 2n+1 ≤ 33 个探针（16 槽上限），probe_ch 容量按此上限（33）。
const RTT_PROBE_BURST_ROUNDS: u32 = 6;

/// recent-typical 伴随指标参数（对齐 Go rttProbeRecentMinSamples /
/// rttProbeJitterAllowMin/MaxUS）。decayed-min 是地板（慢升 0.5ms/s），"同连接内
/// 持续劣化"（拥塞、路由漂移，不触发重连）最长 ~90s 才被排名反映；recent 是样本
/// EWMA（α=1/2，约 2 个采样窗 ≈5s 跟随 75%），用于把排名键抬到"当前典型时延"。
const RTT_PROBE_RECENT_MIN_SAMPLES: usize = 2;
const RTT_PROBE_JITTER_ALLOW_MIN_US: i64 = 200;
const RTT_PROBE_JITTER_ALLOW_MAX_US: i64 = 5000;

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
    /// 选路 rank 为**有效值**（max(decayed-min 地板, recent-typical − 抖动容差)）
    /// 编码；display 为纯地板 + δ 抬升（显示层）。ret_congest_us 为回程拥塞抬升
    /// （回程有效值 − 回程地板，≥0；None=本轮回程无测量，保持旧值）。
    fn publish_one_way(
        &self,
        fwd: Option<(u64, u64)>, // (选路 rank 编码, 显示 µs)
        ret: Option<(u64, u64)>,
        ret_congest_us: Option<i64>,
        updated_ms: u64,
    );
    /// 探针超时（sweep_pending 清理过期 pending 时回调）：路径疑似黑洞，发出
    /// 槽位累计连续超时（对齐 Go b.probeTimeoutStreak.Add(1)）。
    fn note_probe_timeout(&self) {}
    /// 探针回包到达（absorb 收到任何回包时回调，时间戳有效性不影响健康判定）：
    /// 清零发出槽位的超时连击（对齐 Go b.probeTimeoutStreak.Store(0)）。
    fn note_probe_reply(&self) {}
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
    // recent / recent_dev / recent_n per (src,dst) 的 recent-typical 伴随指标
    // （对齐 Go recent/recentDev/recentN）：样本 EWMA（α=1/2）、|样本−EWMA| 的
    // EWMA（≈MAD）、样本计数。recent 参与排名前须 ≥ RTT_PROBE_RECENT_MIN_SAMPLES
    // 个样本（防首样本离群钉死典型值）。与 decay 同 key 同生命周期（重连一并
    // 清除）。单位 ns，0=未建立。
    recent: HashMap<(u32, u32), u64>,
    recent_dev: HashMap<(u32, u32), u64>,
    recent_n: HashMap<(u32, u32), usize>,
    // last_target 上轮 resolve 的 connIndex→目标对象。槽位换新 Backend（断线
    // 重拨/网络切换）时清 decay/recent 键并置满收敛爆发，防止新连接继承旧连接
    // 的时延地板（对齐 Go lastBackend，Arc 指针等同性判定）。
    last_target: HashMap<usize, Arc<dyn ProbeTarget>>,
    nonce: u32,
    rotate: usize,
    /// 剩余收敛爆发轮数（kick/重拨时置满，每轮递减；对齐 Go burst）。
    burst: u32,
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
            recent: HashMap::with_capacity(32),
            recent_dev: HashMap::with_capacity(32),
            recent_n: HashMap::with_capacity(32),
            last_target: HashMap::with_capacity(8),
            nonce: 0,
            rotate: 0,
            burst: 0,
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
                        // kick 语义=拓扑可能变了（后端注册/stall 恢复）：置满收敛
                        // 爆发，让新路径的全生成集在数百毫秒内覆盖，而不是等轮转
                        // ~2.5s（对齐 Go kick 分支）。
                        state.burst = RTT_PROBE_BURST_ROUNDS;
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
        // 重拨即拓扑变化：清该槽位全部探针状态并置满收敛爆发，新连接从无偏
        // 估计快速重新收敛（full-set 覆盖 ~1 轮而非轮转 n 轮）。
        self.detect_reconnected_conns(state, &active);
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

        // 收敛爆发期（或稳态 fast 模式）：每轮发全生成集。爆发轮数随轮递减，
        // 结束后回到低开销轮转（对齐 Go issueRound burst 分支）。
        if state.burst > 0 || RTT_PROBE_FAST_MODE_ALL {
            if state.burst > 0 {
                state.burst -= 1;
            }
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

    /// detect_reconnected_conns 槽位换新 Backend（断线重拨/网络切换）检测
    /// （对齐 Go detectReconnectedConns）：按 resolve 的目标对象指针等同性判定，
    /// 换新即清该槽位全部探针状态并置满收敛爆发。
    fn detect_reconnected_conns(&self, state: &mut RttState, active: &[usize]) {
        for &idx in active {
            let Some(b) = (self.resolve)(idx) else {
                continue;
            };
            if let Some(prev) = state.last_target.get(&idx) {
                if Arc::ptr_eq(prev, &b) {
                    continue;
                }
            }
            state.last_target.insert(idx, b);
            state.burst = RTT_PROBE_BURST_ROUNDS;
            let keys: Vec<(u32, u32)> = state
                .decay
                .keys()
                .filter(|k| k.0 == idx as u32 || k.1 == idx as u32)
                .copied()
                .collect();
            for key in keys {
                state.decay.remove(&key);
                state.last_decay.remove(&key);
                state.recent.remove(&key);
                state.recent_dev.remove(&key);
                state.recent_n.remove(&key);
            }
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
        self.sweep_pending(state);
        let mut payload = Vec::new();
        rp::append_rtt_probe_frame(&mut payload, nonce, reply_on as u32);
        if !b.push_probe(payload) {
            // 通道满：放弃本次探针，移除 pending。
            state.pending.remove(&nonce);
        }
    }

    fn sweep_pending(&self, state: &mut RttState) {
        let now = Instant::now();
        // 先收集（nonce, 发出槽位），再清理：清理时对发出槽位累计探针超时。
        let expired: Vec<(u32, usize)> = state
            .pending
            .iter()
            .filter(|(_, p)| {
                now.duration_since(p.issued)
                    > Duration::from_millis(RTT_PROBE_PENDING_TIMEOUT_MS)
            })
            .map(|(k, p)| (*k, p.src_conn))
            .collect();
        for (k, src_conn) in expired {
            state.pending.remove(&k);
            // 探针超时=路径疑似黑洞：对发出槽位累计连续超时（任一回包到达即
            // 清零，见 absorb），选路层按 sched_health_penalty_us 施加递增罚时。
            // 此前超时只被静默丢弃——黑洞路径的 decayed-min 地板保持陈旧低值、
            // min_rtt 不变，会持续赢得排名。槽位换新 Backend 时计数随旧对象
            // 废弃，无需显式清除（与 decay 键的 last_target 清理独立）。
            if let Some(b) = (self.resolve)(src_conn) {
                b.note_probe_timeout();
            }
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

    /// 收到回包：查 nonce、算 RTT、更新 decayed-min 与 recent-typical、重算 fwd/ret。
    fn absorb(&self, state: &mut RttState, fr: RttFrame) {
        let Some(p) = state.pending.remove(&fr.nonce) else {
            return;
        };
        // 回包到达即清零发出槽位的超时连击：即使时间戳无效（下方 return）也代表
        // 往返可达——黑洞不带白，时间戳只影响样本质量不影响健康判定。
        if let Some(b) = (self.resolve)(p.src_conn) {
            b.note_probe_reply();
        }
        let recv_ns = fr.recv_at_ns;
        if fr.send_ts == 0 || fr.send_ts > recv_ns {
            return; // 无有效 send_ts 或时钟异常，丢弃
        }
        let mut rtt = recv_ns - fr.send_ts;
        if rtt == 0 {
            rtt = 1; // 同机回环/同纳秒收发：clamp 到 1ns，防止 decay 存 0 与"未测量"哨兵混淆
        }
        Self::update_decay(state, p.src_conn as u32, p.reply_on as u32, rtt);
        Self::update_recent(state, p.src_conn as u32, p.reply_on as u32, rtt);
        self.recompute_all(state);
    }

    /// update_recent recent-typical 伴随指标：样本 EWMA（α=1/2）+ |样本−EWMA| 的
    /// EWMA（≈MAD）。decayed-min 是"历史最优地板"，对同连接内持续劣化（拥塞、
    /// 路由漂移——不触发重连）只能靠 0.5ms/s 慢升追赶（45ms 劣化 ≈90s）；EWMA 约
    /// 2 个采样窗（~5s）即可跟随 75%，供 recompute_all 把排名键抬到当前典型时延。
    /// 与 update_decay 同 key 生命周期（重连一并清除，见 detect_reconnected_conns）。
    fn update_recent(state: &mut RttState, src: u32, dst: u32, sample_ns: u64) {
        let sample_ns = if sample_ns == 0 { 1 } else { sample_ns };
        let key = (src, dst);
        let n = state.recent_n.get(&key).copied().unwrap_or(0) + 1;
        state.recent_n.insert(key, n);
        let prev = state.recent.get(&key).copied().unwrap_or(0);
        if n == 1 || prev == 0 {
            // 首样本只建立基线不产出 typical：单个样本可能是离群值，等第二个样本
            // 校准后才让 recent 参与排名（与 clockOffsetMinSamples 同思路）。
            state.recent.insert(key, sample_ns);
            state.recent_dev.insert(key, 0);
            return;
        }
        let dev = if sample_ns >= prev {
            sample_ns - prev
        } else {
            prev - sample_ns
        };
        state.recent.insert(key, (prev + sample_ns) / 2);
        let prev_dev = state.recent_dev.get(&key).copied().unwrap_or(0);
        state.recent_dev.insert(key, (prev_dev + dev) / 2);
    }

    /// recent_jitter_allow_us 由 recent_dev（≈MAD，ns）换算排名用的抖动容差
    /// （µs）：排名键抬升量为 typical − 2·MAD，容差内的抖动不惩罚（稳定路径不受
    /// EWMA 噪声影响），容差外（持续劣化）才抬升。钳制防 MAD 极端值（无线链路
    /// mad 可达数十 ms）把排名键抬成等效"禁用该路径"。
    fn recent_jitter_allow_us(dev_ns: u64) -> i64 {
        let allow = one_way_us(dev_ns) as i64 * 2;
        allow.clamp(RTT_PROBE_JITTER_ALLOW_MIN_US, RTT_PROBE_JITTER_ALLOW_MAX_US)
    }

    /// effective_one_way 选路用的有效单向值：地板与 recent-typical − 抖动容差取大
    /// （对齐 Go effectiveOneWay）。typical 缺席（样本 < RTT_PROBE_RECENT_MIN_SAMPLES）
    /// 时退纯地板——与历史行为一致，单样本可能是离群值。
    fn effective_one_way(floor: i64, typ: i64, has_typ: bool, dev_ns: u64) -> i64 {
        if !has_typ {
            return floor;
        }
        let cand = typ - Self::recent_jitter_allow_us(dev_ns);
        if cand > floor {
            cand
        } else {
            floor
        }
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

        // 双路发布：原始有符号相对量（可负）供选路，δ 抬升非负副本供面板显示。
        // δ 只进显示——选路回退链（min_rtt/2、SRTT/2）不带 δ，混排时不抵消会
        // 扭曲排名（见 decompose_one_way/display_delta_us 注释）。
        //
        // 选路值不是纯地板而是"有效去程"：max(decayed-min 地板, recent-typical −
        // 抖动容差)。地板慢升 0.5ms/s，对同连接内持续劣化（拥塞/路由漂移，不触发
        // 重连）最长 ~90s 才反映；EWMA typical ~5s 跟随，把这样的路径及时从排名
        // 上压下去（near 窗口与 fwd 门消费同一有效值，慢路径同样拿不到 parity）。
        // 显示层保持地板值：面板的 fwd_oneway_us 与 rank_key_us 本就是"面板读数 vs
        // 调度依据"两条刻意分开的数。
        let (fwd_raw, ret_raw) = decompose_one_way(&state.decay, &state.active, ref_c, half_ref);
        let delta = display_delta_us(&fwd_raw, &ret_raw);
        let (fwd_typ, ret_typ) = decompose_recent(&state.recent, &state.recent_n, &state.active, ref_c, half_ref);
        for &i in &state.active {
            let Some(b) = (self.resolve)(i) else {
                continue;
            };
            let fwd = fwd_raw.get(&i).map(|&f| {
                let typ = fwd_typ.get(&i).copied();
                let dev = state
                    .recent_dev
                    .get(&(i as u32, ref_c as u32))
                    .copied()
                    .unwrap_or(0);
                let eff = Self::effective_one_way(f, typ.unwrap_or(f), typ.is_some(), dev);
                (one_way_rank_encode(eff), (f + delta) as u64)
            });
            let ret_info = ret_raw.get(&i).map(|&r| {
                let typ = ret_typ.get(&i).copied();
                let dev = state
                    .recent_dev
                    .get(&(ref_c as u32, i as u32))
                    .copied()
                    .unwrap_or(0);
                let eff = Self::effective_one_way(r, typ.unwrap_or(r), typ.is_some(), dev);
                (one_way_rank_encode(eff), (r + delta) as u64, eff - r)
            });
            let ret = ret_info.map(|(rank, display, _)| (rank, display));
            // 回程拥塞抬升 = 有效值 − 地板 = 探针回程的排队深度。探针回包从
            // 对端的 writer 注入本连接（reply_on=i），与对端下行数据共用发送
            // 队列——该抬升即"本端 ACK 在对端下行数据后面排了多深"，是双向
            // 吞吐区间回程拥塞门（rttMode）的直接输入。typ 缺席时 eff=r ⇒
            // 抬升 0（无拥塞证据，不制造伪信号）。
            let ret_congest = ret_info.map(|(_, _, congest)| congest);
            b.publish_one_way(fwd, ret, ret_congest, now_ms);
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

/// decompose_recent recent-typical 的同锚分解（对齐 Go decomposeRecent）：与
/// decompose_one_way 同一 halfRef 锚（地板尺度），把每对 (i,ref)/(ref,i) 的样本
/// EWMA 换算成有符号相对量。仅包含样本数 ≥ RTT_PROBE_RECENT_MIN_SAMPLES 的方向；
/// ref 自身用 (ref,ref) 的 typical 半值（当前自回包 RTT 的一半相对地板锚）。EWMA
/// 是"当前典型"而地板是"历史最优"，二者相减保留同一相对序——持续劣化的路径
/// typical 抬升、稳定路径 typical ≈ 地板，argmin/near 窗口差值中的公共项（B_ref
/// 等）同样抵消。
fn decompose_recent(
    recent: &HashMap<(u32, u32), u64>,
    recent_n: &HashMap<(u32, u32), usize>,
    active: &[usize],
    ref_c: usize,
    half_ref: u64,
) -> (HashMap<usize, i64>, HashMap<usize, i64>) {
    let mut fwd_x = HashMap::with_capacity(active.len());
    let mut ret_x = HashMap::with_capacity(active.len());
    let has_typ = |k: (u32, u32)| -> bool {
        recent_n.get(&k).copied().unwrap_or(0) >= RTT_PROBE_RECENT_MIN_SAMPLES
    };
    for &i in active {
        if i == ref_c {
            let key = (ref_c as u32, ref_c as u32);
            if has_typ(key) {
                let v = recent.get(&key).copied().unwrap_or(0);
                let t = one_way_us(v) as i64 / 2 - half_ref as i64;
                fwd_x.insert(i, t);
                ret_x.insert(i, t);
            }
            continue;
        }
        let fk = (i as u32, ref_c as u32);
        if has_typ(fk) {
            let v = recent.get(&fk).copied().unwrap_or(0);
            fwd_x.insert(i, one_way_us(v) as i64 - half_ref as i64);
        }
        let rk = (ref_c as u32, i as u32);
        if has_typ(rk) {
            let v = recent.get(&rk).copied().unwrap_or(0);
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
    /// 本端收到回包（采集）时刻，solve 按它做样本老化（对齐 Go offsetSample.at）。
    at: Instant,
}

/// 样本最大年龄（对齐 Go clockOffsetSampleMaxAge）。256 样本 ≈2 分钟，网络切换
/// 后旧 regime 会拖住 θ 中位数；超龄样本直接从估计集剔除，θ 在 ~1 分钟内完成向
/// 新状态的收敛（其余寿命由 ref 切换时的整体重置兜底）。
const CLOCK_OFFSET_SAMPLE_MAX_AGE: Duration = Duration::from_secs(120);

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
            // 两个分支都必须置 dirty（对齐 Go add）：否则缓冲未满时新样本永不
            // 触发重解，θ 停在不可信态（新测试 estimator_ages_out_stale_samples
            // 暴露的既有缺陷）。
            self.dirty = true;
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
        let now = Instant::now();
        let mut est: Vec<i64> = Vec::with_capacity(n);
        for s in &self.samples {
            // 样本老化：超龄样本属于旧网络状态（路由切换、路径迁移），留在集合
            // 里会让 θ 中位数在新旧 regime 之间拖 ~2 分钟。
            if now.duration_since(s.at) > CLOCK_OFFSET_SAMPLE_MAX_AGE {
                continue;
            }
            // 只过滤缺时间戳的哨兵样本；t2<t1 / t4<t3 是跨钟（A↔B）比较，B 慢于
            // A 属合法状态（θ<0），据此丢弃会让估计器对负偏移系统性失明（对齐
            // Go solve 的过滤纪律；此前 Rust 多滤了跨钟样本，属前置偏差，本次
            // 对齐修复）。
            if s.t1 == 0 || s.t2 == 0 || s.t3 == 0 || s.t4 == 0 {
                continue;
            }
            let f = (s.t2.wrapping_sub(s.t1)) as i64; // 去程分量 F + θ
            let b = (s.t4.wrapping_sub(s.t3)) as i64; // 回程分量 B - θ
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
        if ref_c != state.target {
            // ref 变化 = 被测链路换了：θ 是"该条链路的去/回程不对称度"，旧 ref 的
            // 样本对新 ref 毫无意义——整体重置估计器，θ 从不可信态重新收敛（面板
            // 显示同步丢失，~8 个样本 ≈4s 恢复），而不是让新旧链路的 θ 混合出
            // 无人持有的伪值（对齐 Go issueRound 的 ref 切换重置）。
            state.est = ClockEstimator::new(state.est.publish.clone());
            state.target = ref_c;
        }
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
    ///
    /// t2 必须取读循环的到达时刻（fr.recv_at_ns，与 absorb 的 t4 同一打点位置），
    /// 而非本 goroutine 的 time.Now()：后者混入 replies 通道（cap 64）+ 线程
    /// 唤醒延迟 d——负载下 d 系统性偏大且方差小，会让 θ 估计带 +d/2 的固定偏置
    /// 却"低不确定度收敛"到错值。t3 依旧取注入时刻（writer 队列延迟属于回程
    /// 链路，本来就该计入 B−θ 分量，off_ts 显式回填的意义所在）。
    fn respond(&self, _state: &mut ClockState, fr: ClockFrame) {
        let Some(b) = (self.resolve)(fr.conn as usize) else {
            return;
        };
        let now_ms = unix_ms();
        let recv_ts = fr.recv_at_ns;
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
            // 采集时刻对齐读循环到达时刻（fr.recv_at_ns 反推 Instant），而非
            // 本线程 now——absorb 已滞后 replies 通道 + 唤醒延迟。
            at: Instant::now().checked_sub(Duration::from_nanos(
                unix_ns().saturating_sub(recv_ns),
            ))
            .unwrap_or_else(Instant::now),
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
                at: Instant::now(),
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
            at: Instant::now(),
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
                at: Instant::now(),
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

    // ---------- recent-typical 伴随指标（对齐 Go rtt_probe.go 新增块） ----------

    #[test]
    fn update_recent_ewma_and_mad_semantics() {
        let mut state = RttState {
            pending: HashMap::new(),
            decay: HashMap::new(),
            last_decay: HashMap::new(),
            recent: HashMap::new(),
            recent_dev: HashMap::new(),
            recent_n: HashMap::new(),
            last_target: HashMap::new(),
            nonce: 0,
            rotate: 0,
            burst: 0,
            ref_conn: 0,
            active: Vec::new(),
        };
        // 首样本只建基线不产出 typical（防首样本离群钉死典型值）：recent 存
        // 基线、MAD=0，参与排名须待 recentN ≥ RTT_PROBE_RECENT_MIN_SAMPLES。
        RttProbeScheduler::update_recent(&mut state, 1, 0, 10_000_000);
        assert_eq!(state.recent_n[&(1, 0)], 1);
        assert_eq!(state.recent[&(1, 0)], 10_000_000);
        assert_eq!(state.recent_dev[&(1, 0)], 0);
        // 第二样本 12ms：EWMA = (10+12)/2 = 11ms；MAD = (0+2)/2 = 1ms。
        RttProbeScheduler::update_recent(&mut state, 1, 0, 12_000_000);
        assert_eq!(state.recent[&(1, 0)], 11_000_000);
        assert_eq!(state.recent_dev[&(1, 0)], 1_000_000);
        assert_eq!(state.recent_n[&(1, 0)], 2);
        // 第三样本 8ms：EWMA = (11+8)/2 = 9.5ms；MAD = (1+3)/2 = 2ms。
        RttProbeScheduler::update_recent(&mut state, 1, 0, 8_000_000);
        assert_eq!(state.recent[&(1, 0)], 9_500_000);
        assert_eq!(state.recent_dev[&(1, 0)], 2_000_000);
    }

    #[test]
    fn recent_jitter_allow_us_is_clamped() {
        // allow = 2×MAD(µs)，钳制到 [200, 5000]。
        assert_eq!(RttProbeScheduler::recent_jitter_allow_us(0), 200);
        assert_eq!(RttProbeScheduler::recent_jitter_allow_us(100_000), 200); // 2×100µs=200
        assert_eq!(RttProbeScheduler::recent_jitter_allow_us(1_000_000), 2_000);
        // 无线链路 MAD 可达数十 ms：钳到 5000µs 防止抬成等效禁用。
        assert_eq!(RttProbeScheduler::recent_jitter_allow_us(40_000_000), 5_000);
    }

    #[test]
    fn effective_one_way_takes_max_of_floor_and_typical() {
        // typical 缺席 → 纯地板（历史行为）。
        assert_eq!(RttProbeScheduler::effective_one_way(5_000, 9_000, false, 0), 5_000);
        // typical − 2·MAD 低于地板 → 地板。
        assert_eq!(RttProbeScheduler::effective_one_way(5_000, 6_000, true, 1_000_000), 5_000);
        // typical − 容差高于地板 → 抬升生效（持续劣化路径被压下去）。
        assert_eq!(RttProbeScheduler::effective_one_way(5_000, 40_000, true, 1_000_000), 38_000);
    }

    #[test]
    fn decompose_recent_requires_min_samples() {
        let mut recent = HashMap::new();
        let mut recent_n = HashMap::new();
        // (1,0) 有 2 个样本（达标）、(0,1) 只有 1 个（不达标）。
        recent.insert((1u32, 0u32), 4_000_000);
        recent_n.insert((1u32, 0u32), 2);
        recent.insert((0u32, 1u32), 1_000_000);
        recent_n.insert((0u32, 1u32), 1);
        let (fwd, ret) = decompose_recent(&recent, &recent_n, &[0, 1], 0, 1_000);
        // fwd_1 = 4ms(µs) − 1ms(µs) = 3000µs；ref 自身无 typical（不发布）。
        assert_eq!(fwd[&1], 3000);
        assert!(!fwd.contains_key(&0));
        // ret_1 样本数不足 → 不发布。
        assert!(!ret.contains_key(&1));
    }

    #[test]
    fn estimator_accepts_cross_clock_negative_theta() {
        // B 慢于 A（t2<t1、t4<t3）属合法跨钟状态，θ<0：不得据此丢弃样本
        // （此前 Rust 多滤了跨钟样本，估计器对负偏移系统性失明）。
        let mut est = ClockEstimator::new(Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        }));
        for i in 0..CLOCK_OFFSET_MIN_SAMPLES + 4 {
            let base = 10_000u64 + (i as u64) * 10;
            est.add(OffsetSample {
                // F = t2−t1 = −1000（跨钟，B 钟慢 1µs）；B = t4−t3 = +1000。
                t1: base + 2000,
                t2: base + 1000, // t2 < t1：合法
                t3: base + 1000,
                t4: base + 2000, // t4 > t3
                _conn: 0,
                at: Instant::now(),
            });
        }
        est.refresh();
        assert!(est.publish.converged.load(Ordering::Relaxed));
        // θ = ((t2−t1) − (t4−t3))/2 = (−1000 − 1000)/2 = −1000ns。
        assert_eq!(est.publish.theta_ns.load(Ordering::Relaxed), -1000);
    }

    #[test]
    fn estimator_ages_out_stale_samples() {
        let mut est = ClockEstimator::new(Arc::new(ClockPublish {
            theta_ns: AtomicI64::new(0),
            unc_us: AtomicU64::new(0),
            converged: AtomicBool::new(false),
        }));
        // 全部样本按 200s 前采集：超 CLOCK_OFFSET_SAMPLE_MAX_AGE(120s) 全剔除。
        let stale = Instant::now() - Duration::from_secs(200);
        for i in 0..CLOCK_OFFSET_MIN_SAMPLES + 4 {
            let base = 1000u64 + (i as u64) * 10;
            est.add(OffsetSample {
                t1: base,
                t2: base + 5000,
                t3: base + 5000,
                t4: base + 10000,
                _conn: 0,
                at: stale,
            });
        }
        est.refresh();
        assert!(!est.publish.converged.load(Ordering::Relaxed));
        // 新鲜样本进来即可收敛（旧 regime 不再拖住中位数）。
        for i in 0..CLOCK_OFFSET_MIN_SAMPLES {
            let base = 1000u64 + (i as u64) * 10;
            est.add(OffsetSample {
                t1: base,
                t2: base + 5000,
                t3: base + 5000,
                t4: base + 10000,
                _conn: 0,
                at: Instant::now(),
            });
        }
        est.refresh();
        assert!(est.publish.converged.load(Ordering::Relaxed));
    }
}
