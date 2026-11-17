use crate::routing_policy::RoutingPolicy;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

pub const ACTIVE2_PRESSURE: u64 = 24 * 1024;
pub const ACTIVE3_PRESSURE: u64 = 96 * 1024;
pub const ACTIVE4_PRESSURE: u64 = 256 * 1024;
pub const FALLBACK_RATE_BYTES_PER_SEC: u64 = 25_000_000;
const RATE_SAMPLE_MIN_BYTES: u64 = 64 * 1024;
const RATE_SAMPLE_MAX_US: u64 = 2_000_000;
const DEMAND_SAMPLE_MIN_US: u64 = 500;
pub const ACTIVE2_RATE_BYTES_PER_SEC: u64 = 40_000_000;
pub const ACTIVE3_RATE_BYTES_PER_SEC: u64 = 100_000_000;
pub const ACTIVE4_RATE_BYTES_PER_SEC: u64 = 180_000_000;
const CARRY_BONUS_US: u64 = 150;
const STICKY_MIN_US: u64 = 500;
const STICKY_MAX_US: u64 = 5_000;
const RTT_HYSTERESIS_MIN_US: u32 = 5_000;
pub const UNKNOWN_RTT_US: u32 = 50_000;

/// 连续 RTT 采样失败达到该次数即置 stalled。RTT 每 200ms 采样一次，
/// 3 次 ≈ 600ms，足以过滤瞬时 syscall 抖动（对齐 Go rttFailuresStall）。
const RTT_FAILURES_STALL: u32 = 3;

#[inline]
fn mono_us() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START
        .get_or_init(Instant::now)
        .elapsed()
        .as_micros()
        .min(u64::MAX as u128) as u64
}

#[inline]
pub(crate) fn service_us(bytes: u64, rate: u64) -> u64 {
    if bytes == 0 {
        return 0;
    }
    let rate = rate.max(1);
    bytes.saturating_mul(1_000_000) / rate
}

#[inline]
fn service_ns(bytes: u64, rate: u64) -> i64 {
    if bytes == 0 {
        return 0;
    }
    let ns = bytes.saturating_mul(1_000_000_000) / rate.max(1);
    ns.min(i64::MAX as u64) as i64
}

#[inline]
fn sticky_slack_us(rtt: u32) -> u64 {
    let mut slack = (rtt as u64) / 16;
    if slack < STICKY_MIN_US {
        slack = STICKY_MIN_US;
    }
    if slack > STICKY_MAX_US {
        slack = STICKY_MAX_US;
    }
    slack
}

#[inline]
fn sub_saturating(v: &AtomicU64, n: u64) {
    if n == 0 {
        return;
    }
    let mut old = v.load(Ordering::Relaxed);
    loop {
        if old == 0 {
            return;
        }
        let next = old.saturating_sub(n);
        match v.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return,
            Err(actual) => old = actual,
        }
    }
}

#[derive(Debug)]
pub struct SchedulerBackendState {
    pub queued_bytes: AtomicU64,
    pub rate_bytes_per_sec: AtomicU64,
    pub eta_us: AtomicU64,
    pub active: AtomicBool,
    pub carry_pending: Arc<AtomicBool>,
    pub assigned_bytes: AtomicU64,
    pub assigned_batches: AtomicU64,
    pub fec_assigned_bytes: AtomicU64,
    pub fec_assigned_batches: AtomicU64,
    pub virtual_finish_ns: AtomicI64,
    // 健康感知：stalled 标记该后端已被判定为不健康，调度器不再向其分配数据。
    // rtt_failures 是连续 RTT 采样失败计数（对齐 Go backend_health.go）。
    pub stalled: AtomicBool,
    pub rtt_failures: AtomicU32,
    // 内核 min_rtt（无拥塞地板往返，µs）。0 = 尚未观测到（代理/非 Linux/刚建立），
    // 与 SRTT 分离：排名/资格包络用 min_rtt（稳定地板），ETA 遥测用 SRTT（含瞬时
    // 拥塞，预测更准）。对齐 Go path_quality.go adaptiveBackendMinRTT。
    pub min_rtt_cache: AtomicU32,
    // 跨路径探针单向时延（µs，raw+ONE_WAY_RANK_ZERO_US 编码，恒 >0，0=未收敛）。
    // 由探针调度器（阶段 2.5）发布；未接线前恒 0，选路走 min_rtt/2→SRTT/2 回退链。
    pub fwd_rank_us: AtomicU64,
    pub ret_rank_us: AtomicU64,
    // 显示层副本（δ 抬升非负，供快照/面板；对齐 Go fwdOneWayUS/retOneWayUS）。
    // 选路层用 fwd_rank_us/ret_rank_us（有符号原始相对量），二者绝不混用。
    pub fwd_one_way_us: AtomicU64,
    pub ret_one_way_us: AtomicU64,
    // 最近一次探针重算的 Unix 毫秒时刻（对齐 Go probeUpdatedAt；0=未收敛）。
    pub probe_updated_at: AtomicU64,
    // oneWayMode：0=roundtrip 兼容（等价 rtt/2）、1=fwd（本端 egress）、2=ret。
    // 对齐 Go client.go 的 oneWayMode* 常量；egress 方向两端均为 fwd。
    pub one_way_mode: AtomicI32,
    sample_bytes: AtomicU64,
    sample_start_us: AtomicU64,
}

impl Default for SchedulerBackendState {
    fn default() -> Self {
        Self {
            queued_bytes: AtomicU64::new(0),
            rate_bytes_per_sec: AtomicU64::new(0),
            eta_us: AtomicU64::new(0),
            active: AtomicBool::new(false),
            carry_pending: Arc::new(AtomicBool::new(false)),
            assigned_bytes: AtomicU64::new(0),
            assigned_batches: AtomicU64::new(0),
            fec_assigned_bytes: AtomicU64::new(0),
            fec_assigned_batches: AtomicU64::new(0),
            virtual_finish_ns: AtomicI64::new(0),
            stalled: AtomicBool::new(false),
            rtt_failures: AtomicU32::new(0),
            min_rtt_cache: AtomicU32::new(0),
            fwd_rank_us: AtomicU64::new(0),
            ret_rank_us: AtomicU64::new(0),
            fwd_one_way_us: AtomicU64::new(0),
            ret_one_way_us: AtomicU64::new(0),
            probe_updated_at: AtomicU64::new(0),
            one_way_mode: AtomicI32::new(crate::routing_policy::ONE_WAY_MODE_FWD),
            sample_bytes: AtomicU64::new(0),
            sample_start_us: AtomicU64::new(0),
        }
    }
}

impl SchedulerBackendState {
    #[inline]
    pub fn add_queued(&self, n: u64) {
        if n != 0 {
            self.queued_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn complete_queued(&self, n: u64) {
        sub_saturating(&self.queued_bytes, n);
    }

    #[inline]
    pub fn note_assigned(&self, n: u64) {
        if n != 0 {
            self.assigned_bytes.fetch_add(n, Ordering::Relaxed);
            self.assigned_batches.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn note_fec_assigned(&self, n: u64) {
        if n != 0 {
            self.fec_assigned_bytes.fetch_add(n, Ordering::Relaxed);
            self.fec_assigned_batches.fetch_add(1, Ordering::Relaxed);
        }
    }

    // ---- 健康感知（对齐 Go backend_health.go） ----

    /// mark_stalled 置位 stalled 标记（幂等）。调度器不再向该后端分配数据。
    #[inline]
    pub fn mark_stalled(&self) {
        self.stalled.store(true, Ordering::Relaxed);
    }

    /// is_stalled 返回该后端是否已被判定为不健康。
    #[inline]
    pub fn is_stalled(&self) -> bool {
        self.stalled.load(Ordering::Relaxed)
    }

    /// note_rtt_success 记录一次成功的 RTT 采样并清零失败计数。
    #[inline]
    pub fn note_rtt_success(&self) {
        self.rtt_failures.store(0, Ordering::Relaxed);
    }

    /// note_rtt_failure 记录一次失败的 RTT 采样；连续 RTT_FAILURES_STALL 次
    /// 即置 stalled（对齐 Go noteRTTFailure）。
    #[inline]
    pub fn note_rtt_failure(&self) {
        if self.rtt_failures.fetch_add(1, Ordering::Relaxed) + 1 >= RTT_FAILURES_STALL {
            self.mark_stalled();
        }
    }

    /// Called by this backend's sole TLS writer after the queued payload has
    /// actually drained to the transport. The EWMA is observational only: it
    /// feeds ETA/WebUI, never the WFQ scheduling weight.
    pub fn observe_delivered(&self, n: u64) {
        if n == 0 {
            return;
        }
        let now = mono_us();
        let start = self.sample_start_us.load(Ordering::Relaxed);
        if start == 0 {
            self.sample_start_us.store(now.max(1), Ordering::Relaxed);
            self.sample_bytes.store(n, Ordering::Relaxed);
            return;
        }
        let bytes = self
            .sample_bytes
            .fetch_add(n, Ordering::Relaxed)
            .saturating_add(n);
        if bytes < RATE_SAMPLE_MIN_BYTES {
            return;
        }
        let elapsed = now.saturating_sub(start);
        if elapsed > RATE_SAMPLE_MAX_US {
            self.sample_start_us.store(now.max(1), Ordering::Relaxed);
            self.sample_bytes.store(0, Ordering::Relaxed);
            return;
        }
        if elapsed < 200 {
            return;
        }
        let inst = bytes.saturating_mul(1_000_000) / elapsed.max(1);
        if inst == 0 {
            return;
        }
        let old = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        self.rate_bytes_per_sec.store(
            if old == 0 {
                inst
            } else {
                (old.saturating_mul(7).saturating_add(inst)) / 8
            },
            Ordering::Relaxed,
        );
        self.sample_bytes.store(0, Ordering::Relaxed);
        self.sample_start_us.store(now.max(1), Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> SchedulerSnapshot {
        SchedulerSnapshot {
            queued_bytes: self.queued_bytes.load(Ordering::Relaxed),
            rate_mbps: self.rate_bytes_per_sec.load(Ordering::Relaxed) as f64 * 8.0 / 1_000_000.0,
            eta_us: self.eta_us.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            carry_pending: self.carry_pending.load(Ordering::Relaxed),
            assigned_bytes: self.assigned_bytes.load(Ordering::Relaxed),
            assigned_batches: self.assigned_batches.load(Ordering::Relaxed),
            fec_assigned_bytes: self.fec_assigned_bytes.load(Ordering::Relaxed),
            fec_assigned_batches: self.fec_assigned_batches.load(Ordering::Relaxed),
            stalled: self.is_stalled(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SchedulerSnapshot {
    pub queued_bytes: u64,
    pub rate_mbps: f64,
    pub eta_us: u64,
    pub active: bool,
    pub carry_pending: bool,
    pub assigned_bytes: u64,
    pub assigned_batches: u64,
    pub fec_assigned_bytes: u64,
    pub fec_assigned_batches: u64,
    pub stalled: bool,
}

pub trait AdaptiveBackend {
    fn scheduler_state(&self) -> &SchedulerBackendState;
    fn scheduler_rtt_us(&self) -> u32;
    fn scheduler_queue_len(&self) -> usize;
    fn scheduler_queue_capacity(&self) -> usize;

    /// 内核 min_rtt（无拥塞地板往返，µs）+ 是否未知。未知时优先退回 SRTT（若
    /// 已知），再退 UNKNOWN_RTT_US 哨兵——对齐 Go adaptiveBackendMinRTT。不可把
    /// 50000µs 哨兵当真实 RTT 用：它会抬高包络地板，把合格路径挡在候选集外。
    fn scheduler_min_rtt_us(&self) -> (u32, bool) {
        let min = self.scheduler_state().min_rtt_cache.load(Ordering::Relaxed);
        if min == 0 || min == UNKNOWN_RTT_US {
            let srt = self.scheduler_rtt_us();
            if srt != 0 && srt != UNKNOWN_RTT_US {
                return (srt, false);
            }
            return (UNKNOWN_RTT_US, true);
        }
        (min, false)
    }

    /// 跨路径探针单向时延（µs，有符号，可负=快于 ref 基准）+ 是否已收敛。
    /// 未收敛返回 None；选路层据此走 min_rtt/2→SRTT/2 回退链（对齐 Go
    /// adaptiveBackendOneWayUS）。探针调度器接线（阶段 2.5）前恒为 None。
    fn scheduler_one_way_converged(&self) -> Option<i64> {
        let st = self.scheduler_state();
        let enc = match st.one_way_mode.load(Ordering::Relaxed) {
            crate::routing_policy::ONE_WAY_MODE_FWD => st.fwd_rank_us.load(Ordering::Relaxed),
            crate::routing_policy::ONE_WAY_MODE_RET => st.ret_rank_us.load(Ordering::Relaxed),
            _ => 0,
        };
        if enc > 0 {
            Some(crate::routing_policy::one_way_rank_decode(enc))
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct AdaptivePortState {
    input_total_bytes: AtomicU64,
    input_rate_bytes_per_sec: AtomicU64,
    sample_total_bytes: AtomicU64,
    sample_at_us: AtomicU64,
    pub active_paths: AtomicUsize,
    pub pressure_bytes: AtomicU64,
    // 调度器待命输入队列字节（对齐 Go AsyncPort.inputQueuedBytes），计入压力。
    pub input_queued_bytes: AtomicU64,
    // 当前 routing_algo 的 int32 码（对齐 Go AsyncPort.routingAlgo，热更原子读取）。
    pub routing_algo: AtomicI32,
}

impl Default for AdaptivePortState {
    fn default() -> Self {
        Self {
            input_total_bytes: AtomicU64::new(0),
            input_rate_bytes_per_sec: AtomicU64::new(0),
            sample_total_bytes: AtomicU64::new(0),
            sample_at_us: AtomicU64::new(0),
            active_paths: AtomicUsize::new(0),
            pressure_bytes: AtomicU64::new(0),
            input_queued_bytes: AtomicU64::new(0),
            routing_algo: AtomicI32::new(0),
        }
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    idx: usize,
    base_us: i64,
    rtt_us: u32,
    was_active: bool,
    virtual_ns: i64,
}

impl AdaptivePortState {
    #[inline]
    pub fn note_input(&self, n: u64) {
        if n != 0 {
            self.input_total_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    #[inline]
    pub fn input_rate_bytes_per_sec(&self) -> u64 {
        self.input_rate_bytes_per_sec.load(Ordering::Relaxed)
    }

    /// 调度器待命输入队列增长（对齐 Go noteInputQueued）。
    #[inline]
    pub fn note_input_queued(&self, n: u64) {
        if n != 0 {
            self.input_queued_bytes.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// 调度器待命输入队列缩减（对齐 Go noteInputDequeued，饱和防下溢）。
    #[inline]
    pub fn note_input_dequeued(&self, n: u64) {
        sub_saturating(&self.input_queued_bytes, n);
    }

    /// 热更 routing_algo（对齐 Go AsyncPort.routingAlgo 的原子 store）。
    #[inline]
    pub fn set_routing_algo(&self, algo: &str) {
        self.routing_algo
            .store(crate::routing_policy::routing_algo_code(algo), Ordering::Relaxed);
    }

    /// 当前 routing_algo 码（对齐 Go routingAlgoCode；0=auto）。
    #[inline]
    pub fn routing_algo_code(&self) -> i32 {
        self.routing_algo.load(Ordering::Relaxed)
    }

    fn observe_input_demand(&self) -> u64 {
        let now = mono_us().max(1);
        let last = self.sample_at_us.load(Ordering::Acquire);
        let total = self.input_total_bytes.load(Ordering::Relaxed);
        if last == 0 {
            if self
                .sample_at_us
                .compare_exchange(0, now, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                self.sample_total_bytes.store(total, Ordering::Relaxed);
            }
            return self.input_rate_bytes_per_sec();
        }
        let elapsed = now.saturating_sub(last);
        if elapsed < DEMAND_SAMPLE_MIN_US {
            return self.input_rate_bytes_per_sec();
        }
        if self
            .sample_at_us
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return self.input_rate_bytes_per_sec();
        }
        let prev = self.sample_total_bytes.swap(total, Ordering::AcqRel);
        let delta = total.saturating_sub(prev);
        let inst = delta.saturating_mul(1_000_000) / elapsed.max(1);
        let old = self.input_rate_bytes_per_sec();
        let next = if old == 0 || elapsed > 250_000 {
            inst
        } else {
            (old.saturating_mul(3).saturating_add(inst)) / 4
        };
        self.input_rate_bytes_per_sec.store(next, Ordering::Relaxed);
        next
    }

    pub fn active_target(pressure: u64, demand_rate: u64, eligible: usize) -> usize {
        if eligible == 0 {
            return 0;
        }
        let want = if pressure >= ACTIVE4_PRESSURE || demand_rate >= ACTIVE4_RATE_BYTES_PER_SEC {
            4
        } else if pressure >= ACTIVE3_PRESSURE || demand_rate >= ACTIVE3_RATE_BYTES_PER_SEC {
            3
        } else if pressure >= ACTIVE2_PRESSURE || demand_rate >= ACTIVE2_RATE_BYTES_PER_SEC {
            2
        } else {
            1
        };
        want.min(eligible)
    }

    #[inline]
    fn healthy<B: AdaptiveBackend>(b: &B) -> bool {
        // stalled 后端已被判定为不健康（读写失败/连续 RTT 采样失败），立即跳过，
        // 不再把数据送进死路径（对齐 Go adaptive_multipath.go isStalled）。
        if b.scheduler_state().is_stalled() {
            return false;
        }
        let cap = b.scheduler_queue_capacity();
        cap > 2 && b.scheduler_queue_len() < cap.saturating_sub(2)
    }

    /// 所有后端均不可用（stalled/满队列/RTT 超限）时的兜底选路。优先选一条未
    /// stalled 的后端，避免回退到死路径；全部 stalled 时才取 preferred/首条兜底
    /// （对齐 Go client.go pickAdaptiveBackend 的兜底逻辑）。
    fn fallback_idx<B: AdaptiveBackend>(backends: &[Arc<B>], preferred: Option<usize>) -> usize {
        if let Some(p) = preferred.filter(|i| *i < backends.len()) {
            if !backends[p].scheduler_state().is_stalled() {
                return p;
            }
        }
        if let Some(i) = backends
            .iter()
            .position(|b| !b.scheduler_state().is_stalled())
        {
            return i;
        }
        preferred.filter(|i| *i < backends.len()).unwrap_or(0)
    }

    /// Rust dispatches one VPNFrame at a time, so incoming_bytes is the frame
    /// payload charge rather than Go's 12 KiB batch charge. All other policy is
    /// intentionally identical to the validated Go scheduler.
    pub fn pick<B: AdaptiveBackend>(
        &self,
        backends: &[Arc<B>],
        preferred: Option<usize>,
        incoming_bytes: u64,
    ) -> Option<usize> {
        if backends.is_empty() {
            self.active_paths.store(0, Ordering::Relaxed);
            return None;
        }
        self.note_input(incoming_bytes);
        let policy = crate::routing_policy::routing_policy_for_code(
            self.routing_algo.load(Ordering::Relaxed),
        );
        let demand_rate = self.observe_input_demand();

        // 单后端快路径：跳过三遍全量扫描/ETA/排名（对齐 Go len==1 分支）。
        if backends.len() == 1 {
            let b = &backends[0];
            if !Self::healthy(b.as_ref()) {
                let chosen = Self::fallback_idx(backends, preferred);
                Self::commit_single(backends, chosen);
                self.active_paths.store(1, Ordering::Relaxed);
                return Some(chosen);
            }
            let st = b.scheduler_state();
            st.active.store(true, Ordering::Relaxed);
            st.virtual_finish_ns.store(0, Ordering::Relaxed);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(0);
        }

        // 压力 = 本批 + 输入队列 + 全后端排队（对齐 Go schedulerPressureFor）。
        let mut pressure = incoming_bytes
            .saturating_add(self.input_queued_bytes.load(Ordering::Relaxed));
        for b in backends {
            pressure =
                pressure.saturating_add(b.scheduler_state().queued_bytes.load(Ordering::Relaxed));
        }
        self.pressure_bytes.store(pressure, Ordering::Relaxed);

        let (min_rtt, max_rtt, reference_rate, healthy) = Self::scan_envelope(backends);
        if healthy == 0 {
            let chosen = Self::fallback_idx(backends, preferred);
            Self::commit_single(backends, chosen);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }

        let mut cands = self.build_candidates(
            policy,
            backends,
            incoming_bytes,
            min_rtt,
            max_rtt,
            reference_rate,
        );
        if cands.is_empty() {
            // 全部后端被并发排除（唯一健康者在扫描间隙被 markStalled）：补齐成员
            // 维护，否则 active 集残留旧值、activePaths 计数失真。
            let chosen = Self::fallback_idx(backends, preferred);
            Self::commit_single(backends, chosen);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }
        Self::rank_candidates(&mut cands);

        let active = Self::active_target(pressure, demand_rate, cands.len());
        let best_base = cands[0].base_us;
        if !policy.wfq || active == 1 {
            let chosen = Self::commit_single_sticky(backends, &cands, preferred, best_base, policy);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }
        let chosen = Self::dispatch_wfq(backends, &cands, active, incoming_bytes);
        self.active_paths.store(active, Ordering::Relaxed);
        Some(chosen)
    }

    /// scan_envelope 单遍合并健康计数、热身最小 RTT、资格包络与参考速率（对齐
    /// Go scanEnvelope）。minWarmed 只计"有 RTT 且完成热身（rate>0）"的健康路径
    /// ——否则测量顺序可能永久压缩候选集；参考速率只计包络内（或 fairStart）路径。
    fn scan_envelope<B: AdaptiveBackend>(
        backends: &[Arc<B>],
    ) -> (u32, u64, u64, usize) {
        let mut min_warmed = u32::MAX;
        let mut healthy = 0usize;
        for b in backends {
            if !Self::healthy(b.as_ref()) {
                continue;
            }
            healthy += 1;
            let (rtt, unknown) = b.scheduler_min_rtt_us();
            let cold = b
                .scheduler_state()
                .rate_bytes_per_sec
                .load(Ordering::Relaxed)
                == 0;
            if !unknown && !cold && rtt < min_warmed {
                min_warmed = rtt;
            }
        }
        let min_rtt = if min_warmed == u32::MAX {
            UNKNOWN_RTT_US
        } else {
            min_warmed
        };
        let rtt_slack = RTT_HYSTERESIS_MIN_US.max(min_rtt / 4);
        let max_rtt = min_rtt as u64 + rtt_slack as u64;
        let mut reference_rate = FALLBACK_RATE_BYTES_PER_SEC;
        for b in backends {
            // 与第一遍对齐：stalled/队满路径的 rate 不参与参考速率。
            if !Self::healthy(b.as_ref()) {
                continue;
            }
            let (rtt, unknown) = b.scheduler_min_rtt_us();
            let cold = b
                .scheduler_state()
                .rate_bytes_per_sec
                .load(Ordering::Relaxed)
                == 0;
            let fair_start = unknown || cold;
            let r = if fair_start { min_rtt } else { rtt };
            if !fair_start && (r as u64) > max_rtt {
                continue;
            }
            let rate = b
                .scheduler_state()
                .rate_bytes_per_sec
                .load(Ordering::Relaxed);
            if rate > reference_rate {
                reference_rate = rate;
            }
        }
        (min_rtt, max_rtt, reference_rate, healthy)
    }

    /// build_candidates 构建候选集：资格包络 + stall/队满排除，按策略算主排名键
    /// （对齐 Go buildEligibleCandidates）。
    fn build_candidates<B: AdaptiveBackend>(
        &self,
        policy: RoutingPolicy,
        backends: &[Arc<B>],
        incoming_bytes: u64,
        min_rtt: u32,
        max_rtt: u64,
        reference_rate: u64,
    ) -> Vec<Candidate> {
        let mut cands = Vec::with_capacity(backends.len());
        for (idx, b) in backends.iter().enumerate() {
            let st = b.scheduler_state();
            if !Self::healthy(b.as_ref()) {
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            // SRTT 用于 ETA 遥测（含当前拥塞）；min_rtt 用于资格包络与候选排序。
            let srt = b.scheduler_rtt_us();
            let (rtt, unknown) = b.scheduler_min_rtt_us();
            let cold = st.rate_bytes_per_sec.load(Ordering::Relaxed) == 0;
            let fair_start = unknown || cold;
            let rtt_rank = if fair_start { min_rtt } else { rtt };
            if !fair_start && (rtt_rank as u64) > max_rtt {
                // 冷路径完成热身却真正落在包络外：清掉过期成员。
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            let eta_rate = {
                let r = st.rate_bytes_per_sec.load(Ordering::Relaxed);
                if r == 0 {
                    reference_rate
                } else {
                    r
                }
            };
            let mut eta = (srt as u64) / 2
                + service_us(
                    st.queued_bytes.load(Ordering::Relaxed).saturating_add(incoming_bytes),
                    eta_rate.max(1),
                );
            if st.carry_pending.load(Ordering::Relaxed) && eta > CARRY_BONUS_US {
                eta -= CARRY_BONUS_US;
            }
            st.eta_us.store(eta, Ordering::Relaxed);
            // 主排名键：one-way 为有符号原始相对量（探针收敛时负=快于 ref 基准）。
            // 完全未测路径（one-way/min_rtt/SRTT 全未知）折到参考 minRTT/2。
            let mut one_way = Self::backend_one_way_us(b.as_ref());
            if b.scheduler_one_way_converged().is_none() {
                let (_, mr_unknown) = b.scheduler_min_rtt_us();
                let srt_raw = b.scheduler_rtt_us();
                let srtt_unknown = srt_raw == 0 || srt_raw == UNKNOWN_RTT_US;
                if mr_unknown && srtt_unknown {
                    one_way = (min_rtt as i64) / 2;
                }
            }
            let sched_rate = FALLBACK_RATE_BYTES_PER_SEC;
            let base_us = crate::routing_policy::candidate_rank_us(
                policy, one_way, rtt_rank, srt, incoming_bytes, sched_rate,
            );
            cands.push(Candidate {
                idx,
                base_us,
                rtt_us: rtt_rank,
                was_active: st.active.load(Ordering::Relaxed),
                virtual_ns: st.virtual_finish_ns.load(Ordering::Relaxed),
            });
        }
        cands
    }

    /// 探针单向时延回退链（对齐 Go adaptiveBackendOneWayUS）：收敛的跨路径原始
    /// 相对量优先，否则回退 min_rtt/2（无拥塞地板），再退 SRTT/2。
    pub(crate) fn backend_one_way_us<B: AdaptiveBackend>(b: &B) -> i64 {
        if let Some(v) = b.scheduler_one_way_converged() {
            return v;
        }
        if let (mr, false) = b.scheduler_min_rtt_us() {
            return (mr as i64) / 2;
        }
        (b.scheduler_rtt_us() as i64) / 2
    }

    /// 按主排名键稳定排序（baseUS 平局→rttUS→wasActive，热路径优先；对齐 Go
    /// rankCandidates）。
    fn rank_candidates(cands: &mut [Candidate]) {
        for i in 1..cands.len() {
            let x = cands[i];
            let mut j = i;
            while j > 0 {
                let p = &cands[j - 1];
                let before = x.base_us < p.base_us
                    || (x.base_us == p.base_us && x.rtt_us < p.rtt_us)
                    || (x.base_us == p.base_us
                        && x.rtt_us == p.rtt_us
                        && x.was_active
                        && !p.was_active);
                if !before {
                    break;
                }
                cands[j] = cands[j - 1];
                j -= 1;
            }
            cands[j] = x;
        }
    }

    /// 单活跃路径提交：置 active + 清空虚拟债务（对齐 Go commitSinglePath 的清
    /// 债动作 + fallbackSinglePath）。
    fn commit_single<B: AdaptiveBackend>(backends: &[Arc<B>], chosen: usize) {
        for (i, b) in backends.iter().enumerate() {
            let st = b.scheduler_state();
            st.active.store(i == chosen, Ordering::Relaxed);
            st.virtual_finish_ns.store(0, Ordering::Relaxed);
        }
    }

    /// 单路径提交 + sticky 滞回（对齐 Go commitSinglePath）：严格模式直接取
    /// rank[0]；sticky 模式在粘滞带内保留当前路径。
    fn commit_single_sticky<B: AdaptiveBackend>(
        backends: &[Arc<B>],
        cands: &[Candidate],
        preferred: Option<usize>,
        best_base: i64,
        policy: RoutingPolicy,
    ) -> usize {
        let mut chosen = cands[0].idx;
        if policy.sticky {
            if let Some(current) = preferred {
                if current != chosen {
                    if let Some(c) = cands.iter().find(|c| c.idx == current) {
                        let slack = sticky_slack_us(c.rtt_us);
                        if c.base_us <= best_base.saturating_add(slack as i64) {
                            chosen = current;
                        }
                    }
                }
            }
        }
        Self::commit_single(backends, chosen);
        chosen
    }

    /// 活跃集内按虚拟服务债务分摊（WFQ/stride）：债务不随墙钟衰减，快速写者清空
    /// 浅队列后仍会把连续批次条带化到不同活跃路径（对齐 Go dispatchWFQ）。
    fn dispatch_wfq<B: AdaptiveBackend>(
        backends: &[Arc<B>],
        cands: &[Candidate],
        active: usize,
        incoming_bytes: u64,
    ) -> usize {
        let mut epoch: Option<i64> = None;
        for c in cands.iter().take(active) {
            if c.was_active {
                epoch = Some(epoch.map_or(c.virtual_ns, |e| e.min(c.virtual_ns)));
            }
        }
        let epoch = epoch.unwrap_or(0);
        for (rank, c) in cands.iter().enumerate() {
            let st = backends[c.idx].scheduler_state();
            if rank >= active {
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
            } else {
                if !c.was_active {
                    st.virtual_finish_ns.store(epoch, Ordering::Relaxed);
                }
                st.active.store(true, Ordering::Relaxed);
            }
        }

        let mut min_virtual = i64::MAX;
        for c in cands.iter().take(active) {
            min_virtual = min_virtual.min(
                backends[c.idx]
                    .scheduler_state()
                    .virtual_finish_ns
                    .load(Ordering::Relaxed),
            );
        }
        if min_virtual != 0 && min_virtual != i64::MAX {
            for c in cands.iter().take(active) {
                backends[c.idx]
                    .scheduler_state()
                    .virtual_finish_ns
                    .fetch_sub(min_virtual, Ordering::Relaxed);
            }
        }

        let score = |idx: usize| -> i64 {
            let s = backends[idx].scheduler_state();
            let mut v = s.virtual_finish_ns.load(Ordering::Relaxed)
                + service_ns(
                    s.queued_bytes.load(Ordering::Relaxed),
                    FALLBACK_RATE_BYTES_PER_SEC,
                );
            if s.carry_pending.load(Ordering::Relaxed) {
                v = v.saturating_sub((CARRY_BONUS_US * 1_000) as i64);
            }
            v
        };
        let mut chosen = cands[0];
        let mut chosen_score = score(chosen.idx);
        for c in cands.iter().take(active).skip(1) {
            let s = score(c.idx);
            if s < chosen_score || (s == chosen_score && c.rtt_us < chosen.rtt_us) {
                chosen = *c;
                chosen_score = s;
            }
        }
        backends[chosen.idx]
            .scheduler_state()
            .virtual_finish_ns
            .fetch_add(
                service_ns(incoming_bytes, FALLBACK_RATE_BYTES_PER_SEC),
                Ordering::Relaxed,
            );
        chosen.idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    struct TestBackend {
        rtt: AtomicU32,
        q_len: AtomicUsize,
        cap: usize,
        sched: SchedulerBackendState,
    }

    impl TestBackend {
        fn new(rtt: u32) -> Self {
            Self {
                rtt: AtomicU32::new(rtt),
                q_len: AtomicUsize::new(0),
                cap: 32,
                sched: SchedulerBackendState::default(),
            }
        }
    }

    impl AdaptiveBackend for TestBackend {
        fn scheduler_state(&self) -> &SchedulerBackendState {
            &self.sched
        }
        fn scheduler_rtt_us(&self) -> u32 {
            self.rtt.load(Ordering::Relaxed)
        }
        fn scheduler_queue_len(&self) -> usize {
            self.q_len.load(Ordering::Relaxed)
        }
        fn scheduler_queue_capacity(&self) -> usize {
            self.cap
        }
    }

    /// 构造带单向时延估计（fwd/ret，µs）与 min_rtt 的合成后端（对齐 Go
    /// oneWayBackend）。egress 方向用 oneWayModeFwd，使 scheduler_one_way_converged
    /// 使用 fwd 而非回退 min_rtt/2。
    fn one_way_backend(min_rtt: u32, fwd_us: i64, ret_us: i64, rate: u64) -> TestBackend {
        let mut b = TestBackend::new(min_rtt);
        b.sched.min_rtt_cache.store(min_rtt, Ordering::Relaxed);
        b.sched.fwd_rank_us.store(
            crate::routing_policy::one_way_rank_encode(fwd_us),
            Ordering::Relaxed,
        );
        b.sched.ret_rank_us.store(
            crate::routing_policy::one_way_rank_encode(ret_us),
            Ordering::Relaxed,
        );
        if rate > 0 {
            b.sched.rate_bytes_per_sec.store(rate, Ordering::Relaxed);
        }
        b.sched
            .one_way_mode
            .store(crate::routing_policy::ONE_WAY_MODE_FWD, Ordering::Relaxed);
        b
    }

    // ---- 移植 Go adaptive_switch_test.go（单向时延切换/滞回/冷路径） ----

    /// 切换核心：当前活跃路径之外存在 egress 单向时延显著更好（> 滞回 slack）
    /// 的健康路径时，调度器必须切换过去。
    #[test]
    fn switch_to_strictly_better_one_way_path() {
        let p = AdaptivePortState::default();
        // 当前活跃：fwd=82ms（滞回 slack = clamp(168ms/16,0.5,5)=5ms）
        let active = Arc::new(one_way_backend(168_000, 82_000, 80_000, 30_000_000));
        // 更优候选：fwd=70ms，比活跃好 12ms（远超 5ms slack）
        let better = Arc::new(one_way_backend(166_000, 70_000, 90_000, 20_000_000));
        let backends = vec![active.clone(), better.clone()];
        let got = p.pick(&backends, Some(0), 8 * 1024).unwrap();
        assert_eq!(got, 1, "strictly-better path not adopted");
        assert!(better.sched.active.load(Ordering::Relaxed));
        assert!(!active.sched.active.load(Ordering::Relaxed));
    }

    /// 滞回核心：更优候选只差 3ms（< 5ms slack）时保持当前路径。
    #[test]
    fn switch_rejects_within_sticky_slack() {
        let p = AdaptivePortState::default();
        let active = Arc::new(one_way_backend(168_000, 82_000, 80_000, 30_000_000));
        let slightly = Arc::new(one_way_backend(166_000, 79_000, 90_000, 20_000_000));
        let backends = vec![active.clone(), slightly.clone()];
        let got = p.pick(&backends, Some(0), 8 * 1024).unwrap();
        assert_eq!(got, 0, "within sticky slack must not switch");
    }

    /// 滞回边界：候选比活跃好 6ms（> 5ms 封顶 slack）时必须切换。
    #[test]
    fn switch_to_better_beyond_slack_boundary() {
        let p = AdaptivePortState::default();
        let active = Arc::new(one_way_backend(168_000, 82_000, 80_000, 30_000_000));
        let beyond = Arc::new(one_way_backend(166_000, 76_000, 90_000, 20_000_000));
        let backends = vec![active, beyond.clone()];
        let got = p.pick(&backends, Some(0), 8 * 1024).unwrap();
        assert_eq!(got, 1, "6ms-better path not adopted");
    }

    /// 不变量：多路径派发后 chosen 必须处于活跃集合。
    #[test]
    fn preferred_is_always_active_after_multipath() {
        let p = AdaptivePortState::default();
        let a = Arc::new(one_way_backend(160_000, 80_000, 80_000, 30_000_000));
        let b = Arc::new(one_way_backend(170_000, 85_000, 85_000, 30_000_000));
        let backends = vec![a.clone(), b.clone()];
        // 高负载（incoming >= ACTIVE2_PRESSURE）：进入多路径模式（active=2）。
        let got = p.pick(&backends, None, ACTIVE2_PRESSURE).unwrap();
        assert!(
            backends[got].sched.active.load(Ordering::Relaxed),
            "chosen backend must be active after multi-path dispatch"
        );
    }

    /// 冷启动/未测路径不得仅凭未知 RTT 的乐观估计抢走活跃槽位：未测路径
    /// （min_rtt 与 SRTT 全未知）应排在已测健康路径之后，而不是被当成"最佳"。
    #[test]
    fn cold_unmeasured_path_does_not_steal_slot() {
        let p = AdaptivePortState::default();
        let warm = Arc::new(one_way_backend(170_000, 85_000, 85_000, 30_000_000));
        // 全新路径：rtt/min_rtt 为 0（尚未采样），rate=0（冷）。
        let cold = Arc::new(TestBackend::new(0));
        let backends = vec![warm.clone(), cold.clone()];
        let got = p.pick(&backends, Some(0), 8 * 1024).unwrap();
        assert_eq!(got, 0, "cold unmeasured path stole active slot");
    }

    #[test]
    fn active_target_matches_go_thresholds() {
        assert_eq!(AdaptivePortState::active_target(0, 0, 4), 1);
        assert_eq!(AdaptivePortState::active_target(ACTIVE2_PRESSURE, 0, 4), 2);
        assert_eq!(AdaptivePortState::active_target(ACTIVE3_PRESSURE, 0, 4), 3);
        assert_eq!(AdaptivePortState::active_target(ACTIVE4_PRESSURE, 0, 4), 4);
        assert_eq!(AdaptivePortState::active_target(ACTIVE4_PRESSURE, 0, 2), 2);
    }

    #[test]
    fn low_rate_path_is_sticky() {
        let p = AdaptivePortState::default();
        let a = Arc::new(TestBackend::new(20_000));
        let b = Arc::new(TestBackend::new(20_000));
        let paths = vec![a, b];
        let first = p.pick(&paths, None, 1400).unwrap();
        let second = p.pick(&paths, Some(first), 1400).unwrap();
        assert_eq!(first, second);
        assert_eq!(p.active_paths.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn materially_slower_rtt_is_excluded() {
        let p = AdaptivePortState::default();
        let paths = vec![
            Arc::new(TestBackend::new(20_000)),
            Arc::new(TestBackend::new(21_000)),
            Arc::new(TestBackend::new(60_000)),
        ];
        // 热路径（对齐 Go TestAdaptiveSchedulerExcludesMateriallySlowerRTT）：
        // 包络只对完成热身（rate>0）且有 RTT 的路径收紧，冷路径全部 fairStart。
        for path in &paths {
            path.sched
                .rate_bytes_per_sec
                .store(100_000_000, Ordering::Relaxed);
        }
        let _ = p.pick(&paths, None, ACTIVE4_PRESSURE);
        assert!(paths[0].sched.active.load(Ordering::Relaxed));
        assert!(paths[1].sched.active.load(Ordering::Relaxed));
        assert!(!paths[2].sched.active.load(Ordering::Relaxed));
        assert_eq!(p.active_paths.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn high_demand_stripes_equal_rtt_paths() {
        let p = AdaptivePortState::default();
        let paths: Vec<_> = (0..4).map(|_| Arc::new(TestBackend::new(20_000))).collect();
        // Direct pressure is sufficient to open all paths; logical debt then
        // keeps consecutive frame charges from collapsing onto one backend.
        let mut counts = [0usize; 4];
        let mut preferred = None;
        for _ in 0..40 {
            let idx = p.pick(&paths, preferred, ACTIVE4_PRESSURE).unwrap();
            counts[idx] += 1;
            preferred = Some(idx);
        }
        assert!(counts.iter().all(|n| *n > 0), "counts={counts:?}");
        let min = *counts.iter().min().unwrap();
        let max = *counts.iter().max().unwrap();
        assert!(max - min <= 2, "counts={counts:?}");
    }

    #[test]
    fn carry_is_only_a_tie_breaker() {
        let p = AdaptivePortState::default();
        // 热路径：包络需 min_rtt 收紧才让 40k 的 far 被排除（对齐 Go 测试模式）。
        let warm = |t: &TestBackend| {
            t.sched
                .rate_bytes_per_sec
                .store(100_000_000, Ordering::Relaxed);
        };
        let a = Arc::new(TestBackend::new(20_000));
        warm(&a);
        let b = Arc::new(TestBackend::new(20_000));
        warm(&b);
        b.sched.carry_pending.store(true, Ordering::Relaxed);
        let paths = vec![a.clone(), b.clone()];
        let idx = p.pick(&paths, None, ACTIVE2_PRESSURE).unwrap();
        assert_eq!(idx, 1);

        let far = Arc::new(TestBackend::new(40_000));
        warm(&far);
        far.sched.carry_pending.store(true, Ordering::Relaxed);
        let paths = vec![a, far];
        let idx = p.pick(&paths, None, ACTIVE2_PRESSURE).unwrap();
        assert_eq!(idx, 0);
    }

    #[test]
    fn queue_accounting_saturates() {
        let s = SchedulerBackendState::default();
        s.add_queued(1400);
        assert_eq!(s.queued_bytes.load(Ordering::Relaxed), 1400);
        s.complete_queued(1400);
        assert_eq!(s.queued_bytes.load(Ordering::Relaxed), 0);
        s.complete_queued(1400);
        assert_eq!(s.queued_bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn stalled_backend_is_unhealthy() {
        let b = TestBackend::new(20_000);
        assert!(AdaptivePortState::healthy(&b));
        b.sched.mark_stalled();
        assert!(!AdaptivePortState::healthy(&b));
    }

    #[test]
    fn pick_falls_back_to_first_non_stalled_when_all_unhealthy() {
        let p = AdaptivePortState::default();
        // 三条都被判 stalled（队列为空但 stalled），pick 应回退到首条非 stalled 兜底
        // 或 preferred。全部 stalled 时取 preferred/0。
        let paths: Vec<_> = (0..3).map(|_| Arc::new(TestBackend::new(20_000))).collect();
        for b in &paths {
            b.sched.mark_stalled();
        }
        let idx = p.pick(&paths, Some(2), ACTIVE4_PRESSURE).unwrap();
        assert_eq!(idx, 2, "全部 stalled 时回退 preferred");

        // 首条非 stalled 优先：preferred 是 stalled 的 1 号，应选 0 号。
        let paths2 = vec![
            Arc::new(TestBackend::new(20_000)),
            Arc::new(TestBackend::new(20_000)),
        ];
        paths2[1].sched.mark_stalled();
        let idx2 = p.pick(&paths2, Some(1), ACTIVE4_PRESSURE).unwrap();
        assert_eq!(idx2, 0, "preferred stalled 时回退首条非 stalled");
    }
}

#[cfg(test)]
mod fec_assignment_telemetry_tests {
    use super::*;

    #[test]
    fn fec_assignment_is_reported_separately_from_data() {
        let s = SchedulerBackendState::default();
        s.note_assigned(1200);
        s.note_fec_assigned(300);
        let snap = s.snapshot();
        assert_eq!(snap.assigned_bytes, 1200);
        assert_eq!(snap.assigned_batches, 1);
        assert_eq!(snap.fec_assigned_bytes, 300);
        assert_eq!(snap.fec_assigned_batches, 1);
    }

    #[test]
    fn rtt_failures_stall_after_threshold() {
        let s = SchedulerBackendState::default();
        assert!(!s.is_stalled());
        // RTT_FAILURES_STALL 次失败后置 stalled。
        for _ in 0..RTT_FAILURES_STALL {
            s.note_rtt_failure();
        }
        assert!(s.is_stalled());
        // 成功采样清零失败计数；但 stalled 一旦置位不自动清除（对齐 Go）。
        s.note_rtt_success();
        assert_eq!(s.rtt_failures.load(Ordering::Relaxed), 0);
        assert!(s.is_stalled());
        // 新对象：未达阈值前不 stalled。
        let s2 = SchedulerBackendState::default();
        s2.note_rtt_failure();
        s2.note_rtt_failure();
        assert!(!s2.is_stalled());
        assert_eq!(s2.rtt_failures.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn stalled_is_reported_in_snapshot() {
        let s = SchedulerBackendState::default();
        assert!(!s.snapshot().stalled);
        s.mark_stalled();
        assert!(s.snapshot().stalled);
    }
}
