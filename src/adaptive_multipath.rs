use crate::routing_policy::RoutingPolicy;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use parking_lot::Mutex;
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
/// 粘滞滞回下限 1ms：低 RTT 路径的 rtt/16（如 5ms 路径 → 312µs）窄于排名键
/// 自身允许的抖动容差（探针层 200–5000µs），500µs 带宽会在抖动边界 churn。
/// 1ms 对亚 10ms 路径仍是紧滞回（切换响应 <1 个抖动窗），只消除边界抖动。
const STICKY_MIN_US: u64 = 1_000;
const STICKY_MAX_US: u64 = 5_000;
const RTT_HYSTERESIS_MIN_US: u32 = 5_000;
pub const UNKNOWN_RTT_US: u32 = 50_000;

/// writer 循环的 TCP_INFO/容量采样周期（ms，对齐 Go backend_health.go
/// rttSampleInterval；与 note_capacity_sample 的窗口基准共用，两处必须一致）。
pub const RTT_SAMPLE_INTERVAL_MS: u64 = 200;

/// 重传惩罚（对齐 Go retransPenaltyUS）：最近采样窗（200ms）内每次 TCP 重传段
/// 在兜底 backendScore 上加的微秒数。重传意味着路径正在丢段——时延地板对丢包
/// 不敏感，丢包路径的"真实质量"应显著差于其地板。
pub const RETRANS_PENALTY_US: u64 = 2_000;

/// 健康罚时的默认单位值（µs，对齐 Go retransRankPenaltyUS/probeTimeoutPenaltyUS
/// 与 schedHealthPenaltyDefaultUS）：每次探针连续超时/每个 200ms 窗重传段在
/// adaptive 排名键上加的微秒数，可配 sched_health_penalty_us 热更，0=禁用。
pub const SCHED_HEALTH_PENALTY_DEFAULT_US: u32 = 2_000;
/// 罚时总量封顶：超时与重传各自封顶到该值，防大量事件叠加把排名键抬成等效禁用。
pub const SCHED_HEALTH_PENALTY_MAX_US: u64 = 10_000;
/// sched_health_penalty_us 配置上限：超过它单次事件即顶满总量封顶。
pub const SCHED_HEALTH_PENALTY_MAX_CONFIG_US: i64 = 60_000;

/// 内核 RTT 有效地板发布前的最少采样数（对齐 Go rttEffMinSamples）。首样本可能
/// 是握手期离群值（TCP 慢启动/拥塞窗口未稳），与探针层 recent 最少样本同纪律。
const RTT_EFF_MIN_SAMPLES: u32 = 2;

/// 活跃路径数上限（对齐 Go adaptiveActiveMax）。阈值式与容量驱动扩张都封顶在
/// 4——与历史行为一致，也匹配 FEC parity 目标与接收端重排窗口的小集合假设。
const ADAPTIVE_ACTIVE_MAX: usize = 4;

/// 资格门准入窗口默认值（ms，对齐 Go schedEnvelopeDefaultMs）。
pub const SCHED_ENVELOPE_DEFAULT_MS: u64 = 20;
/// 资格门准入窗口配置范围（对齐 Go schedEnvelopeMinMs/MaxMs）。
pub const SCHED_ENVELOPE_MIN_MS: i64 = 1;
pub const SCHED_ENVELOPE_MAX_MS: i64 = 500;

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

/// 内核 RTT 有效地板的慢升速率（µs 地板用 ns 累计）：与探针层
/// probe_scheduler::RTT_PROBE_DECAY_PER_SEC_NS 同一常量（0.5ms/s，RTT 尺度），
/// 对齐 Go noteRTTSample 复用 rttProbeDecayPerSecNS。
const RTT_EFF_DECAY_PER_SEC_NS: u64 = 500_000;

/// decayed-min 更新纯函数（对齐 Go decayedMinUpdate）：cur==0 直接取样本；
/// elapsed>0 按每秒 decay 慢升；样本更低即快降。elapsed<0（时钟回拨）不慢升。
fn decayed_min_update(cur: u64, elapsed_ns: i64, sample: u64, decay_per_sec_ns: u64) -> u64 {
    if cur == 0 {
        return sample;
    }
    let mut cur = cur;
    if elapsed_ns > 0 {
        cur = cur.saturating_add((elapsed_ns as u64) / 1_000_000_000 * decay_per_sec_ns);
    }
    if sample < cur {
        cur = sample;
    }
    cur
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
    // 双向时钟偏移 θ（ns，客户端视角相对服务端）+ 不确定度 U（µs）+ 是否可信。
    // 由 AsyncPort 的 set_clock_offset_theta 在快照前发布（对齐 Go
    // schedulerConnJSON.clock_offset_*）；0/0/false=未收敛。
    pub clock_offset_ns: AtomicI64,
    pub clock_offset_unc_us: AtomicU64,
    pub clock_offset_converged: AtomicBool,
    // oneWayMode：0=roundtrip 兼容（等价 rtt/2）、1=fwd（本端 egress）、2=ret。
    // 对齐 Go client.go 的 oneWayMode* 常量；egress 方向两端均为 fwd。
    pub one_way_mode: AtomicI32,
    // 回程拥塞抬升（µs，≥0，对齐 Go retCongestUS）：回程有效值 − 回程 decayed-min
    // 地板 = 探针回程排队深度 = 对端发送方向（本端 ACK 方向）的排队深度。双向
    // 吞吐区间（rttMode）的回程拥塞门据此排除"ACK 被对端下行数据踩死"的路径。
    // 0=未收敛或无拥塞。由探针调度器发布。
    pub ret_congest_us: AtomicI64,
    // TCP 重传差分（对齐 Go retransDelta）：最近采样窗（200ms）的重传段数，
    // backendScore 重传惩罚与 adaptive 健康罚时的输入。0=本窗无重传。
    pub retrans_delta: AtomicU32,
    // 跨路径探针连续超时计数（对齐 Go probeTimeoutStreak）：该槽位发出的探针
    // 连续未回包，任一回包到达即清零。>0 = 路径疑似黑洞，排名层按
    // sched_health_penalty_us 施加递增罚时。
    pub probe_timeout_streak: AtomicU32,
    // 饱和门控容量估计（对齐 Go deliverRateBytesPerSec）：conn.Write 阻塞 ≥ 半窗
    // 才结算，EWMA α=1/2。容量加权 WFQ 的权重源；0=未测得（回退防饿地板/25MB/s）。
    pub deliver_rate_bytes_per_sec: AtomicU64,
    // 非饱和窗的 BDP 容量下界（对齐 Go bdpRateBytesPerSec，cwnd×mss/srtt）。
    // 永不饱和的快路径借此获得真实量级的容量估计。0=未测得。
    pub bdp_rate_bytes_per_sec: AtomicU64,
    // 内核 RTT 有效地板（对齐 Go effRttUS，decayed-min over SRTT 采样：慢升
    // 0.5ms/s、快降）。0=未建立（回退 min_rtt/SRTT 链）。修复 tcpi_min_rtt 是
    // min-ever、对持续劣化永久钝感的问题。
    pub eff_rtt_us: AtomicU32,
    // writer/采样线程独占的窗口累计与差分基线。Rust 侧采样与 TLS 写在同一连接
    // 线程（对齐 Go 同 goroutine 纪律），但字段必须住 &self：Mutex 承载"单一
    // 写者"语义，锁窗口仅覆盖两次字段读写。
    capacity_window: Mutex<CapacityWindow>,
    rtt_eff: Mutex<RttEffAccum>,
    sample_bytes: AtomicU64,
    sample_start_us: AtomicU64,
}

/// writer 写阻塞时长/载荷的采样窗累计（对齐 Go writeBusyNS/writeWindowBytes）。
#[derive(Debug, Default)]
struct CapacityWindow {
    write_busy_ns: i64,
    write_window_bytes: u64,
    retrans_base: u32,
    retrans_base_set: bool,
}

/// 内核 RTT 有效地板的 decayed-min 累计（对齐 Go rttEffFloorNS/rttEffN/rttEffLast）。
#[derive(Debug, Default)]
struct RttEffAccum {
    floor_ns: u64,
    n: u32,
    last: Option<Instant>,
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
            clock_offset_ns: AtomicI64::new(0),
            clock_offset_unc_us: AtomicU64::new(0),
            clock_offset_converged: AtomicBool::new(false),
            one_way_mode: AtomicI32::new(crate::routing_policy::ONE_WAY_MODE_FWD),
            ret_congest_us: AtomicI64::new(0),
            retrans_delta: AtomicU32::new(0),
            probe_timeout_streak: AtomicU32::new(0),
            deliver_rate_bytes_per_sec: AtomicU64::new(0),
            bdp_rate_bytes_per_sec: AtomicU64::new(0),
            eff_rtt_us: AtomicU32::new(0),
            capacity_window: Mutex::new(CapacityWindow::default()),
            rtt_eff: Mutex::new(RttEffAccum::default()),
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

    /// note_retrans 吸收一次 TCP_INFO 采样的 tcpi_total_retrans 累计值，按采样窗
    /// 做差发布到 retrans_delta（对齐 Go Backend.noteRetrans）。采样线程独占；
    /// 计数回绕/新 socket（total < base）按"重置基线"处理，本窗不产 delta。
    pub fn note_retrans(&self, total: u32) {
        let mut w = self.capacity_window.lock();
        if !w.retrans_base_set {
            w.retrans_base_set = true;
            w.retrans_base = total;
            return; // 首采样只建基线：握手期累积的重传不计入首窗
        }
        if total < w.retrans_base {
            w.retrans_base = total;
            return;
        }
        self.retrans_delta
            .store(total - w.retrans_base, Ordering::Relaxed);
        w.retrans_base = total;
    }

    /// note_rtt_sample 以 200ms 一次的 SRTT 采样维护内核 RTT 的有效地板
    /// （decayed-min：慢升 0.5ms/s、快降，对齐 Go Backend.noteRTTSample）。
    /// 瞬时拥塞把 SRTT 抬高只持续几个采样窗，地板不动；持续劣化让地板慢升
    /// 最终跟上；恢复时新样本低于地板，快降立即自愈。
    pub fn note_rtt_sample(&self, rtt_us: u32) {
        if rtt_us == 0 {
            return;
        }
        let mut w = self.rtt_eff.lock();
        let now = Instant::now();
        let elapsed_ns = w
            .last
            .map(|t| now.saturating_duration_since(t).as_nanos() as i64)
            .unwrap_or(0);
        w.last = Some(now);
        // decayed_min_update 自带回拨守卫（elapsed<0 不慢升）。
        w.floor_ns = decayed_min_update(
            w.floor_ns,
            elapsed_ns,
            rtt_us as u64 * 1000,
            RTT_EFF_DECAY_PER_SEC_NS,
        );
        w.n = w.n.saturating_add(1);
        if w.n < RTT_EFF_MIN_SAMPLES {
            return;
        }
        self.eff_rtt_us.store(
            (w.floor_ns / 1000).min(u32::MAX as u64) as u32,
            Ordering::Relaxed,
        );
    }

    /// note_write 累计一个采样窗的写阻塞时长与成功载荷（对齐 Go writer 循环
    /// 的 writeBusyNS/writeWindowBytes 逐窗累积）。与 note_capacity_sample 同
    /// 连接线程调用（Go writer goroutine 独占纪律的 Rust 对应）。
    #[inline]
    pub fn note_write(&self, busy_ns: i64, payload_bytes: u64) {
        let mut w = self.capacity_window.lock();
        w.write_busy_ns = w.write_busy_ns.saturating_add(busy_ns);
        w.write_window_bytes = w.write_window_bytes.saturating_add(payload_bytes);
    }

    /// note_capacity_sample 结算一个采样窗的路径容量估计（对齐 Go
    /// Backend.noteCapacitySample，采样线程独占）。
    ///
    /// 容量权重的反馈陷阱：writer-drain 速率是"被喂多少测多少"的量——欠估路径
    /// 拿不到流量就永远欠估。饱和门控是防反馈的关键：写阻塞（socket 发送缓冲
    /// 打满）≥ 半窗时 drain 速率才等于路径容量，bytes/busy 即容量；EWMA α=1/2。
    /// 非饱和窗补充 BDP 下界（cwnd×mss/srtt，拥塞窗口隐含的吞吐上界，独立
    /// EWMA），让永不饱和的快路径进入真实量级。
    pub fn note_capacity_sample(&self, window_ns: i64, cwnd: u32, snd_mss: u32, srtt_us: u32) {
        let (busy, bytes) = {
            let mut w = self.capacity_window.lock();
            let (busy, bytes) = (w.write_busy_ns, w.write_window_bytes);
            w.write_busy_ns = 0;
            w.write_window_bytes = 0;
            (busy, bytes)
        };
        if bytes == 0 {
            return; // 空窗：无流量即无测量
        }
        if busy > 0 && busy * 2 >= window_ns {
            // 饱和窗：阻塞时长 ≈ 载荷/容量，bytes/busy 即容量。
            let cap_bytes_per_sec = (bytes as f64 / busy as f64 * 1e9) as u64;
            if cap_bytes_per_sec == 0 {
                return;
            }
            let old = self.deliver_rate_bytes_per_sec.load(Ordering::Relaxed);
            let next = if old == 0 {
                cap_bytes_per_sec
            } else {
                (old + cap_bytes_per_sec) / 2
            };
            self.deliver_rate_bytes_per_sec.store(next, Ordering::Relaxed);
            return;
        }
        // 非饱和窗：writer-drain 速率是"被喂速率"，不是容量——deliverRate 保留
        // 上次饱和测量；改用 BDP 下界补齐永不饱和路径的容量估计。
        if cwnd == 0 || snd_mss == 0 || srtt_us == 0 {
            return;
        }
        let bdp = cwnd as u64 * snd_mss as u64 * 1_000_000_000 / (srtt_us as u64 * 1000);
        if bdp == 0 {
            return;
        }
        let old = self.bdp_rate_bytes_per_sec.load(Ordering::Relaxed);
        let next = if old == 0 { bdp } else { (old + bdp) / 2 };
        self.bdp_rate_bytes_per_sec.store(next, Ordering::Relaxed);
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
        // min_rtt 未知（0 或哨兵）时省略（omitempty），不可当作真实值暴露。
        let (min_rtt, unknown) = self.min_rtt_known();
        // 容量权重只在明确测得时填充，未测得路径不显示伪 0（对齐 Go
        // deliver_rate_mbps 的 omitempty 语义）。
        let deliver_rate = self.deliver_rate_bytes_per_sec.load(Ordering::Relaxed);
        SchedulerSnapshot {
            queued_bytes: self.queued_bytes.load(Ordering::Relaxed),
            rate_mbps: self.rate_bytes_per_sec.load(Ordering::Relaxed) as f64 * 8.0 / 1_000_000.0,
            deliver_rate_mbps: deliver_rate as f64 * 8.0 / 1_000_000.0,
            eta_us: self.eta_us.load(Ordering::Relaxed),
            active: self.active.load(Ordering::Relaxed),
            carry_pending: self.carry_pending.load(Ordering::Relaxed),
            assigned_bytes: self.assigned_bytes.load(Ordering::Relaxed),
            assigned_batches: self.assigned_batches.load(Ordering::Relaxed),
            fec_assigned_bytes: self.fec_assigned_bytes.load(Ordering::Relaxed),
            fec_assigned_batches: self.fec_assigned_batches.load(Ordering::Relaxed),
            stalled: self.is_stalled(),
            fwd_oneway_us: self.fwd_one_way_us.load(Ordering::Relaxed),
            ret_oneway_us: self.ret_one_way_us.load(Ordering::Relaxed),
            min_rtt_us: if unknown { 0 } else { min_rtt as u64 },
            eff_rtt_us: self.eff_rtt_us.load(Ordering::Relaxed) as u64,
            probe_timeout_streak: self.probe_timeout_streak.load(Ordering::Relaxed),
            retrans_delta: self.retrans_delta.load(Ordering::Relaxed),
            ret_congest_us: self.ret_congest_us.load(Ordering::Relaxed),
            probe_at_ms: self.probe_updated_at.load(Ordering::Relaxed),
            clock_offset_ns: self.clock_offset_ns.load(Ordering::Relaxed),
            clock_offset_unc_us: self.clock_offset_unc_us.load(Ordering::Relaxed),
            clock_offset_converged: self.clock_offset_converged.load(Ordering::Relaxed),
        }
    }

    /// min_rtt 已知值 + 是否未知（0 或哨兵视为未知）。
    fn min_rtt_known(&self) -> (u32, bool) {
        let v = self.min_rtt_cache.load(Ordering::Relaxed);
        if v == 0 || v == UNKNOWN_RTT_US {
            (0, true)
        } else {
            (v, false)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SchedulerSnapshot {
    pub queued_bytes: u64,
    pub rate_mbps: f64,
    /// 饱和门控容量估计（note_capacity_sample 的 EWMA，即 WFQ 容量权重的来源，
    /// Mbps）。0=尚未测得饱和窗。与 rate_mbps（writer-drain"被喂速率"）并置：
    /// 非饱和路径两者差异巨大——这正是容量加权与字节公平的差别所在。
    #[serde(skip_serializing_if = "is_zero_f64")]
    pub deliver_rate_mbps: f64,
    pub eta_us: u64,
    pub active: bool,
    pub carry_pending: bool,
    pub assigned_bytes: u64,
    pub assigned_batches: u64,
    pub fec_assigned_bytes: u64,
    pub fec_assigned_batches: u64,
    pub stalled: bool,
    #[serde(skip_serializing_if = "is_zero")]
    pub fwd_oneway_us: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub ret_oneway_us: u64,
    #[serde(skip_serializing_if = "is_zero")]
    pub min_rtt_us: u64,
    /// 有效内核 RTT（decayed-min 地板）；0=未建立（回退 min_rtt/SRTT）。与
    /// min_rtt_us 长期背离 = 存在 min-ever 地板无法反映的持续劣化。
    #[serde(skip_serializing_if = "is_zero")]
    pub eff_rtt_us: u64,
    /// 探针连续超时计数（任一回包到达即清零）。>0 = 路径疑似黑洞。
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub probe_timeout_streak: u32,
    /// 最近采样窗（200ms）的 TCP 重传段数。重传=路径正在丢段的信号。
    #[serde(skip_serializing_if = "is_zero_u32")]
    pub retrans_delta: u32,
    /// 回程拥塞抬升（µs，≥0）：回程有效值 − 回程地板 = 对端发送排队深度。
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub ret_congest_us: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub probe_at_ms: u64,
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub clock_offset_ns: i64,
    #[serde(skip_serializing_if = "is_zero")]
    pub clock_offset_unc_us: u64,
    #[serde(skip_serializing_if = "is_false")]
    pub clock_offset_converged: bool,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn is_zero_u32(v: &u32) -> bool {
    *v == 0
}
fn is_zero_f64(v: &f64) -> bool {
    *v == 0.0
}
fn is_zero_i64(v: &i64) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
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

    /// 回程有效单向时延（µs，有符号）+ 是否已收敛（对齐 Go backendRetUS）：
    /// 回程 = 对端发送方向 = 本端 ACK 方向。oneWayMode 为 roundtrip 兼容模式
    /// （0）时不消费探针（与 scheduler_one_way_converged 同契约）。双向吞吐
    /// 区间（rttMode）的往返排名键与回程拥塞门消费该值。
    fn scheduler_ret_one_way_converged(&self) -> Option<i64> {
        let st = self.scheduler_state();
        if st.one_way_mode.load(Ordering::Relaxed) == crate::routing_policy::ONE_WAY_MODE_ROUNDTRIP
        {
            return None;
        }
        let enc = st.ret_rank_us.load(Ordering::Relaxed);
        if enc > 0 {
            Some(crate::routing_policy::one_way_rank_decode(enc))
        } else {
            None
        }
    }

    /// 有效内核 RTT（µs）+ 是否未知（对齐 Go adaptiveBackendEffectiveRTT）：
    /// eff_rtt_us 已建立（≥RTT_EFF_MIN_SAMPLES 个 SRTT 采样）时优先——decayed-min
    /// 地板对持续劣化敏感、对瞬时拥塞稳定；未建立时回退 min_rtt/SRTT 链。
    fn scheduler_effective_rtt_us(&self) -> (u32, bool) {
        let v = self.scheduler_state().eff_rtt_us.load(Ordering::Relaxed);
        if v > 0 {
            return (v, false);
        }
        self.scheduler_min_rtt_us()
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
    // 健康罚时单位值（µs，对齐 Go AsyncPort.healthPenaltyUS）：每次探针连续超时/
    // 每个 200ms 窗重传段在排名键上加的微秒数。0=禁用。默认 2000；可配
    // sched_health_penalty_us 热更。调度器每批读取。
    health_penalty_us: AtomicU32,
    // 资格门准入窗口（µs，对齐 Go AsyncPort.schedEnvelopeUS）。默认 20ms（Go
    // schedEnvelopeDefaultMs）。Rust 调度器尚未镜像 fwd 门维度（Go f3c5dce，
    // 前置欠账），本窗口当前作为双向吞吐区间（rttMode）回程拥塞门的判定窗消费
    // （sched_envelope_ms 配置，可热更）。
    sched_envelope_us: AtomicU64,
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
            // 健康罚时默认 2ms/事件：sched_health_penalty_us 未配置/热更为 0 之外
            // 的值前，先给调度器一个可用的默认（0 在配置语义里是"显式禁用"）。
            health_penalty_us: AtomicU32::new(SCHED_HEALTH_PENALTY_DEFAULT_US),
            sched_envelope_us: AtomicU64::new(SCHED_ENVELOPE_DEFAULT_MS * 1000),
        }
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    idx: usize,
    base_us: i64,
    rtt_us: u32,
    /// per-path 计费/排名速率：容量估计（饱和门控 deliver_rate，BDP 下界补齐），
    /// 未测路径回退保守 25MB/s（公平启动）。容量加权 WFQ 的权重与 auto 排名的
    /// 服务时间项共用（对齐 Go backendCandidate.schedRate）。
    sched_rate: u64,
    /// 探针已收敛（排名键来自跨路径探针实测）。未测路径的回退键是乐观的内核
    /// 地板，与已测探针值跨尺度混排会让冷路径系统性抢跑：按此字段分类排序，
    /// 已测恒先于未测（对齐 Go backendCandidate.measured）。
    measured: bool,
    was_active: bool,
    virtual_ns: i64,
}

/// 资格扫描的单遍观测快照（对齐 Go envelopeObs）：scan_envelope 首读一次，
/// 候选构建（可能因包络放宽跑多次）与目标计算复用，保证批内多次重建共享同一
/// wasActive/RTT 事实。
struct EnvelopeObs {
    alive: bool,
    /// scheduler_effective_rtt_us 首读（有效地板，未建立时回退 min_rtt/SRTT）。
    rtt: u32,
    unknown_rtt: bool,
    cold: bool,
    rate: u64,
    /// 容量权重首读（饱和门控测量；0=未测得）。
    deliver_rate: u64,
    /// BDP 容量下界首读（非饱和窗 cwnd×mss/srtt 估计；0=未测得）。
    bdp_rate: u64,
    /// 批首的活跃标志快照。候选构建每批可能跑多次（包络放宽重建），而基础轮
    /// 会清 active——放宽重建若现场重读会把"上一批已活跃、本轮被误清"的路径
    /// 当成新加入，dispatch_wfq 把它的服务债务重置到 epoch。首读快照使批内
    /// 多次重建共享同一 was_active 事实。
    active: bool,
    cap: usize,
    q_len: usize,
    stalled: bool,
}

/// 本批资格门的批级状态（对齐 Go envelopeGate 的 Rust 侧子集）。Rust 调度器
/// 尚未镜像 Go 的 fwd 门维度（sched_envelope=fwd，Go f3c5dce 引入，前置欠账），
/// 这里只承载双向吞吐区间标记与回程拥塞窗——二者独立于门维度生效。
#[derive(Clone, Copy)]
struct EnvelopeGate {
    /// 双向吞吐区间（本端需求 ≥ 多路径区间阈值）：TCP ACK 自钟控下吞吐由
    /// cwnd/(F+B) 决定——fwd 系排名键升级为往返（fwd+ret 之和），并启用回程
    /// 拥塞副门。交互区间保持纯 fwd（慢回程不损交互时延，原设计意图成立）。
    rtt_mode: bool,
    /// 回程拥塞门的判定窗口（µs）＝ sched_envelope_ms 配置值。抬升超窗即排除。
    /// 不随放宽变化：放宽换的是"乱序界"，回程拥塞是容量事实。
    ret_window_us: u64,
}

/// widenRTTEnvelope rtt 资格门的按需放宽（对齐 Go widenRTTEnvelope）：slack 放大
/// 2^factor_exp 倍，封顶 8× 基准 slack。backlog/高需求下饥饿代价 > 乱序代价
/// ——接收端重排窗口本就有界，包络的历史使命（限界乱序）让位于聚合吞吐。
fn widen_rtt_envelope(min_rtt: u32, max_rtt: u64, factor_exp: u32) -> u64 {
    let base_slack = max_rtt - min_rtt as u64;
    let mut widened = base_slack << factor_exp;
    let cap_slack = base_slack.saturating_mul(8);
    if widened > cap_slack {
        widened = cap_slack;
    }
    min_rtt as u64 + widened
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

    /// 设定路径健康罚时的单位值（µs，对齐 Go SetSchedHealthPenaltyUs）：每次
    /// 探针连续超时/每个 200ms 窗重传段在排名键上加的微秒数。0=禁用健康罚时。
    /// 可热更，调度器每批读取。负值按 0 处理（配置校验层应先拦）。
    #[inline]
    pub fn set_sched_health_penalty_us(&self, us: i64) {
        let v = if us < 0 { 0 } else { us.min(u32::MAX as i64) as u32 };
        self.health_penalty_us.store(v, Ordering::Relaxed);
    }

    /// 当前健康罚时单位值（µs），0=禁用（对齐 Go SchedHealthPenaltyUs）。
    #[inline]
    pub fn sched_health_penalty_us(&self) -> u32 {
        self.health_penalty_us.load(Ordering::Relaxed)
    }

    /// 热更资格门准入窗口（ms，对齐 Go SetSchedEnvelopeMs）。越界值按边界钳制
    /// （配置校验层应先拦）。
    #[inline]
    pub fn set_sched_envelope_ms(&self, ms: i64) {
        let clamped = ms.clamp(SCHED_ENVELOPE_MIN_MS, SCHED_ENVELOPE_MAX_MS);
        self.sched_envelope_us
            .store(clamped.max(0) as u64 * 1000, Ordering::Relaxed);
    }

    /// 当前资格门准入窗口（µs）。
    #[inline]
    pub fn sched_envelope_us(&self) -> u64 {
        self.sched_envelope_us.load(Ordering::Relaxed)
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

    /// capacity_starved 容量驱动扩张/成员选择的触发判定（对齐 Go capacityStarved）：
    /// 需求超过已实测容量（饱和门控 deliver_rate）路径合计的 80%，同时返回已实测
    /// 路径数。writer-drain 速率不参与（被喂速率，防正反馈）；BDP 下界也不参与
    /// ——它是估计值且应用受限期可能虚高，留给压力阈值兜底。
    /// demand×5 > cap×4 ⟺ demand > 0.8×cap（整数安全）。
    fn capacity_starved(demand_rate: u64, obs: &[EnvelopeObs]) -> (bool, usize) {
        let mut measured_cap = 0u64;
        let mut measured_count = 0usize;
        for o in obs {
            if !o.alive || o.deliver_rate == 0 {
                continue;
            }
            measured_cap += o.deliver_rate;
            measured_count += 1;
        }
        (
            measured_cap > 0 && demand_rate.saturating_mul(5) > measured_cap.saturating_mul(4),
            measured_count,
        )
    }

    /// adaptive_demand_path_target 需求驱动的活跃目标分量（对齐 Go
    /// adaptiveDemandPathTarget）：需求阈值（40/100/180MB/s）是无实测容量时的
    /// 主要 proactive 信号；实测容量就绪后新增容量驱动扩张——需求超过已测容量
    /// 合计的 80% 时把目标抬到「已测路径数 + 1」，让未测路径凭防饿地板参与承载
    /// 并修正测量。封顶 ADAPTIVE_ACTIVE_MAX。
    fn adaptive_demand_path_target(demand_rate: u64, obs: &[EnvelopeObs]) -> usize {
        let mut want = 1usize;
        if demand_rate >= ACTIVE4_RATE_BYTES_PER_SEC {
            want = 4;
        } else if demand_rate >= ACTIVE3_RATE_BYTES_PER_SEC {
            want = 3;
        } else if demand_rate >= ACTIVE2_RATE_BYTES_PER_SEC {
            want = 2;
        }
        let (starved, measured_count) = Self::capacity_starved(demand_rate, obs);
        if starved {
            want = want.max(measured_count.saturating_add(1));
        }
        want.min(ADAPTIVE_ACTIVE_MAX)
    }

    /// adaptive_active_path_target 活跃路径目标 = max(压力分量, 需求分量)
    /// （对齐 Go adaptiveActivePathTarget）。压力阈值（reactive，backlog 硬信号）
    /// 沿用历史行为；需求分量见 adaptive_demand_path_target。返回值不按候选数
    /// 收口：候选不足时由调用方放宽资格包络，再按实际候选数收口。
    fn adaptive_active_path_target(pressure: u64, demand_rate: u64, obs: &[EnvelopeObs]) -> usize {
        let want = if pressure >= ACTIVE4_PRESSURE {
            4
        } else if pressure >= ACTIVE3_PRESSURE {
            3
        } else if pressure >= ACTIVE2_PRESSURE {
            2
        } else {
            1
        };
        want.max(Self::adaptive_demand_path_target(demand_rate, obs))
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

        // 双向吞吐区间（rttMode）：需求进入多路径区间后，TCP ACK 自钟控把吞吐钉
        // 在 cwnd/(F+B)——门与 fwd 系排名键升级往返维度。交互区间保持纯 fwd：
        // 小批量交付时延仍由去程决定，慢回程不损交互时延。
        let rtt_mode = demand_rate >= ACTIVE2_RATE_BYTES_PER_SEC;
        let (obs, min_rtt, max_rtt, reference_rate, healthy) = Self::scan_envelope(backends);
        if healthy == 0 {
            let chosen = Self::fallback_idx(backends, preferred);
            Self::commit_single(backends, chosen);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }
        let gate = EnvelopeGate {
            rtt_mode,
            ret_window_us: self.sched_envelope_us(),
        };
        let mut cands = self.build_candidates(
            policy,
            &obs,
            backends,
            incoming_bytes,
            min_rtt,
            max_rtt,
            reference_rate,
            gate,
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

        let mut active = Self::adaptive_active_path_target(pressure, demand_rate, &obs);
        let best_base = cands[0].base_us;
        if !policy.wfq || active == 1 {
            let chosen =
                Self::commit_single_sticky(backends, &cands, preferred, best_base, policy);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }
        // 活跃目标超过候选数（包络把健康路径挡在门外）：逐级放宽资格包络并重建
        // 候选集（×2 → ×4 → ×8 封顶）。放宽只由需求驱动分量触发：压力是瞬时
        // backlog 信号，突发靠现有活跃路径排空即可；持续需求饥饿时饥饿代价才
        // 大于乱序代价——重排窗口本就有界。回程拥塞门（rttMode）的窗口不随放宽
        // 变化——它是容量事实，不是乱序界。
        let demand_want = Self::adaptive_demand_path_target(demand_rate, &obs);
        let starved = Self::capacity_starved(demand_rate, &obs).0;
        if demand_want > cands.len() && healthy > cands.len() {
            for widen_exp in 1u32..=3 {
                if demand_want <= cands.len() || healthy <= cands.len() {
                    break;
                }
                let widened_rtt = widen_rtt_envelope(min_rtt, max_rtt, widen_exp);
                cands = self.build_candidates(
                    policy,
                    &obs,
                    backends,
                    incoming_bytes,
                    min_rtt,
                    widened_rtt,
                    reference_rate,
                    gate,
                );
                Self::rank_candidates(&mut cands);
            }
        }
        if active > cands.len() {
            active = cands.len();
        }
        // 容量饥饿下的成员选择：延迟序 top-k 会把"低容量低延迟"路径全数送进
        // 活跃集，把唯一的高容量路径挤在席位之外——聚合吞吐被封顶在低容量组合
        // 上（WFQ 权重只能分配已入选者，救不了没进场的）。与容量驱动扩张同一
        // 触发判定下，成员改按 sched_rate 降序选取（容量并列保延迟 rank 稳定序）。
        // 容量充足（非饥饿）时保持延迟序——交互流量优先、乱序风险小。
        if starved && cands.len() > active {
            cands.sort_by(|a, b| b.sched_rate.cmp(&a.sched_rate));
        }
        if active == 1 {
            let chosen =
                Self::commit_single_sticky(backends, &cands, preferred, cands[0].base_us, policy);
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }
        let chosen = Self::dispatch_wfq(backends, &cands, active, incoming_bytes);
        self.active_paths.store(active, Ordering::Relaxed);
        Some(chosen)
    }

    /// scan_envelope 单遍合并健康计数、有效地板最小 RTT、资格包络与参考速率
    /// （对齐 Go scanEnvelope）。minWarmed 只计"有 RTT 且完成热身（rate>0）"的
    /// 健康路径——否则测量顺序可能永久压缩候选集；参考速率只计包络内
    /// （或 fairStart）路径。同时产出批级观测快照（EnvelopeObs），供候选构建
    /// （可因包络放宽跑多次）与活跃目标计算复用。
    fn scan_envelope<B: AdaptiveBackend>(
        backends: &[Arc<B>],
    ) -> (Vec<EnvelopeObs>, u32, u64, u64, usize) {
        let mut obs: Vec<EnvelopeObs> = backends
            .iter()
            .map(|b| {
                let cap = b.scheduler_queue_capacity();
                let q_len = b.scheduler_queue_len();
                let stalled = b.scheduler_state().is_stalled();
                EnvelopeObs {
                    alive: false,
                    rtt: 0,
                    unknown_rtt: true,
                    cold: true,
                    rate: 0,
                    deliver_rate: 0,
                    bdp_rate: 0,
                    active: false,
                    cap,
                    q_len,
                    stalled,
                }
            })
            .collect();
        let mut min_warmed = u32::MAX;
        let mut healthy = 0usize;
        for (i, b) in backends.iter().enumerate() {
            let o = &mut obs[i];
            if o.cap == 0 || o.q_len >= o.cap.saturating_sub(2) || o.stalled {
                continue;
            }
            o.alive = true;
            healthy += 1;
            // 有效地板优先（decayed-min over SRTT，note_rtt_sample）：对持续劣化
            // 敏感、对瞬时拥塞稳定；未建立时回退 min_rtt/SRTT 链（历史行为）。
            let (rtt, unknown) = b.scheduler_effective_rtt_us();
            o.rtt = rtt;
            o.unknown_rtt = unknown;
            o.rate = b.scheduler_state().rate_bytes_per_sec.load(Ordering::Relaxed);
            o.deliver_rate = b
                .scheduler_state()
                .deliver_rate_bytes_per_sec
                .load(Ordering::Relaxed);
            o.bdp_rate = b
                .scheduler_state()
                .bdp_rate_bytes_per_sec
                .load(Ordering::Relaxed);
            o.active = b.scheduler_state().active.load(Ordering::Relaxed);
            o.cold = o.rate == 0;
            if !unknown && !o.cold && rtt < min_warmed {
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
        for o in &obs {
            // 与第一遍同一次观察：stalled/队满路径的 rate 不参与参考速率（仅冷
            // 路径 ETA 回退用），死路径不应抬高它。
            if !o.alive {
                continue;
            }
            let fair_start = o.unknown_rtt || o.cold;
            if !fair_start && (o.rtt as u64) > max_rtt {
                continue;
            }
            if o.rate > reference_rate {
                reference_rate = o.rate;
            }
        }
        (obs, min_rtt, max_rtt, reference_rate, healthy)
    }

    /// build_candidates 构建候选集：资格包络（含双向吞吐区间的回程拥塞门）+
    /// stall/队满排除，按策略算主排名键（对齐 Go buildEligibleCandidates）。
    /// g 为本批资格门状态；obs 为 scan_envelope 的批级首读快照，放宽重建时复用
    /// 同一份 was_active/RTT 事实。
    fn build_candidates<B: AdaptiveBackend>(
        &self,
        policy: RoutingPolicy,
        obs: &[EnvelopeObs],
        backends: &[Arc<B>],
        incoming_bytes: u64,
        min_rtt: u32,
        max_rtt: u64,
        reference_rate: u64,
        g: EnvelopeGate,
    ) -> Vec<Candidate> {
        let mut cands = Vec::with_capacity(backends.len());
        // 组内最大实测容量（饱和门控样本）：防饿地板的输入。BDP 下界不参与地板
        // ——它是"未饱和路径"的估计，与防饿地板（对实测容量的保守折算）语义不同。
        let mut max_deliver = 0u64;
        for o in obs {
            if o.deliver_rate > max_deliver {
                max_deliver = o.deliver_rate;
            }
        }
        for (idx, b) in backends.iter().enumerate() {
            let st = b.scheduler_state();
            let o = &obs[idx];
            // 排除子原因（对齐 Go publishExcluded 的四类分列）：面板要回答的
            // 是"为什么没选它"。Rust 尚未镜像 Go 的排除原因观测位（前置欠账），
            // 仅做排除动作。
            if o.cap == 0 || o.q_len >= o.cap.saturating_sub(2) || o.stalled {
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            // SRTT 用于 ETA 遥测（含当前拥塞，预测更准）；有效 RTT 已在扫描阶段
            // 首读（obs）。
            let srt = b.scheduler_rtt_us();
            let srtt_unknown = srt == 0 || srt == UNKNOWN_RTT_US;
            let mr = o.rtt;
            let unknown_rtt = o.unknown_rtt;
            let cold = o.cold;
            let fair_start = unknown_rtt || cold;
            let rtt_rank = if fair_start {
                // 公平启动路径按组内热身地板参与排序（仅 bootstrap 期）。
                min_rtt
            } else {
                mr
            };
            let fwd_val = Self::backend_one_way_us(b.as_ref());
            let fwd_ok = b.scheduler_one_way_converged().is_some();
            let mut one_way = fwd_val;
            let mut one_way_ok = fwd_ok;
            if g.rtt_mode {
                // 双向吞吐区间：排名键升级为往返（fwd+ret 之和，公共常数与 i 无关，
                // argmin 即真实往返 argmin——TCP ACK 自钟控下吞吐由 cwnd/(F+B) 决
                // 定）。任一方向未收敛 → 本路径无往返键 → 未测类；回退链在该模式
                // 下不折半（kernel RTT 全值与已收敛探针往返同尺度）。
                match (fwd_ok, b.scheduler_ret_one_way_converged()) {
                    (true, Some(ret)) => one_way = fwd_val + ret,
                    _ => {
                        one_way = 0;
                        one_way_ok = false;
                    }
                }
            }
            if !fair_start && mr as u64 > max_rtt {
                // 冷路径完成热身却真正落在资格门外（rtt 门）：清掉过期成员。
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            // 双向吞吐区间的回程拥塞门：探针回程抬升 = 对端发送排队深度 = 本端
            // ACK 排队深度，超窗即排除。独立于门维度——内核往返地板门（min_rtt
            // 是无拥塞地板）对回程拥塞同样钝感。交互区间不启用。
            if g.rtt_mode
                && st.ret_congest_us.load(Ordering::Relaxed) > g.ret_window_us as i64
            {
                st.active.store(false, Ordering::Relaxed);
                st.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            let eta_rate = if cold { reference_rate } else { o.rate };
            let mut eta = (srt as u64) / 2
                + service_us(
                    st.queued_bytes.load(Ordering::Relaxed).saturating_add(incoming_bytes),
                    eta_rate.max(1),
                );
            if st.carry_pending.load(Ordering::Relaxed) && eta > CARRY_BONUS_US {
                eta -= CARRY_BONUS_US;
            }
            st.eta_us.store(eta, Ordering::Relaxed);
            // 调度债务按路径容量计费（容量加权 WFQ）：权重来自饱和门控的容量采样
            // （note_capacity_sample——写阻塞 ≥ 半窗才结算，writer 未饱和时的 drain
            // 速率是"被喂速率"，直接做权重会正反馈饿死欠估路径）。未测得容量的
            // 路径拿「组内最大容量 / 4」的防饿地板；全组都未测得时统一回退保守
            // 25MB/s（等效字节公平）。永不饱和的快路径由 BDP 下界补齐容量估计。
            // 该速率同时参与 auto 算法的服务时间排名项，使 auto 与 latency_sticky
            // （纯地板）真正区分。
            let mut sched_rate = o.deliver_rate;
            if o.bdp_rate > sched_rate {
                sched_rate = o.bdp_rate;
            }
            let floor = max_deliver / 4;
            if sched_rate < floor {
                sched_rate = floor;
            }
            if sched_rate == 0 {
                sched_rate = FALLBACK_RATE_BYTES_PER_SEC;
            }
            // 主排名键按当前算法计算（candidate_rank_us）。one_way 为有符号原始
            // 相对量（探针已收敛时，负值=快于 ref 基准；双向吞吐区间为 fwd+ret
            // 之和）。回退链复用本轮首读：
            //   交互区间：有效 RTT/min_rtt 已知 → mr/2；SRTT 已知 → SRTT/2；
            //     两者皆未知（全未测）→ 组内 minRTT/2（哨兵折半，与历史覆盖一致）。
            //   双向吞吐区间：同一链不折半（mr/minRTT/srt 全值）。
            // 回退键只用于"组内无已测路径"时的排序与 fair-start 喂量：跨尺度混排
            // 由 rank_candidates 的 measured 分类隔离，冷路径不再凭乐观地板抢跑。
            if !one_way_ok {
                let halve: i64 = if g.rtt_mode { 1 } else { 2 };
                one_way = if !unknown_rtt {
                    mr as i64 / halve
                } else if srtt_unknown {
                    min_rtt as i64 / halve
                } else {
                    srt as i64 / halve
                };
            }
            let mut base_us = crate::routing_policy::candidate_rank_us(
                policy, one_way, rtt_rank, srt, incoming_bytes, sched_rate,
            );
            // 健康罚时（与排名维度正交，统一加性，总量封顶 SCHED_HEALTH_PENALTY_MAX_US）：
            // 单位值可配 sched_health_penalty_us（默认 2ms/事件，0=禁用）。
            //   探针连续超时——黑洞嫌疑，decayed-min 地板与 min_rtt 对它都钝感；
            //   TCP 重传——丢段信号，时延地板对它钝感。
            let unit = self.health_penalty_us.load(Ordering::Relaxed) as i64;
            if unit > 0 {
                base_us += (st.probe_timeout_streak.load(Ordering::Relaxed) as u64)
                    .saturating_mul(unit as u64)
                    .min(SCHED_HEALTH_PENALTY_MAX_US) as i64;
                base_us += (st.retrans_delta.load(Ordering::Relaxed) as u64)
                    .saturating_mul(unit as u64)
                    .min(SCHED_HEALTH_PENALTY_MAX_US) as i64;
            }
            cands.push(Candidate {
                idx,
                base_us,
                rtt_us: rtt_rank,
                sched_rate,
                measured: one_way_ok,
                was_active: o.active,
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

    /// 按主排名键稳定排序（对齐 Go rankCandidates）。
    ///
    /// measured 分类先于一切数值比较：未测路径的排名键来自回退链（有效 RTT/min_rtt
    /// 折半、SRTT/2、组地板折半），系统性低于已测探针值（后者含 TLS 写、调度、
    /// 锚定抬升的协议开销，且被 halfRef≥1ms 抬底）——纯数值排序会让任何冷路径
    /// 恒压过任何已测路径：拓扑变化（新连接注册/重拨）时活跃路径必然向未测路径
    /// 游移一个探针收敛周期（burst ~500ms，轮转最多 n×500ms）。已测恒先于未测；
    /// 全部未测（探针未协商/未收敛）时同组无分离，排序与历史行为一致。
    fn rank_candidates(cands: &mut [Candidate]) {
        for i in 1..cands.len() {
            let x = cands[i];
            let mut j = i;
            while j > 0 && candidate_rank_less(&x, &cands[j - 1]) {
                cands[j] = cands[j - 1];
                j -= 1;
            }
            cands[j] = x;
        }
    }

    /// 单活跃路径提交：置 active + 清空虚拟债务（对齐 Go commitSinglePath 的清
    /// 债动作 + fallbackSinglePath）。稳态快路径（chosen 已是唯一活跃路径）跳过
    /// 冗余清零——单路径态无人计费债务，归纳成立恒为 0，省掉每批两次原子写。
    fn commit_single<B: AdaptiveBackend>(backends: &[Arc<B>], chosen: usize) {
        for (i, b) in backends.iter().enumerate() {
            let st = b.scheduler_state();
            if i == chosen && st.active.load(Ordering::Relaxed) {
                continue;
            }
            st.active.store(i == chosen, Ordering::Relaxed);
            st.virtual_finish_ns.store(0, Ordering::Relaxed);
        }
    }

    /// 单路径提交 + sticky 滞回（对齐 Go commitSinglePath）：严格模式直接取
    /// rank[0]；sticky 模式在粘滞带内保留当前路径。
    ///
    /// baseUS 含本批服务时间项（auto：svc(incoming, schedRate)），粘滞比较键会随
    /// 批大小漂移——但 svc 差有硬上界：Rust 逐帧计费（incoming ≤ ~1.5KiB）、
    /// schedRate ≥ 25MB/s 回退地板 ⇒ 两路径 svc 差 ≪ sticky 下限 1ms，漂移被滞回
    /// 带下限完全吸收。
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
                        // 未测路径不得凭乐观回退键粘滞压过已测最优：回退键（min_rtt/2
                        // 等）系统性低于已测探针值，放行会把活跃路径单向锁死在未测
                        // 路径上，直到其探针收敛。粘滞只在同一测量类内生效。
                        if !(!c.measured && cands[0].measured) {
                            let slack = sticky_slack_us(c.rtt_us);
                            if c.base_us <= best_base.saturating_add(slack as i64) {
                                chosen = current;
                            }
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
            // 逻辑服务债务的计费速率与排名键同源：该候选自身的容量估计
            // （capacity-weighted WFQ，对齐 Go logicalDispatchScoreNS 按候选
            // schedRate 计费）。新激活路径必须拿到足以测量的份额而不是被保守
            // 回退费率永久惩罚。
            let rate = cands
                .iter()
                .find(|c| c.idx == idx)
                .map(|c| c.sched_rate)
                .unwrap_or(FALLBACK_RATE_BYTES_PER_SEC);
            let mut v = s.virtual_finish_ns.load(Ordering::Relaxed)
                + service_ns(s.queued_bytes.load(Ordering::Relaxed), rate);
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
                service_ns(incoming_bytes, chosen.sched_rate),
                Ordering::Relaxed,
            );
        chosen.idx
    }
}

/// candidate_rank_less 候选全序（对齐 Go candidateRankLess）：measured 分类、
/// baseUS、rttUS、wasActive。同组内平局先比 rttUS 再比 wasActive——热路径优先，
/// 消除"冷路径靠注册顺序抢槽"的顺序巧合。
fn candidate_rank_less(a: &Candidate, b: &Candidate) -> bool {
    if a.measured != b.measured {
        return a.measured;
    }
    if a.base_us != b.base_us {
        return a.base_us < b.base_us;
    }
    if a.rtt_us != b.rtt_us {
        return a.rtt_us < b.rtt_us;
    }
    a.was_active && !b.was_active
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing_policy::one_way_rank_encode;
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

    /// 构造带指定实测容量（饱和门控样本）的扫描观测项（capacity 测试助手）。
    fn obs_with_deliver(deliver_rate: u64) -> EnvelopeObs {
        EnvelopeObs {
            alive: true,
            rtt: 20_000,
            unknown_rtt: false,
            cold: false,
            rate: 30_000_000,
            deliver_rate,
            bdp_rate: 0,
            active: true,
            cap: 32,
            q_len: 0,
            stalled: false,
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
        // 需求阈值分量（40/100/180MB/s；无实测容量时的主要 proactive 信号）。
        let no_obs: Vec<EnvelopeObs> = Vec::new();
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(0, &no_obs),
            1
        );
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(
                ACTIVE2_RATE_BYTES_PER_SEC,
                &no_obs
            ),
            2
        );
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(
                ACTIVE3_RATE_BYTES_PER_SEC,
                &no_obs
            ),
            3
        );
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(
                ACTIVE4_RATE_BYTES_PER_SEC,
                &no_obs
            ),
            4
        );
        // 压力分量沿用历史行为（reactive，backlog 硬信号），与需求分量取大。
        assert_eq!(
            AdaptivePortState::adaptive_active_path_target(ACTIVE4_PRESSURE, 0, &no_obs),
            4
        );
        assert_eq!(
            AdaptivePortState::adaptive_active_path_target(0, 0, &no_obs),
            1
        );
    }

    #[test]
    fn capacity_starved_triggers_measured_capacity_expansion() {
        // 两条已测容量路径各 20MB/s：合计 40MB/s。需求 35MB/s = 0.875×cap >
        // 0.8×cap（且低于 ACTIVE2 阈值 40MB/s）→ 饥饿，目标抬到已测路径数 + 1
        // = 3（对齐 Go capacity-driven expansion 语义）。
        let obs = vec![obs_with_deliver(20_000_000), obs_with_deliver(20_000_000)];
        let (starved, measured) = AdaptivePortState::capacity_starved(35_000_000, &obs);
        assert!(starved);
        assert_eq!(measured, 2);
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(35_000_000, &obs),
            3
        );
        // 需求 20MB/s = 0.5×cap < 0.8×cap → 不饥饿，走需求阈值分量（1）。
        let (starved, _) = AdaptivePortState::capacity_starved(20_000_000, &obs);
        assert!(!starved);
        assert_eq!(AdaptivePortState::adaptive_demand_path_target(20_000_000, &obs), 1);
        // writer-drain 速率不参与饥饿判定：单条 200MB/s 的 rate 不算实测容量。
        let unmeasured = vec![obs_with_deliver(0)];
        let (starved, measured) = AdaptivePortState::capacity_starved(190_000_000, &unmeasured);
        assert!(!starved);
        assert_eq!(measured, 0);
        // 高需求 + 充足实测容量：阈值分量主导，封顶 4。
        let four = vec![
            obs_with_deliver(100_000_000),
            obs_with_deliver(100_000_000),
            obs_with_deliver(100_000_000),
            obs_with_deliver(100_000_000),
        ];
        assert_eq!(
            AdaptivePortState::adaptive_demand_path_target(190_000_000, &four),
            4
        );
    }

    #[test]
    fn widen_rtt_envelope_doubles_and_caps_at_eight() {
        // 基准 slack = maxRTT - minRTT = 4000µs：×2 → minRTT + 8000。
        assert_eq!(widen_rtt_envelope(20_000, 24_000, 1), 28_000);
        assert_eq!(widen_rtt_envelope(20_000, 24_000, 3), 52_000);
        // 封顶 8×基准 slack（32_000）：factorExp=4 请求 64_000，被 cap 到 8×。
        assert_eq!(widen_rtt_envelope(20_000, 24_000, 4), 20_000 + 32_000);
    }

    #[test]
    fn sticky_slack_floor_is_one_millisecond() {
        // 低 RTT 路径的 rtt/16 窄于排名键自身允许的抖动容差，滞回下限 1ms。
        assert_eq!(sticky_slack_us(3_000), 1_000);
        assert_eq!(sticky_slack_us(20_000), 1_250);
        assert_eq!(sticky_slack_us(200_000), 5_000);
    }

    #[test]
    fn measured_paths_rank_before_unmeasured_ones() {
        // 未测路径的回退键（内核地板折半）系统性低于已测探针值：纯数值排序会让
        // 冷路径恒压过已测路径（对齐 Go candidateRankLess 的钉死注释）。
        let mut measured = TestBackend::new(50_000);
        measured.sched.min_rtt_cache.store(50_000, Ordering::Relaxed);
        measured.sched.rate_bytes_per_sec.store(30_000_000, Ordering::Relaxed);
        measured
            .sched
            .fwd_rank_us
            .store(one_way_rank_encode(20_000), Ordering::Relaxed);
        let cold = TestBackend::new(0); // 全未测：回退键 = 组内 minRTT/2，乐观
        let backends = vec![Arc::new(cold), Arc::new(measured)];
        let p = AdaptivePortState::default();
        let (obs, min_rtt, max_rtt, reference_rate, _healthy) =
            AdaptivePortState::scan_envelope(&backends);
        let gate = EnvelopeGate { rtt_mode: false, ret_window_us: 20_000 };
        let mut cands = p.build_candidates(
            crate::routing_policy::routing_policy_for_code(0),
            &obs,
            &backends,
            1400,
            min_rtt,
            max_rtt,
            reference_rate,
            gate,
        );
        AdaptivePortState::rank_candidates(&mut cands);
        assert_eq!(cands[0].idx, 1, "measured path must rank first");
        assert!(cands[0].measured);
        assert!(!cands[1].measured);
    }

    #[test]
    fn health_penalty_raises_blackhole_and_retransmit_rank() {
        // 探针连续超时 + 重传段按 sched_health_penalty_us 单位值加性罚时，总量
        // 封顶 10ms（对齐 Go buildEligibleCandidates 的健康罚时块）。
        let mut b = TestBackend::new(50_000);
        b.sched.min_rtt_cache.store(50_000, Ordering::Relaxed);
        b.sched.rate_bytes_per_sec.store(30_000_000, Ordering::Relaxed);
        b.sched.probe_timeout_streak.store(2, Ordering::Relaxed);
        b.sched.retrans_delta.store(3, Ordering::Relaxed);
        let backends = vec![Arc::new(b)];
        let p = AdaptivePortState::default();
        let (obs, min_rtt, max_rtt, reference_rate, _healthy) =
            AdaptivePortState::scan_envelope(&backends);
        let gate = EnvelopeGate { rtt_mode: false, ret_window_us: 20_000 };
        let cands = p.build_candidates(
            crate::routing_policy::routing_policy_for_code(0),
            &obs,
            &backends,
            1400,
            min_rtt,
            max_rtt,
            reference_rate,
            gate,
        );
        // 单位 2ms：2 次超时 = 4ms，3 段重传 = 6ms，合计罚时 10ms（未触顶）。
        let mut clean = TestBackend::new(50_000);
        clean.sched.min_rtt_cache.store(50_000, Ordering::Relaxed);
        clean.sched.rate_bytes_per_sec.store(30_000_000, Ordering::Relaxed);
        let base = {
            let backends2 = vec![Arc::new(clean)];
            let (obs2, min_rtt2, max_rtt2, ref2, _) = AdaptivePortState::scan_envelope(&backends2);
            p.build_candidates(
                crate::routing_policy::routing_policy_for_code(0),
                &obs2,
                &backends2,
                1400,
                min_rtt2,
                max_rtt2,
                ref2,
                gate,
            )[0]
            .base_us
        };
        assert_eq!(
            cands[0].base_us - base,
            (2 + 3) * SCHED_HEALTH_PENALTY_DEFAULT_US as i64
        );
        // 0 = 显式禁用。
        p.set_sched_health_penalty_us(0);
        let (obs3, min_rtt3, max_rtt3, ref3, _) = AdaptivePortState::scan_envelope(&backends);
        let cands3 = p.build_candidates(
            crate::routing_policy::routing_policy_for_code(0),
            &obs3,
            &backends,
            1400,
            min_rtt3,
            max_rtt3,
            ref3,
            gate,
        );
        assert_eq!(cands3[0].base_us, base);
    }

    #[test]
    fn note_retrans_windows_and_resets_on_counter_rollback() {
        let s = SchedulerBackendState::default();
        s.note_retrans(5); // 首采样只建基线
        assert_eq!(s.retrans_delta.load(Ordering::Relaxed), 0);
        s.note_retrans(8);
        assert_eq!(s.retrans_delta.load(Ordering::Relaxed), 3);
        s.note_retrans(8);
        assert_eq!(s.retrans_delta.load(Ordering::Relaxed), 0);
        s.note_retrans(4); // 新 socket/回绕：重置基线，本窗不产 delta
        assert_eq!(s.retrans_delta.load(Ordering::Relaxed), 0);
        s.note_retrans(9);
        assert_eq!(s.retrans_delta.load(Ordering::Relaxed), 5);
    }

    #[test]
    fn note_capacity_sample_saturation_gated_with_bdp_floor() {
        let s = SchedulerBackendState::default();
        // 窗 200ms；写阻塞 150ms ≥ 半窗 → 饱和窗：bytes/busy 即容量。
        s.note_write(150_000_000, 30_000_000);
        s.note_capacity_sample(200_000_000, 0, 0, 0);
        let cap = s.deliver_rate_bytes_per_sec.load(Ordering::Relaxed);
        assert_eq!(cap, 200_000_000); // 30MB / 0.15s = 200MB/s
        // 非饱和窗 + TCP_INFO 可用 → BDP 下界独立 EWMA（deliverRate 保留）。
        s.note_write(10_000_000, 30_000_000);
        // cwnd=1000, mss=1400, srtt=20ms → BDP = 1000*1400*1e9/(20000*1000) = 70MB/s
        s.note_capacity_sample(200_000_000, 1000, 1400, 20_000);
        assert_eq!(s.deliver_rate_bytes_per_sec.load(Ordering::Relaxed), cap);
        assert_eq!(
            s.bdp_rate_bytes_per_sec.load(Ordering::Relaxed),
            70_000_000
        );
        // 空窗（无流量）不测量。
        s.note_capacity_sample(200_000_000, 1000, 1400, 20_000);
        assert_eq!(
            s.bdp_rate_bytes_per_sec.load(Ordering::Relaxed),
            70_000_000
        );
    }

    #[test]
    fn effective_rtt_floor_decays_slow_up_fast_down() {
        let s = SchedulerBackendState::default();
        // 首样本只累计不发布（rttEffMinSamples 纪律）。
        s.note_rtt_sample(50_000);
        assert_eq!(s.eff_rtt_us.load(Ordering::Relaxed), 0);
        // 第二个样本等值 → 地板 50ms 立即发布。
        s.note_rtt_sample(50_000);
        assert_eq!(s.eff_rtt_us.load(Ordering::Relaxed), 50_000);
        // 瞬时拥塞（80ms）不动地板（慢升 0.5ms/s 远小于一个采样窗）。
        s.note_rtt_sample(80_000);
        assert_eq!(s.eff_rtt_us.load(Ordering::Relaxed), 50_000);
        // 恢复（40ms）快降立即自愈。
        s.note_rtt_sample(40_000);
        assert_eq!(s.eff_rtt_us.load(Ordering::Relaxed), 40_000);
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
