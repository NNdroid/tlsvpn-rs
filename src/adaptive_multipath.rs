use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicUsize, Ordering};
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
const UNKNOWN_RTT_US: u32 = 50_000;

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
fn service_us(bytes: u64, rate: u64) -> u64 {
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
    pub virtual_finish_ns: AtomicI64,
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
            virtual_finish_ns: AtomicI64::new(0),
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

    #[inline]
    fn effective_rate(&self) -> u64 {
        let v = self.rate_bytes_per_sec.load(Ordering::Relaxed);
        if v == 0 {
            FALLBACK_RATE_BYTES_PER_SEC
        } else {
            v
        }
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
}

pub trait AdaptiveBackend {
    fn scheduler_state(&self) -> &SchedulerBackendState;
    fn scheduler_rtt_us(&self) -> u32;
    fn scheduler_queue_len(&self) -> usize;
    fn scheduler_queue_capacity(&self) -> usize;
}

#[derive(Debug)]
pub struct AdaptivePortState {
    input_total_bytes: AtomicU64,
    input_rate_bytes_per_sec: AtomicU64,
    sample_total_bytes: AtomicU64,
    sample_at_us: AtomicU64,
    pub active_paths: AtomicUsize,
    pub pressure_bytes: AtomicU64,
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
        }
    }
}

#[derive(Clone, Copy)]
struct Candidate {
    idx: usize,
    base_us: u64,
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
        let cap = b.scheduler_queue_capacity();
        cap > 2 && b.scheduler_queue_len() < cap.saturating_sub(2)
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
        let demand_rate = self.observe_input_demand();
        let mut pressure = incoming_bytes;
        for b in backends {
            pressure =
                pressure.saturating_add(b.scheduler_state().queued_bytes.load(Ordering::Relaxed));
        }
        self.pressure_bytes.store(pressure, Ordering::Relaxed);

        let mut min_rtt = u32::MAX;
        for b in backends {
            if !Self::healthy(b.as_ref()) {
                continue;
            }
            let rtt = match b.scheduler_rtt_us() {
                0 => UNKNOWN_RTT_US,
                v => v,
            };
            min_rtt = min_rtt.min(rtt);
        }
        if min_rtt == u32::MAX {
            for (i, b) in backends.iter().enumerate() {
                b.scheduler_state().active.store(i == 0, Ordering::Relaxed);
                b.scheduler_state()
                    .virtual_finish_ns
                    .store(0, Ordering::Relaxed);
            }
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(0);
        }
        let rtt_slack = RTT_HYSTERESIS_MIN_US.max(min_rtt / 4);
        let max_rtt = min_rtt as u64 + rtt_slack as u64;

        let mut reference_rate = FALLBACK_RATE_BYTES_PER_SEC;
        for b in backends {
            let rtt = match b.scheduler_rtt_us() {
                0 => UNKNOWN_RTT_US,
                v => v,
            };
            if rtt as u64 <= max_rtt {
                reference_rate = reference_rate.max(
                    b.scheduler_state()
                        .rate_bytes_per_sec
                        .load(Ordering::Relaxed),
                );
            }
        }

        let mut cands = Vec::with_capacity(backends.len());
        for (idx, b) in backends.iter().enumerate() {
            let state = b.scheduler_state();
            let rtt = match b.scheduler_rtt_us() {
                0 => UNKNOWN_RTT_US,
                v => v,
            };
            let eta_rate = {
                let r = state.rate_bytes_per_sec.load(Ordering::Relaxed);
                if r == 0 {
                    reference_rate
                } else {
                    r
                }
            };
            let mut eta = rtt as u64 / 2
                + service_us(
                    state
                        .queued_bytes
                        .load(Ordering::Relaxed)
                        .saturating_add(incoming_bytes),
                    eta_rate.max(1),
                );
            if state.carry_pending.load(Ordering::Relaxed) && eta > CARRY_BONUS_US {
                eta -= CARRY_BONUS_US;
            }
            state.eta_us.store(eta, Ordering::Relaxed);
            if !Self::healthy(b.as_ref()) || rtt as u64 > max_rtt {
                state.active.store(false, Ordering::Relaxed);
                state.virtual_finish_ns.store(0, Ordering::Relaxed);
                continue;
            }
            cands.push(Candidate {
                idx,
                base_us: rtt as u64 / 2 + service_us(incoming_bytes, FALLBACK_RATE_BYTES_PER_SEC),
                rtt_us: rtt,
                was_active: state.active.load(Ordering::Relaxed),
                virtual_ns: state.virtual_finish_ns.load(Ordering::Relaxed),
            });
        }
        if cands.is_empty() {
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(preferred.filter(|i| *i < backends.len()).unwrap_or(0));
        }
        cands.sort_by_key(|c| (c.base_us, c.rtt_us, c.idx));
        let active = Self::active_target(pressure, demand_rate, cands.len());

        if active == 1 {
            let mut chosen = cands[0].idx;
            if let Some(current) = preferred {
                if current != chosen {
                    if let Some(c) = cands.iter().find(|c| c.idx == current) {
                        let mut slack = (c.rtt_us / 16) as u64;
                        slack = slack.clamp(STICKY_MIN_US, STICKY_MAX_US);
                        if c.base_us <= cands[0].base_us.saturating_add(slack) {
                            chosen = current;
                        }
                    }
                }
            }
            for (i, b) in backends.iter().enumerate() {
                b.scheduler_state()
                    .active
                    .store(i == chosen, Ordering::Relaxed);
                b.scheduler_state()
                    .virtual_finish_ns
                    .store(0, Ordering::Relaxed);
            }
            self.active_paths.store(1, Ordering::Relaxed);
            return Some(chosen);
        }

        let mut epoch: Option<i64> = None;
        for c in cands.iter().take(active) {
            if c.was_active {
                epoch = Some(epoch.map_or(c.virtual_ns, |e| e.min(c.virtual_ns)));
            }
        }
        let epoch = epoch.unwrap_or(0);
        for (rank, c) in cands.iter().enumerate() {
            let state = backends[c.idx].scheduler_state();
            if rank >= active {
                state.active.store(false, Ordering::Relaxed);
                state.virtual_finish_ns.store(0, Ordering::Relaxed);
            } else {
                if !c.was_active {
                    state.virtual_finish_ns.store(epoch, Ordering::Relaxed);
                }
                state.active.store(true, Ordering::Relaxed);
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
        self.active_paths.store(active, Ordering::Relaxed);
        Some(chosen.idx)
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
        let a = Arc::new(TestBackend::new(20_000));
        let b = Arc::new(TestBackend::new(20_000));
        b.sched.carry_pending.store(true, Ordering::Relaxed);
        let paths = vec![a.clone(), b.clone()];
        let idx = p.pick(&paths, None, ACTIVE2_PRESSURE).unwrap();
        assert_eq!(idx, 1);

        let far = Arc::new(TestBackend::new(40_000));
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
}
