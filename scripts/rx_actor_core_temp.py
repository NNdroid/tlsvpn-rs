#!/usr/bin/env python3
from pathlib import Path


def replace_once(path, old, new):
    p = Path(path)
    s = p.read_text()
    if old not in s:
        raise SystemExit(f"marker not found in {path}: {old[:120]!r}")
    p.write_text(s.replace(old, new, 1))

# Module registration.
replace_once("src/main.rs", "pub mod protocol;\n", "pub mod protocol;\npub mod rx_actor;\n")

# Actor-only FEC fence methods: same state machine, no parking_lot mutex lock when
# the session worker owns the object exclusively.
p = Path("src/protocol.rs")
s = p.read_text()
marker = "    pub fn generation(&self) -> u64 {\n        *self.generation.lock()\n    }\n"
insert = '''    pub fn reset_actor(&mut self) {
        *self.generation.get_mut() = 0;
        self.window.store(0, Ordering::Release);
    }

    pub fn apply_actor(&mut self, control: FecModeControl) -> bool {
        if control.generation == 0
            || control.boundary == 0
            || (control.op != FEC_MODE_SUSPEND && control.op != FEC_MODE_RESUME)
        {
            return false;
        }
        let generation = self.generation.get_mut();
        if control.generation <= *generation {
            return false;
        }
        let (from, _) = self.window();
        *generation = control.generation;
        match control.op {
            FEC_MODE_SUSPEND => self
                .window
                .store(pack_window(control.boundary, 0), Ordering::Release),
            FEC_MODE_RESUME => {
                if from == 0 || control.boundary <= from {
                    self.window.store(0, Ordering::Release);
                } else {
                    self.window.store(
                        pack_window(from, control.boundary),
                        Ordering::Release,
                    );
                }
            }
            _ => unreachable!(),
        }
        true
    }

'''
if marker not in s:
    raise SystemExit("protocol actor insertion marker not found")
p.write_text(s.replace(marker, insert + marker, 1))

# Actor-owned FEC API. Existing shared API remains untouched for the static
# single-connection fast path and direct tests.
p = Path("src/fec.rs")
s = p.read_text()
marker = "    fn group_start_of(&self, seq: u32) -> u32 {\n"
actor = r'''    pub fn stats_actor(&mut self) -> (u64, u64) {
        let inner = self.inner.get_mut();
        (inner.recovered, inner.lost)
    }

    pub fn reset_actor(&mut self) {
        let inner = self.inner.get_mut();
        for (_, mut g) in inner.groups.drain() {
            if let Some(parity) = g.parity.take() {
                release_frame_vec(parity);
            }
        }
        inner.done.fill(0);
        self.cleanup_before.store(0, Ordering::Release);
        self.retired_before.store(0, Ordering::Release);
        self.fence.reset_actor();
    }

    fn maybe_retire_old_groups_actor(&mut self, expected: u32) {
        let boundary = self.cleanup_before.load(Ordering::Acquire);
        if boundary == 0 || self.retired_before.load(Ordering::Acquire) >= boundary {
            return;
        }
        if expected == 0 || expected < boundary {
            return;
        }
        self.retired_before.store(boundary, Ordering::Release);
        let inner = self.inner.get_mut();
        let doomed: Vec<u32> = inner
            .groups
            .keys()
            .copied()
            .filter(|start| *start < boundary)
            .collect();
        for start in doomed {
            if let Some(mut g) = inner.groups.remove(&start) {
                if let Some(parity) = g.parity.take() {
                    release_frame_vec(parity);
                }
            }
        }
    }

    fn handle_mode_control_actor(&mut self, control: FecModeControl, expected: u32) {
        if !self.fence.apply_actor(control) {
            return;
        }
        let (from, until) = self.fence.window();
        if from == 0 {
            return;
        }
        Self::atomic_max(&self.cleanup_before, from);
        {
            let inner = self.inner.get_mut();
            Self::drop_groups_in_range(inner, from, until);
        }
        self.maybe_retire_old_groups_actor(expected);
    }

    /// Session-actor data path. The decoder is owned by one RX worker, so this
    /// mutates `inner` through Mutex::get_mut() and does not acquire the shared
    /// decoder mutex used by the legacy/direct path.
    pub fn on_data_actor(
        &mut self,
        seq: u32,
        frame: &Arc<Vec<u8>>,
        reorder_expected: u32,
    ) -> Option<(u32, Arc<Vec<u8>>)> {
        if frame.is_empty() || seq == 0 || self.static_single.load(Ordering::Acquire) {
            return None;
        }
        if self.fence.bypass_data(seq) {
            if seq & 0xff == 0 {
                self.maybe_retire_old_groups_actor(reorder_expected);
            }
            return None;
        }
        let retired = self.retired_before.load(Ordering::Acquire);
        if retired != 0 && seq < retired {
            return None;
        }
        let k = self.k;
        let full_mask = self.full_mask;
        let start = seq - ((seq - 1) % k as u32);
        let inner = self.inner.get_mut();
        if is_done(&inner.done, start, k) {
            return None;
        }
        let complete;
        {
            let g = entry(&mut inner.groups, start);
            let bit = seq - start;
            let mask = 1u64 << bit;
            if g.got_mask & mask != 0 {
                return None;
            }
            g.got_mask |= mask;
            complete = g.got_mask == full_mask;
            if !complete {
                if frame.len() > g.acc.len() {
                    g.acc.resize(frame.len(), 0);
                }
                xor_into(&mut g.acc, frame);
            }
        }
        if complete {
            if let Some(mut g) = inner.groups.remove(&start) {
                if let Some(parity) = g.parity.take() {
                    release_frame_vec(parity);
                }
            }
            mark_done(&mut inner.done, start, k);
            return None;
        }
        let mut recovered = None;
        try_recover(inner, start, k, &mut |s, f| recovered = Some((s, f)));
        recovered
    }

    pub fn on_control_actor(
        &mut self,
        payload: &[u8],
        reorder_expected: u32,
    ) -> Result<Option<(u32, Arc<Vec<u8>>)>, String> {
        match control_kind(payload)? {
            CONTROL_KIND_FEC_PARITY => self.on_parity_actor(payload, reorder_expected),
            CONTROL_KIND_FEC_MODE => {
                let control = FecModeControl::parse(payload)?;
                self.handle_mode_control_actor(control, reorder_expected);
                Ok(None)
            }
            kind => Err(format!("unsupported protocol-v3 control kind 0x{kind:02x}")),
        }
    }

    fn on_parity_actor(
        &mut self,
        payload: &[u8],
        reorder_expected: u32,
    ) -> Result<Option<(u32, Arc<Vec<u8>>)>, String> {
        if self.static_single.load(Ordering::Acquire) {
            return Ok(None);
        }
        if payload.len() < 7 || payload[0] != CONTROL_KIND_FEC_PARITY {
            return Err("malformed FEC_PARITY header".into());
        }
        let start = BigEndian::read_u32(&payload[1..5]);
        let k = payload[5] as usize;
        if start == 0 || k != self.k || (start - 1) % self.k as u32 != 0 {
            return Err(format!("invalid FEC_PARITY start={start} k={k}"));
        }
        self.maybe_retire_old_groups_actor(reorder_expected);
        let retired = self.retired_before.load(Ordering::Acquire);
        if retired != 0 && start < retired {
            return Ok(None);
        }
        let desc_len = 6 + 4 * k;
        let tag_len = self.ic.as_ref().map(|c| c.tag_len()).unwrap_or(0);
        if payload.len() < desc_len + tag_len {
            return Err("truncated FEC_PARITY descriptor/body".into());
        }
        let mut lens = Vec::with_capacity(k);
        let mut max_len = 0usize;
        for i in 0..k {
            let l = BigEndian::read_u32(&payload[6 + 4 * i..10 + 4 * i]) as usize;
            if l + tag_len > payload.len() - desc_len {
                return Err("invalid FEC_PARITY member length".into());
            }
            lens.push(l);
            max_len = max_len.max(l);
        }
        let mut pb = acquire_frame_vec(max_len);
        if let Some(ic) = &self.ic {
            let mut aad = [0u8; 8];
            aad[0..4].copy_from_slice(&((max_len + tag_len) as u32).to_be_bytes());
            aad[4..8].copy_from_slice(&start.to_be_bytes());
            match ic.open_to(
                &mut pb,
                &payload[desc_len..desc_len + max_len + tag_len],
                start,
                &aad,
            ) {
                Ok(plain) => {
                    let n = plain.len();
                    pb.truncate(n);
                }
                Err(_) => {
                    release_frame_vec(pb);
                    return Err("FEC_PARITY AEAD failure".into());
                }
            }
        } else {
            pb.copy_from_slice(&payload[desc_len..desc_len + max_len]);
        }
        let k_self = self.k;
        let inner = self.inner.get_mut();
        let retired = self.retired_before.load(Ordering::Acquire);
        if (retired != 0 && start < retired) || is_done(&inner.done, start, k_self) {
            release_frame_vec(pb);
            return Ok(None);
        }
        {
            let g = entry(&mut inner.groups, start);
            if g.parity.is_some() {
                release_frame_vec(pb);
                return Ok(None);
            }
            g.k = k;
            g.lens = lens;
            g.parity = Some(pb);
        }
        let mut recovered = None;
        try_recover(inner, start, k_self, &mut |s, f| recovered = Some((s, f)));
        // `inner` borrow ends before the next actor cleanup call.
        let _ = inner;
        self.maybe_retire_old_groups_actor(reorder_expected);
        Ok(recovered)
    }

'''
if marker not in s:
    raise SystemExit("fec actor insertion marker not found")
p.write_text(s.replace(marker, actor + marker, 1))

rx_actor = r'''use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, Sender};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::buffer::{release_shared_frame, DeDuplicator, ReorderBuffer, ReorderStats};
use crate::fec::FecDecoder;

pub const RX_ACTOR_BATCH_CAP: usize = 16;
const RX_ACTOR_QUEUE_DEPTH: usize = 256;

type RxDelivery = Arc<dyn Fn(Vec<Arc<Vec<u8>>>) + Send + Sync>;

pub struct RxFrame {
    pub seq: u32,
    pub data: Arc<Vec<u8>>,
}

struct ProducerError {
    failed: AtomicBool,
    message: Mutex<Option<String>>,
}

impl ProducerError {
    fn new() -> Self {
        Self {
            failed: AtomicBool::new(false),
            message: Mutex::new(None),
        }
    }
    fn fail(&self, message: String) {
        *self.message.lock() = Some(message);
        self.failed.store(true, Ordering::Release);
    }
    fn take(&self) -> Option<String> {
        if !self.failed.swap(false, Ordering::AcqRel) {
            return None;
        }
        self.message.lock().take()
    }
}

struct BatchWork {
    generation: u64,
    frames: Vec<RxFrame>,
    error: Arc<ProducerError>,
}

enum Work {
    Batch(BatchWork),
    Reconfigure {
        generation: u64,
        fec: Option<FecDecoder>,
        done: Sender<()>,
    },
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RxActorSnapshot {
    pub generation: u64,
    pub recovered: u64,
    pub lost: u64,
    pub fec_bypass: bool,
    pub reorder: ReorderStats,
}

struct ActorStats {
    generation: AtomicU64,
    recovered: AtomicU64,
    lost: AtomicU64,
    fec_bypass: AtomicBool,
    gap_events: AtomicU64,
    timeout_flushes: AtomicU64,
    skipped_frames: AtomicU64,
}

impl ActorStats {
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(1),
            recovered: AtomicU64::new(0),
            lost: AtomicU64::new(0),
            fec_bypass: AtomicBool::new(false),
            gap_events: AtomicU64::new(0),
            timeout_flushes: AtomicU64::new(0),
            skipped_frames: AtomicU64::new(0),
        }
    }
    fn snapshot(&self) -> RxActorSnapshot {
        RxActorSnapshot {
            generation: self.generation.load(Ordering::Acquire),
            recovered: self.recovered.load(Ordering::Relaxed),
            lost: self.lost.load(Ordering::Relaxed),
            fec_bypass: self.fec_bypass.load(Ordering::Relaxed),
            reorder: ReorderStats {
                gap_events: self.gap_events.load(Ordering::Relaxed),
                timeout_flushes: self.timeout_flushes.load(Ordering::Relaxed),
                skipped_frames: self.skipped_frames.load(Ordering::Relaxed),
            },
        }
    }
}

pub struct RxSessionActor {
    tx: Sender<Work>,
    generation: AtomicU64,
    control: Mutex<()>,
    pool_rx: Receiver<Vec<RxFrame>>,
    stats: Arc<ActorStats>,
}

impl RxSessionActor {
    pub fn new(delivery: RxDelivery, initial_fec: Option<FecDecoder>) -> Arc<Self> {
        let (tx, rx) = bounded::<Work>(RX_ACTOR_QUEUE_DEPTH);
        let (pool_tx, pool_rx) = bounded::<Vec<RxFrame>>(RX_ACTOR_QUEUE_DEPTH);
        let stats = Arc::new(ActorStats::new());
        let worker_stats = stats.clone();
        std::thread::spawn(move || run_actor(rx, pool_tx, delivery, initial_fec, worker_stats));
        Arc::new(Self {
            tx,
            generation: AtomicU64::new(1),
            control: Mutex::new(()),
            pool_rx,
            stats,
        })
    }

    pub fn producer(self: &Arc<Self>) -> RxProducer {
        let _guard = self.control.lock();
        RxProducer {
            tx: self.tx.clone(),
            pool_rx: self.pool_rx.clone(),
            generation: self.generation.load(Ordering::Acquire),
            batch: None,
            error: Arc::new(ProducerError::new()),
        }
    }

    /// Fence the old receive generation, then replace FEC/reorder/dedup state on
    /// the worker. Producers created before this call are stale by construction;
    /// their late batches are discarded after the barrier.
    pub fn reconfigure(&self, fec: Option<FecDecoder>) {
        let _guard = self.control.lock();
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let (done_tx, done_rx) = bounded(1);
        if self
            .tx
            .send(Work::Reconfigure {
                generation,
                fec,
                done: done_tx,
            })
            .is_ok()
        {
            let _ = done_rx.recv();
        }
    }

    pub fn snapshot(&self) -> RxActorSnapshot {
        self.stats.snapshot()
    }
}

pub struct RxProducer {
    tx: Sender<Work>,
    pool_rx: Receiver<Vec<RxFrame>>,
    generation: u64,
    batch: Option<Vec<RxFrame>>,
    error: Arc<ProducerError>,
}

impl RxProducer {
    fn acquire(&self) -> Vec<RxFrame> {
        self.pool_rx
            .try_recv()
            .unwrap_or_else(|_| Vec::with_capacity(RX_ACTOR_BATCH_CAP))
    }

    pub fn push(&mut self, seq: u32, data: Arc<Vec<u8>>) -> bool {
        if self.error.failed.load(Ordering::Acquire) {
            release_shared_frame(data);
            return false;
        }
        if self.batch.is_none() {
            self.batch = Some(self.acquire());
        }
        let batch = self.batch.as_mut().unwrap();
        batch.push(RxFrame { seq, data });
        let flush = batch.len() >= RX_ACTOR_BATCH_CAP || seq == 0;
        if flush {
            self.flush()
        } else {
            true
        }
    }

    pub fn flush(&mut self) -> bool {
        let Some(frames) = self.batch.take() else {
            return !self.error.failed.load(Ordering::Acquire);
        };
        if frames.is_empty() {
            self.batch = Some(frames);
            return true;
        }
        match self.tx.send(Work::Batch(BatchWork {
            generation: self.generation,
            frames,
            error: self.error.clone(),
        })) {
            Ok(()) => true,
            Err(err) => {
                if let Work::Batch(mut b) = err.0 {
                    for frame in b.frames.drain(..) {
                        release_shared_frame(frame.data);
                    }
                }
                false
            }
        }
    }

    pub fn take_error(&self) -> Option<String> {
        self.error.take()
    }
}

impl Drop for RxProducer {
    fn drop(&mut self) {
        if let Some(mut frames) = self.batch.take() {
            for frame in frames.drain(..) {
                release_shared_frame(frame.data);
            }
        }
    }
}

fn publish_stats(
    stats: &ActorStats,
    generation: u64,
    recovered_base: u64,
    lost_base: u64,
    fec: &mut Option<FecDecoder>,
    reorder: &ReorderBuffer,
) {
    let (recovered, lost, bypass) = if let Some(dec) = fec.as_mut() {
        let (r, l) = dec.stats_actor();
        (recovered_base.saturating_add(r), lost_base.saturating_add(l), dec.bypass_snapshot())
    } else {
        (recovered_base, lost_base, false)
    };
    let rs = reorder.stats();
    stats.generation.store(generation, Ordering::Release);
    stats.recovered.store(recovered, Ordering::Relaxed);
    stats.lost.store(lost, Ordering::Relaxed);
    stats.fec_bypass.store(bypass, Ordering::Relaxed);
    stats.gap_events.store(rs.gap_events, Ordering::Relaxed);
    stats.timeout_flushes.store(rs.timeout_flushes, Ordering::Relaxed);
    stats.skipped_frames.store(rs.skipped_frames, Ordering::Relaxed);
}

fn deliver_ready(delivery: &RxDelivery, ready: &mut Vec<Arc<Vec<u8>>>) {
    if ready.is_empty() {
        return;
    }
    let mut out = Vec::with_capacity(ready.capacity().max(RX_ACTOR_BATCH_CAP));
    std::mem::swap(&mut out, ready);
    delivery(out);
}

fn insert_pair(
    reorder: &mut ReorderBuffer,
    ready: &mut Vec<Arc<Vec<u8>>>,
    seq: u32,
    frame: Arc<Vec<u8>>,
    recovered: Option<(u32, Arc<Vec<u8>>)>,
) {
    match recovered {
        Some((rseq, rframe)) if rseq < seq => {
            reorder.insert_into(rseq, rframe, ready);
            reorder.insert_into(seq, frame, ready);
        }
        Some((rseq, rframe)) if rseq > seq => {
            reorder.insert_into(seq, frame, ready);
            reorder.insert_into(rseq, rframe, ready);
        }
        Some((_rseq, rframe)) => {
            release_shared_frame(rframe);
            reorder.insert_into(seq, frame, ready);
        }
        None => reorder.insert_into(seq, frame, ready),
    }
}

fn release_batch(mut frames: Vec<RxFrame>, pool_tx: &Sender<Vec<RxFrame>>) {
    for frame in frames.drain(..) {
        release_shared_frame(frame.data);
    }
    let _ = pool_tx.try_send(frames);
}

fn run_actor(
    rx: Receiver<Work>,
    pool_tx: Sender<Vec<RxFrame>>,
    delivery: RxDelivery,
    mut fec: Option<FecDecoder>,
    stats: Arc<ActorStats>,
) {
    let mut generation = 1u64;
    let mut reorder = ReorderBuffer::new();
    let dedup = DeDuplicator::new();
    let mut ready = Vec::with_capacity(64);
    let mut recovered_base = 0u64;
    let mut lost_base = 0u64;

    loop {
        let timeout = reorder.next_timeout().unwrap_or(Duration::from_millis(250));
        match rx.recv_timeout(timeout) {
            Ok(Work::Reconfigure {
                generation: new_generation,
                fec: mut new_fec,
                done,
            }) => {
                if let Some(old) = fec.as_mut() {
                    let (r, l) = old.stats_actor();
                    recovered_base = recovered_base.saturating_add(r);
                    lost_base = lost_base.saturating_add(l);
                    old.reset_actor();
                }
                if let Some(new) = new_fec.as_mut() {
                    new.reset_actor();
                }
                fec = new_fec;
                generation = new_generation;
                reorder.reset();
                dedup.reset();
                publish_stats(
                    &stats,
                    generation,
                    recovered_base,
                    lost_base,
                    &mut fec,
                    &reorder,
                );
                let _ = done.send(());
            }
            Ok(Work::Batch(mut batch)) => {
                if batch.generation != generation {
                    release_batch(batch.frames, &pool_tx);
                    continue;
                }
                let mut failed = None;
                for item in batch.frames.drain(..) {
                    let seq = item.seq;
                    let data = item.data;
                    if seq == 0 {
                        let Some(dec) = fec.as_mut() else {
                            release_shared_frame(data);
                            failed = Some(format!(
                                "protocol v{} typed control without negotiated FEC",
                                crate::protocol::PROTOCOL_VERSION
                            ));
                            break;
                        };
                        match dec.on_control_actor(&data, reorder.expected_seq_snapshot()) {
                            Ok(Some((rseq, recovered))) => {
                                reorder.insert_into(rseq, recovered, &mut ready);
                            }
                            Ok(None) => {}
                            Err(e) => {
                                release_shared_frame(data);
                                failed = Some(format!("protocol v3 control error: {e}"));
                                break;
                            }
                        }
                        release_shared_frame(data);
                        continue;
                    }

                    let recovered = fec
                        .as_mut()
                        .and_then(|dec| dec.on_data_actor(seq, &data, reorder.expected_seq_snapshot()));
                    if !dedup.is_duplicate(seq) {
                        insert_pair(&mut reorder, &mut ready, seq, data, recovered);
                    } else {
                        release_shared_frame(data);
                        if let Some((_seq, frame)) = recovered {
                            reorder.insert_into(_seq, frame, &mut ready);
                        }
                    }
                }
                // Any frames left after a protocol failure were never consumed.
                for item in batch.frames.drain(..) {
                    release_shared_frame(item.data);
                }
                batch.frames.clear();
                let _ = pool_tx.try_send(batch.frames);
                deliver_ready(&delivery, &mut ready);
                if let Some(error) = failed {
                    batch.error.fail(error);
                }
                publish_stats(
                    &stats,
                    generation,
                    recovered_base,
                    lost_base,
                    &mut fec,
                    &reorder,
                );
            }
            Err(RecvTimeoutError::Timeout) => {
                reorder.flush_timeout_into(&mut ready);
                deliver_ready(&delivery, &mut ready);
                publish_stats(
                    &stats,
                    generation,
                    recovered_base,
                    lost_base,
                    &mut fec,
                    &reorder,
                );
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::FecEncoder;
    use std::sync::mpsc;
    use std::time::Duration;

    fn actor_with_output() -> (Arc<RxSessionActor>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let delivery: RxDelivery = Arc::new(move |batch| {
            for frame in batch {
                tx.send((*frame).clone()).unwrap();
                release_shared_frame(frame);
            }
        });
        (RxSessionActor::new(delivery, None), rx)
    }

    #[test]
    fn actor_reorders_one_owned_batch() {
        let (actor, rx) = actor_with_output();
        let mut p = actor.producer();
        assert!(p.push(1, Arc::new(vec![1])));
        assert!(p.push(3, Arc::new(vec![3])));
        assert!(p.push(2, Arc::new(vec![2])));
        assert!(p.flush());
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), vec![1]);
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), vec![2]);
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), vec![3]);
    }

    #[test]
    fn actor_epoch_barrier_discards_old_producer_batches() {
        let (actor, rx) = actor_with_output();
        let mut old = actor.producer();
        assert!(old.push(1, Arc::new(vec![0xaa])));
        actor.reconfigure(None);
        assert!(old.flush());
        let mut current = actor.producer();
        assert!(current.push(1, Arc::new(vec![0xbb])));
        assert!(current.flush());
        assert_eq!(rx.recv_timeout(Duration::from_secs(1)).unwrap(), vec![0xbb]);
        assert!(rx.recv_timeout(Duration::from_millis(80)).is_err());
        assert_eq!(actor.snapshot().generation, 2);
    }

    #[test]
    fn actor_fec_recovers_and_delivers_missing_member() {
        let (actor, rx) = actor_with_output();
        actor.reconfigure(Some(FecDecoder::new(4, None)));
        let mut enc = FecEncoder::new(4, None);
        let mut parity = None;
        let payloads: Vec<Vec<u8>> = (0..4).map(|i| vec![0x10 + i as u8; 32 + i]).collect();
        for (i, payload) in payloads.iter().enumerate() {
            parity = enc.add((i + 1) as u32, payload).or(parity);
        }
        let parity = parity.expect("K=4 parity");
        let mut p = actor.producer();
        assert!(p.push(1, Arc::new(payloads[0].clone())));
        assert!(p.push(3, Arc::new(payloads[2].clone())));
        assert!(p.push(4, Arc::new(payloads[3].clone())));
        assert!(p.push(0, Arc::new(parity)));
        assert!(p.flush());
        for want in &payloads {
            assert_eq!(&rx.recv_timeout(Duration::from_secs(1)).unwrap(), want);
        }
        let snap = actor.snapshot();
        assert_eq!(snap.recovered, 1);
        assert_eq!(snap.lost, 0);
    }

    #[test]
    fn typed_control_without_fec_reports_to_originating_producer() {
        let (actor, _rx) = actor_with_output();
        let mut p = actor.producer();
        assert!(p.push(0, Arc::new(vec![crate::protocol::CONTROL_KIND_FEC_MODE; 16])));
        for _ in 0..50 {
            if let Some(err) = p.take_error() {
                assert!(err.contains("without negotiated FEC"));
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("actor did not report protocol error");
    }
}
'''
Path("src/rx_actor.rs").write_text(rx_actor)
