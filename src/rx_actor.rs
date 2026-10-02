use parking_lot::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;

use crate::buffer::{release_shared_frame, DeDuplicator, ReorderBuffer, ReorderStats};
use crate::fec::FecDecoder;

pub const RX_ACTOR_BATCH_CAP: usize = 16;
/// Process-local controls for reproducible dataplane comparisons. These do not
/// alter the wire/config contract and are sampled only once, outside frame loops.
pub fn rx_batch_size() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| match std::env::var("TLSVPN_RX_BATCH_SIZE").ok().and_then(|s| s.parse().ok()) {
        Some(n @ (16 | 32 | 64 | 128)) => n,
        _ => RX_ACTOR_BATCH_CAP,
    })
}

pub fn rx_bypass_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var("TLSVPN_RX_BYPASS").as_deref() != Ok("0"))
}
const RX_ACTOR_IDLE_POLL: Duration = Duration::from_millis(250);

/// Delivery consumes a ready vector and returns an empty vector for reuse.
/// Client mode can exchange it with TapDelivery's existing pool; server mode
/// drains and returns the same allocation.
pub type RxDelivery = Arc<dyn Fn(Vec<Arc<Vec<u8>>>) -> Vec<Arc<Vec<u8>>> + Send + Sync>;

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

#[derive(Clone, Copy, Debug, Default)]
pub struct RxActorSnapshot {
    pub generation: u64,
    pub recovered: u64,
    pub lost: u64,
    pub fec_bypass: bool,
    pub reorder: ReorderStats,
}

/// Session receive state guarded by one outer ownership lock.
///
/// FEC and reorder use their actor-only lock-free entry points while this lock
/// is held. This keeps one logical owner without a reader -> channel -> worker
/// context switch for every batch.
struct RxActorState {
    generation: u64,
    fec: Option<FecDecoder>,
    reorder: ReorderBuffer,
    dedup: DeDuplicator,
    recovered_base: u64,
    lost_base: u64,
}

impl RxActorState {
    fn new(fec: Option<FecDecoder>) -> Self {
        Self {
            generation: 1,
            fec,
            reorder: ReorderBuffer::new(),
            dedup: DeDuplicator::new(),
            recovered_base: 0,
            lost_base: 0,
        }
    }
}

pub struct RxSessionActor {
    generation: AtomicU64,
    control: Mutex<()>,
    state: Mutex<RxActorState>,
    delivery: RxDelivery,
    timeout_thread: Mutex<Option<std::thread::Thread>>,
}

impl RxSessionActor {
    pub fn new(delivery: RxDelivery, initial_fec: Option<FecDecoder>) -> Arc<Self> {
        let actor = Arc::new(Self {
            generation: AtomicU64::new(1),
            control: Mutex::new(()),
            state: Mutex::new(RxActorState::new(initial_fec)),
            delivery,
            timeout_thread: Mutex::new(None),
        });

        // Cold path only: normal frames are processed by the reader that owns
        // state. The timer exists solely to release a real reorder gap when no
        // more packets arrive.
        let weak = Arc::downgrade(&actor);
        let handle = std::thread::spawn(move || timeout_loop(weak));
        *actor.timeout_thread.lock() = Some(handle.thread().clone());
        drop(handle);
        actor
    }

    pub fn producer(self: &Arc<Self>) -> RxProducer {
        let _guard = self.control.lock();
        RxProducer {
            actor: self.clone(),
            generation: self.generation.load(Ordering::Acquire),
            batch: Vec::with_capacity(rx_batch_size()),
            batch_cap: rx_batch_size(),
            ready: Vec::with_capacity(64),
            error: Arc::new(ProducerError::new()),
        }
    }

    /// Fence the old receive generation and replace FEC/reorder/dedup state.
    pub fn reconfigure(&self, mut fec: Option<FecDecoder>) {
        let _guard = self.control.lock();
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        {
            let mut state = self.state.lock();
            if let Some(old) = state.fec.as_mut() {
                let (r, l) = old.stats_actor();
                old.reset_actor();
                state.recovered_base = state.recovered_base.saturating_add(r);
                state.lost_base = state.lost_base.saturating_add(l);
            }
            if let Some(new) = fec.as_mut() {
                new.reset_actor();
            }
            state.fec = fec;
            state.generation = generation;
            state.reorder.reset();
            state.dedup.reset();
        }
        self.wake_timeout_thread();
    }

    pub fn snapshot(&self) -> RxActorSnapshot {
        // Dashboard sampling is cold path. Read the authoritative state instead
        // of publishing multiple atomics on every RX batch.
        let mut state = self.state.lock();
        let recovered_base = state.recovered_base;
        let lost_base = state.lost_base;
        let (recovered, lost, fec_bypass) = if let Some(dec) = state.fec.as_mut() {
            let (r, l) = dec.stats_actor();
            (
                recovered_base.saturating_add(r),
                lost_base.saturating_add(l),
                dec.bypass_snapshot(),
            )
        } else {
            (recovered_base, lost_base, false)
        };
        RxActorSnapshot {
            generation: state.generation,
            recovered,
            lost,
            fec_bypass,
            reorder: state.reorder.stats(),
        }
    }

    fn process_batch(
        &self,
        generation: u64,
        frames: &mut Vec<RxFrame>,
        ready: &mut Vec<Arc<Vec<u8>>>,
        error: &ProducerError,
    ) {
        if frames.is_empty() {
            return;
        }

        let mut protocol_error = None;
        let wake_timeout;
        {
            let mut guard = self.state.lock();
            if generation != guard.generation {
                for frame in frames.drain(..) {
                    release_shared_frame(frame.data);
                }
                return;
            }

            for item in frames.drain(..) {
                if let Err(e) = process_item(&mut guard, ready, item) {
                    protocol_error = Some(e);
                    break;
                }
            }
            for item in frames.drain(..) {
                release_shared_frame(item.data);
            }
            wake_timeout = guard.reorder.next_timeout().is_some();
        }

        self.deliver_reusing(ready);
        if let Some(message) = protocol_error {
            error.fail(message);
        }
        if wake_timeout {
            self.wake_timeout_thread();
        }
    }

    fn deliver_reusing(&self, ready: &mut Vec<Arc<Vec<u8>>>) {
        if ready.is_empty() {
            return;
        }
        let out = std::mem::take(ready);
        let mut returned = (self.delivery)(out);
        // Delivery contract requires an empty vector. Be defensive so a buggy
        // callback cannot leak frame ownership into the next reorder batch.
        if !returned.is_empty() {
            for frame in returned.drain(..) {
                release_shared_frame(frame);
            }
        }
        *ready = returned;
        if ready.capacity() < RX_ACTOR_BATCH_CAP {
            ready.reserve(RX_ACTOR_BATCH_CAP - ready.capacity());
        }
    }

    fn flush_timeout_into(&self, ready: &mut Vec<Arc<Vec<u8>>>) {
        {
            let mut state = self.state.lock();
            state.reorder.flush_timeout_into(ready);
        }
        self.deliver_reusing(ready);
    }

    fn next_timeout(&self) -> Duration {
        self.state
            .lock()
            .reorder
            .next_timeout()
            .unwrap_or(RX_ACTOR_IDLE_POLL)
    }

    fn wake_timeout_thread(&self) {
        if let Some(thread) = self.timeout_thread.lock().as_ref() {
            thread.unpark();
        }
    }
}

pub struct RxProducer {
    actor: Arc<RxSessionActor>,
    generation: u64,
    batch: Vec<RxFrame>,
    batch_cap: usize,
    ready: Vec<Arc<Vec<u8>>>,
    error: Arc<ProducerError>,
}

impl RxProducer {
    pub fn push(&mut self, seq: u32, data: Arc<Vec<u8>>) -> bool {
        if self.error.failed.load(Ordering::Acquire) {
            release_shared_frame(data);
            return false;
        }
        self.batch.push(RxFrame { seq, data });
        if self.batch.len() >= self.batch_cap || seq == 0 {
            self.flush()
        } else {
            true
        }
    }

    pub fn flush(&mut self) -> bool {
        if self.batch.is_empty() {
            return !self.error.failed.load(Ordering::Acquire);
        }
        self.actor.process_batch(
            self.generation,
            &mut self.batch,
            &mut self.ready,
            &self.error,
        );
        true
    }

    pub fn take_error(&self) -> Option<String> {
        self.error.take()
    }
}

impl Drop for RxProducer {
    fn drop(&mut self) {
        for frame in self.batch.drain(..) {
            release_shared_frame(frame.data);
        }
        for frame in self.ready.drain(..) {
            release_shared_frame(frame);
        }
    }
}

fn timeout_loop(actor: Weak<RxSessionActor>) {
    let mut ready = Vec::with_capacity(64);
    loop {
        let Some(strong) = actor.upgrade() else {
            break;
        };
        let wait = strong.next_timeout();
        drop(strong);
        std::thread::park_timeout(wait);
        let Some(strong) = actor.upgrade() else {
            break;
        };
        strong.flush_timeout_into(&mut ready);
    }
}

fn process_item(
    state: &mut RxActorState,
    ready: &mut Vec<Arc<Vec<u8>>>,
    item: RxFrame,
) -> Result<(), String> {
    let seq = item.seq;
    let data = item.data;

    if seq == 0 {
        let expected = state.reorder.expected_seq_snapshot();
        let Some(dec) = state.fec.as_mut() else {
            release_shared_frame(data);
            return Err(format!(
                "protocol v{} typed control without negotiated FEC",
                crate::protocol::PROTOCOL_VERSION
            ));
        };
        match dec.on_control_actor(&data, expected) {
            Ok(Some((rseq, recovered))) => {
                state.reorder.insert_into(rseq, recovered, ready);
            }
            Ok(None) => {}
            Err(e) => {
                release_shared_frame(data);
                return Err(format!("protocol v3 control error: {e}"));
            }
        }
        release_shared_frame(data);
        return Ok(());
    }

    let expected = state.reorder.expected_seq_snapshot();
    let recovered = state
        .fec
        .as_mut()
        .and_then(|dec| dec.on_data_actor(seq, &data, expected));
    if !state.dedup.is_duplicate(seq) {
        insert_pair(&mut state.reorder, ready, seq, data, recovered);
    } else {
        release_shared_frame(data);
        if let Some((rseq, frame)) = recovered {
            state.reorder.insert_into(rseq, frame, ready);
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fec::FecEncoder;
    use std::sync::mpsc;

    fn actor_with_output() -> (Arc<RxSessionActor>, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel();
        let delivery: RxDelivery = Arc::new(move |mut batch| {
            for frame in batch.drain(..) {
                tx.send((*frame).clone()).unwrap();
                release_shared_frame(frame);
            }
            batch
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
        assert!(p.push(
            0,
            Arc::new(vec![crate::protocol::CONTROL_KIND_FEC_MODE; 16])
        ));
        let err = p.take_error().expect("actor must report protocol error");
        assert!(err.contains("without negotiated FEC"));
    }

    #[test]
    fn producer_reuses_input_and_output_batch_allocations() {
        let (actor, _rx) = actor_with_output();
        let mut p = actor.producer();
        let input_ptr = p.batch.as_ptr();
        let output_cap = p.ready.capacity();
        for seq in 1..=64 {
            assert!(p.push(seq, Arc::new(vec![seq as u8])));
        }
        assert!(p.flush());
        assert_eq!(p.batch.as_ptr(), input_ptr);
        assert!(p.ready.capacity() >= output_cap);
    }
}
