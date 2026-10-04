#!/usr/bin/env python3
from pathlib import Path

path = Path("src/net.rs")
text = path.read_text()

# A second push is expected after the workflow commits the real source change.
# Make that pass a no-op instead of trying to apply the same textual patch twice.
if 'TLSVPN_TX_ADAPTIVE_BATCH' in text:
    raise SystemExit(0)


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one match, got {count}: {old[:80]!r}")
    text = text.replace(old, new, 1)

replace_once(
'''const OWNED_BATCH_MAX_BYTES: u64 = 8 * 1024;
// Conservative framing allowance: 10-byte TLSVPN header + up to a 16-byte
// inner AEAD tag, rounded up so a batch accepted under the budget cannot push
// the rustls plaintext buffer past its hard record limit.
const OWNED_BATCH_WIRE_OVERHEAD_PER_FRAME: usize = 32;
''',
'''const OWNED_BATCH_MAX_BYTES: u64 = 8 * 1024;
// Conservative framing allowance: 10-byte TLSVPN header + up to a 16-byte
// inner AEAD tag, rounded up so a batch accepted under the budget cannot push
// the rustls plaintext buffer past its hard record limit.
const OWNED_BATCH_WIRE_OVERHEAD_PER_FRAME: usize = 32;

/// Zero-wait TX batching policy. At low queue pressure, smaller ownership
/// batches let the TLS writer consume work sooner; when a burst/backlog is
/// already present, grow geometrically back to the existing 8-frame ceiling.
/// The byte cap remains authoritative, so this never enlarges a TLS write.
#[inline]
fn adaptive_tx_batch_limit(queued_frames: usize, incoming_frames: usize, configured_max: usize) -> usize {
    let pressure = queued_frames.saturating_add(incoming_frames).max(1);
    let target = pressure.min(8).next_power_of_two().min(8);
    target.min(configured_max.max(1))
}

#[cfg(test)]
#[test]
fn adaptive_tx_batch_limit_scales_without_exceeding_static_cap() {
    assert_eq!(adaptive_tx_batch_limit(0, 1, 8), 1);
    assert_eq!(adaptive_tx_batch_limit(0, 2, 8), 2);
    assert_eq!(adaptive_tx_batch_limit(0, 3, 8), 4);
    assert_eq!(adaptive_tx_batch_limit(1, 3, 8), 4);
    assert_eq!(adaptive_tx_batch_limit(4, 1, 8), 8);
    assert_eq!(adaptive_tx_batch_limit(32, 1, 8), 8);
    assert_eq!(adaptive_tx_batch_limit(32, 1, 4), 4);
}
''')

replace_once(
'''pub struct OwnedBatchQueue {
    inner: Mutex<OwnedBatchQueueInner>,
    capacity_frames: usize,
    max_batch_frames: usize,
}
''',
'''pub struct OwnedBatchQueue {
    inner: Mutex<OwnedBatchQueueInner>,
    capacity_frames: usize,
    max_batch_frames: usize,
    adaptive_batch: bool,
}
''')

replace_once(
'''            capacity_frames: capacity_frames.max(1),
            max_batch_frames: tx_batch_size(),
        }
    }

    #[inline]
    pub fn try_push(&self, frame: VPNFrame, bytes: u64) -> Result<(), VPNFrame> {
''',
'''            capacity_frames: capacity_frames.max(1),
            max_batch_frames: tx_batch_size(),
            adaptive_batch: std::env::var("TLSVPN_TX_ADAPTIVE_BATCH").as_deref() == Ok("1"),
        }
    }

    #[inline]
    fn batch_limit(&self, queued_frames: usize, incoming_frames: usize) -> usize {
        if self.adaptive_batch {
            adaptive_tx_batch_limit(queued_frames, incoming_frames, self.max_batch_frames)
        } else {
            self.max_batch_frames
        }
    }

    #[inline]
    pub fn try_push(&self, frame: VPNFrame, bytes: u64) -> Result<(), VPNFrame> {
''')

replace_once(
'''        if inner.frames >= self.capacity_frames {
            return Err(frame);
        }
        Self::push_locked(&mut inner, frame, bytes, self.max_batch_frames);
        Ok(())
''',
'''        if inner.frames >= self.capacity_frames {
            return Err(frame);
        }
        let max_batch_frames = self.batch_limit(inner.frames, 1);
        Self::push_locked(&mut inner, frame, bytes, max_batch_frames);
        Ok(())
''')

replace_once(
'''        let count = input.len().min(self.capacity_frames.saturating_sub(inner.frames));
        let mut bytes = 0;
        for frame in input.drain(..count) {
            let n = frame.data.len() as u64;
            bytes += n;
            Self::push_locked(&mut inner, frame, n, self.max_batch_frames);
        }
''',
'''        let count = input.len().min(self.capacity_frames.saturating_sub(inner.frames));
        let max_batch_frames = self.batch_limit(inner.frames, count);
        let mut bytes = 0;
        for frame in input.drain(..count) {
            let n = frame.data.len() as u64;
            bytes += n;
            Self::push_locked(&mut inner, frame, n, max_batch_frames);
        }
''')

replace_once(
'''        let b = &backends[0];
        let mut inner = queue.inner.lock();
        let mut accepted = 0;
        let mut accepted_bytes = 0;
        for data in frames.drain(..) {
''',
'''        let b = &backends[0];
        let mut inner = queue.inner.lock();
        let batch_limit = queue.batch_limit(inner.frames, frames.len());
        let mut accepted = 0;
        let mut accepted_bytes = 0;
        for data in frames.drain(..) {
''')

replace_once(
'''            OwnedBatchQueue::push_locked(&mut inner, VPNFrame { seq, data }, bytes, queue.max_batch_frames);
''',
'''            OwnedBatchQueue::push_locked(&mut inner, VPNFrame { seq, data }, bytes, batch_limit);
''')

path.write_text(text)
