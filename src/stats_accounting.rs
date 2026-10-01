use std::sync::atomic::{AtomicU64, Ordering};

use crate::protocol::CONTROL_KIND_FEC_PARITY;

/// Application-wire counters matching Go's `txFrameCounters` domain.
/// These count only batches accepted by the rustls plaintext writer, not FEC
/// generation/enqueue attempts. `*_wire_bytes` include the 10-byte TLSVPN frame
/// header and AEAD tag, but cover padding is accounted separately below.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TxFrameTotals {
    pub data_frames: u64,
    pub parity_frames: u64,
    pub control_frames: u64,
    pub data_wire_bytes: u64,
    pub parity_wire_bytes: u64,
}

impl TxFrameTotals {
    #[inline]
    pub fn add_frame(&mut self, seq: u32, payload: &[u8], wire_bytes: usize) {
        if seq != 0 {
            self.data_frames = self.data_frames.saturating_add(1);
            self.data_wire_bytes = self.data_wire_bytes.saturating_add(wire_bytes as u64);
        } else if payload.first().copied() == Some(CONTROL_KIND_FEC_PARITY) {
            self.parity_frames = self.parity_frames.saturating_add(1);
            self.parity_wire_bytes = self.parity_wire_bytes.saturating_add(wire_bytes as u64);
        } else {
            self.control_frames = self.control_frames.saturating_add(1);
        }
    }
}

#[derive(Debug, Default)]
pub struct TxFrameCounters {
    data_frames: AtomicU64,
    parity_frames: AtomicU64,
    control_frames: AtomicU64,
    data_wire_bytes: AtomicU64,
    parity_wire_bytes: AtomicU64,
}

impl TxFrameCounters {
    #[inline]
    pub fn record(&self, totals: TxFrameTotals) {
        self.data_frames.fetch_add(totals.data_frames, Ordering::Relaxed);
        self.parity_frames.fetch_add(totals.parity_frames, Ordering::Relaxed);
        self.control_frames.fetch_add(totals.control_frames, Ordering::Relaxed);
        self.data_wire_bytes.fetch_add(totals.data_wire_bytes, Ordering::Relaxed);
        self.parity_wire_bytes.fetch_add(totals.parity_wire_bytes, Ordering::Relaxed);
    }

    #[inline]
    pub fn snapshot(&self) -> TxFrameTotals {
        TxFrameTotals {
            data_frames: self.data_frames.load(Ordering::Relaxed),
            parity_frames: self.parity_frames.load(Ordering::Relaxed),
            control_frames: self.control_frames.load(Ordering::Relaxed),
            data_wire_bytes: self.data_wire_bytes.load(Ordering::Relaxed),
            parity_wire_bytes: self.parity_wire_bytes.load(Ordering::Relaxed),
        }
    }
}

static PADDING_WIRE_BYTES: AtomicU64 = AtomicU64::new(0);
static PADDING_BYTES: AtomicU64 = AtomicU64::new(0);

/// Cover-padding accounting follows Go: update only after a successful rustls
/// plaintext write so dashboard bytes and padding have the same commit point.
#[inline]
pub fn record_padding_write(wire_bytes: usize, pad_bytes: usize) {
    PADDING_WIRE_BYTES.fetch_add(wire_bytes as u64, Ordering::Relaxed);
    PADDING_BYTES.fetch_add(pad_bytes as u64, Ordering::Relaxed);
}

#[inline]
pub fn padding_snapshot() -> (u64, u64) {
    (
        PADDING_WIRE_BYTES.load(Ordering::Relaxed),
        PADDING_BYTES.load(Ordering::Relaxed),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_domains_match_go_written_contract() {
        let mut t = TxFrameTotals::default();
        t.add_frame(1, b"data", 14);
        t.add_frame(0, &[CONTROL_KIND_FEC_PARITY, 1, 2, 3, 4, 4], 16);
        t.add_frame(0, &[0x02, 1, 0, 0], 14);
        assert_eq!(t.data_frames, 1);
        assert_eq!(t.parity_frames, 1);
        assert_eq!(t.control_frames, 1);
        assert_eq!(t.data_wire_bytes, 14);
        assert_eq!(t.parity_wire_bytes, 16);
    }
}
