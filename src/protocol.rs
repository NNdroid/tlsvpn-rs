use parking_lot::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

pub const PROTOCOL_VERSION: i64 = 3;

pub const CONTROL_KIND_FEC_PARITY: u8 = 0x01;
pub const CONTROL_KIND_FEC_MODE: u8 = 0x02;

pub const FEC_MODE_SUSPEND: u8 = 1;
pub const FEC_MODE_RESUME: u8 = 2;
pub const FEC_MODE_WIRE_LEN: usize = 16;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FecModeControl {
    pub generation: u64,
    pub op: u8,
    pub boundary: u32,
}

impl FecModeControl {
    pub fn encode(self) -> [u8; FEC_MODE_WIRE_LEN] {
        let mut out = [0u8; FEC_MODE_WIRE_LEN];
        out[0] = CONTROL_KIND_FEC_MODE;
        out[1] = self.op;
        // out[2..4] are protocol-v3 flags and MUST remain zero.
        out[4..12].copy_from_slice(&self.generation.to_be_bytes());
        out[12..16].copy_from_slice(&self.boundary.to_be_bytes());
        out
    }

    pub fn parse(payload: &[u8]) -> Result<Self, String> {
        if payload.len() != FEC_MODE_WIRE_LEN {
            return Err(format!(
                "FEC_MODE length {} != {}",
                payload.len(),
                FEC_MODE_WIRE_LEN
            ));
        }
        if payload[0] != CONTROL_KIND_FEC_MODE {
            return Err(format!("not FEC_MODE control kind 0x{:02x}", payload[0]));
        }
        if payload[2] != 0 || payload[3] != 0 {
            return Err("FEC_MODE flags must be zero in protocol v3".into());
        }
        let op = payload[1];
        if op != FEC_MODE_SUSPEND && op != FEC_MODE_RESUME {
            return Err(format!("invalid FEC_MODE op {}", op));
        }
        let generation = u64::from_be_bytes(payload[4..12].try_into().unwrap());
        let boundary = u32::from_be_bytes(payload[12..16].try_into().unwrap());
        if generation == 0 || boundary == 0 {
            return Err("FEC_MODE generation and boundary must be non-zero".into());
        }
        Ok(Self {
            generation,
            op,
            boundary,
        })
    }
}

pub fn control_kind(payload: &[u8]) -> Result<u8, String> {
    let kind = payload
        .first()
        .copied()
        .ok_or_else(|| "empty payload is KEEPALIVE, not a typed control".to_string())?;
    match kind {
        CONTROL_KIND_FEC_PARITY | CONTROL_KIND_FEC_MODE => Ok(kind),
        _ => Err(format!("unsupported protocol-v3 control kind 0x{kind:02x}")),
    }
}

#[inline]
pub fn fec_group_start(seq: u32, k: usize) -> u32 {
    if seq == 0 {
        return 0;
    }
    let k = k.clamp(2, 64) as u32;
    seq - ((seq - 1) % k)
}

/// First complete arithmetic FEC group boundary at or after seq. Zero means
/// the current uint32 sequence epoch has no remaining complete boundary.
pub fn fec_next_group_start(seq: u32, k: usize) -> u32 {
    if seq == 0 {
        return 0;
    }
    let k = k.clamp(2, 64) as u32;
    let offset = (seq - 1) % k;
    if offset == 0 {
        return seq;
    }
    let delta = k - offset;
    (seq as u64)
        .checked_add(delta as u64)
        .filter(|next| *next <= u32::MAX as u64)
        .map(|next| next as u32)
        .unwrap_or(0)
}

#[inline]
fn pack_window(from: u32, until: u32) -> u64 {
    ((from as u64) << 32) | until as u64
}

#[inline]
fn unpack_window(v: u64) -> (u32, u32) {
    ((v >> 32) as u32, v as u32)
}

/// Receiver-side sender-authoritative dynamic FEC state. Data hot paths read
/// only `window`; generation ordering is a control-plane mutex operation.
pub struct FecRxFenceState {
    generation: Mutex<u64>,
    window: AtomicU64,
}

impl Default for FecRxFenceState {
    fn default() -> Self {
        Self {
            generation: Mutex::new(0),
            window: AtomicU64::new(0),
        }
    }
}

impl FecRxFenceState {
    pub fn reset(&self) {
        *self.generation.lock() = 0;
        self.window.store(0, Ordering::Release);
    }

    pub fn generation(&self) -> u64 {
        *self.generation.lock()
    }

    pub fn window(&self) -> (u32, u32) {
        unpack_window(self.window.load(Ordering::Acquire))
    }

    pub fn apply(&self, control: FecModeControl) -> bool {
        if control.generation == 0
            || control.boundary == 0
            || (control.op != FEC_MODE_SUSPEND && control.op != FEC_MODE_RESUME)
        {
            return false;
        }

        let mut generation = self.generation.lock();
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
                // A newer RESUME may overtake an older SUSPEND on another TCP
                // stream. If the SUSPEND was never observed, active decode is the
                // conservative/correct state; only CPU optimization is lost.
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

    #[inline]
    pub fn bypass_data(&self, seq: u32) -> bool {
        if seq == 0 {
            return false;
        }
        let (from, until) = self.window();
        from != 0 && seq >= from && (until == 0 || seq < until)
    }

    #[inline]
    pub fn bypass_parity(&self, group_start: u32) -> bool {
        if group_start == 0 {
            return false;
        }
        let (from, until) = self.window();
        from != 0 && group_start >= from && (until == 0 || group_start < until)
    }
}

/// Sender-side topology transition state. The current control remains available
/// after a transition so a newly joined backend can be synchronized before its
/// first governed data record.
#[derive(Debug, Default)]
pub struct FecTxModeState {
    seen_multipath: bool,
    suspended: bool,
    generation: u64,
    current: Option<FecModeControl>,
}

impl FecTxModeState {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn current(&self) -> Option<FecModeControl> {
        self.current
    }

    pub fn suspended(&self) -> bool {
        self.suspended
    }

    /// Observe the physical sender topology immediately before dispatching seq.
    /// Startup 1→2 is not a transition until a real SUSPEND has existed.
    pub fn observe(&mut self, paths: usize, seq: u32, k: usize) -> Option<FecModeControl> {
        if paths >= 2 {
            if !self.seen_multipath {
                self.seen_multipath = true;
                return None;
            }
            if self.suspended {
                let boundary = fec_next_group_start(seq, k);
                if boundary == 0 {
                    return None;
                }
                self.generation = self.generation.saturating_add(1).max(1);
                let control = FecModeControl {
                    generation: self.generation,
                    op: FEC_MODE_RESUME,
                    boundary,
                };
                self.suspended = false;
                self.current = Some(control);
                return Some(control);
            }
            return None;
        }

        if paths == 1 && self.seen_multipath && !self.suspended {
            self.generation = self.generation.saturating_add(1).max(1);
            let control = FecModeControl {
                generation: self.generation,
                op: FEC_MODE_SUSPEND,
                boundary: fec_group_start(seq, k),
            };
            self.suspended = true;
            self.current = Some(control);
            return Some(control);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v3_fec_mode_codec_matches_go_golden() {
        let c = FecModeControl {
            generation: 0x0102_0304_0506_0708,
            op: FEC_MODE_SUSPEND,
            boundary: 9,
        };
        let wire = c.encode();
        assert_eq!(
            hex::encode(wire),
            "02010000010203040506070800000009"
        );
        assert_eq!(FecModeControl::parse(&wire).unwrap(), c);

        let mut malformed = wire;
        malformed[0] = 0;
        assert!(FecModeControl::parse(&malformed).is_err());
        malformed = wire;
        malformed[3] = 1;
        assert!(FecModeControl::parse(&malformed).is_err());
        assert!(FecModeControl::parse(&wire[..wire.len() - 1]).is_err());
    }

    #[test]
    fn v3_control_kind_is_strict() {
        assert_eq!(control_kind(&[CONTROL_KIND_FEC_PARITY]).unwrap(), 0x01);
        assert_eq!(control_kind(&[CONTROL_KIND_FEC_MODE]).unwrap(), 0x02);
        assert!(control_kind(&[0x7f]).is_err());
        assert!(control_kind(&[]).is_err());
    }

    #[test]
    fn mode_boundaries_do_not_wrap_epoch() {
        for (seq, group, next) in [
            (1, 1, 1),
            (2, 1, 5),
            (3, 1, 5),
            (4, 1, 5),
            (5, 5, 5),
            (6, 5, 9),
            (7, 5, 9),
            (8, 5, 9),
            (9, 9, 9),
        ] {
            assert_eq!(fec_group_start(seq, 4), group);
            assert_eq!(fec_next_group_start(seq, 4), next);
        }
        assert_eq!(fec_next_group_start(u32::MAX - 1, 4), 0);
        assert_eq!(fec_next_group_start(u32::MAX, 4), 0);
    }

    #[test]
    fn suspend_and_resume_define_exact_bypass_window() {
        let rx = FecRxFenceState::default();
        assert!(rx.apply(FecModeControl {
            generation: 1,
            op: FEC_MODE_SUSPEND,
            boundary: 5,
        }));
        for seq in 1..5 {
            assert!(!rx.bypass_data(seq));
        }
        for seq in 5..=8 {
            assert!(rx.bypass_data(seq));
        }
        assert!(rx.apply(FecModeControl {
            generation: 2,
            op: FEC_MODE_RESUME,
            boundary: 9,
        }));
        assert_eq!(rx.window(), (5, 9));
        for seq in 5..9 {
            assert!(rx.bypass_data(seq));
        }
        assert!(!rx.bypass_data(9));
        assert!(rx.bypass_parity(5));
        assert!(!rx.bypass_parity(9));
    }

    #[test]
    fn rapid_transitions_never_regress_generation() {
        let rx = FecRxFenceState::default();
        for control in [
            FecModeControl {
                generation: 1,
                op: FEC_MODE_SUSPEND,
                boundary: 5,
            },
            FecModeControl {
                generation: 2,
                op: FEC_MODE_RESUME,
                boundary: 9,
            },
            FecModeControl {
                generation: 3,
                op: FEC_MODE_SUSPEND,
                boundary: 13,
            },
            FecModeControl {
                generation: 4,
                op: FEC_MODE_RESUME,
                boundary: 17,
            },
        ] {
            assert!(rx.apply(control));
        }
        assert!(!rx.apply(FecModeControl {
            generation: 2,
            op: FEC_MODE_RESUME,
            boundary: 9,
        }));
        assert_eq!(rx.generation(), 4);
        assert_eq!(rx.window(), (13, 17));
    }

    #[test]
    fn startup_single_does_not_emit_fake_transition() {
        let mut tx = FecTxModeState::default();
        assert_eq!(tx.observe(1, 1, 4), None);
        assert_eq!(tx.observe(2, 2, 4), None);
        let suspend = tx.observe(1, 7, 4).unwrap();
        assert_eq!(suspend.op, FEC_MODE_SUSPEND);
        assert_eq!(suspend.boundary, 5);
        let resume = tx.observe(2, 7, 4).unwrap();
        assert_eq!(resume.op, FEC_MODE_RESUME);
        assert_eq!(resume.boundary, 9);
    }

    #[test]
    fn stale_cross_stream_control_cannot_regress_receiver() {
        let rx = FecRxFenceState::default();
        assert!(rx.apply(FecModeControl {
            generation: 11,
            op: FEC_MODE_RESUME,
            boundary: 9,
        }));
        assert!(!rx.apply(FecModeControl {
            generation: 10,
            op: FEC_MODE_SUSPEND,
            boundary: 5,
        }));
        assert_eq!(rx.generation(), 11);
        assert_eq!(rx.window(), (0, 0));
    }
}
