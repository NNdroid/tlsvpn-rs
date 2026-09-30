#!/usr/bin/env python3
from pathlib import Path
import re


def replace_once(path: str, old: str, new: str) -> None:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"{path}: expected one match, found {count}\n--- needle ---\n{old[:800]}")
    p.write_text(text.replace(old, new, 1))


def replace_all(path: str, old: str, new: str) -> int:
    p = Path(path)
    text = p.read_text()
    count = text.count(old)
    if count:
        p.write_text(text.replace(old, new))
    return count


def regex_once(path: str, pattern: str, repl: str) -> None:
    p = Path(path)
    text = p.read_text()
    new, count = re.subn(pattern, repl, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"{path}: regex expected one match, found {count}: {pattern[:300]}")
    p.write_text(new)


# ---- expose protocol-v3 module ----
replace_once("src/main.rs", "pub mod peer_info;\n", "pub mod peer_info;\npub mod protocol;\n")

# ---- exact protocol version everywhere ----
for path in ["src/client.rs", "src/server.rs", "src/api.rs", "examples/interop_client.rs", "tests/protocol_conformance.rs"]:
    p = Path(path)
    s = p.read_text()
    s = re.sub(r"protocol_version:\s*2\b", "protocol_version: crate::protocol::PROTOCOL_VERSION", s)
    s = s.replace("req.protocol_version != 2", "req.protocol_version != crate::protocol::PROTOCOL_VERSION")
    s = s.replace("resp.protocol_version != 2", "resp.protocol_version != crate::protocol::PROTOCOL_VERSION")
    s = s.replace("protocol_version == 2", "protocol_version == crate::protocol::PROTOCOL_VERSION")
    s = s.replace("protocol v2", "protocol v3")
    s = s.replace("protocol-v2", "protocol-v3")
    p.write_text(s)

# standalone example is its own crate, so use a literal exact v3 rather than crate::protocol.
p = Path("examples/interop_client.rs")
s = p.read_text().replace("protocol_version: crate::protocol::PROTOCOL_VERSION", "protocol_version: 3")
s = s.replace("const FEC_MAGIC: u8 = 0xFE;", "const CONTROL_KIND_FEC_PARITY: u8 = 0x01;")
s = s.replace("FEC_MAGIC", "CONTROL_KIND_FEC_PARITY")
p.write_text(s)

# Runtime API reports the exact protocol.
p = Path("src/api.rs")
s = p.read_text()
s = re.sub(r"protocol_version:\s*2\b", "protocol_version: crate::protocol::PROTOCOL_VERSION", s)
s = s.replace('r#"{\\"protocol_version\\":2,', 'r#"{\\"protocol_version\\":3,')
s = s.replace("旧服务端", "不完整服务端")
s = s.replace("旧客户端", "不完整客户端")
s = s.replace("旧版一致", "既定行为一致")
p.write_text(s)

# ---- reorder cold progress probe ----
replace_once(
    "src/buffer.rs",
    '''    pub fn stats(&self) -> ReorderStats {
        self.stats
    }
''',
    '''    pub fn stats(&self) -> ReorderStats {
        self.stats
    }

    /// Cold-path ordered-delivery progress snapshot used by dynamic FEC cleanup.
    /// Callers already serialize ReorderBuffer through its session mutex; this
    /// accessor deliberately adds no per-packet atomic store to the reorder path.
    pub fn expected_seq_snapshot(&self) -> u32 {
        self.expected_seq
    }
''',
)

# ---- FEC encoder + decoder: replace v2 magic and port Go P0/P1/P2a-c semantics ----
p = Path("src/fec.rs")
s = p.read_text()
s = s.replace("use parking_lot::Mutex;", "use parking_lot::{Mutex, RwLock};")
s = s.replace("use std::sync::Arc;", "use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};\nuse std::sync::Arc;")
s = s.replace("use crate::crypto::*;", "use crate::crypto::*;\nuse crate::protocol::*;")
s = s.replace("pub const FEC_MAGIC: u8 = 0xFE;\n", "")
s = s.replace("FEC_MAGIC", "CONTROL_KIND_FEC_PARITY")
s = s.replace("[1B 0xFE]", "[1B kind=0x01]")
s = s.replace("向所有连接广播", "按 FEC 路径策略发送")
s = s.replace("广播重复校验帧", "重复校验帧")
# is_parity_frame remains only as a typed-kind helper for tests/non-hot diagnostics.
s = s.replace(
    "/// 判断一个已解密线路帧是否为 XOR 校验帧（对齐 Go isParityFrame）\npub fn is_parity_frame(frame: &[u8]) -> bool {\n    frame.len() >= 7 && frame[0] == CONTROL_KIND_FEC_PARITY\n}\n",
    "/// Protocol-v3 typed FEC_PARITY discriminator. Receive loops use the strict\\n/// FecDecoder::on_control dispatcher rather than silently ignoring other kinds.\npub fn is_parity_frame(frame: &[u8]) -> bool {\n    frame.len() >= 7 && frame[0] == CONTROL_KIND_FEC_PARITY\n}\n".replace("\\n", "\n"),
)

# Encoder fields/new/add fast-path.
s = s.replace(
'''    ic: Option<Arc<InnerCipher>>,
    parity_sent: u64,
}''',
'''    ic: Option<Arc<InnerCipher>>,
    parity_sent: u64,
    multipath: bool,
    armed: bool,
}''', 1)
s = s.replace(
'''            parity_sent: 0,
        }''',
'''            parity_sent: 0,
            // Direct encoder tests keep immediate-encoding semantics until an
            // AsyncPort supplies the physical topology.
            multipath: true,
            armed: true,
        }''', 1)
s = s.replace(
'''    pub fn parity_sent(&self) -> u64 {
        self.parity_sent
    }

    /// 把一个数据帧计入当前分组；凑满 K 帧时生成校验帧并重置分组。
''',
'''    pub fn parity_sent(&self) -> u64 {
        self.parity_sent
    }

    pub fn group_size(&self) -> usize {
        self.k
    }

    /// Update sender physical topology. A collapse discards any partial group;
    /// after multipath returns encoding re-arms only on a complete arithmetic
    /// group boundary so RX and TX cannot disagree about group membership.
    pub fn set_physical_path_count(&mut self, paths: usize) {
        let multipath = paths >= 2;
        if multipath == self.multipath {
            return;
        }
        self.multipath = multipath;
        if !multipath {
            if !self.seqs.is_empty() || self.active_len != 0 {
                self.reset();
            }
            self.armed = false;
        } else {
            self.armed = false;
        }
    }

    /// 把一个数据帧计入当前分组；凑满 K 帧时生成校验帧并重置分组。
''', 1)
s = s.replace(
'''        if data.is_empty() {
            return None;
        }
        self.seqs.push(seq);''',
'''        if data.is_empty() || !self.multipath {
            return None;
        }
        if !self.armed {
            if seq == 0 || (seq - 1) % self.k as u32 != 0 {
                return None;
            }
            self.armed = true;
        }
        self.seqs.push(seq);''', 1)

# Replace decoder section up to done_slot with v3 dynamic implementation.
start = s.index("pub struct FecDecoder {")
end = s.index("#[inline]\nfn done_slot", start)
new_decoder = r'''pub struct FecDecoder {
    k: usize,
    full_mask: u64,
    static_single: AtomicBool,
    pub fence: FecRxFenceState,
    cleanup_before: AtomicU32,
    retired_before: AtomicU32,
    reorder_progress: RwLock<Option<Arc<dyn Fn() -> u32 + Send + Sync>>>,
    control_mu: Mutex<()>,
    ic: Option<Arc<InnerCipher>>,
    inner: Mutex<FecDecoderInner>,
}

impl FecDecoder {
    pub fn new(k: usize, ic: Option<Arc<InnerCipher>>) -> Self {
        let k = clamp_fec_group(k);
        let full_mask = if k == 64 { u64::MAX } else { (1u64 << k) - 1 };
        Self {
            k,
            full_mask,
            static_single: AtomicBool::new(false),
            fence: FecRxFenceState::default(),
            cleanup_before: AtomicU32::new(0),
            retired_before: AtomicU32::new(0),
            reorder_progress: RwLock::new(None),
            control_mu: Mutex::new(()),
            ic,
            inner: Mutex::new(FecDecoderInner {
                groups: HashMap::with_capacity(64),
                done: [0; FEC_DONE_CACHE],
                recovered: 0,
                lost: 0,
            }),
        }
    }

    pub fn set_reorder_progress(&self, f: Arc<dyn Fn() -> u32 + Send + Sync>) {
        *self.reorder_progress.write() = Some(f);
    }

    pub fn set_static_single_path(&self, single: bool) {
        if !single {
            self.static_single.store(false, Ordering::Release);
            return;
        }
        if !self.static_single.swap(true, Ordering::AcqRel) {
            self.reset_state_preserve_static();
        }
    }

    fn reset_state_preserve_static(&self) {
        let _control = self.control_mu.lock();
        let mut inner = self.inner.lock();
        for (_, mut g) in inner.groups.drain() {
            if let Some(parity) = g.parity.take() {
                release_frame_vec(parity);
            }
        }
        inner.done.fill(0);
        self.cleanup_before.store(0, Ordering::Release);
        self.retired_before.store(0, Ordering::Release);
        drop(inner);
        self.fence.reset();
    }

    pub fn reset(&self) {
        self.reset_state_preserve_static();
    }

    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.lock();
        (inner.recovered, inner.lost)
    }

    pub fn retired_before(&self) -> u32 {
        self.retired_before.load(Ordering::Acquire)
    }

    fn atomic_max(dst: &AtomicU32, next: u32) {
        if next == 0 {
            return;
        }
        let mut old = dst.load(Ordering::Acquire);
        while next > old {
            match dst.compare_exchange_weak(old, next, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => break,
                Err(actual) => old = actual,
            }
        }
    }

    fn drop_groups_in_range(inner: &mut FecDecoderInner, from: u32, until: u32) {
        if from == 0 {
            return;
        }
        let doomed: Vec<u32> = inner
            .groups
            .keys()
            .copied()
            .filter(|start| *start >= from && (until == 0 || *start < until))
            .collect();
        for start in doomed {
            if let Some(mut g) = inner.groups.remove(&start) {
                if let Some(parity) = g.parity.take() {
                    release_frame_vec(parity);
                }
            }
        }
    }

    fn maybe_retire_old_groups_locked(&self, inner: &mut FecDecoderInner) {
        let boundary = self.cleanup_before.load(Ordering::Acquire);
        if boundary == 0 || self.retired_before.load(Ordering::Acquire) >= boundary {
            return;
        }
        let Some(progress) = self.reorder_progress.read().clone() else {
            return;
        };
        let expected = progress();
        if expected == 0 || expected < boundary {
            return;
        }
        self.retired_before.store(boundary, Ordering::Release);
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

    fn cleanup_by_reorder_progress(&self) {
        let boundary = self.cleanup_before.load(Ordering::Acquire);
        if boundary == 0 || self.retired_before.load(Ordering::Acquire) >= boundary {
            return;
        }
        let mut inner = self.inner.lock();
        self.maybe_retire_old_groups_locked(&mut inner);
    }

    fn handle_mode_control(&self, control: FecModeControl) {
        let _control = self.control_mu.lock();
        if !self.fence.apply(control) {
            return;
        }
        let (from, until) = self.fence.window();
        if from == 0 {
            return;
        }
        Self::atomic_max(&self.cleanup_before, from);
        let mut inner = self.inner.lock();
        Self::drop_groups_in_range(&mut inner, from, until);
        self.maybe_retire_old_groups_locked(&mut inner);
    }

    /// Strict protocol-v3 post-handshake seq=0 dispatcher.
    pub fn on_control(
        &self,
        payload: &[u8],
        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
    ) -> Result<(), String> {
        match control_kind(payload)? {
            CONTROL_KIND_FEC_PARITY => self.on_parity_strict(payload, out),
            CONTROL_KIND_FEC_MODE => {
                let control = FecModeControl::parse(payload)?;
                self.handle_mode_control(control);
                Ok(())
            }
            kind => Err(format!("unsupported protocol-v3 control kind 0x{kind:02x}")),
        }
    }

    pub fn on_data(
        &self,
        seq: u32,
        frame: &Arc<Vec<u8>>,
        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
    ) {
        if frame.is_empty() || seq == 0 || self.static_single.load(Ordering::Acquire) {
            return;
        }
        if self.fence.bypass_data(seq) {
            if seq & 0xff == 0 {
                self.cleanup_by_reorder_progress();
            }
            return;
        }
        let retired = self.retired_before.load(Ordering::Acquire);
        if retired != 0 && seq < retired {
            return;
        }
        let mut inner = self.inner.lock();
        let retired = self.retired_before.load(Ordering::Acquire);
        if self.static_single.load(Ordering::Acquire)
            || self.fence.bypass_data(seq)
            || (retired != 0 && seq < retired)
        {
            return;
        }
        self.on_data_locked(&mut inner, seq, frame, out);
    }

    pub fn on_data_batch(
        &self,
        frames: &[(u32, Arc<Vec<u8>>)],
        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
    ) {
        if frames.is_empty() || self.static_single.load(Ordering::Acquire) {
            return;
        }
        let mut inner = self.inner.lock();
        for (seq, frame) in frames {
            if *seq == 0 || frame.is_empty() {
                continue;
            }
            if self.fence.bypass_data(*seq) {
                if *seq & 0xff == 0 {
                    self.maybe_retire_old_groups_locked(&mut inner);
                }
                continue;
            }
            let retired = self.retired_before.load(Ordering::Acquire);
            if retired != 0 && *seq < retired {
                continue;
            }
            self.on_data_locked(&mut inner, *seq, frame, out);
        }
    }

    fn on_data_locked(
        &self,
        inner: &mut FecDecoderInner,
        seq: u32,
        frame: &Arc<Vec<u8>>,
        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
    ) {
        let start = self.group_start_of(seq);
        if is_done(&inner.done, start, self.k) {
            return;
        }
        let mut complete = false;
        {
            let g = entry(&mut inner.groups, start);
            let bit = seq - start;
            let mask = 1u64 << bit;
            if g.got_mask & mask != 0 {
                return;
            }
            g.got_mask |= mask;
            complete = g.got_mask == self.full_mask;
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
            mark_done(&mut inner.done, start, self.k);
            return;
        }
        try_recover(inner, start, self.k, out);
    }

    /// Non-strict helper retained for direct unit tests. Network receive loops
    /// MUST use on_control so malformed typed controls terminate the connection.
    pub fn on_parity(&self, payload: &[u8], out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {
        let _ = self.on_parity_strict(payload, out);
    }

    fn on_parity_strict(
        &self,
        payload: &[u8],
        out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
    ) -> Result<(), String> {
        if self.static_single.load(Ordering::Acquire) {
            return Ok(());
        }
        if payload.len() < 7 || payload[0] != CONTROL_KIND_FEC_PARITY {
            return Err("malformed FEC_PARITY header".into());
        }
        let start = BigEndian::read_u32(&payload[1..5]);
        let k = payload[5] as usize;
        if start == 0 || k != self.k || (start - 1) % self.k as u32 != 0 {
            return Err(format!("invalid FEC_PARITY start={start} k={k}"));
        }
        self.cleanup_by_reorder_progress();
        let retired = self.retired_before.load(Ordering::Acquire);
        if retired != 0 && start < retired {
            return Ok(());
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
            let plain = ic
                .open_to(
                    &mut pb,
                    &payload[desc_len..desc_len + max_len + tag_len],
                    start,
                    &aad,
                )
                .map_err(|e| format!("FEC_PARITY AEAD failure: {e}"))?;
            let n = plain.len();
            pb.truncate(n);
        } else {
            pb.copy_from_slice(&payload[desc_len..desc_len + max_len]);
        }

        let mut inner = self.inner.lock();
        let retired = self.retired_before.load(Ordering::Acquire);
        if (retired != 0 && start < retired) || is_done(&inner.done, start, self.k) {
            release_frame_vec(pb);
            return Ok(());
        }
        {
            let g = entry(&mut inner.groups, start);
            if g.parity.is_some() {
                release_frame_vec(pb);
                return Ok(());
            }
            g.k = k;
            g.lens = lens;
            g.parity = Some(pb);
        }
        try_recover(&mut inner, start, self.k, out);
        self.maybe_retire_old_groups_locked(&mut inner);
        Ok(())
    }

    fn group_start_of(&self, seq: u32) -> u32 {
        seq - ((seq - 1) % self.k as u32)
    }
}

'''
s = s[:start] + new_decoder + s[end:]
p.write_text(s)

# ---- AsyncPort: sender topology authority and per-backend fence generation ----
p = Path("src/net.rs")
s = p.read_text()
s = s.replace("use crate::frame::{FramePayload, VPNFrame};", "use crate::frame::{FramePayload, VPNFrame};\nuse crate::protocol::{FecModeControl, FecTxModeState};")
s = s.replace(
'''pub struct Backend {
    pub ch: Sender<VPNFrame>,''',
'''pub struct Backend {
    pub fec_fence_gen: AtomicU64,
    pub ch: Sender<VPNFrame>,''', 1)
s = s.replace(
'''    encoder: Mutex<Option<FecEncoder>>,
    encoder_enabled: AtomicBool,''',
'''    encoder: Mutex<Option<FecEncoder>>,
    fec_mode: Mutex<FecTxModeState>,
    encoder_enabled: AtomicBool,''', 1)
s = s.replace(
'''            encoder: Mutex::new(None),
            encoder_enabled: AtomicBool::new(false),''',
'''            encoder: Mutex::new(None),
            fec_mode: Mutex::new(FecTxModeState::default()),
            encoder_enabled: AtomicBool::new(false),''', 1)
s = s.replace(
'''        self.parity_cursor.store(0, Ordering::Release);
        let enabled = k >= crate::fec::FEC_MIN_GROUP;''',
'''        self.parity_cursor.store(0, Ordering::Release);
        self.fec_mode.lock().reset();
        for backend in self.backends.read().iter() {
            backend.fec_fence_gen.store(0, Ordering::Release);
        }
        let enabled = k >= crate::fec::FEC_MIN_GROUP;''', 1)

# Add fenced backend enqueue helper after try_send_payload_to.
needle = '''    fn send_payload_to(&self, b: &Backend, seq: u32, data: FramePayload) -> u64 {
'''
helper = r'''    fn try_send_payload_to_fenced(
        &self,
        b: &Backend,
        seq: u32,
        data: FramePayload,
        control: Option<FecModeControl>,
    ) -> Result<(), FramePayload> {
        if let Some(control) = control {
            if b.fec_fence_gen.load(Ordering::Acquire) < control.generation {
                let control_payload = FramePayload::Owned(control.encode().to_vec());
                if let Err(returned) = self.try_send_payload_to(b, 0, control_payload) {
                    returned.release();
                    return Err(data);
                }
                // Channel enqueue completed before publication. Any thread that
                // observes this generation can only enqueue governed data after
                // the control record already exists in this backend FIFO.
                b.fec_fence_gen
                    .store(control.generation, Ordering::Release);
            }
        }
        self.try_send_payload_to(b, seq, data)
    }

'''
if needle not in s:
    raise SystemExit("src/net.rs: send_payload_to anchor missing")
s = s.replace(needle, helper + needle, 1)

# Extend data fallback method to accept current control and use fenced enqueue.
s = s.replace(
'''        seq: u32,
        data: FramePayload,
    ) -> Option<usize> {''',
'''        seq: u32,
        data: FramePayload,
        control: Option<FecModeControl>,
    ) -> Option<usize> {''', 1)
s = s.replace("match self.try_send_payload_to(&backends[idx], seq, data) {", "match self.try_send_payload_to_fenced(&backends[idx], seq, data, control) {", 1)
s = s.replace("match self.try_send_payload_to(b, seq, data) {", "match self.try_send_payload_to_fenced(b, seq, data, control) {", 1)

old_write = '''        // FEC 只借用 payload bytes；Owned/Shared 的所有权都继续向 backend 移动。
        let parity = if self.encoder_enabled.load(Ordering::Relaxed) {
            self.encoder
                .lock()
                .as_mut()
                .and_then(|enc| enc.add(seq, frame.as_slice()))
        } else {
            None
        };

        let selected_idx = self.selected_data_backend_index(&backends, incoming_bytes);
        let data_idx = self.send_data_payload_to_any(&backends, selected_idx, seq, frame);
'''
new_write = '''        // FEC-enabled dispatch serializes topology observation, encoder state and
        // fence publication. The control itself is sent only on the backend that
        // actually accepts governed data after scheduler fallback.
        let (parity, current_control) = if self.encoder_enabled.load(Ordering::Relaxed) {
            let mut mode = self.fec_mode.lock();
            let mut encoder = self.encoder.lock();
            if let Some(enc) = encoder.as_mut() {
                enc.set_physical_path_count(backends.len());
                let _ = mode.observe(backends.len(), seq, enc.group_size());
                let control = mode.current();
                (enc.add(seq, frame.as_slice()), control)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        let selected_idx = self.selected_data_backend_index(&backends, incoming_bytes);
        let data_idx = self.send_data_payload_to_any(
            &backends,
            selected_idx,
            seq,
            frame,
            current_control,
        );
'''
if old_write not in s:
    raise SystemExit("src/net.rs: write_payload FEC block missing")
s = s.replace(old_write, new_write, 1)
p.write_text(s)

# Add fec_fence_gen field to every Backend literal across source files.
for path in Path("src").glob("*.rs"):
    text = path.read_text()
    text = text.replace(
        "Arc::new(Backend {\n",
        "Arc::new(Backend {\n            fec_fence_gen: std::sync::atomic::AtomicU64::new(0),\n",
    )
    path.write_text(text)

# ---- strict client v3 control dispatch and decoder lifecycle ----
p = Path("src/client.rs")
s = p.read_text()
s = s.replace("protocol_version: 2,", "protocol_version: crate::protocol::PROTOCOL_VERSION,")
s = s.replace("if resp.protocol_version != 2 {", "if resp.protocol_version != crate::protocol::PROTOCOL_VERSION {")
# Decoder rebuild gets static topology + reorder progress callback.
s = s.replace(
'''                *cl.fec_dec.lock() = Some(Arc::new(FecDecoder::new(negotiated, fec_rx.clone())));
                cl.tx_port.reset_epoch(negotiated, fec_tx.clone());''',
'''                let dec = Arc::new(FecDecoder::new(negotiated, fec_rx.clone()));
                dec.set_static_single_path(cl.conns_count == 1);
                let reorder = cl.reorder_buf.clone();
                dec.set_reorder_progress(Arc::new(move || reorder.lock().expected_seq_snapshot()));
                *cl.fec_dec.lock() = Some(dec);
                cl.tx_port.reset_epoch(negotiated, fec_tx.clone());''', 1)
# Existing decoder also tracks configured topology; exact v3 has no unknown topology fallback.
s = s.replace(
'''        if st.enc_algo != enc_algo {''',
'''        if let Some(dec) = cl.fec_dec.lock().as_ref() {
            dec.set_static_single_path(cl.conns_count == 1);
        }
        if st.enc_algo != enc_algo {''', 1)
old_client_control = '''                            let data = Arc::new(data);
                            if seq == 0 {
                                if let Some(dec) = &fec_dec {
                                    if fec::is_parity_frame(&data) {
                                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                            reorder_input.push((s, f));
                                        };
                                        dec.on_parity(&data, &mut sink);
                                        release_shared_frame(data);
                                        continue;
                                    }
                                }
                            }

                            if fec_dec.is_some() {
                                fec_data_batch.push((seq, data.clone()));
                            }
'''
new_client_control = '''                            let data = Arc::new(data);
                            if seq == 0 {
                                let Some(dec) = &fec_dec else {
                                    close_reason = format!(
                                        "protocol v{} typed control without negotiated FEC",
                                        crate::protocol::PROTOCOL_VERSION
                                    );
                                    release_shared_frame(data);
                                    conn_closed = true;
                                    break 'socket_read;
                                };
                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                    reorder_input.push((s, f));
                                };
                                if let Err(e) = dec.on_control(&data, &mut sink) {
                                    close_reason = format!("protocol v3 control error: {e}");
                                    release_shared_frame(data);
                                    conn_closed = true;
                                    break 'socket_read;
                                }
                                release_shared_frame(data);
                                continue;
                            }

                            if fec_dec.is_some() {
                                fec_data_batch.push((seq, data.clone()));
                            }
'''
if old_client_control not in s:
    raise SystemExit("src/client.rs: seq0 parity block missing")
s = s.replace(old_client_control, new_client_control, 1)
p.write_text(s)

# ---- strict server v3 + decoder progress/static topology ----
p = Path("src/server.rs")
s = p.read_text()
s = s.replace("if req.protocol_version != 2 {", "if req.protocol_version != crate::protocol::PROTOCOL_VERSION {")
s = s.replace("protocol_version: req.protocol_version,", "protocol_version: crate::protocol::PROTOCOL_VERSION,")
old_server_control = '''                    if seq == 0 {
                        if let Some(dec) = &fec_dec {
                            if fec::is_parity_frame(&data) {
                                let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                                    reorder_input.push((s, f));
                                };
                                dec.on_parity(&data, &mut sink);
                                release_shared_frame(data);
                                continue;
                            }
                        }
                    }

                    if fec_dec.is_some() {
                        fec_data_batch.push((seq, data.clone()));
                    }
'''
new_server_control = '''                    if seq == 0 {
                        let Some(dec) = &fec_dec else {
                            debug!("protocol v3 typed control without negotiated FEC");
                            release_shared_frame(data);
                            *close = true;
                            break;
                        };
                        let mut sink = |s: u32, f: Arc<Vec<u8>>| {
                            reorder_input.push((s, f));
                        };
                        if let Err(e) = dec.on_control(&data, &mut sink) {
                            debug!("protocol v3 control error: {}", e);
                            release_shared_frame(data);
                            *close = true;
                            break;
                        }
                        release_shared_frame(data);
                        continue;
                    }

                    if fec_dec.is_some() {
                        fec_data_batch.push((seq, data.clone()));
                    }
'''
if old_server_control not in s:
    raise SystemExit("src/server.rs: seq0 parity block missing")
s = s.replace(old_server_control, new_server_control, 1)
# Every authenticated handshake installs current exact-topology static bypass and cleanup progress,
# including a newly rotated decoder.
anchor = '''    let epoch_snapshot = c_sess.epoch_state.read();
'''
insert = '''    {
        let epoch = c_sess.epoch_state.read();
        if let Some(dec) = &epoch.fec_dec {
            dec.set_static_single_path(req.brutal_conns == 1);
            let reorder = c_sess.reorder_buf.clone();
            dec.set_reorder_progress(Arc::new(move || reorder.lock().expected_seq_snapshot()));
        }
    }

'''
if anchor not in s:
    raise SystemExit("src/server.rs: epoch snapshot anchor missing")
s = s.replace(anchor, insert + anchor, 1)
p.write_text(s)

# ---- API comments/tests: no rolling compatibility language ----
p = Path("src/api.rs")
s = p.read_text()
s = s.replace("protocol v2", "protocol v3")
s = s.replace("新客户端把缺失视为旧服务端；旧客户端由 serde 默认忽略未知字段，支持滚动升级。", "该字段为诊断信息；缺失只表示 peer 未提供诊断元数据，不改变 v3 协议语义。")
s = s.replace('r#"{\\"protocol_version\\":2,', 'r#"{\\"protocol_version\\":3,')
p.write_text(s)

# ---- Cross-language golden contract: require v3 + typed controls ----
p = Path("tests/protocol_conformance.rs")
s = p.read_text()
s = s.replace("    #[allow(dead_code)]\n    version: u32,", "    version: u32,\n    #[serde(default)]\n    control_frames: Vec<ControlFrameVec>,")
insert_after = '''struct FrameHeaderVec {
    data_len: u32,
    pad_len: u16,
    seq: u32,
    header_hex: String,
}
'''
control_struct = '''
#[derive(Deserialize)]
struct ControlFrameVec {
    name: String,
    payload_hex: String,
}
'''
if insert_after not in s:
    raise SystemExit("protocol_conformance.rs: FrameHeaderVec block missing")
s = s.replace(insert_after, insert_after + control_struct, 1)
# Add required v3 test before first PSK test.
marker = "#[test]\nfn test_psk_hash_matches_go() {"
v3test = r'''#[test]
fn test_protocol_v3_typed_controls_match_go() {
    let g = golden_or_skip!();
    assert_eq!(g.version, 3, "Go golden contract must be protocol v3");
    let controls: std::collections::HashMap<_, _> = g
        .control_frames
        .iter()
        .map(|v| (v.name.as_str(), v.payload_hex.as_str()))
        .collect();
    assert_eq!(
        controls.get("fec_mode_suspend").copied(),
        Some("02010000010203040506070800000009")
    );
    let parity = controls
        .get("fec_parity_k2")
        .expect("missing fec_parity_k2 golden control");
    assert!(parity.starts_with("01"), "FEC_PARITY must use control kind 0x01");
}

'''
if marker not in s:
    raise SystemExit("protocol_conformance.rs: PSK test marker missing")
s = s.replace(marker, v3test + marker, 1)
p.write_text(s)

# ---- Remove stale v2 constants/comments in the source tree ----
for path in Path("src").glob("*.rs"):
    s = path.read_text()
    s = s.replace("protocol_version: 2", "protocol_version: crate::protocol::PROTOCOL_VERSION")
    s = s.replace("protocol_version != 2", "protocol_version != crate::protocol::PROTOCOL_VERSION")
    s = s.replace("protocol v2", "protocol v3")
    s = s.replace("protocol-v2", "protocol-v3")
    path.write_text(s)

print("Rust protocol-v3 dynamic FEC migration applied")
