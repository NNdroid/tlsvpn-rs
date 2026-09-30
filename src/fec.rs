// XOR 奇偶校验 FEC，逐行为对齐 Go fec.go：
//
// 编码（端口级）：每 K 个数据帧生成 1 个校验帧（负载 = K 个成员明文负载的
// 逐字节异或），按 FEC 路径策略发送；数据帧本身仍按 MinRTT 单路分发。
// 校验帧线路格式（沿用 10 字节头，seq=0、不加密）：
//   [1B kind=0x01][4B groupStart(大端)][1B K][K×4B 成员长度][异或载荷]
// -encrypt 开启时异或载荷以 groupStart 为 seq 用本方向加密器加密（GCM 附标签）。
//
// 解码（会话级）：数据帧到达计入所属组累加器；校验帧到达且组内恰好缺 1 帧
// 时恢复并按原 seq 注入重排缓冲。组起点固定 ≡ 1 (mod K)。
// 同组丢 ≥2 帧不可恢复（组保持挂起，由在途上限淘汰），重复校验帧按组
// start 去重。与 Go 一致：lost 仅统计"持有校验帧且组终结"时的缺失数。
use byteorder::{BigEndian, ByteOrder};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use crate::buffer::{acquire_frame_vec, release_frame_vec};
use crate::crypto::*;
use crate::protocol::*;

pub const FEC_MIN_GROUP: usize = 2;
pub const FEC_MAX_GROUP: usize = 64;
const FEC_MAX_PENDING_GROUPS: usize = 512;
const FEC_DONE_CACHE: usize = 256;
const FEC_DONE_MASK: usize = FEC_DONE_CACHE - 1;

pub fn clamp_fec_group(k: usize) -> usize {
    k.clamp(FEC_MIN_GROUP, FEC_MAX_GROUP)
}

/// 归一服务端 FEC 分组策略区间：任一端点为 0 表示"不额外限制"，取协议边界
/// （min → FEC_MIN_GROUP，max → FEC_MAX_GROUP）。负数保持原样，交给配置校验报错。
/// 对齐 Go applyDefaults 的 0 哨兵语义；配置路径与绕过它的调用方（测试、嵌入）
/// 都必须给出同一个结论。
pub fn normalize_fec_group_bounds(min: i64, max: i64) -> (i64, i64) {
    (
        if min == 0 { FEC_MIN_GROUP as i64 } else { min },
        if max == 0 { FEC_MAX_GROUP as i64 } else { max },
    )
}

/// acc[i] ^= data[i]。x86 上运行时检测 AVX2（32 字节/步，逐字节约 8-16 倍），
/// 其他平台或无 AVX2 时回退 u64 分块。
#[inline]
fn xor_into(acc: &mut [u8], data: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { xor_into_avx2(acc, data) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // AArch64 baseline 包含 Advanced SIMD/NEON；R5S 等 ARM64 设备直接走
        // 128-bit XOR，避免逐 8 字节循环成为 FEC 热点。
        return unsafe { xor_into_neon(acc, data) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    xor_into_u64(acc, data);
}

#[inline]
fn xor_combine(out: &mut [u8], parity: &[u8], acc: &[u8]) {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            return unsafe { xor_combine_avx2(out, parity, acc) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        return unsafe { xor_combine_neon(out, parity, acc) };
    }
    #[cfg(not(target_arch = "aarch64"))]
    xor_combine_u64(out, parity, acc);
}

#[inline]
fn xor_into_u64(acc: &mut [u8], data: &[u8]) {
    let n8 = data.len() / 8;
    let (a8, a1) = acc.split_at_mut(n8 * 8);
    let (d8, d1) = data.split_at(n8 * 8);
    for (a, d) in a8.chunks_exact_mut(8).zip(d8.chunks_exact(8)) {
        let x =
            u64::from_ne_bytes(a.try_into().unwrap()) ^ u64::from_ne_bytes(d.try_into().unwrap());
        a.copy_from_slice(&x.to_ne_bytes());
    }
    for (a, d) in a1.iter_mut().zip(d1.iter()) {
        *a ^= *d;
    }
}

/// out[i] = parity[i] ^ acc[i]（u64 回退路径）
#[inline]
fn xor_combine_u64(out: &mut [u8], parity: &[u8], acc: &[u8]) {
    let n = out.len().min(parity.len()).min(acc.len());
    let n8 = n / 8;
    for i in 0..n8 {
        let o = i * 8;
        let x = u64::from_ne_bytes(parity[o..o + 8].try_into().unwrap())
            ^ u64::from_ne_bytes(acc[o..o + 8].try_into().unwrap());
        out[o..o + 8].copy_from_slice(&x.to_ne_bytes());
    }
    for i in n8 * 8..n {
        out[i] = parity[i] ^ acc[i];
    }
}

// ---------- AVX2 路径（x86_64 专用） ----------

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_into_avx2(acc: &mut [u8], data: &[u8]) {
    use std::arch::x86_64::*;
    let n = data.len();
    let n32 = n / 32;
    let mut i = 0usize;
    for _ in 0..n32 {
        let a = _mm256_loadu_si256(acc.as_ptr().add(i) as *const __m256i);
        let d = _mm256_loadu_si256(data.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            acc.as_mut_ptr().add(i) as *mut __m256i,
            _mm256_xor_si256(a, d),
        );
        i += 32;
    }
    // 尾部 u64
    let tail_start = n32 * 32;
    let rest = &mut acc[tail_start..];
    let dtail = &data[tail_start..];
    let n8 = dtail.len() / 8;
    for j in 0..n8 {
        let o = j * 8;
        let x = u64::from_ne_bytes(rest[o..o + 8].try_into().unwrap())
            ^ u64::from_ne_bytes(dtail[o..o + 8].try_into().unwrap());
        rest[o..o + 8].copy_from_slice(&x.to_ne_bytes());
    }
    for (a, d) in rest[n8 * 8..].iter_mut().zip(dtail[n8 * 8..].iter()) {
        *a ^= *d;
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn xor_combine_avx2(out: &mut [u8], parity: &[u8], acc: &[u8]) {
    use std::arch::x86_64::*;
    let n = out.len().min(parity.len()).min(acc.len());
    let n32 = n / 32;
    let mut i = 0usize;
    for _ in 0..n32 {
        let p = _mm256_loadu_si256(parity.as_ptr().add(i) as *const __m256i);
        let a = _mm256_loadu_si256(acc.as_ptr().add(i) as *const __m256i);
        _mm256_storeu_si256(
            out.as_mut_ptr().add(i) as *mut __m256i,
            _mm256_xor_si256(p, a),
        );
        i += 32;
    }
    let tail_start = n32 * 32;
    let (oret, ptail, atail) = (
        &mut out[tail_start..n],
        &parity[tail_start..n],
        &acc[tail_start..n],
    );
    for (o, (p, a)) in oret.iter_mut().zip(ptail.iter().zip(atail.iter())) {
        *o = p ^ a;
    }
}

// ---------- NEON 路径（AArch64 baseline） ----------

#[cfg(target_arch = "aarch64")]
unsafe fn xor_into_neon(acc: &mut [u8], data: &[u8]) {
    use std::arch::aarch64::*;
    let n = acc.len().min(data.len());
    let n16 = n / 16;
    let mut i = 0usize;
    for _ in 0..n16 {
        let a = vld1q_u8(acc.as_ptr().add(i));
        let d = vld1q_u8(data.as_ptr().add(i));
        vst1q_u8(acc.as_mut_ptr().add(i), veorq_u8(a, d));
        i += 16;
    }
    for (a, d) in acc[i..n].iter_mut().zip(data[i..n].iter()) {
        *a ^= *d;
    }
}

#[cfg(target_arch = "aarch64")]
unsafe fn xor_combine_neon(out: &mut [u8], parity: &[u8], acc: &[u8]) {
    use std::arch::aarch64::*;
    let n = out.len().min(parity.len()).min(acc.len());
    let n16 = n / 16;
    let mut i = 0usize;
    for _ in 0..n16 {
        let p = vld1q_u8(parity.as_ptr().add(i));
        let a = vld1q_u8(acc.as_ptr().add(i));
        vst1q_u8(out.as_mut_ptr().add(i), veorq_u8(p, a));
        i += 16;
    }
    for j in i..n {
        out[j] = parity[j] ^ acc[j];
    }
}

/// Protocol-v3 typed FEC_PARITY discriminator. Receive loops use the strict
/// FecDecoder::on_control dispatcher rather than silently ignoring other kinds.
pub fn is_parity_frame(frame: &[u8]) -> bool {
    frame.len() >= 7 && frame[0] == CONTROL_KIND_FEC_PARITY
}

// ---------- 编码器（端口级，串行调用，无需加锁，对齐 fecEncoder） ----------

pub struct FecEncoder {
    k: usize,
    seqs: Vec<u32>,
    lens: Vec<usize>,
    acc: Vec<u8>,
    active_len: usize,
    ic: Option<Arc<InnerCipher>>,
    parity_sent: u64,
    multipath: bool,
    armed: bool,
}

impl FecEncoder {
    pub fn new(k: usize, ic: Option<Arc<InnerCipher>>) -> Self {
        let k = clamp_fec_group(k);
        Self {
            k,
            seqs: Vec::with_capacity(k),
            lens: Vec::with_capacity(k),
            // 常见 Ethernet payload 一次扩到 2KB 档，之后复用。
            acc: Vec::with_capacity(2048),
            active_len: 0,
            ic,
            // encoder 本身已由 AsyncPort mutex 串行访问，无需再做原子计数。
            parity_sent: 0,
            // Direct encoder tests keep immediate-encoding semantics until an
            // AsyncPort supplies the physical topology.
            multipath: true,
            armed: true,
        }
    }

    pub fn parity_sent(&self) -> u64 {
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
    /// 返回 Some(parity) 表示校验帧就绪（载荷所有权归调用方，广播后释放）。
    pub fn add(&mut self, seq: u32, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() || !self.multipath {
            return None;
        }
        if !self.armed {
            if seq == 0 || (seq - 1) % self.k as u32 != 0 {
                return None;
            }
            self.armed = true;
        }
        self.seqs.push(seq);
        self.lens.push(data.len());
        if data.len() > self.acc.len() {
            self.acc.resize(data.len(), 0);
        }
        self.active_len = self.active_len.max(data.len());
        xor_into(&mut self.acc[..data.len()], data);
        if self.seqs.len() < self.k {
            return None;
        }
        let parity = self.build_parity();
        self.parity_sent = self.parity_sent.saturating_add(1);
        self.reset();
        Some(parity)
    }

    fn reset(&mut self) {
        self.seqs.clear();
        self.lens.clear();
        self.acc[..self.active_len].fill(0);
        self.active_len = 0;
    }

    fn build_parity(&mut self) -> Vec<u8> {
        let max_len = self.active_len;
        let tag_len = self.ic.as_ref().map(|c| c.tag_len()).unwrap_or(0);
        let mut buf = acquire_frame_vec(6 + 4 * self.lens.len() + max_len + tag_len);
        buf[0] = CONTROL_KIND_FEC_PARITY;
        BigEndian::write_u32(&mut buf[1..5], self.seqs[0]);
        buf[5] = self.lens.len() as u8;
        let mut off = 6;
        for l in &self.lens {
            BigEndian::write_u32(&mut buf[off..off + 4], *l as u32);
            off += 4;
        }
        buf[off..off + max_len].copy_from_slice(&self.acc[..max_len]);
        if let Some(ic) = &self.ic {
            // 校验帧线路负载 = 描述符 + 加密后的异或载荷，以 groupStart 为 seq
            ic.seal_in_place(
                &mut buf[off..off + max_len + tag_len],
                max_len,
                self.seqs[0],
                (max_len + tag_len) as u32,
            );
        }
        buf
    }
}

// ---------- 解码器（会话级，多连接并发，对齐 fecDecoder） ----------

struct FecGroupState {
    k: usize,
    lens: Vec<usize>,
    got_mask: u64,
    acc: Vec<u8>,
    parity: Option<Vec<u8>>,
}

struct FecDecoderInner {
    groups: HashMap<u32, FecGroupState>,
    done: [u32; FEC_DONE_CACHE],
    recovered: u64,
    lost: u64,
}

pub struct FecDecoder {
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
        let complete;
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
                .map_err(|_| "FEC_PARITY AEAD failure".to_string())?;
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

#[inline]
fn done_slot(start: u32, k: usize) -> usize {
    (((start - 1) / k as u32) as usize) & FEC_DONE_MASK
}

#[inline]
fn is_done(done: &[u32; FEC_DONE_CACHE], start: u32, k: usize) -> bool {
    start != 0 && done[done_slot(start, k)] == start
}

#[inline]
fn mark_done(done: &mut [u32; FEC_DONE_CACHE], start: u32, k: usize) {
    if start != 0 {
        done[done_slot(start, k)] = start;
    }
}

/// 拿到组条目；组数超限时淘汰起点最老者（对齐 newGroupLocked：
/// 淘汰不标记 done，其迟到成员只会自然过期）
fn entry<'a>(groups: &'a mut HashMap<u32, FecGroupState>, start: u32) -> &'a mut FecGroupState {
    if groups.len() >= FEC_MAX_PENDING_GROUPS && !groups.contains_key(&start) {
        if let Some(oldest_start) = groups.keys().copied().min() {
            if let Some(mut old) = groups.remove(&oldest_start) {
                if let Some(parity) = old.parity.take() {
                    release_frame_vec(parity);
                }
            }
        }
    }
    groups.entry(start).or_insert_with(|| FecGroupState {
        k: 0,
        lens: Vec::new(),
        got_mask: 0,
        acc: Vec::new(),
        parity: None,
    })
}

/// 组内恰好缺 1 帧且校验帧已到 → 异或恢复并输出（对齐 tryRecoverLocked）
fn try_recover(
    inner: &mut FecDecoderInner,
    start: u32,
    k: usize,
    out: &mut dyn FnMut(u32, Arc<Vec<u8>>),
) {
    // 阶段一：只读检查 + 计算恢复帧
    let mut rec: Option<(Vec<u8>, usize)> = None;
    {
        let Some(g) = inner.groups.get_mut(&start) else {
            return;
        };
        if g.k == 0 {
            return;
        }
        let Some(parity) = &g.parity else { return };
        let mut missing: Option<usize> = None;
        let mut missing_count = 0;
        for i in 0..g.k {
            if g.got_mask & (1u64 << i) == 0 {
                missing_count += 1;
                if missing_count > 1 {
                    return; // 同组丢多帧，等待剩余成员
                }
                missing = Some(i);
            }
        }
        if let Some(mi) = missing {
            // 丢失帧可能比所有已到达帧都长：累加器零扩展到该长度
            let n = g.lens[mi];
            if n > g.acc.len() {
                g.acc.resize(n, 0);
            }
            let mut r = acquire_frame_vec(n);
            xor_combine(&mut r, parity, &g.acc);
            rec = Some((r, mi));
        }
        // missing 为 None：全员到齐，校验帧没有存在的意义了
    }

    // 阶段二：终结组（lost 统计与 Go finishGroupLocked 一致：
    // 持有校验帧时终结 → 缺失成员计为确认丢失）
    if let Some((_, mi)) = &rec {
        if let Some(g) = inner.groups.get_mut(&start) {
            g.got_mask |= 1u64 << mi;
        }
    }
    if let Some(mut g) = inner.groups.remove(&start) {
        if let Some(parity) = g.parity.take() {
            let lost_n = (0..g.k).filter(|i| g.got_mask & (1u64 << i) == 0).count() as u64;
            inner.lost += lost_n;
            release_frame_vec(parity);
        }
        mark_done(&mut inner.done, start, k);
    }

    // 阶段三：输出恢复帧
    if let Some((r, mi)) = rec {
        inner.recovered += 1;
        out(start + mi as u32, Arc::new(r));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex as StdMutex;

    fn run_roundtrip(k: usize, drop_indices: &[usize], encrypt: bool) -> (usize, usize, usize) {
        let psk = "fec_test_psk";
        let ic_enc = if encrypt {
            Some(Arc::new(InnerCipher::gcm(psk, &[7u8; 8]).unwrap()))
        } else {
            None
        };
        let ic_dec = if encrypt {
            Some(Arc::new(InnerCipher::gcm(psk, &[7u8; 8]).unwrap()))
        } else {
            None
        };
        let mut enc = FecEncoder::new(k, ic_enc);
        let dec = FecDecoder::new(k, ic_dec);

        let recovered: StdMutex<Vec<(u32, Vec<u8>)>> = StdMutex::new(Vec::new());
        {
            let mut sink = |seq: u32, f: Arc<Vec<u8>>| {
                recovered.lock().unwrap().push((seq, (*f).clone()));
            };
            let total = k * 3;
            for i in 0..total {
                let payload = vec![((i * 31) % 251) as u8; 100 + (i * 13) % 200];
                let seq = (i + 1) as u32;
                // 编码端总是计入并可能产出校验帧
                let parity = enc.add(seq, &payload);
                if drop_indices.contains(&i) {
                    // 数据帧丢失：接收端只见其余成员
                } else {
                    dec.on_data(seq, &Arc::new(payload.clone()), &mut |_, _| {});
                }
                if let Some(parity) = parity {
                    dec.on_parity(&parity, &mut sink);
                }
            }
        }
        let got = recovered.lock().unwrap();
        (got.len(), dec.stats().0 as usize, dec.stats().1 as usize)
    }

    #[test]
    fn fec_batch_data_matches_single_frame_recovery() {
        let k = 4;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let mut data_batch = Vec::new();
        let mut parity = Vec::new();
        for i in 0..8usize {
            let seq = (i + 1) as u32;
            let payload = vec![(i as u8) + 1; 256 + i];
            if i != 2 && i != 6 {
                data_batch.push((seq, Arc::new(payload.clone())));
            }
            if let Some(p) = enc.add(seq, &payload) {
                parity.push(p);
            }
        }
        let mut recovered = Vec::new();
        dec.on_data_batch(&data_batch, &mut |seq, frame| {
            recovered.push((seq, frame.len()));
        });
        for p in &parity {
            dec.on_parity(p, &mut |seq, frame| recovered.push((seq, frame.len())));
        }
        for p in parity {
            release_frame_vec(p);
        }
        recovered.sort_unstable();
        assert_eq!(recovered, vec![(3, 258), (7, 262)]);
        assert_eq!(dec.stats(), (2, 0));
    }

    #[test]
    fn fec_recovers_single_drop_per_group() {
        // 每组丢 1 帧（组大小 4，丢第 0、5、9 帧），应全部恢复
        let (out, rec, lost) = run_roundtrip(4, &[0, 5, 9], false);
        assert_eq!(out, 3, "应恢复 3 帧");
        assert_eq!(rec, 3);
        assert_eq!(lost, 0);
    }

    #[test]
    fn fec_encrypted_roundtrip() {
        let (out, rec, lost) = run_roundtrip(2, &[1], true);
        assert_eq!(out, 1);
        assert_eq!(rec, 1);
        assert_eq!(lost, 0);
    }

    #[test]
    fn fec_double_drop_stays_pending() {
        // 同组丢 2 帧 → 不可恢复；与 Go 一致组保持挂起，lost 不计数
        let k = 4;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let mut out_count = 0;
        let mut sink = |_seq: u32, _f: Arc<Vec<u8>>| {
            out_count += 1;
        };
        let mut parity = None;
        for i in 0..k {
            let payload = vec![i as u8; 120];
            let seq = (i + 1) as u32;
            if i == 0 || i == 1 {
                let _ = enc.add(seq, &payload);
            } else {
                dec.on_data(seq, &Arc::new(payload.clone()), &mut |_, _| {});
            }
            if let Some(p) = enc.add(seq, &payload) {
                parity = Some(p);
            }
        }
        dec.on_parity(&parity.unwrap(), &mut sink);
        assert_eq!(out_count, 0);
        let (_, lost) = dec.stats();
        assert_eq!(lost, 0, "挂起组不计入确认丢失（对齐 Go）");
    }

    #[test]
    fn fec_duplicate_parity_ignored() {
        let k = 2;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let mut out_count = 0;
        let mut sink = |_seq: u32, _f: Arc<Vec<u8>>| {
            out_count += 1;
        };
        // 第一组：seq 1,2 全部到达 + 校验帧广播两份（多连接副本）
        let mut parity = None;
        for i in 0..2 {
            let payload = vec![0xA5u8; 64];
            let seq = (i + 1) as u32;
            dec.on_data(seq, &Arc::new(payload.clone()), &mut |_, _| {});
            if let Some(p) = enc.add(seq, &payload) {
                parity = Some(p);
            }
        }
        let parity = parity.expect("K=2 组满应产出校验帧");
        dec.on_parity(&parity, &mut sink);
        dec.on_parity(&parity, &mut sink); // 重复副本应被忽略
        assert_eq!(out_count, 0, "全员到齐时校验帧不应产出恢复帧");
    }

    #[test]
    fn fec_recover_first_frame_loss() {
        // 验收标准（对齐 Go TestFECRecoverFirstFrameLoss）：组首帧丢失时
        // 待定组不得被错误锚定，校验帧到达后按 group_start 对齐恢复 seq=1
        let k = 4;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let got: StdMutex<Vec<(u32, Vec<u8>)>> = StdMutex::new(Vec::new());
        {
            let mut sink = |seq: u32, f: Arc<Vec<u8>>| {
                got.lock().unwrap().push((seq, (*f).clone()));
            };
            let payloads: Vec<Vec<u8>> = (0..4).map(|i| vec![(i + 1) as u8; 50 + i * 10]).collect();
            // 组首（seq=1）丢失：仅 seq 2,3,4 到达
            for i in 1..4 {
                dec.on_data(
                    (i + 1) as u32,
                    &Arc::new(payloads[i].clone()),
                    &mut |_, _| {},
                );
            }
            let mut parity = None;
            for (i, p) in payloads.iter().enumerate() {
                if let Some(pp) = enc.add((i + 1) as u32, p) {
                    parity = Some(pp);
                }
            }
            dec.on_parity(&parity.unwrap(), &mut sink);
        }
        let g = got.lock().unwrap();
        assert_eq!(g.len(), 1, "应恰好恢复组首帧");
        assert_eq!(g[0].0, 1, "恢复帧必须是组首 seq=1");
        assert_eq!(g[0].1, payloads_ref(), "恢复内容不符");
    }

    fn payloads_ref() -> Vec<u8> {
        vec![1u8; 50]
    }

    #[test]
    fn fec_parity_before_members() {
        // 验收标准：校验帧先于其成员到达也要正确（乱序宽容）——
        // 组先由校验帧创建，成员迟到后仍能完成恢复
        let k = 2;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let got: StdMutex<Vec<u32>> = StdMutex::new(Vec::new());
        {
            let mut sink = |seq: u32, _f: Arc<Vec<u8>>| {
                got.lock().unwrap().push(seq);
            };
            let p1 = vec![0xAu8; 40];
            let p2 = vec![0xBu8; 40];
            // 编码端先产出校验帧
            assert!(enc.add(1, &p1).is_none());
            let parity = enc.add(2, &p2).expect("K=2 组满应产出校验帧");
            // 校验帧先到（成员尚未到达）
            dec.on_parity(&parity, &mut sink);
            assert!(got.lock().unwrap().is_empty(), "无成员时不得产出恢复帧");
            // 成员 seq=1 后到：恰好缺 1 帧 + 校验帧在 → 立即恢复 seq=2
            dec.on_data(1, &Arc::new(p1), &mut sink);
            assert_eq!(*got.lock().unwrap(), vec![2], "应立即恢复 seq=2");
            // 迟到的真帧 seq=2：组已终结，不得重复输出
            dec.on_data(2, &Arc::new(p2), &mut sink);
            assert_eq!(got.lock().unwrap().len(), 1, "终结组吸收迟到成员");
        }
    }

    #[test]
    fn fec_zero_length_frames_do_not_consume_slots() {
        // 对齐 Go a2701e4 验收：零长数据帧必须被忽略且不得占用分组槽位
        let k = 2;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let got: StdMutex<Vec<u32>> = StdMutex::new(Vec::new());
        {
            let mut sink = |seq: u32, _f: Arc<Vec<u8>>| {
                got.lock().unwrap().push(seq);
            };
            let p1 = vec![7u8; 40];
            // 零长帧：编码器忽略、解码器忽略
            assert!(enc.add(1, &[]).is_none(), "零长帧不参与分组");
            dec.on_data(1, &Arc::new(Vec::new()), &mut |_, _| {});
            assert!(enc.add(2, &p1).is_none());
            // 正常帧 seq=2 到达（分组起点仍 ≡1 mod K，与零长帧无关）
            let parity = enc.add(3, &p1).expect("seq 2+3 组满");
            dec.on_data(2, &Arc::new(p1.clone()), &mut |_, _| {});
            dec.on_data(3, &Arc::new(p1), &mut sink);
            dec.on_parity(&parity, &mut sink);
            // 若零长帧曾占用槽位，组 1..3 会被视为缺 seq=1 而伪造恢复
            assert!(got.lock().unwrap().is_empty(), "零长帧不得毒化分组恢复");
        }
    }

    #[test]
    fn fec_recovered_seq_in_order() {
        // 恢复帧的 seq 必须是组内缺失成员的原 seq
        let k = 3;
        let mut enc = FecEncoder::new(k, None);
        let dec = FecDecoder::new(k, None);
        let got: StdMutex<Vec<u32>> = StdMutex::new(Vec::new());
        {
            let mut sink = |seq: u32, _f: Arc<Vec<u8>>| {
                got.lock().unwrap().push(seq);
            };
            let mut parity = None;
            for i in 0..k {
                let payload = vec![(i + 7) as u8; 100 + i * 40];
                let seq = (i + 1) as u32;
                if i == 1 {
                    let _ = enc.add(seq, &payload); // seq=2 丢失
                } else {
                    dec.on_data(seq, &Arc::new(payload.clone()), &mut |_, _| {});
                }
                if let Some(p) = enc.add(seq, &payload) {
                    parity = Some(p);
                }
            }
            dec.on_parity(&parity.unwrap(), &mut sink);
        }
        assert_eq!(*got.lock().unwrap(), vec![2], "恢复帧应携带原 seq=2");
    }

    #[test]
    fn dynamic_rx_bypasses_single_path_interval_and_resumes() {
        let dec = FecDecoder::new(4, None);
        let mut sink = |_: u32, _: Arc<Vec<u8>>| {};
        dec.on_control(
            &FecModeControl {
                generation: 1,
                op: FEC_MODE_SUSPEND,
                boundary: 5,
            }
            .encode(),
            &mut sink,
        )
        .unwrap();
        for seq in 5..=8 {
            dec.on_data(seq, &Arc::new(vec![seq as u8]), &mut sink);
        }
        assert!(dec.inner.lock().groups.is_empty());

        dec.on_control(
            &FecModeControl {
                generation: 2,
                op: FEC_MODE_RESUME,
                boundary: 9,
            }
            .encode(),
            &mut sink,
        )
        .unwrap();
        dec.on_data(9, &Arc::new(vec![9]), &mut sink);
        assert!(dec.inner.lock().groups.contains_key(&9));
    }

    #[test]
    fn dynamic_suspend_drops_only_abandoned_groups() {
        let progress = Arc::new(AtomicU32::new(1));
        let dec = FecDecoder::new(4, None);
        let progress_reader = progress.clone();
        dec.set_reorder_progress(Arc::new(move || progress_reader.load(Ordering::Acquire)));
        let mut sink = |_: u32, _: Arc<Vec<u8>>| {};

        for seq in [1, 2, 5, 6] {
            dec.on_data(seq, &Arc::new(vec![seq as u8]), &mut sink);
        }
        dec.on_control(
            &FecModeControl {
                generation: 1,
                op: FEC_MODE_SUSPEND,
                boundary: 5,
            }
            .encode(),
            &mut sink,
        )
        .unwrap();

        let inner = dec.inner.lock();
        assert!(inner.groups.contains_key(&1));
        assert!(!inner.groups.contains_key(&5));
    }

    #[test]
    fn dynamic_old_groups_retire_only_after_reorder_crosses_fence() {
        let progress = Arc::new(AtomicU32::new(4));
        let dec = FecDecoder::new(4, None);
        let progress_reader = progress.clone();
        dec.set_reorder_progress(Arc::new(move || progress_reader.load(Ordering::Acquire)));
        let mut sink = |_: u32, _: Arc<Vec<u8>>| {};
        dec.on_data(1, &Arc::new(vec![1]), &mut sink);
        dec.on_data(2, &Arc::new(vec![2]), &mut sink);
        dec.on_control(
            &FecModeControl {
                generation: 1,
                op: FEC_MODE_SUSPEND,
                boundary: 5,
            }
            .encode(),
            &mut sink,
        )
        .unwrap();
        assert!(dec.inner.lock().groups.contains_key(&1));

        progress.store(5, Ordering::Release);
        dec.cleanup_by_reorder_progress();
        assert_eq!(dec.retired_before(), 5);
        assert!(dec.inner.lock().groups.is_empty());

        dec.on_data(1, &Arc::new(vec![1]), &mut sink);
        assert!(dec.inner.lock().groups.is_empty());
    }

    #[test]
    fn protocol_v3_rejects_unknown_and_malformed_controls() {
        let dec = FecDecoder::new(4, None);
        let mut sink = |_: u32, _: Arc<Vec<u8>>| {};
        assert!(dec.on_control(&[0x7f, 1, 2, 3], &mut sink).is_err());
        let mut bad = FecModeControl {
            generation: 1,
            op: FEC_MODE_SUSPEND,
            boundary: 5,
        }
        .encode();
        bad[2] = 1;
        assert!(dec.on_control(&bad, &mut sink).is_err());
    }
}
