// XOR 奇偶校验 FEC，逐行为对齐 Go fec.go：
//
// 编码（端口级）：每 K 个数据帧生成 1 个校验帧（负载 = K 个成员明文负载的
// 逐字节异或），向所有连接广播；数据帧本身仍按 MinRTT 单路分发。
// 校验帧线路格式（沿用 10 字节头，seq=0、不加密）：
//   [1B 0xFE][4B groupStart(大端)][1B K][K×4B 成员长度][异或载荷]
// -encrypt 开启时异或载荷以 groupStart 为 seq 用本方向加密器加密（GCM 附标签）。
//
// 解码（会话级）：数据帧到达计入所属组累加器；校验帧到达且组内恰好缺 1 帧
// 时恢复并按原 seq 注入重排缓冲。组起点固定 ≡ 1 (mod K)。
// 同组丢 ≥2 帧不可恢复（组保持挂起，由在途上限淘汰），广播重复校验帧按组
// start 去重。与 Go 一致：lost 仅统计"持有校验帧且组终结"时的缺失数。
use byteorder::{BigEndian, ByteOrder};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;

use crate::crypto::*;

pub const FEC_MAGIC: u8 = 0xFE;
pub const FEC_MIN_GROUP: usize = 2;
pub const FEC_MAX_GROUP: usize = 64;
const FEC_MAX_PENDING_GROUPS: usize = 512;
const FEC_DONE_CACHE: usize = 64;

pub fn clamp_fec_group(k: usize) -> usize {
    k.clamp(FEC_MIN_GROUP, FEC_MAX_GROUP)
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

/// 判断一个已解密线路帧是否为 XOR 校验帧（对齐 Go isParityFrame）
pub fn is_parity_frame(frame: &[u8]) -> bool {
    frame.len() >= 7 && frame[0] == FEC_MAGIC
}

// ---------- 编码器（端口级，串行调用，无需加锁，对齐 fecEncoder） ----------

pub struct FecEncoder {
    k: usize,
    seqs: Vec<u32>,
    lens: Vec<usize>,
    acc: Vec<u8>,
    ic: Option<Arc<InnerCipher>>,
    parity_sent: std::sync::atomic::AtomicU64,
}

impl FecEncoder {
    pub fn new(k: usize, ic: Option<Arc<InnerCipher>>) -> Self {
        Self {
            k: clamp_fec_group(k),
            seqs: Vec::new(),
            lens: Vec::new(),
            acc: Vec::new(),
            ic,
            parity_sent: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn parity_sent(&self) -> u64 {
        use std::sync::atomic::Ordering::Relaxed;
        self.parity_sent.load(Relaxed)
    }

    /// 把一个数据帧计入当前分组；凑满 K 帧时生成校验帧并重置分组。
    /// 返回 Some(parity) 表示校验帧就绪（载荷所有权归调用方，广播后释放）。
    pub fn add(&mut self, seq: u32, data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() {
            return None;
        }
        self.seqs.push(seq);
        self.lens.push(data.len());
        if data.len() > self.acc.len() {
            self.acc.resize(data.len(), 0);
        }
        xor_into(&mut self.acc, data);
        if self.seqs.len() < self.k {
            return None;
        }
        let parity = self.build_parity();
        use std::sync::atomic::Ordering::Relaxed;
        self.parity_sent.fetch_add(1, Relaxed);
        self.reset();
        Some(parity)
    }

    fn reset(&mut self) {
        self.seqs.clear();
        self.lens.clear();
        for b in self.acc.iter_mut() {
            *b = 0;
        }
    }

    fn build_parity(&mut self) -> Vec<u8> {
        let max_len = self.acc.len();
        let tag_len = self.ic.as_ref().map(|c| c.tag_len()).unwrap_or(0);
        let mut buf = vec![0u8; 6 + 4 * self.lens.len() + max_len + tag_len];
        buf[0] = FEC_MAGIC;
        BigEndian::write_u32(&mut buf[1..5], self.seqs[0]);
        buf[5] = self.lens.len() as u8;
        let mut off = 6;
        for l in &self.lens {
            BigEndian::write_u32(&mut buf[off..off + 4], *l as u32);
            off += 4;
        }
        buf[off..off + max_len].copy_from_slice(&self.acc);
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
    done: Vec<u32>,
    recovered: u64,
    lost: u64,
}

pub struct FecDecoder {
    k: usize,
    ic: Option<Arc<InnerCipher>>,
    inner: Mutex<FecDecoderInner>,
}

impl FecDecoder {
    /// k 必须与对端编码分组大小一致（来自握手协商）；
    /// ic 为对端→本端方向的解密器（校验帧用 groupStart 作 seq 解密）。
    pub fn new(k: usize, ic: Option<Arc<InnerCipher>>) -> Self {
        Self {
            k: clamp_fec_group(k),
            ic,
            inner: Mutex::new(FecDecoderInner {
                groups: HashMap::new(),
                done: Vec::new(),
                recovered: 0,
                lost: 0,
            }),
        }
    }

    pub fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.groups.clear();
        inner.done.clear();
    }

    pub fn stats(&self) -> (u64, u64) {
        let inner = self.inner.lock();
        (inner.recovered, inner.lost)
    }

    /// 记录一个已解密的数据帧。out 为恢复帧输出回调（按原 seq 注入重排缓冲）。
    pub fn on_data(&self, seq: u32, frame: &Arc<Vec<u8>>, out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {
        if frame.is_empty() || seq == 0 {
            return;
        }
        let start = self.group_start_of(seq);
        let mut inner = self.inner.lock();
        if is_done(&inner.done, start) {
            return;
        }
        {
            let g = entry(&mut inner.groups, start);
            let bit = seq - start;
            let mask = 1u64 << bit;
            if g.got_mask & mask != 0 {
                return; // 重复到达
            }
            g.got_mask |= mask;
            if frame.len() > g.acc.len() {
                g.acc.resize(frame.len(), 0);
            }
            xor_into(&mut g.acc, frame);
        }
        try_recover(&mut inner, start, out);
    }

    /// 处理一个校验帧负载（已解密线路帧 seq=0）。
    pub fn on_parity(&self, payload: &[u8], out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {
        if payload.len() < 7 || payload[0] != FEC_MAGIC {
            return;
        }
        let start = BigEndian::read_u32(&payload[1..5]);
        let k = payload[5] as usize;
        if start == 0
            || k < FEC_MIN_GROUP
            || k > FEC_MAX_GROUP
            || k != self.k
            || (start - 1) % k as u32 != 0
        {
            return;
        }
        let desc_len = 6 + 4 * k;
        let tag_len = self.ic.as_ref().map(|c| c.tag_len()).unwrap_or(0);
        if payload.len() < desc_len + tag_len {
            return;
        }
        let mut lens = Vec::with_capacity(k);
        let mut max_len = 0usize;
        for i in 0..k {
            let l = BigEndian::read_u32(&payload[6 + 4 * i..10 + 4 * i]) as usize;
            if l + tag_len > payload.len() - desc_len {
                return; // 描述符与负载长度自洽性校验失败
            }
            lens.push(l);
            if l > max_len {
                max_len = l;
            }
        }

        let mut pb = vec![0u8; max_len];
        if let Some(ic) = &self.ic {
            // 解密校验载荷；AAD 与编码端一致：[加密区域长度(4BE) || groupStart(4BE)]
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
                    return; // GCM 校验失败，整组放弃
                }
            }
        } else {
            pb.copy_from_slice(&payload[desc_len..desc_len + max_len]);
        }

        let mut inner = self.inner.lock();
        if is_done(&inner.done, start) {
            return;
        }
        {
            let g = entry(&mut inner.groups, start);
            if g.parity.is_some() {
                return; // 同组重复校验帧（多连接广播副本）
            }
            g.k = k;
            g.lens = lens;
            g.parity = Some(pb);
        }
        try_recover(&mut inner, start, out);
    }

    fn group_start_of(&self, seq: u32) -> u32 {
        seq - ((seq - 1) % self.k as u32)
    }
}

fn is_done(done: &[u32], start: u32) -> bool {
    done.contains(&start)
}

fn mark_done(done: &mut Vec<u32>, start: u32) {
    done.push(start);
    if done.len() > FEC_DONE_CACHE {
        let drop = done.len() - FEC_DONE_CACHE;
        done.drain(..drop);
    }
}

/// 拿到组条目；组数超限时淘汰起点最老者（对齐 newGroupLocked：
/// 淘汰不标记 done，其迟到成员只会自然过期）
fn entry<'a>(groups: &'a mut HashMap<u32, FecGroupState>, start: u32) -> &'a mut FecGroupState {
    if groups.len() >= FEC_MAX_PENDING_GROUPS && !groups.contains_key(&start) {
        if let Some(oldest_start) = groups.keys().copied().min() {
            groups.remove(&oldest_start);
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
fn try_recover(inner: &mut FecDecoderInner, start: u32, out: &mut dyn FnMut(u32, Arc<Vec<u8>>)) {
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
            let mut r = vec![0u8; n];
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
        if let Some(_parity) = g.parity.take() {
            let lost_n = (0..g.k).filter(|i| g.got_mask & (1u64 << i) == 0).count() as u64;
            inner.lost += lost_n;
        }
        mark_done(&mut inner.done, start);
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
}
