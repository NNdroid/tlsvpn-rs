use byteorder::{BigEndian, ByteOrder};
use std::io::{self, ErrorKind, Read};

use crate::buffer::*;
use crate::crypto::*;
use crate::utils::*;

/// 成帧：10 字节头 [4B dataLen][2B padLen][4B seq] + 载荷 + 填充。
///
/// ic 为内层加密器：None 表示明文；seq=0 的控制/握手/校验帧恒不加密
/// （协议约定，接收端以此区分控制帧与数据帧）。GCM 模式密文后附 16B 标签，
/// 线路 dataLen = 明文长 + tagLen（对齐 Go appendPaddedFrame）。
pub fn append_padded_frame(buf: &mut Vec<u8>, seq: u32, data: &[u8], ic: Option<&InnerCipher>) {
    let data_len = data.len();
    let enc_tag = match ic {
        Some(c) if seq != 0 && data_len > 0 => c.tag_len(),
        _ => 0,
    };
    // 填充按线路长度计算（明文 + GCM 标签），不是明文长度：
    // GCM 密文比明文多 16B 标签，按明文长度分桶会把同一线路长度
    // 的帧划进不同的桶，破坏 bucket 模式的"固定长度分布"。
    let pad_len = crate::crypto::pad_length(data_len + enc_tag);

    let start_idx = buf.len();
    let needed = 10 + data_len + enc_tag + pad_len;
    // 逐段追加，既避免 resize 清零整块 payload/padding，也不把未初始化容量
    // 通过 set_len 暴露成 &[u8]（后者违反 Vec 的初始化约束，属于未定义行为）。
    buf.reserve(needed);

    let wire_len = (data_len + enc_tag) as u32;
    buf.extend_from_slice(&wire_len.to_be_bytes());
    buf.extend_from_slice(&(pad_len as u16).to_be_bytes());
    buf.extend_from_slice(&seq.to_be_bytes());
    buf.extend_from_slice(data);
    if enc_tag > 0 {
        buf.resize(buf.len() + enc_tag, 0);
    }

    if data_len > 0 {
        let payload_start = start_idx + 10;
        if let Some(c) = ic {
            if seq != 0 {
                c.seal_in_place(
                    &mut buf[payload_start..payload_start + data_len + enc_tag],
                    data_len,
                    seq,
                    wire_len,
                );
            }
        }
    }

    if pad_len > 0 {
        let offset = RNG.with(|rng| rng.borrow_mut().gen_range(0, PADDING_CACHE.len() - pad_len));
        buf.extend_from_slice(&PADDING_CACHE[offset..offset + pad_len]);
    }
}

/// 发送无需去重的控制帧（seq=0，明文），对齐 Go writeStreamFrame
pub fn write_stream_frame(buf: &mut Vec<u8>, frame: &[u8]) {
    buf.clear();
    append_padded_frame(buf, 0, frame, None);
}

pub struct FrameScanner {
    buffer: Vec<u8>,
    offset: usize,
    // 当前允许的帧负载上限：认证前的握手帧用小上限，认证通过后恢复线路
    // 全量上限（见 set_max_data_len）。默认给全量上限，这样只在握手路径上
    // 需要显式收紧。
    max_data_len: usize,
}

// 与 Go FrameScanner 对齐的常量
pub const HEADER_SIZE: usize = 10;
pub const MAX_DATA_LENGTH: usize = 65535 * 2;
/// 认证前首帧上限。合法握手 JSON < 2KB；不设限的话攻击者用 10 字节帧头声明
/// 131070 长度即可把扫描缓冲扩到 131KB/连接，预认证并发连接无上限，构成
/// 内存放大。
pub const HANDSHAKE_DATA_LENGTH: usize = 16 * 1024;

impl FrameScanner {
    pub fn new() -> Self {
        // 初始 16KB 覆盖典型 MTU 帧的聚合，大帧按需增长。旧值 70KB 对 1.5KB
        // 帧是 45 倍冗余，多连接下白占内存并放大内存扫描开销。
        Self {
            buffer: Vec::with_capacity(HANDSHAKE_DATA_LENGTH),
            offset: 0,
            max_data_len: MAX_DATA_LENGTH,
        }
    }

    /// 调整帧负载上限，认证前收紧、认证后放开配对使用（对齐 Go 的
    /// FrameScanner.SetMaxDataLen）。
    pub fn set_max_data_len(&mut self, n: usize) {
        self.max_data_len = n;
    }

    /// 供服务端"内层首字节嗅探"使用：返回缓冲区下一个待解析字节
    pub fn peek_first_byte(&self) -> Option<u8> {
        if self.buffer.len() > self.offset {
            Some(self.buffer[self.offset])
        } else {
            None
        }
    }

    /// 如果当前扫描缓冲已经含有完整帧，优先直接取出，不触碰底层 reader。
    ///
    /// TCP/TLS 一次 read 经常带回多帧；旧实现每次 read_frame() 都先再次调用
    /// reader.read()，即使 buffer 里已经有完整帧，也会额外制造一次
    /// read/WOULDBLOCK syscall。Go FrameScanner 一直是“缓存优先”，这里对齐它。
    fn take_buffered_frame(&mut self) -> io::Result<Option<(Vec<u8>, u32)>> {
        let available = self.buffer.len() - self.offset;
        if available < HEADER_SIZE {
            return Ok(None);
        }

        let data_len =
            BigEndian::read_u32(&self.buffer[self.offset..self.offset + 4]) as usize;
        let pad_len =
            BigEndian::read_u16(&self.buffer[self.offset + 4..self.offset + 6]) as usize;
        let seq = BigEndian::read_u32(&self.buffer[self.offset + 6..self.offset + 10]);

        if data_len > self.max_data_len {
            self.buffer.clear();
            self.offset = 0;
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "invalid frame data length",
            ));
        }

        let total_len = data_len + pad_len;
        if available < HEADER_SIZE + total_len {
            return Ok(None);
        }

        let payload_start = self.offset + HEADER_SIZE;
        self.offset += HEADER_SIZE + total_len;

        let out = if data_len == 0 {
            // 心跳/控制帧：返回空帧给调用方，由读循环刷新读超时。
            (Vec::new(), seq)
        } else {
            let mut data = acquire_frame_vec(data_len);
            data.copy_from_slice(&self.buffer[payload_start..payload_start + data_len]);
            (data, seq)
        };

        self.compact_consumed();
        Ok(Some(out))
    }

    #[inline]
    fn compact_consumed(&mut self) {
        if self.offset > 0 && (self.offset == self.buffer.len() || self.offset > 16384) {
            let remain = self.buffer.len() - self.offset;
            self.buffer.copy_within(self.offset.., 0);
            self.buffer.truncate(remain);
            self.offset = 0;
        }
    }

    /// 读取一帧。与 Go 行为一致：
    /// - 优先消费扫描缓冲中已经完整的帧，避免每帧额外 read/WOULDBLOCK；
    /// - dataLen > max_data_len → InvalidData 错误并清空缓冲；
    /// - dataLen == 0 的空帧返回空 Vec，供调用方刷新空闲计时；
    /// - 无完整帧且底层暂不可读时返回 Ok(None)。
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<(Vec<u8>, u32)>> {
        loop {
            if let Some(frame) = self.take_buffered_frame()? {
                return Ok(Some(frame));
            }

            // 有已消费前缀时先整理，给后续 socket read 尽量大的连续尾部。
            self.compact_consumed();

            if self.buffer.len() == self.buffer.capacity() {
                self.buffer.reserve(16384);
            }
            let spare = (self.buffer.capacity() - self.buffer.len()).min(16384);
            let base = self.buffer.as_mut_ptr_range().start;
            match reader
                .read(unsafe { std::slice::from_raw_parts_mut(base.add(self.buffer.len()), spare) })
            {
                Ok(0) => return Ok(None),
                Ok(n) => unsafe {
                    self.buffer.set_len(self.buffer.len() + n);
                },
                Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }

}

/// AsyncPort/backend 内部的 payload 所有权。
///
/// - Owned: 数据只会投递到一条 backend 时直接移动 pooled Vec，不分配 Arc 控制块；
/// - Shared: VSwitch 洪泛/重排等确实存在多 owner 时保留 Arc 零拷贝共享。
pub enum FramePayload {
    Owned(Vec<u8>),
    Shared(std::sync::Arc<Vec<u8>>),
}

impl FramePayload {
    #[inline]
    pub fn from_shared(data: std::sync::Arc<Vec<u8>>) -> Self {
        match std::sync::Arc::try_unwrap(data) {
            Ok(buf) => Self::Owned(buf),
            Err(shared) => Self::Shared(shared),
        }
    }

    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Owned(buf) => buf,
            Self::Shared(buf) => buf,
        }
    }

    #[inline]
    pub fn release(self) {
        match self {
            Self::Owned(buf) => release_frame_vec(buf),
            Self::Shared(buf) => release_shared_frame(buf),
        }
    }

    #[inline]
    pub fn into_shared(self) -> std::sync::Arc<Vec<u8>> {
        match self {
            Self::Owned(buf) => std::sync::Arc::new(buf),
            Self::Shared(buf) => buf,
        }
    }

    #[cfg(test)]
    #[inline]
    pub fn data_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}

impl std::ops::Deref for FramePayload {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

pub struct VPNFrame {
    pub seq: u32,
    pub data: FramePayload,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 填充必须按线路长度（明文 + GCM 标签）分桶，而不是明文长度。
    /// 128 号桶边界落在明文 112B 上（112 + 16B 标签 = 128）：
    /// 按线路长度算应填 0，误按明文长度算会填 16——两者可区分。
    #[test]
    fn padding_is_keyed_on_wire_length() {
        let _g = crate::crypto::PAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = crate::crypto::pad_mode_name();
        let _ = crate::crypto::set_pad_mode("bucket");

        let salt: [u8; 8] = [7; 8];
        let ic = InnerCipher::gcm("e2e_secret", &salt).unwrap();

        for &(pt_len, want_data_len, want_pad) in
            &[(112usize, 128usize, 118usize), (113, 129, 117), (0, 0, 118)]
        {
            let data = vec![0xABu8; pt_len];
            let mut buf = Vec::new();
            append_padded_frame(&mut buf, 1, &data, Some(&ic));

            let data_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
            let pad_len = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;

            assert_eq!(
                buf.len(),
                10 + data_len + pad_len,
                "帧总长必须自洽（头部 + 载荷 + 填充）"
            );
            assert_eq!(
                data_len, want_data_len,
                "明文 {}B 加密后线路 dataLen 应为 {}（含 16B 标签）",
                pt_len, want_data_len
            );
            assert_eq!(
                pad_len, want_pad,
                "明文 {}B（线路 {}B）应填 {}B",
                pt_len, want_data_len, want_pad
            );
        }

        // off 模式：任何长度都不填充
        let _ = crate::crypto::set_pad_mode("off");
        let data = vec![0u8; 300];
        let mut buf = Vec::new();
        append_padded_frame(&mut buf, 2, &data, Some(&ic));
        assert_eq!(
            u16::from_be_bytes(buf[4..6].try_into().unwrap()),
            0,
            "off 模式必须零填充"
        );

        // seq==0 的控制帧恒不加密，标签不占线路长度
        let mut buf = Vec::new();
        append_padded_frame(&mut buf, 0, &data, Some(&ic));
        let data_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(data_len, 300, "seq==0 的帧不得附加加密标签");

        let _ = crate::crypto::set_pad_mode(&prev);
    }

    // ---------- 预认证帧长上限（档 E） ----------

    fn append_frame_head(buf: &mut Vec<u8>, data_len: u32, pad_len: u16, seq: u32) {
        buf.extend_from_slice(&data_len.to_be_bytes());
        buf.extend_from_slice(&pad_len.to_be_bytes());
        buf.extend_from_slice(&seq.to_be_bytes());
    }

    struct OneBurstReader {
        data: Vec<u8>,
        sent: bool,
        reads: usize,
    }

    impl std::io::Read for OneBurstReader {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.reads += 1;
            if self.sent {
                return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
            }
            assert!(out.len() >= self.data.len());
            out[..self.data.len()].copy_from_slice(&self.data);
            self.sent = true;
            Ok(self.data.len())
        }
    }

    #[test]
    fn buffered_frames_are_consumed_before_reader_reentry() {
        let mut burst = Vec::new();
        append_frame_head(&mut burst, 3, 0, 11);
        burst.extend_from_slice(b"one");
        append_frame_head(&mut burst, 3, 0, 12);
        burst.extend_from_slice(b"two");

        let mut reader = OneBurstReader { data: burst, sent: false, reads: 0 };
        let mut scanner = FrameScanner::new();

        let (first, first_seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(first_seq, 11);
        assert_eq!(first, b"one");
        assert_eq!(
            reader.reads, 1,
            "首个完整帧到达后不应再额外 read 一次只为拿到 WouldBlock"
        );
        release_frame_vec(first);

        let (second, second_seq) = scanner.read_frame(&mut reader).unwrap().unwrap();
        assert_eq!(second_seq, 12);
        assert_eq!(second, b"two");
        assert_eq!(
            reader.reads, 1,
            "扫描缓冲已有第二帧时必须零 syscall 直接返回"
        );
        release_frame_vec(second);
    }

    #[test]
    fn over_limit_header_errors_without_buffer_bloat() {
        // 攻击面：10 字节帧头声明 16385 字节负载，只送帧头。扫描器必须立刻
        // 报错，而不能按声明长度把缓冲撑到 16KB 以上——预认证并发无上限，
        // 放大倍数会直接乘到连接数上。
        let mut stream = Vec::new();
        append_frame_head(&mut stream, HANDSHAKE_DATA_LENGTH as u32 + 1, 0, 0);
        stream.extend_from_slice(&[0u8; 5]);

        let mut s = FrameScanner::new();
        s.set_max_data_len(HANDSHAKE_DATA_LENGTH);
        let err = s
            .read_frame(&mut std::io::Cursor::new(stream))
            .expect_err("超限帧头必须立刻报错");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            s.buffer.capacity() <= HANDSHAKE_DATA_LENGTH * 2,
            "扫描缓冲膨胀到 {}，仅凭一个超限帧头就吃掉了远超握手上限的内存",
            s.buffer.capacity()
        );
        // 缓冲被清空：错误路径不能留下半帧残骸影响后续读取
        assert_eq!(s.buffer.len(), 0);
        assert_eq!(s.offset, 0);
    }

    #[test]
    fn large_frame_reads_after_relaxing_the_limit() {
        // 认证通过后恢复线路全量上限：jumbo 帧合法，不能因为收紧握手路径
        // 而把数据面一起卡死。
        let data = vec![0x5Au8; MAX_DATA_LENGTH];
        let mut stream = Vec::new();
        append_frame_head(&mut stream, MAX_DATA_LENGTH as u32, 0, 7);
        stream.extend_from_slice(&data);
        assert!(
            stream.capacity() > HANDSHAKE_DATA_LENGTH,
            "测试前置条件：完整帧必须超过初始缓冲容量"
        );

        let mut s = FrameScanner::new();
        s.set_max_data_len(HANDSHAKE_DATA_LENGTH);
        assert!(
            s.read_frame(&mut std::io::Cursor::new(stream.clone()))
                .is_err(),
            "收紧状态下同一帧必须被拒绝"
        );
        s.set_max_data_len(MAX_DATA_LENGTH);
        let (got, seq) = s
            .read_frame(&mut std::io::Cursor::new(stream))
            .unwrap()
            .unwrap();
        assert_eq!(seq, 7);
        assert_eq!(got.len(), MAX_DATA_LENGTH);
        assert!(got.iter().all(|&b| b == 0x5A));

        // 上限是"大于才拒"：恰好等于上限的帧必须通过
        let mut exact = Vec::new();
        append_frame_head(&mut exact, MAX_DATA_LENGTH as u32, 0, 0);
        exact.extend_from_slice(&data);
        let mut s2 = FrameScanner::new();
        let (got2, _) = s2
            .read_frame(&mut std::io::Cursor::new(exact))
            .unwrap()
            .unwrap();
        assert_eq!(got2.len(), MAX_DATA_LENGTH);

        // 空帧（心跳）不受上限影响
        let mut hb = Vec::new();
        append_frame_head(&mut hb, 0, 0, 42);
        let mut s3 = FrameScanner::new();
        s3.set_max_data_len(0);
        let (got3, seq3) = s3
            .read_frame(&mut std::io::Cursor::new(hb))
            .unwrap()
            .unwrap();
        assert!(got3.is_empty());
        assert_eq!(seq3, 42);
    }

    /// 桶填充同样以线路长度为输入：明文 184B + 16B 标签 = 线路 200B，
    /// record 210B 落在 256 桶 → pad 恰为 46。若误拿明文 184B 当输入
    /// （record 194B）会得到 62——两者不同，所以这个等值断言能锁住分桶依据。
    #[test]
    fn bucket_padding_uses_wire_length() {
        let _g = crate::crypto::PAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = crate::crypto::pad_mode_name();
        let _ = crate::crypto::set_pad_mode("bucket");

        let salt: [u8; 8] = [9; 8];
        let ic = InnerCipher::gcm("e2e_secret", &salt).unwrap();

        for _ in 0..30 {
            let mut buf = Vec::new();
            append_padded_frame(&mut buf, 3, &[0u8; 184], Some(&ic));
            let pad_len = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;
            assert_eq!(
                pad_len, 46,
                "明文 184B / 线路 200B 应填到 256 桶 → pad 46（按明文算会是 62），实际 {}",
                pad_len
            );
        }

        let _ = crate::crypto::set_pad_mode(&prev);
    }
}
