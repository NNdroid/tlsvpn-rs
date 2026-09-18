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
    // reserve + set_len 代替 resize：省掉对即将全部覆写区域的 memset
    buf.reserve(needed);
    unsafe {
        buf.set_len(start_idx + needed);
    }

    let wire_len = (data_len + enc_tag) as u32;
    buf[start_idx..start_idx + 4].copy_from_slice(&wire_len.to_be_bytes());
    buf[start_idx + 4..start_idx + 6].copy_from_slice(&(pad_len as u16).to_be_bytes());
    buf[start_idx + 6..start_idx + 10].copy_from_slice(&seq.to_be_bytes());

    if data_len > 0 {
        let payload_start = start_idx + 10;
        buf[payload_start..payload_start + data_len].copy_from_slice(data);
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
        let pad_start = start_idx + 10 + data_len + enc_tag;
        let offset = RNG.with(|rng| rng.borrow_mut().gen_range(0, PADDING_CACHE.len() - pad_len));
        buf[pad_start..pad_start + pad_len]
            .copy_from_slice(&PADDING_CACHE[offset..offset + pad_len]);
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
}

// 与 Go FrameScanner 对齐的常量
const HEADER_SIZE: usize = 10;
const MAX_DATA_LENGTH: usize = 65535 * 2;

impl FrameScanner {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(70 * 1024),
            offset: 0,
        }
    }

    /// 供服务端"内层首字节嗅探"使用：返回缓冲区下一个待解析字节
    pub fn peek_first_byte(&self) -> Option<u8> {
        if self.buffer.len() > self.offset {
            Some(self.buffer[self.offset])
        } else {
            None
        }
    }

    /// 读取一帧。与 Go 行为一致：
    /// - dataLen > 65535*2 → InvalidData 错误并清空缓冲；
    /// - dataLen == 0 的空帧（心跳等）直接跳过，不返回给调用方；
    /// - 无完整帧时返回 Ok(None)。
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<(Vec<u8>, u32)>> {
        // 直接读进缓冲的空闲尾部，省一次 16KB 栈→堆中转拷贝。
        // 与 bytes crate 内部相同的 spare-capacity 模式：read 只写前 n 字节，
        // 写完立即 set_len 暴露且仅暴露已初始化部分。
        loop {
            if self.buffer.len() == self.buffer.capacity() {
                self.buffer.reserve(16384);
            }
            let spare = (self.buffer.capacity() - self.buffer.len()).min(16384);
            let base = self.buffer.as_mut_ptr_range().start;
            match reader
                .read(unsafe { std::slice::from_raw_parts_mut(base.add(self.buffer.len()), spare) })
            {
                Ok(0) => break,
                Ok(n) => unsafe {
                    self.buffer.set_len(self.buffer.len() + n);
                },
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        loop {
            let available = self.buffer.len() - self.offset;
            if available < HEADER_SIZE {
                break;
            }
            let data_len = BigEndian::read_u32(&self.buffer[self.offset..self.offset + 4]) as usize;
            let pad_len =
                BigEndian::read_u16(&self.buffer[self.offset + 4..self.offset + 6]) as usize;
            let seq = BigEndian::read_u32(&self.buffer[self.offset + 6..self.offset + 10]);
            let total_len = data_len + pad_len;

            if data_len > MAX_DATA_LENGTH {
                self.buffer.clear();
                self.offset = 0;
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "invalid frame data length",
                ));
            }

            if available >= HEADER_SIZE + total_len {
                self.offset += HEADER_SIZE + total_len;

                if data_len == 0 {
                    // 心跳/控制帧：返回空帧给调用方，由读循环刷新读超时。
                    // 旧实现（Go 与本仓库）在此静默跳过，导致空闲隧道的
                    // 30 秒读超时永不刷新、每 30 秒被误杀重连一次
                    // （对齐 Go a2701e4 后的 ReadFrame 语义）。
                    if self.offset > 0 && (self.offset == self.buffer.len() || self.offset > 16384)
                    {
                        let remain = self.buffer.len() - self.offset;
                        self.buffer.copy_within(self.offset.., 0);
                        self.buffer.truncate(remain);
                        self.offset = 0;
                    }
                    return Ok(Some((Vec::new(), seq)));
                }

                let mut data = Vec::with_capacity(data_len.max(64));
                data.extend_from_slice(
                    &self.buffer[self.offset - total_len..self.offset - total_len + data_len],
                );

                // 压缩缓冲区（对齐 Go：offset==len 或 offset>16384 时整理）
                if self.offset > 0 && (self.offset == self.buffer.len() || self.offset > 16384) {
                    let remain = self.buffer.len() - self.offset;
                    self.buffer.copy_within(self.offset.., 0);
                    self.buffer.truncate(remain);
                    self.offset = 0;
                }

                return Ok(Some((data, seq)));
            }
            break;
        }

        if self.offset > 0 && (self.offset == self.buffer.len() || self.offset > 16384) {
            let remain = self.buffer.len() - self.offset;
            self.buffer.copy_within(self.offset.., 0);
            self.buffer.truncate(remain);
            self.offset = 0;
        }
        Ok(None)
    }
}

#[derive(Clone)]
pub struct VPNFrame {
    pub seq: u32,
    pub data: std::sync::Arc<Vec<u8>>,
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
            &[(112usize, 128usize, 0usize), (113, 129, 127), (0, 0, 0)]
        {
            let data = vec![0xABu8; pt_len];
            let mut buf = Vec::new();
            append_padded_frame(&mut buf, 1, &data, Some(&ic));

            let data_len =
                u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
            let pad_len = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;

            assert_eq!(
                buf.len(),
                10 + data_len + pad_len,
                "帧总长必须自洽（头部 + 载荷 + 填充）"
            );
            assert_eq!(
                data_len,
                want_data_len,
                "明文 {}B 加密后线路 dataLen 应为 {}（含 16B 标签）",
                pt_len,
                want_data_len
            );
            assert_eq!(
                pad_len,
                want_pad,
                "明文 {}B（线路 {}B）应填 {}B",
                pt_len,
                want_data_len,
                want_pad
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
        assert_eq!(
            data_len, 300,
            "seq==0 的帧不得附加加密标签"
        );

        let _ = crate::crypto::set_pad_mode(&prev);
    }

    /// legacy 阈值同样以线路长度为输入：明文 184B → 线路 200B 落在
    /// [100,299] 区间，而不是明文 184B 所在的 [300,499] 区间。
    #[test]
    fn legacy_thresholds_use_wire_length() {
        let _g = crate::crypto::PAD_TEST_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let prev = crate::crypto::pad_mode_name();
        let _ = crate::crypto::set_pad_mode("legacy");

        let salt: [u8; 8] = [9; 8];
        let ic = InnerCipher::gcm("e2e_secret", &salt).unwrap();

        // 明文 184B：线路 200B → [100,299]；若按明文长度算是 [300,499]
        for _ in 0..300 {
            let mut buf = Vec::new();
            append_padded_frame(&mut buf, 3, &[0u8; 184], Some(&ic));
            let pad_len = u16::from_be_bytes(buf[4..6].try_into().unwrap()) as usize;
            assert!(
                (100..=299).contains(&pad_len),
                "明文 184B / 线路 200B 的 legacy 填充应在 [100,299]，实际 {}",
                pad_len
            );
        }

        let _ = crate::crypto::set_pad_mode(&prev);
    }
}
