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
    let pad_len = crate::crypto::get_padding_length(data_len);

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
                    continue; // 忽略空包（心跳/填充帧），对齐 Go
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
