use aes::Aes256;
use byteorder::{BigEndian, ByteOrder};
use ctr::cipher::KeyIvInit;
use sha2::Digest;
use std::io::{self, ErrorKind, Read};
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

pub type Aes256Ctr = ctr::Ctr128BE<Aes256>;

use crate::buffer::*;
use crate::crypto::*;
use crate::utils::*;

pub fn append_tls_frame(buf: &mut Vec<u8>, seq: u32, data: &[u8], key: &[u8], iv: &[u8]) {
    let pad_len = get_padding_length(data.len());
    let start_idx = buf.len();
    buf.extend_from_slice(&[0; 10]);

    BigEndian::write_u32(&mut buf[start_idx..start_idx + 4], data.len() as u32);
    BigEndian::write_u16(&mut buf[start_idx + 4..start_idx + 6], pad_len as u16);
    BigEndian::write_u32(&mut buf[start_idx + 6..start_idx + 10], seq);

    if !data.is_empty() {
        let data_start = buf.len();
        buf.extend_from_slice(data);
        if seq != 0 && !key.is_empty() {
            xor_crypt_in_place(&mut buf[data_start..], seq, key, iv);
        }
    }

    if pad_len > 0 {
        let offset = RNG.with(|rng| rng.borrow_mut().gen_range(0, PADDING_CACHE.len() - pad_len));
        buf.extend_from_slice(&PADDING_CACHE[offset..offset + pad_len]);
    }
}

pub struct FrameScanner {
    buffer: Vec<u8>,
    offset: usize,
}

impl FrameScanner {
    pub fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(65536 * 4),
            offset: 0,
        }
    }
    pub fn read_frame<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<(Vec<u8>, u32)>> {
        let mut temp = [0u8; 16384];
        loop {
            match reader.read(&mut temp) {
                Ok(0) => break,
                Ok(n) => self.buffer.extend_from_slice(&temp[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        let available = self.buffer.len() - self.offset;
        if available >= 10 {
            let data_len = BigEndian::read_u32(&self.buffer[self.offset..self.offset + 4]) as usize;
            let pad_len =
                BigEndian::read_u16(&self.buffer[self.offset + 4..self.offset + 6]) as usize;
            let seq = BigEndian::read_u32(&self.buffer[self.offset + 6..self.offset + 10]);
            let total_len = data_len + pad_len;

            if total_len > 65536 * 2 {
                self.buffer.clear();
                self.offset = 0;
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Invalid frame header",
                ));
            }

            if available >= 10 + total_len {
                let mut data = get_frame();
                data.clear();
                data.extend_from_slice(&self.buffer[self.offset + 10..self.offset + 10 + data_len]);
                self.offset += 10 + total_len;

                if self.offset > 16384 && self.buffer.len() - self.offset < 16384 {
                    let remain = self.buffer.len() - self.offset;
                    self.buffer.copy_within(self.offset.., 0);
                    self.buffer.truncate(remain);
                    self.offset = 0;
                } else if self.offset == self.buffer.len() {
                    self.buffer.clear();
                    self.offset = 0;
                }

                return Ok(Some((data, seq)));
            }
        }
        Ok(None)
    }
}

#[derive(Clone)]
pub struct VPNFrame {
    pub seq: u32,
    pub data: Vec<u8>,
}
