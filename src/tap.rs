use std::io;
use tun_rs::SyncDevice;

#[cfg(target_os = "linux")]
pub const TAP_IDEAL_BATCH_SIZE: usize = tun_rs::IDEAL_BATCH_SIZE;
#[cfg(not(target_os = "linux"))]
pub const TAP_IDEAL_BATCH_SIZE: usize = 1;

#[inline]
pub fn tap_batch_raw_buffer_size() -> usize {
    #[cfg(target_os = "linux")]
    {
        return tun_rs::VIRTIO_NET_HDR_LEN + 65535;
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

/// Abstraction over the L2 TAP device. Both the real kernel TAP
/// (`tun_rs::SyncDevice`) and the in-memory backend (`MemTap`) implement it, so
/// the rest of the stack (vswitch, tunnel, handshake, FEC, encryption) is
/// identical for both.
/// TAP MTU excludes the Ethernet header. Reserve enough L2/VLAN headroom and
/// keep the common 1500-MTU case inside the 2 KiB hot-frame pool.
#[inline]
pub fn tap_read_buffer_size(mtu: u16) -> usize {
    (usize::from(mtu.max(576)) + 64).max(2048)
}

pub trait TapDevice: Send + Sync {
    fn send(&self, data: &[u8]) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;

    fn recv_batch(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
    ) -> io::Result<usize> {
        let _ = original_buffer;
        if bufs.is_empty() || sizes.is_empty() {
            return Ok(0);
        }
        let n = self.recv(&mut bufs[0])?;
        sizes[0] = n;
        Ok(1)
    }
}


impl TapDevice for SyncDevice {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        SyncDevice::send(self, data).map(|_| ())
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        SyncDevice::recv(self, buf)
    }

    #[cfg(target_os = "linux")]
    fn recv_batch(
        &self,
        original_buffer: &mut [u8],
        bufs: &mut [Vec<u8>],
        sizes: &mut [usize],
    ) -> io::Result<usize> {
        self.recv_multiple(original_buffer, bufs, sizes, 0)
    }
}


/// In-memory TAP backend used when `--tap mem` is requested (CI/e2e on runners
/// that cannot create a real TAP device, e.g. GitHub hosted runners lack
/// CAP_NET_ADMIN). Writes are dropped (there is no real subnet behind it);
/// reads block forever (no downstream traffic) so the stack threads park until
/// the process exits. The actual tunnel (TLS handshake, FEC, encryption) runs
/// identically to the real-TAP path.
pub struct MemTap;

impl TapDevice for MemTap {
    fn send(&self, _data: &[u8]) -> io::Result<()> {
        Ok(())
    }
    fn recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        std::thread::park();
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tap_read_buffer_keeps_standard_mtu_in_hot_frame_class() {
        assert_eq!(tap_read_buffer_size(1500), 2048);
        assert_eq!(tap_read_buffer_size(576), 2048);
        assert_eq!(tap_read_buffer_size(9000), 9064);
    }
}
