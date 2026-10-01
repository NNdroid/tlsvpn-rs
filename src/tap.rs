use std::io;
use tun_rs::SyncDevice;

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
    /// Opportunistic drain by the device's sole reader; never wait for a batch.
    fn try_recv(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::WouldBlock.into())
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
    fn try_recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::fd::AsRawFd;
        let mut fd = libc::pollfd { fd: self.as_raw_fd(), events: libc::POLLIN, revents: 0 };
        // Only the TAP read thread consumes this fd. Readability cannot be
        // stolen by another reader between poll(0) and recv.
        let n = unsafe { libc::poll(&mut fd, 1, 0) };
        if n < 0 { return Err(io::Error::last_os_error()); }
        if n == 0 { return Err(io::ErrorKind::WouldBlock.into()); }
        if fd.revents & libc::POLLIN == 0 { return Err(io::ErrorKind::BrokenPipe.into()); }
        SyncDevice::recv(self, buf)
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
