use std::io;
use tun_rs::SyncDevice;

/// Abstraction over the L2 TAP device. Both the real kernel TAP
/// (`tun_rs::SyncDevice`) and the in-memory backend (`MemTap`) implement it, so
/// the rest of the stack (vswitch, tunnel, handshake, FEC, encryption) is
/// identical for both.
pub trait TapDevice: Send + Sync {
    fn send(&self, data: &[u8]) -> io::Result<()>;
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
}

impl TapDevice for SyncDevice {
    fn send(&self, data: &[u8]) -> io::Result<()> {
        SyncDevice::send(self, data).map(|_| ())
    }
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
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
