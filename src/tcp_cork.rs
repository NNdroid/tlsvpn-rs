use crate::net::{get_tcp_mss, get_tcp_rtt};
use std::io;
use std::time::{Duration, Instant};

const RTT_THRESHOLD_US: u32 = 1_000;
const MAX_DELAY_US: u64 = 150;
const FALLBACK_MSS: usize = 1_440;

#[cfg(target_os = "linux")]
pub(crate) trait CorkSocket: std::os::fd::AsRawFd {}
#[cfg(target_os = "linux")]
impl<T: std::os::fd::AsRawFd> CorkSocket for T {}

#[cfg(not(target_os = "linux"))]
pub(crate) trait CorkSocket {}
#[cfg(not(target_os = "linux"))]
impl<T> CorkSocket for T {}

#[inline]
fn policy_for_rtt(rtt_us: u32) -> Option<Duration> {
    if rtt_us > 0 && rtt_us < RTT_THRESHOLD_US {
        return None;
    }
    let delay_us = if rtt_us == 0 {
        MAX_DELAY_US
    } else {
        ((rtt_us as u64) / 8).min(MAX_DELAY_US)
    };
    Some(Duration::from_micros(delay_us.max(1)))
}

#[cfg(target_os = "linux")]
fn set_tcp_cork<S: CorkSocket>(stream: &S, enabled: bool) -> io::Result<()> {
    let value: libc::c_int = if enabled { 1 } else { 0 };
    let fd = <S as std::os::fd::AsRawFd>::as_raw_fd(stream);
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_CORK,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_tcp_cork<S: CorkSocket>(_stream: &S, _enabled: bool) -> io::Result<()> {
    Ok(())
}

/// Carries only the final partial TCP segment across authenticated TLSVPN data
/// batches. Full MSS segments remain eligible to leave immediately under
/// TCP_CORK; no synthetic payload bytes are generated.
pub(crate) struct TlsBatchCork {
    enabled: bool,
    corked: bool,
    mss: usize,
    progress: usize,
    delay: Duration,
    deadline: Option<Instant>,
}

impl TlsBatchCork {
    #[inline]
    pub(crate) fn disabled() -> Self {
        Self {
            enabled: false,
            corked: false,
            mss: FALLBACK_MSS,
            progress: 0,
            delay: Duration::from_micros(MAX_DELAY_US),
            deadline: None,
        }
    }

    pub(crate) fn new<S: CorkSocket>(stream: &S) -> Self {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = stream;
            Self::disabled()
        }

        #[cfg(target_os = "linux")]
        {
            let Some(delay) = policy_for_rtt(get_tcp_rtt(stream)) else {
                return Self::disabled();
            };
            let measured_mss = get_tcp_mss(stream);
            Self {
                enabled: true,
                corked: false,
                mss: if measured_mss >= 256 {
                    measured_mss
                } else {
                    FALLBACK_MSS
                },
                progress: 0,
                delay,
                deadline: None,
            }
        }
    }

    #[inline]
    pub(crate) fn next_timeout(&self, now: Instant) -> Option<Duration> {
        if !self.enabled || !self.corked {
            return None;
        }
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(now))
    }

    #[inline]
    pub(crate) fn before_write<S: CorkSocket>(&mut self, stream: &S, n: usize) {
        if !self.enabled || n == 0 {
            return;
        }
        self.before_write_with(n, Instant::now(), |enabled| set_tcp_cork(stream, enabled));
    }

    fn before_write_with<F>(&mut self, n: usize, now: Instant, mut setter: F)
    where
        F: FnMut(bool) -> io::Result<()>,
    {
        if !self.enabled || n == 0 {
            return;
        }
        if !self.corked {
            if setter(true).is_err() {
                self.enabled = false;
                return;
            }
            self.corked = true;
            self.progress = 0;
            self.deadline = Some(now + self.delay);
        }

        self.progress = self.progress.saturating_add(n);
        if self.progress >= self.mss {
            self.progress %= self.mss;
            self.deadline = Some(now + self.delay);
        } else if self.deadline.is_none() {
            self.deadline = Some(now + self.delay);
        }
    }

    #[inline]
    pub(crate) fn maybe_flush<S: CorkSocket>(&mut self, stream: &S, now: Instant) {
        if !self.enabled || !self.corked {
            return;
        }
        self.maybe_flush_with(now, |enabled| set_tcp_cork(stream, enabled));
    }

    fn maybe_flush_with<F>(&mut self, now: Instant, setter: F)
    where
        F: FnMut(bool) -> io::Result<()>,
    {
        if !self.corked || self.deadline.is_some_and(|deadline| now < deadline) {
            return;
        }
        self.flush_with(setter);
    }

    fn flush_with<F>(&mut self, mut setter: F)
    where
        F: FnMut(bool) -> io::Result<()>,
    {
        if !self.corked {
            return;
        }
        if setter(false).is_err() {
            self.enabled = false;
        }
        self.corked = false;
        self.progress = 0;
        self.deadline = None;
    }

    #[inline]
    pub(crate) fn close<S: CorkSocket>(&mut self, stream: &S) {
        if self.corked {
            self.flush_with(|enabled| set_tcp_cork(stream, enabled));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_cork(mss: usize, rtt_us: u32) -> TlsBatchCork {
        let Some(delay) = policy_for_rtt(rtt_us) else {
            return TlsBatchCork::disabled();
        };
        TlsBatchCork {
            enabled: true,
            corked: false,
            mss,
            progress: 0,
            delay,
            deadline: None,
        }
    }

    #[test]
    fn rtt_policy_matches_go() {
        assert_eq!(policy_for_rtt(80), None);
        assert_eq!(policy_for_rtt(999), None);
        assert_eq!(policy_for_rtt(1_000), Some(Duration::from_micros(125)));
        assert_eq!(policy_for_rtt(8_000), Some(Duration::from_micros(150)));
        assert_eq!(policy_for_rtt(0), Some(Duration::from_micros(150)));
    }

    #[test]
    fn disabled_fast_path_never_touches_socket_setter() {
        let mut cork = TlsBatchCork::disabled();
        let mut calls = Vec::new();
        cork.before_write_with(1500, Instant::now(), |on| {
            calls.push(on);
            Ok(())
        });
        assert!(calls.is_empty());
        assert!(cork.next_timeout(Instant::now()).is_none());
    }

    #[test]
    fn tiny_writes_do_not_extend_old_tail_forever() {
        let t0 = Instant::now();
        let mut cork = test_cork(1440, 8_000);
        let mut calls = Vec::new();
        cork.before_write_with(100, t0, |on| {
            calls.push(on);
            Ok(())
        });
        let first_deadline = cork.deadline.unwrap();
        cork.before_write_with(100, t0 + Duration::from_micros(50), |on| {
            calls.push(on);
            Ok(())
        });
        assert_eq!(cork.deadline, Some(first_deadline));
        assert_eq!(calls, vec![true]);
    }

    #[test]
    fn full_mss_of_progress_refreshes_deadline() {
        let t0 = Instant::now();
        let mut cork = test_cork(1440, 8_000);
        let mut calls = Vec::new();
        cork.before_write_with(900, t0, |on| {
            calls.push(on);
            Ok(())
        });
        cork.before_write_with(600, t0 + Duration::from_micros(80), |on| {
            calls.push(on);
            Ok(())
        });
        assert_eq!(
            cork.deadline,
            Some(t0 + Duration::from_micros(80 + MAX_DELAY_US))
        );
        assert_eq!(calls, vec![true]);
    }

    #[test]
    fn deadline_flush_and_close_uncork_exactly_once_each() {
        let t0 = Instant::now();
        let mut cork = test_cork(1440, 8_000);
        let mut calls = Vec::new();
        cork.before_write_with(100, t0, |on| {
            calls.push(on);
            Ok(())
        });
        cork.maybe_flush_with(t0 + Duration::from_micros(151), |on| {
            calls.push(on);
            Ok(())
        });
        assert_eq!(calls, vec![true, false]);
        assert!(cork.next_timeout(t0 + Duration::from_micros(151)).is_none());

        cork.before_write_with(100, t0 + Duration::from_millis(1), |on| {
            calls.push(on);
            Ok(())
        });
        cork.flush_with(|on| {
            calls.push(on);
            Ok(())
        });
        assert_eq!(calls, vec![true, false, true, false]);
    }

    #[test]
    fn enable_failure_disables_optimization_without_retry_storm() {
        let mut cork = test_cork(1440, 8_000);
        let mut calls = 0usize;
        cork.before_write_with(1500, Instant::now(), |_| {
            calls += 1;
            Err(io::Error::other("unsupported"))
        });
        cork.before_write_with(1500, Instant::now(), |_| {
            calls += 1;
            Ok(())
        });
        assert_eq!(calls, 1);
        assert!(!cork.enabled);
    }
}
