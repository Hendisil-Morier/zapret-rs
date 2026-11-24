//! Persistent `SIOCGIFNAME` socket helper for resolving Linux interface indices without per-packet socket syscalls.

/// RAII owned and borrowed Linux file descriptor wrappers.
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Typed error enum for socket creation failures.
use crate::intercepter::error::IntercepterError;

/// Resolves Linux network interface indices to interface names using one persistent UDP control socket.
#[derive(Debug)]
pub struct IfNameResolver {
    /// Persistent `AF_INET` `SOCK_DGRAM` file descriptor reused for `SIOCGIFNAME` `ioctl` calls.
    sock: OwnedFd,
}

impl IfNameResolver {
    /// Opens an `AF_INET` `SOCK_DGRAM | SOCK_CLOEXEC` control socket for interface name lookups.
    pub fn new() -> Result<Self, IntercepterError> {
        // SAFETY: `libc::socket` takes integer constants and returns a new FD or `-1` on error.
        let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `raw_fd` was just returned by `libc::socket` and is exclusively owned here.
        let sock = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self { sock })
    }

    /// Resolves `ifindex` via `SIOCGIFNAME`, returning `None` for `0` or unknown interfaces.
    pub fn resolve(&self, ifindex: u32) -> Option<String> {
        if ifindex == 0 {
            return None;
        }
        let idx = libc::c_int::try_from(ifindex).ok()?;
        // SAFETY: `libc::ifreq` is a plain C struct for which all-zero initialization is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_ifindex = idx;

        // SAFETY: `SIOCGIFNAME` reads `ifr_ifru.ifru_ifindex` and writes a NUL-terminated name into `ifr_name`.
        let rc = unsafe { libc::ioctl(self.sock.as_raw_fd(), libc::SIOCGIFNAME, &raw mut ifr) };
        if rc < 0 {
            return None;
        }

        let bytes: Vec<u8> = ifr
            .ifr_name
            .iter()
            .copied()
            .take_while(|&ch| ch != 0)
            .map(|ch| ch as u8)
            .collect();
        if bytes.is_empty() {
            None
        } else {
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}
