//! Linux raw socket packet injection and abstract [`PacketSender`] trait for unit/integration testing.

/// Raw C string encoding for `SO_BINDTODEVICE`.
use std::ffi::CString;
/// Raw OS pointer and socket integer types.
use std::ffi::{c_int, c_void};
/// Standard IP address enum for IPv4/IPv6 dispatch.
use std::net::IpAddr;
/// Safe RAII wrapper and borrowing types for Linux file descriptors.
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Raw socket send buffer size constant (`RAW_SNDBUF`).
use crate::packet::constants::RAW_SNDBUF;
/// Typed errors returned during raw socket setup or packet injection.
use crate::rawsend::error::RawSendError;

/// Linux `IP_NODEFRAG` socket option number (may be missing on older headers).
const IP_NODEFRAG: c_int = 22;
/// Linux `IPV6_FREEBIND` socket option number (supported since kernel 4.15).
const IPV6_FREEBIND: c_int = 78;
/// Receive buffer size configured on raw injection sockets (mirrors `darkmagic.c`).
const RAW_SOCK_RCVBUF: c_int = 2048;
/// Kernel skb priority applied to injected raw packets (mirrors `darkmagic.c`).
const RAW_SOCK_PRIORITY: c_int = 6;

/// Trait abstracting raw L3 packet injection so Lua bindings and desync logic can be tested without `CAP_NET_RAW`.
pub trait PacketSender {
    /// Sends a single raw IPv4 or IPv6 packet toward `dst` with firewall mark `fwmark` and optional `ifout`.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>;

    /// Sends `packet` `repeats` consecutive times with identical routing metadata.
    fn send_repeat(
        &mut self,
        repeats: usize,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError> {
        for _ in 0..repeats {
            self.send(dst, fwmark, ifout, packet)?;
        }
        Ok(())
    }
}

/// Open raw socket descriptor paired with cached `SO_MARK` and `SO_BINDTODEVICE` state to elide redundant `setsockopt` calls.
#[derive(Debug)]
struct RawSocketState {
    /// Underlying Linux `SOCK_RAW | SOCK_CLOEXEC` file descriptor.
    fd: OwnedFd,
    /// Last firewall mark successfully applied via `SO_MARK`.
    last_fwmark: Option<u32>,
    /// Last device binding state successfully applied via `SO_BINDTODEVICE` (`Some(None)` = explicitly cleared).
    last_ifout: Option<Option<Box<str>>>,
}

/// Linux `AF_INET`/`AF_INET6` `SOCK_RAW` + `IPPROTO_RAW` packet injector matching `zapret2`'s `rawsend`.
#[derive(Debug, Default)]
pub struct RawSender {
    /// Lazily opened IPv4 raw socket and cached socket option state.
    sock4: Option<RawSocketState>,
    /// Lazily opened IPv6 raw socket and cached socket option state.
    sock6: Option<RawSocketState>,
    /// Whether `SO_BINDTODEVICE` routing fixup is active for IPv4 sends.
    bind_fix4: bool,
    /// Whether `SO_BINDTODEVICE` routing fixup is active for IPv6 sends.
    bind_fix6: bool,
}

impl RawSender {
    /// Creates a new `RawSender` with optional `SO_BINDTODEVICE` fixups for IPv4 and IPv6.
    pub fn new(bind_fix4: bool, bind_fix6: bool) -> Self {
        Self {
            sock4: None,
            sock6: None,
            bind_fix4,
            bind_fix6,
        }
    }

    /// Pre-opens raw sockets before dropping root privileges, tolerating `EAFNOSUPPORT` on IPv6-disabled kernels.
    pub fn preinit(&mut self) -> Result<(), RawSendError> {
        self.ensure_socket(false)?;
        match self.ensure_socket(true) {
            Ok(_) => Ok(()),
            Err(RawSendError::SocketIo(err))
                if err.raw_os_error() == Some(libc::EAFNOSUPPORT) =>
            {
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    /// Ensures the raw socket for `is_v6` is open and returns `&mut RawSocketState`.
    fn ensure_socket(&mut self, is_v6: bool) -> Result<&mut RawSocketState, RawSendError> {
        let slot = if is_v6 {
            &mut self.sock6
        } else {
            &mut self.sock4
        };
        if slot.is_none() {
            let domain = if is_v6 { libc::AF_INET6 } else { libc::AF_INET };
            // SAFETY: `libc::socket` takes integer constants and returns a new FD or `-1` on error.
            let raw_fd = unsafe {
                libc::socket(domain, libc::SOCK_RAW | libc::SOCK_CLOEXEC, libc::IPPROTO_RAW)
            };
            if raw_fd < 0 {
                return Err(RawSendError::SocketIo(std::io::Error::last_os_error()));
            }
            // SAFETY: `raw_fd` was just returned by `libc::socket` and is exclusively owned here.
            let owned = unsafe { OwnedFd::from_raw_fd(raw_fd) };
            let fd = owned.as_raw_fd();

            Self::set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_RCVBUF, RAW_SOCK_RCVBUF)?;
            Self::set_sockopt_int(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (RAW_SNDBUF / 2) as c_int,
            )?;
            Self::set_sockopt_int(fd, libc::SOL_SOCKET, libc::SO_PRIORITY, RAW_SOCK_PRIORITY)?;

            if !is_v6 {
                // `IP_NODEFRAG` is best-effort on older kernels; ignore errors if unsupported.
                let _ = Self::set_sockopt_int(fd, libc::IPPROTO_IP, IP_NODEFRAG, 1);
                Self::set_sockopt_int(fd, libc::IPPROTO_IP, libc::IP_FREEBIND, 1)?;
            } else {
                // `IPV6_FREEBIND` requires Linux >= 4.15; ignore errors on older kernels.
                let _ = Self::set_sockopt_int(fd, libc::SOL_IPV6, IPV6_FREEBIND, 1);
            }

            *slot = Some(RawSocketState {
                fd: owned,
                last_fwmark: None,
                last_ifout: None,
            });
        }
        Ok(slot
            .as_mut()
            .unwrap_or_else(|| unreachable!("socket slot was initialized above")))
    }

    /// Sets an integer socket option on `fd`.
    fn set_sockopt_int(
        fd: RawFd,
        level: c_int,
        optname: c_int,
        value: c_int,
    ) -> Result<(), RawSendError> {
        // SAFETY: `value` is a valid stack `c_int` matching `size_of::<c_int>()`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                optname,
                (&raw const value).cast::<c_void>(),
                std::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            Err(RawSendError::SocketIo(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Sets `SO_MARK` on `fd` to prevent injected packets from re-entering the NFQUEUE rule.
    fn set_fwmark(fd: RawFd, fwmark: u32) -> Result<(), RawSendError> {
        // SAFETY: `fwmark` is a valid `u32` on the stack with exact size `size_of::<u32>()`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&raw const fwmark).cast::<c_void>(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            Err(RawSendError::SocketIo(std::io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    /// Binds `fd` to `ifout` via `SO_BINDTODEVICE`, or clears the device binding when empty/`None`.
    fn bind_to_device(fd: RawFd, ifout: Option<&str>) -> Result<(), RawSendError> {
        match ifout.filter(|name| !name.is_empty()) {
            Some(name) => {
                let c_name = CString::new(name)
                    .map_err(|_| RawSendError::InvalidInterfaceName(name.to_owned()))?;
                let bytes = c_name.as_bytes_with_nul();
                // SAFETY: `bytes` is a NUL-terminated C string valid for the duration of `setsockopt`.
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        bytes.as_ptr().cast::<c_void>(),
                        bytes.len() as libc::socklen_t,
                    )
                };
                if rc < 0 {
                    Err(RawSendError::SocketIo(std::io::Error::last_os_error()))
                } else {
                    Ok(())
                }
            }
            None => {
                // SAFETY: passing length 0 clears `SO_BINDTODEVICE` on Linux without dereferencing pointer.
                let rc = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_SOCKET,
                        libc::SO_BINDTODEVICE,
                        std::ptr::null(),
                        0,
                    )
                };
                if rc < 0 {
                    Err(RawSendError::SocketIo(std::io::Error::last_os_error()))
                } else {
                    Ok(())
                }
            }
        }
    }
    /// Calls `libc::sendto` in an `EINTR`-retrying loop for a prebuilt destination `sockaddr`.
    fn sendto_retry(
        fd: RawFd,
        packet: &[u8],
        addr: *const libc::sockaddr,
        addr_len: libc::socklen_t,
    ) -> Result<(), RawSendError> {
        loop {
            // SAFETY: Caller passes valid `addr` / `addr_len` and `packet` stays valid across `sendto`.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    packet.as_ptr().cast::<c_void>(),
                    packet.len(),
                    0,
                    addr,
                    addr_len,
                )
            };
            if sent >= 0 {
                return Ok(());
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(RawSendError::SocketIo(err));
            }
        }
    }
}

impl PacketSender for RawSender {
    /// Injects a complete L3 packet toward `dst` using the cached raw socket for its IP family.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError> {
        let is_v6 = dst.is_ipv6();
        let bind_fix = if is_v6 { self.bind_fix6 } else { self.bind_fix4 };
        let state = self.ensure_socket(is_v6)?;
        let fd = state.fd.as_raw_fd();

        if state.last_fwmark != Some(fwmark) {
            Self::set_fwmark(fd, fwmark)?;
            state.last_fwmark = Some(fwmark);
        }

        if bind_fix {
            let norm_ifout = ifout.filter(|name| !name.is_empty());
            if state
                .last_ifout
                .as_ref()
                .is_none_or(|cached| cached.as_deref() != norm_ifout)
            {
                Self::bind_to_device(fd, norm_ifout)?;
                state.last_ifout = Some(norm_ifout.map(Box::<str>::from));
            }
        }

        match dst {
            IpAddr::V4(v4) => {
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as libc::sa_family_t,
                    sin_port: 0,
                    sin_addr: libc::in_addr {
                        s_addr: u32::from_ne_bytes(v4.octets()),
                    },
                    sin_zero: [0; 8],
                };
                Self::sendto_retry(
                    fd,
                    packet,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                )
            }
            IpAddr::V6(v6) => {
                // `sin6_port` must remain 0 on Linux raw sockets or `sendto` fails with `EINVAL`.
                let addr = libc::sockaddr_in6 {
                    sin6_family: libc::AF_INET6 as libc::sa_family_t,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: libc::in6_addr {
                        s6_addr: v6.octets(),
                    },
                    sin6_scope_id: 0,
                };
                Self::sendto_retry(
                    fd,
                    packet,
                    (&raw const addr).cast::<libc::sockaddr>(),
                    std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                )
            }
        }
    }
}
