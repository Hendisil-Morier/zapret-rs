//! `SO_PEERCRED` peer credential extraction and UID authorization checks for Unix sockets.

/// Raw descriptor access for issuing `getsockopt(SOL_SOCKET, SO_PEERCRED)`.
use std::os::fd::AsRawFd;
/// Connected Unix domain stream socket inspected for peer credentials.
use std::os::unix::net::UnixStream;

/// Kernel-verified identity of a connected local Unix socket peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCredentials {
    /// Effective user ID of the connecting process.
    pub uid: u32,
    /// Effective group ID of the connecting process.
    pub gid: u32,
    /// Process ID of the connecting process (`0` if unavailable).
    pub pid: i32,
}

/// Predicate determining whether a peer UID is authorized to access `daemon_uid`'s socket.
pub type PeerUidCheck = fn(peer_uid: u32, daemon_uid: u32) -> bool;

/// Returns the current process effective UID (`geteuid`).
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid()` takes no arguments and always succeeds.
    unsafe { libc::geteuid() }
}

/// Default authorization check allowing only peers running as the exact daemon UID.
pub fn same_uid(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

/// Queries the kernel for `SO_PEERCRED` credentials of `stream`.
pub fn peer_credentials(stream: &UnixStream) -> std::io::Result<PeerCredentials> {
    // SAFETY: `libc::ucred` is a plain C struct fully initialized by `getsockopt`.
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `stream` owns a live AF_UNIX socket fd, and `cred`/`len` point to valid storage.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    if usize::try_from(len).unwrap_or(0) < std::mem::size_of::<libc::ucred>() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "short SO_PEERCRED reply",
        ));
    }
    Ok(PeerCredentials { uid: cred.uid, gid: cred.gid, pid: cred.pid })
}
