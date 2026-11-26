//! `SO_PEERCRED` peer credential extraction and UID authorization checks for Unix sockets.

/// Connected control stream inspected for peer credentials.
use crate::control::transport::ControlStream;

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

/// Returns the current process effective UID (`geteuid` on Unix, `0` elsewhere).
#[cfg(unix)]
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid()` takes no arguments and always succeeds.
    unsafe { libc::geteuid() }
}

/// Returns `0` on non-Unix platforms lacking POSIX `geteuid`.
#[cfg(not(unix))]
pub fn current_euid() -> u32 {
    0
}

/// Default authorization check allowing only peers running as the exact daemon UID.
pub fn same_uid(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

/// Queries the kernel for `SO_PEERCRED` credentials of `stream` on Linux.
#[cfg(target_os = "linux")]
pub fn peer_credentials(stream: &ControlStream) -> std::io::Result<PeerCredentials> {
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

/// Queries the kernel for peer UID/GID via `getpeereid` on BSD and macOS.
#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
))]
pub fn peer_credentials(stream: &ControlStream) -> std::io::Result<PeerCredentials> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `stream` owns a live AF_UNIX socket fd and `uid`/`gid` are valid stack pointers.
    let rc = unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PeerCredentials { uid, gid, pid: 0 })
}

/// Returns `Unsupported` on platforms without `SO_PEERCRED` or `getpeereid`.
#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos"
)))]
pub fn peer_credentials(_stream: &ControlStream) -> std::io::Result<PeerCredentials> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "peer credentials unsupported on this OS",
    ))
}
