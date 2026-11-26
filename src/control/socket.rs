//! Safe Unix domain socket binding, symlink refusal, stale-socket probing, and poll helpers.

/// Runtime directory creation (`$XDG_RUNTIME_DIR/zapret-rs`) and environment lookup.
use std::env;
/// C path encoding for symlink-safe parent directory validation via `open(O_NOFOLLOW)`.
#[cfg(unix)]
use std::ffi::CString;
/// Scoped socket bind serialization so process-wide `umask(0177)` has no concurrent races.
use std::fs::{self, DirBuilder};
/// File type and permission error matching when probing pre-existing socket paths.
use std::io::ErrorKind;
/// Loopback TCP listener used on non-Unix targets.
#[cfg(not(unix))]
use std::net::TcpListener;
/// Raw FD access for polling the listening socket and `fchown`/`fstat` directory hardening.
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
/// Raw path bytes passed safely to `libc::open`.
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
/// Unix-specific socket file detection, inode metadata, and permission bits (`0600` / `0700`).
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
/// Unix domain listener binding and liveness probing via `connect`.
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
/// Filesystem path handling for binding and unlinking the control socket.
use std::path::{Path, PathBuf};
/// Global mutex serializing temporary `umask(0177)` changes during socket bind.
#[cfg(unix)]
use std::sync::Mutex;

/// Configuration enum deciding whether and where `nfqws2` binds its control socket.
use crate::config::ControlSocketConfig;
/// Cross-platform IPC stream wrapper.
use crate::control::transport::ControlStream;

/// Relative control socket suffix created under `$XDG_RUNTIME_DIR` when available.
pub const DEFAULT_CONTROL_SOCKET_SUBPATH: &str = "zapret-rs/control.sock";
/// System-wide fallback socket path used when `$XDG_RUNTIME_DIR` is unset (e.g., under systemd).
pub const DEFAULT_SYSTEM_CONTROL_SOCKET: &str = "/run/zapret-rs/control.sock";

/// Global mutex ensuring two concurrent [`bind_control_socket`] calls never clobber umask.
#[cfg(unix)]
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Bound control listener paired with its path and (on Unix) owning `(st_dev, st_ino)` identity.
pub(crate) struct BoundSocket {
    /// Listening Unix domain stream socket configured with `0600` permissions.
    #[cfg(unix)]
    pub(crate) listener: UnixListener,
    /// Listening loopback TCP socket on non-Unix targets.
    #[cfg(not(unix))]
    pub(crate) listener: TcpListener,
    /// Socket/rendezvous path retained for safe cleanup on shutdown.
    pub(crate) path: PathBuf,
    /// Device ID of the newly bound socket file for safe shutdown unlink checks.
    #[cfg(unix)]
    pub(crate) dev: u64,
    /// Inode number of the newly bound socket file for safe shutdown unlink checks.
    #[cfg(unix)]
    pub(crate) ino: u64,
}

impl BoundSocket {
    /// Waits up to `timeout_ms` for a pending connection.
    pub(crate) fn poll_readable(&self, timeout_ms: i32) -> bool {
        #[cfg(unix)]
        {
            poll_listener_readable(&self.listener, timeout_ms)
        }
        #[cfg(not(unix))]
        {
            let _ = timeout_ms;
            std::thread::sleep(std::time::Duration::from_millis(20));
            true
        }
    }

    /// Accepts one pending client stream in non-blocking mode.
    pub(crate) fn accept(&self) -> std::io::Result<ControlStream> {
        #[cfg(unix)]
        {
            self.listener.accept().map(|(s, _)| ControlStream::from_unix(s))
        }
        #[cfg(not(unix))]
        {
            self.listener.accept().map(|(s, _)| ControlStream::from_tcp(s))
        }
    }

    /// Drops the listener and removes the socket/rendezvous file safely.
    pub(crate) fn cleanup(self) {
        let path = self.path;
        #[cfg(unix)]
        let (dev, ino) = (self.dev, self.ino);
        drop(self.listener);
        #[cfg(unix)]
        unlink_if_same_socket(&path, dev, ino);
        #[cfg(not(unix))]
        let _ = fs::remove_file(&path);
    }
}

/// Typed errors returned when binding or running the Unix control socket server.
#[derive(Debug, thiserror::Error)]
pub enum ControlServerError {
    /// Refused to operate on or replace a symbolic link at the socket path.
    #[error("refusing to bind control socket over symlink at {}", .0.display())]
    SymlinkNotAllowed(PathBuf),
    /// Pre-existing file at the socket path is not a Unix domain socket.
    #[error("path {} exists and is not a Unix socket", .0.display())]
    NotASocket(PathBuf),
    /// Probing the existing socket succeeded, proving another daemon instance is running.
    #[error("control socket {} is already served by another running daemon", .0.display())]
    AlreadyRunning(PathBuf),
    /// Parent directory does not exist or OS rejected socket creation/permissions.
    #[error("control socket I/O error at {}: {source}", path.display())]
    Io {
        /// Filesystem path associated with the failing I/O call.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

/// Returns the default control socket path (`$XDG_RUNTIME_DIR/zapret-rs/control.sock` on Unix, or `temp_dir` elsewhere).
pub fn default_control_socket_path() -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR").filter(|val| !val.is_empty()) {
            return PathBuf::from(xdg).join(DEFAULT_CONTROL_SOCKET_SUBPATH);
        }
        PathBuf::from(DEFAULT_SYSTEM_CONTROL_SOCKET)
    }
    #[cfg(not(unix))]
    {
        env::temp_dir().join(DEFAULT_CONTROL_SOCKET_SUBPATH)
    }
}

/// Returns ordered, deduplicated control socket candidates checked when auto-attaching.
pub fn control_socket_candidates(configured: Option<&Path>) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Some(path) = configured {
        out.push(path.to_path_buf());
    }
    if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR").filter(|val| !val.is_empty()) {
        let p = PathBuf::from(xdg).join(DEFAULT_CONTROL_SOCKET_SUBPATH);
        if !out.contains(&p) {
            out.push(p);
        }
    }
    let sys = PathBuf::from(DEFAULT_SYSTEM_CONTROL_SOCKET);
    if !out.contains(&sys) {
        out.push(sys);
    }
    out
}

/// Resolves whether and where `nfqws2` should bind a control socket given config and `--intercept`.
pub fn resolve_control_socket_path(
    policy: &ControlSocketConfig,
    intercept: bool,
) -> Option<PathBuf> {
    match policy {
        ControlSocketConfig::Auto => intercept.then(default_control_socket_path),
        ControlSocketConfig::Default => Some(default_control_socket_path()),
        ControlSocketConfig::Custom(path) => Some(path.clone()),
        ControlSocketConfig::Disabled => None,
    }
}

/// Ensures the parent directory of `socket_path` exists (`0700` on Unix), rejects symlinks, and chowns to `target_uid`.
#[cfg(unix)]
pub fn prepare_control_socket_dir(
    socket_path: &Path,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
) -> Result<(), ControlServerError> {
    let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };

    if !parent.exists() {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(|source| ControlServerError::Io { path: parent.to_path_buf(), source })?;
    }

    let c_dir = CString::new(parent.as_os_str().as_bytes()).map_err(|_| ControlServerError::Io {
        path: parent.to_path_buf(),
        source: std::io::Error::from_raw_os_error(libc::EINVAL),
    })?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `c_dir` is a NUL-terminated path opened with `O_DIRECTORY | O_NOFOLLOW`.
    let raw_fd = unsafe { libc::open(c_dir.as_ptr(), flags) };
    if raw_fd < 0 {
        return Err(ControlServerError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw_fd` is a valid directory FD exclusively owned here.
    let dir_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

    if let Some(uid) = target_uid {
        let gid = target_gid.unwrap_or(libc::gid_t::MAX);
        // SAFETY: `dir_fd` is verified non-symlink via `O_NOFOLLOW`; `fchown` avoids path TOCTOU races.
        if unsafe { libc::fchown(dir_fd.as_raw_fd(), uid, gid) } != 0 {
            return Err(ControlServerError::Io {
                path: parent.to_path_buf(),
                source: std::io::Error::last_os_error(),
            });
        }
    }
    let _ = dir_fd;
    Ok(())
}

/// Ensures the parent directory of `socket_path` exists on non-Unix targets.
#[cfg(not(unix))]
pub fn prepare_control_socket_dir(
    socket_path: &Path,
    _target_uid: Option<u32>,
    _target_gid: Option<u32>,
) -> Result<(), ControlServerError> {
    let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty()) else {
        return Ok(());
    };
    if !parent.exists() {
        DirBuilder::new()
            .recursive(true)
            .create(parent)
            .map_err(|source| ControlServerError::Io { path: parent.to_path_buf(), source })?;
    }
    Ok(())
}

/// Validates any pre-existing file at `path`, removing only confirmed stale sockets (`ECONNREFUSED`).
#[cfg(unix)]
fn prepare_socket_path(path: &Path) -> Result<(), ControlServerError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return Err(ControlServerError::SymlinkNotAllowed(path.to_path_buf()));
            }
            if !meta.file_type().is_socket() {
                return Err(ControlServerError::NotASocket(path.to_path_buf()));
            }
            match UnixStream::connect(path) {
                Ok(_live) => return Err(ControlServerError::AlreadyRunning(path.to_path_buf())),
                Err(err) if err.kind() == ErrorKind::ConnectionRefused => {
                    fs::remove_file(path).map_err(|source| ControlServerError::Io {
                        path: path.to_path_buf(),
                        source,
                    })?;
                }
                Err(source) => {
                    return Err(ControlServerError::Io {
                        path: path.to_path_buf(),
                        source,
                    });
                }
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ControlServerError::Io { path: path.to_path_buf(), source });
        }
    }
    Ok(())
}

/// Binds a `0600` non-blocking Unix domain listener at `path`, replacing stale sockets safely.
#[cfg(unix)]
pub(crate) fn bind_control_socket(path: &Path) -> Result<BoundSocket, ControlServerError> {
    prepare_socket_path(path)?;

    let listener = {
        let _guard = UMASK_LOCK.lock();
        // SAFETY: Setting process umask `0177` ensures the new socket inode starts mode `0600`.
        let prev_mask = unsafe { libc::umask(0o177) };
        let bind_res = UnixListener::bind(path);
        // SAFETY: Always restore the previous umask immediately after `bind(2)`.
        unsafe { libc::umask(prev_mask) };
        bind_res.map_err(|source| ControlServerError::Io { path: path.to_path_buf(), source })?
    };

    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|source| {
        ControlServerError::Io { path: path.to_path_buf(), source }
    })?;
    listener.set_nonblocking(true).map_err(|source| ControlServerError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    let meta = fs::symlink_metadata(path).map_err(|source| ControlServerError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    if !meta.file_type().is_socket() {
        return Err(ControlServerError::NotASocket(path.to_path_buf()));
    }

    Ok(BoundSocket { listener, path: path.to_path_buf(), dev: meta.dev(), ino: meta.ino() })
}

/// Removes `path` on shutdown only when its current `(dev, ino)` still matches our bound socket.
#[cfg(unix)]
pub(crate) fn unlink_if_same_socket(path: &Path, expected_dev: u64, expected_ino: u64) {
    if let Ok(meta) = fs::symlink_metadata(path)
        && meta.file_type().is_socket()
        && meta.dev() == expected_dev
        && meta.ino() == expected_ino
    {
        let _ = fs::remove_file(path);
    }
}

/// Waits up to `timeout_ms` for `listener` to report a pending connection via `poll(2)`.
#[cfg(unix)]
pub(crate) fn poll_listener_readable(listener: &UnixListener, timeout_ms: i32) -> bool {
    let mut pfd = libc::pollfd { fd: listener.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    loop {
        // SAFETY: `pfd` points to a single initialized `pollfd` struct referencing `listener`'s fd.
        let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        return rc > 0 && (pfd.revents & (libc::POLLIN | libc::POLLERR | libc::POLLHUP)) != 0;
    }
}

/// Binds a non-blocking loopback TCP listener on non-Unix targets and writes its port to `path`.
#[cfg(not(unix))]
pub(crate) fn bind_control_socket(path: &Path) -> Result<BoundSocket, ControlServerError> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(ControlServerError::SymlinkNotAllowed(path.to_path_buf()));
        }
        if crate::control::transport::is_live_control_socket(path) {
            return Err(ControlServerError::AlreadyRunning(path.to_path_buf()));
        }
        let _ = fs::remove_file(path);
    }
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|source| ControlServerError::Io { path: path.to_path_buf(), source })?;
    let port = listener
        .local_addr()
        .map_err(|source| ControlServerError::Io { path: path.to_path_buf(), source })?
        .port();
    listener
        .set_nonblocking(true)
        .map_err(|source| ControlServerError::Io { path: path.to_path_buf(), source })?;
    fs::write(path, port.to_string())
        .map_err(|source| ControlServerError::Io { path: path.to_path_buf(), source })?;
    Ok(BoundSocket { listener, path: path.to_path_buf() })
}
