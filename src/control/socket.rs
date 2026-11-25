//! Safe Unix domain socket binding, symlink refusal, stale-socket probing, and poll helpers.

/// Scoped socket bind serialization so process-wide `umask(0177)` has no concurrent races.
use std::fs;
/// File type and permission error matching when probing pre-existing socket paths.
use std::io::ErrorKind;
/// Raw FD extraction for polling the listening socket without busy-waiting.
use std::os::fd::AsRawFd;
/// Unix-specific socket file detection, inode metadata, and permission bits (`0600`).
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
/// Unix domain listener binding and liveness probing via `connect`.
use std::os::unix::net::{UnixListener, UnixStream};
/// Filesystem path handling for binding and unlinking the control socket.
use std::path::{Path, PathBuf};
/// Global mutex serializing temporary `umask(0177)` changes during socket bind.
use std::sync::Mutex;

/// Global mutex ensuring two concurrent [`bind_control_socket`] calls never clobber umask.
static UMASK_LOCK: Mutex<()> = Mutex::new(());

/// Bound control socket listener paired with its owning `(st_dev, st_ino)` identity.
pub(crate) struct BoundSocket {
    /// Listening Unix domain stream socket configured with `0600` permissions.
    pub(crate) listener: UnixListener,
    /// Socket path retained for safe cleanup on shutdown.
    pub(crate) path: PathBuf,
    /// Device ID of the newly bound socket file for safe shutdown unlink checks.
    pub(crate) dev: u64,
    /// Inode number of the newly bound socket file for safe shutdown unlink checks.
    pub(crate) ino: u64,
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

/// Validates any pre-existing file at `path`, removing only confirmed stale sockets (`ECONNREFUSED`).
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
