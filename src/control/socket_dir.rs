//! Symlink-safe parent directory creation and leaf-only ownership transfer for control sockets.

/// C path encoding for symlink-safe parent directory validation via `open(O_NOFOLLOW)`.
#[cfg(unix)]
use std::ffi::CString;
/// Non-symlink directory creation with restricted `0o700` leaf permissions.
use std::fs::DirBuilder;
/// Error classification matching existing vs newly created directories.
#[cfg(unix)]
use std::io::ErrorKind;
/// Owned directory FD wrappers preventing TOCTOU races across `fstat` and `fchown`.
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
/// Raw path bytes passed safely to `libc::open`.
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
/// Unix `0o700` mode support on [`DirBuilder`].
#[cfg(unix)]
use std::os::unix::fs::DirBuilderExt;
/// Filesystem path inspection for extracting parent and grandparent directories.
use std::path::Path;

/// Typed socket and directory setup errors returned to the daemon startup path.
use crate::control::socket::ControlServerError;

/// POSIX sticky bit (`S_ISVTX = 0o1000`), matching both 16-bit and 32-bit `mode_t` platforms.
#[cfg(unix)]
const POSIX_STICKY_BIT: libc::mode_t = 0o1000;
/// World-writable permission bit (`S_IWOTH = 0o002`), matching both 16-bit and 32-bit `mode_t`.
#[cfg(unix)]
const POSIX_WORLD_WRITE_BIT: libc::mode_t = 0o002;

/// Ensures the parent directory of `socket_path` exists (`0700` on Unix), rejects symlinks,
/// and transfers ownership via `fchown` only when the leaf directory was newly created.
#[cfg(unix)]
pub fn prepare_control_socket_dir(
    socket_path: &Path,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
) -> Result<(), ControlServerError>
{
    let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty())
    else
    {
        return Ok(());
    };
    if let Some(grandparent) = parent.parent().filter(|p| !p.as_os_str().is_empty())
    {
        DirBuilder::new()
            .recursive(true)
            .mode(0o755)
            .create(grandparent)
            .map_err(|source| ControlServerError::Io { path: grandparent.to_path_buf(), source })?;
    }
    let created_fresh = match DirBuilder::new().mode(0o700).create(parent)
    {
        Ok(()) => true,
        Err(err) if err.kind() == ErrorKind::AlreadyExists => false,
        Err(source) =>
        {
            return Err(ControlServerError::Io { path: parent.to_path_buf(), source });
        }
    };

    let c_dir = CString::new(parent.as_os_str().as_bytes()).map_err(|_| ControlServerError::Io {
        path: parent.to_path_buf(),
        source: std::io::Error::from_raw_os_error(libc::EINVAL),
    })?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `c_dir` is a NUL-terminated path opened with `O_DIRECTORY | O_NOFOLLOW`.
    let raw_fd = unsafe { libc::open(c_dir.as_ptr(), flags) };
    if raw_fd < 0
    {
        return Err(ControlServerError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `raw_fd` is a valid directory FD exclusively owned here.
    let dir_fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // SAFETY: `libc::stat` is plain-old-data C struct zeroed cleanly before `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `dir_fd` is valid and `st` points to writable stack storage.
    if unsafe { libc::fstat(dir_fd.as_raw_fd(), &raw mut st) } != 0
    {
        return Err(ControlServerError::Io {
            path: parent.to_path_buf(),
            source: std::io::Error::last_os_error(),
        });
    }

    if created_fresh
    {
        if let Some(uid) = target_uid
        {
            let gid = target_gid.unwrap_or(libc::gid_t::MAX);
            // SAFETY: `dir_fd` is a newly created non-symlink leaf directory; safe to transfer ownership.
            if unsafe { libc::fchown(dir_fd.as_raw_fd(), uid, gid) } != 0
            {
                return Err(ControlServerError::Io {
                    path: parent.to_path_buf(),
                    source: std::io::Error::last_os_error(),
                });
            }
        }
    }
    else
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let expected_uid = target_uid.unwrap_or(euid);
        let sticky_root_shared = st.st_uid == 0 && (st.st_mode & POSIX_STICKY_BIT) != 0;
        if (st.st_uid != expected_uid && !sticky_root_shared)
            || (!sticky_root_shared && (st.st_mode & POSIX_WORLD_WRITE_BIT) != 0)
        {
            return Err(ControlServerError::Io {
                path: parent.to_path_buf(),
                source: std::io::Error::from_raw_os_error(libc::EACCES),
            });
        }
    }
    Ok(())
}

/// Ensures the parent directory of `socket_path` exists on non-Unix targets.
#[cfg(not(unix))]
pub fn prepare_control_socket_dir(
    socket_path: &Path,
    _target_uid: Option<u32>,
    _target_gid: Option<u32>,
) -> Result<(), ControlServerError>
{
    let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty())
    else
    {
        return Ok(());
    };
    if !parent.exists()
    {
        DirBuilder::new()
            .recursive(true)
            .create(parent)
            .map_err(|source| ControlServerError::Io { path: parent.to_path_buf(), source })?;
    }
    Ok(())
}
