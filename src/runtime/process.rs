//! Process lifecycle primitives: UID/GID privilege drop, PID file guard, `chdir`, and daemonization.

/// Raw C string conversion for `getpwnam_r` and `initgroups` libc FFI calls.
use std::ffi::{CString, c_int, c_long};
/// PID file creation, writing, flushing, and removal on teardown.
use std::fs::{File, OpenOptions};
/// Write trait used for formatting the daemon PID into the open file descriptor.
use std::io::Write;
/// `O_NOFOLLOW` open flag preventing symlink target truncation in `PidFileGuard::create`.
use std::os::unix::fs::OpenOptionsExt;
/// Owned and borrowed filesystem path types for `chdir` and PID file management.
use std::path::{Path, PathBuf};

/// Linux capability retention helpers and `SECBIT_NO_SETUID_FIXUP` constant.
use crate::runtime::caps::{SECBIT_NO_SETUID_FIXUP, retain_net_capabilities_for};
/// Typed process lifecycle errors returned to the CLI binary or caller.
use crate::runtime::error::ProcessError;

/// Maximum supplementary GIDs accepted in `--uid` specifications (`MAX_GIDS` in `nfqws.c`).
const MAX_GIDS: usize = 64;
/// Default unprivileged GID applied when `--uid` omits `:gid1,gid2,...` (mirrors `zapret2`).
const DEFAULT_UNPRIVILEGED_GID: libc::gid_t = 0x7FFF_FFFF;
/// Fallback passwd entry scratch buffer size when `sysconf(_SC_GETPW_R_SIZE_MAX)` returns `-1`.
const DEFAULT_GETPW_BUF_LEN: usize = 16 * 1024;
/// Maximum buffer-doubling attempts if `getpwnam_r` reports `ERANGE`.
const MAX_GETPW_ATTEMPTS: usize = 4;

/// Resolved target UID, optional username for `initgroups`, and primary/supplementary GID list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySpec {
    /// Target POSIX numeric user ID.
    pub uid: libc::uid_t,
    /// Optional system username passed to `initgroups(3)` when resolving `--user`.
    pub user: Option<String>,
    /// Target group list (`gids[0]` becomes primary GID; remaining entries apply to `setgroups`).
    pub gids: Vec<libc::gid_t>,
}

/// Parses a numeric `--uid` specification of the form `uid[:gid1,gid2,...]`.
///
/// Matches `zapret2/nfq2/nfqws.c`: omitting `:gid` assigns `[0x7FFF_FFFF]`, while any
/// empty segments, non-numeric IDs, extra colons, or > 64 groups return `InvalidUidSpec`.
pub fn parse_uid_spec(spec: &str) -> Result<IdentitySpec, ProcessError> {
    let trimmed = spec.trim();
    if trimmed.is_empty() {
        return Err(ProcessError::InvalidUidSpec(spec.to_owned()));
    }

    let (uid_part, gids) = match trimmed.split_once(':') {
        Some((uid_str, gid_list)) => {
            if gid_list.is_empty() || gid_list.contains(':') {
                return Err(ProcessError::InvalidUidSpec(spec.to_owned()));
            }
            let mut parsed = Vec::new();
            for item in gid_list.split(',') {
                if item.is_empty() || parsed.len() >= MAX_GIDS {
                    return Err(ProcessError::InvalidUidSpec(spec.to_owned()));
                }
                let gid = item
                    .parse::<libc::gid_t>()
                    .map_err(|_| ProcessError::InvalidUidSpec(spec.to_owned()))?;
                parsed.push(gid);
            }
            (uid_str, parsed)
        }
        None => (trimmed, vec![DEFAULT_UNPRIVILEGED_GID]),
    };

    let uid = uid_part
        .parse::<libc::uid_t>()
        .map_err(|_| ProcessError::InvalidUidSpec(spec.to_owned()))?;

    Ok(IdentitySpec {
        uid,
        user: None,
        gids,
    })
}

/// Resolves a system username via thread-safe `getpwnam_r(3)` into an [`IdentitySpec`].
///
/// Uses `sysconf(_SC_GETPW_R_SIZE_MAX)` and expands on `ERANGE` up to 4 times. Returns
/// `ProcessError::UserLookup` if the account is absent or contains embedded NUL bytes.
pub fn resolve_user_spec(username: &str) -> Result<IdentitySpec, ProcessError> {
    let c_user = CString::new(username)
        .map_err(|_| ProcessError::UserLookup("username contains NUL byte".to_owned()))?;

    // SAFETY: `_SC_GETPW_R_SIZE_MAX` is a standard POSIX sysconf query taking no pointers.
    let suggested = unsafe { libc::sysconf(libc::_SC_GETPW_R_SIZE_MAX) };
    let mut buf_len = usize::try_from(suggested).unwrap_or(DEFAULT_GETPW_BUF_LEN);
    if buf_len < 1024 {
        buf_len = DEFAULT_GETPW_BUF_LEN;
    }

    for _ in 0..MAX_GETPW_ATTEMPTS {
        let mut buf = vec![0u8; buf_len];
        // SAFETY: `libc::passwd` is a C POD struct overwritten by `getpwnam_r` on success.
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();

        // SAFETY: `c_user`, `pwd`, `buf`, and `result` remain valid across `getpwnam_r`.
        let rc = unsafe {
            libc::getpwnam_r(
                c_user.as_ptr(),
                &raw mut pwd,
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &raw mut result,
            )
        };
        if rc == libc::ERANGE {
            buf_len = buf_len.saturating_mul(2);
            continue;
        }
        if rc != 0 {
            let err = std::io::Error::from_raw_os_error(rc);
            return Err(ProcessError::UserLookup(format!("'{username}': {err}")));
        }
        if result.is_null() {
            return Err(ProcessError::UserLookup(format!(
                "non-existent username '{username}'"
            )));
        }
        return Ok(IdentitySpec {
            uid: pwd.pw_uid,
            user: Some(username.to_owned()),
            gids: vec![pwd.pw_gid],
        });
    }

    Err(ProcessError::UserLookup(format!(
        "'{username}': passwd entry exceeded buffer limit"
    )))
}

/// Resolves mutually exclusive `user` and `uid` configuration fields into an optional [`IdentitySpec`].
pub fn resolve_identity(
    user: Option<&str>,
    uid: Option<&str>,
) -> Result<Option<IdentitySpec>, ProcessError> {
    if user.is_some() && uid.is_some() {
        return Err(ProcessError::UserLookup(
            "cannot specify both `user` and `uid`".to_owned(),
        ));
    }
    if let Some(name) = user {
        return resolve_user_spec(name).map(Some);
    }
    if let Some(spec) = uid {
        return parse_uid_spec(spec).map(Some);
    }
    Ok(None)
}

/// Changes the process current working directory (`--chdir`).
pub fn apply_chdir(path: &Path) -> Result<(), ProcessError> {
    std::env::set_current_dir(path).map_err(|source| ProcessError::Chdir {
        path: path.to_path_buf(),
        source,
    })
}

/// Drops root privileges to `id` while preserving or shedding `CAP_NET_ADMIN|CAP_NET_RAW`.
///
/// Mirrors `zapret2/nfq2/sec.c`'s `droproot()` + `dropcaps()` sequence:
/// enables `PR_SET_KEEPCAPS` (unless `SECBIT_NO_SETUID_FIXUP` is already set), updates
/// supplementary groups via `initgroups`/`setgroups`, switches GID/UID, and calls
/// [`retain_net_capabilities`].
pub fn drop_privileges(id: &IdentitySpec, require_net_caps: bool) -> Result<(), ProcessError> {
    drop_privileges_for(id, require_net_caps, false)
}

/// Drops root UID/GID cleanly to `id`, optionally keeping ambient `CAP_NET_ADMIN` for `--nft`.
pub fn drop_privileges_for(
    id: &IdentitySpec,
    require_net_caps: bool,
    preserve_nft_ambient: bool,
) -> Result<(), ProcessError> {
    if id.gids.is_empty() {
        return Err(ProcessError::PrivilegeDrop {
            step: "gids",
            source: std::io::Error::from_raw_os_error(libc::EINVAL),
        });
    }

    // SAFETY: `PR_SET_KEEPCAPS` takes integer flag `1` and ignores trailing arguments on Linux.
    if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1 as libc::c_ulong, 0, 0, 0) } < 0 {
        let source = std::io::Error::last_os_error();
        // SAFETY: `PR_GET_SECUREBITS` reads the calling process securebits bitmask.
        let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
        if bits < 0 || (bits as c_int & SECBIT_NO_SETUID_FIXUP) == 0 {
            return Err(ProcessError::PrivilegeDrop {
                step: "prctl(PR_SET_KEEPCAPS)",
                source,
            });
        }
    }

    if let Some(user) = &id.user {
        let c_user = CString::new(user.as_str())
            .map_err(|_| ProcessError::UserLookup("username contains NUL byte".to_owned()))?;
        // SAFETY: `c_user` is a valid NUL-terminated C string and `id.gids[0]` is a valid `gid_t`.
        if unsafe { libc::initgroups(c_user.as_ptr(), id.gids[0]) } < 0 {
            return Err(ProcessError::PrivilegeDrop {
                step: "initgroups",
                source: std::io::Error::last_os_error(),
            });
        }
    } else {
        // SAFETY: `id.gids` stays valid across `setgroups` with exact length `id.gids.len()`.
        if unsafe { libc::setgroups(id.gids.len() as _, id.gids.as_ptr()) } < 0 {
            return Err(ProcessError::PrivilegeDrop {
                step: "setgroups",
                source: std::io::Error::last_os_error(),
            });
        }
    }

    // SAFETY: `setgid` takes a single numeric `gid_t` value.
    if unsafe { libc::setgid(id.gids[0]) } < 0 {
        return Err(ProcessError::PrivilegeDrop {
            step: "setgid",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `setuid` takes a single numeric `uid_t` value.
    if unsafe { libc::setuid(id.uid) } < 0 {
        return Err(ProcessError::PrivilegeDrop {
            step: "setuid",
            source: std::io::Error::last_os_error(),
        });
    }

    retain_net_capabilities_for(require_net_caps, preserve_nft_ambient)
}

/// Drops UID 0 back to `SUDO_UID`/`SUDO_GID` when launched via `sudo`, retaining only
/// `CAP_NET_ADMIN|CAP_NET_RAW`.
///
/// Returns `Ok(Some((uid, gid)))` when root was dropped, or `Ok(None)` when already non-root or
/// when `SUDO_UID`/`SUDO_GID` are absent.
pub fn drop_sudo_root_if_needed() -> Result<Option<(u32, u32)>, ProcessError> {
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    let Some(uid) = std::env::var("SUDO_UID").ok().and_then(|s| s.parse::<u32>().ok()) else {
        return Ok(None);
    };
    let Some(gid) = std::env::var("SUDO_GID").ok().and_then(|s| s.parse::<u32>().ok()) else {
        return Ok(None);
    };
    if uid == 0 {
        return Ok(None);
    }
    let user = std::env::var("SUDO_USER").ok().filter(|s| !s.is_empty());
    let id = IdentitySpec { uid, gids: vec![gid], user };
    drop_privileges(&id, true)?;
    Ok(Some((uid, gid)))
}

/// RAII handle keeping a PID file pre-opened across privilege drops and removing it on drop.
///
/// Creating the file before dropping privileges lets the daemon write its PID even when the
/// runtime user cannot create new files in `/run`, while recording the absolute path ensures
/// cleanup removes the right file even after `--chdir`.
pub struct PidFileGuard {
    /// Absolute path (when resolvable) removed on teardown.
    path: PathBuf,
    /// Open file descriptor held until `write_current_pid` flushes and closes it.
    file: Option<File>,
}

impl PidFileGuard {
    /// Opens or truncates `path` and arms cleanup on drop.
    pub fn create(path: &Path) -> Result<Self, ProcessError> {
        let abs_path = if path.is_relative() {
            match std::env::current_dir() {
                Ok(cwd) => cwd.join(path),
                Err(_) => path.to_path_buf(),
            }
        } else {
            path.to_path_buf()
        };
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&abs_path)
            .map_err(|source| ProcessError::PidFile {
                path: abs_path.clone(),
                source,
            })?;
        Ok(Self {
            path: abs_path,
            file: Some(file),
        })
    }

    /// Writes `std::process::id()` to the pre-opened PID file, flushes it, and closes the handle.
    pub fn write_current_pid(&mut self) -> Result<(), ProcessError> {
        let Some(mut file) = self.file.take() else {
            return Err(ProcessError::PidFile {
                path: self.path.clone(),
                source: std::io::Error::other("PID file handle already closed"),
            });
        };
        write!(file, "{}", std::process::id()).map_err(|source| ProcessError::PidFile {
            path: self.path.clone(),
            source,
        })?;
        file.flush().map_err(|source| ProcessError::PidFile {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }

    /// Returns the filesystem path protected by this PID guard.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PidFileGuard {
    /// Closes any unwritten handle and removes the PID file best-effort when leaving scope.
    fn drop(&mut self) {
        self.file.take();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Forks into a background session leader and redirects stdin/stdout/stderr to `/dev/null`.
///
/// The parent exits immediately via `libc::_exit(0)` so callers' `Drop` guards (such as
/// [`PidFileGuard`]) are NOT run in the exiting parent process and buffered I/O is not duplicated.
pub fn daemonize() -> Result<(), ProcessError> {
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // SAFETY: Calling `fork()` prior to launching any background worker threads in this process.
    let pid: libc::pid_t = unsafe { libc::fork() };
    if pid < 0 {
        return Err(ProcessError::Daemonize {
            step: "fork",
            source: std::io::Error::last_os_error(),
        });
    }
    if pid > 0 {
        // SAFETY: Immediate `_exit(0)` avoids running parent `Drop` handlers on `PidFileGuard`.
        unsafe { libc::_exit(0) };
    }

    // SAFETY: Child process starts a new session independent of the caller's controlling TTY.
    if unsafe { libc::setsid() } < 0 {
        return Err(ProcessError::Daemonize {
            step: "setsid",
            source: std::io::Error::last_os_error(),
        });
    }

    // SAFETY: `c"/dev/null"` is a static NUL-terminated C path constant.
    let devnull = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
    if devnull < 0 {
        return Err(ProcessError::Daemonize {
            step: "open(/dev/null)",
            source: std::io::Error::last_os_error(),
        });
    }

    for target in [libc::STDIN_FILENO, libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        // SAFETY: `devnull` is a valid open FD redirected atomically onto stdio FD `target`.
        if unsafe { libc::dup2(devnull, target) } < 0 {
            let source = std::io::Error::last_os_error();
            // SAFETY: Close temporary FD before propagating the `dup2` error.
            let _ = unsafe { libc::close(devnull) };
            return Err(ProcessError::Daemonize { step: "dup2", source });
        }
    }

    if (devnull as c_long) > c_long::from(libc::STDERR_FILENO) {
        // SAFETY: `devnull` was duplicated to FDs 0..=2 and is no longer needed separately.
        let _ = unsafe { libc::close(devnull) };
    }
    Ok(())
}
