//! Writable Lua directory setup and `WRITABLE` environment export (`--writable`).

/// Environment lookup and `WRITABLE` export helpers.
use std::env;
/// C string conversion for `libc::open` paths on Unix.
#[cfg(unix)]
use std::ffi::CString;
/// OS string slice for `TMPDIR` overrides.
use std::ffi::OsStr;
/// Filesystem directory creation, canonicalization, and probe file checks.
use std::fs::{self, OpenOptions};
/// Unix-only `DirBuilder` permission mode helper.
#[cfg(unix)]
use std::fs::DirBuilder;
/// Standard I/O error classification for `AlreadyExists` and non-directory targets.
use std::io;
/// Raw FD wrappers preventing path TOCTOU races between directory validation and `fchown`.
#[cfg(unix)]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
/// Raw byte access for paths passed to `libc::open`.
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
/// Unix permissions (`mode`), `st_dev`/`st_ino` verification, and `O_NOFOLLOW` probe flags.
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
/// Owned and borrowed filesystem path types.
use std::path::{Path, PathBuf};
/// Monotonic counter generating unique probe filenames inside existing directories.
use std::sync::atomic::{AtomicU64, Ordering};

/// Writable directory selection enum (`Default` vs `Custom(PathBuf)`).
use crate::config::WritableDirConfig;
/// Typed process lifecycle error surfaced when directory creation or verification fails.
use crate::runtime::error::ProcessError;
/// Target UID specification used to chown newly prepared directories before dropping root.
use crate::runtime::process::IdentitySpec;

/// Default subdirectory appended under `$TMPDIR` or `/tmp` when `--writable` omits a path.
pub const DEFAULT_WRITABLE_SUBDIR: &str = "zapret-rs";

/// Process-local sequence counter avoiding probe file collisions across concurrent checks.
static PROBE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Resolves the default `--writable` directory path from `TMPDIR` or `std::env::temp_dir()`.
pub fn resolve_default_writable_dir(tmpdir: Option<&OsStr>) -> PathBuf {
    let base = tmpdir
        .filter(|val| !val.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(env::temp_dir);
    base.join(DEFAULT_WRITABLE_SUBDIR)
}

/// Verifies `dir` is writable by atomically creating and removing a unique temporary probe file.
fn probe_dir_writable(dir: &Path) -> Result<(), ProcessError> {
    let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_path = dir.join(format!(".zapret_probe_{}_{}", std::process::id(), seq));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    match opts.open(&probe_path) {
        Ok(file) => {
            drop(file);
            let _ = fs::remove_file(&probe_path);
            Ok(())
        }
        Err(source) => Err(ProcessError::WritableDir {
            path: dir.to_path_buf(),
            source,
        }),
    }
}

/// Opens an existing directory without following symlinks and returns `(fd, stat)`.
#[cfg(unix)]
fn open_dir_nofollow(path: &Path) -> Result<(OwnedFd, libc::stat), io::Error> {
    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `c_path` is a valid NUL-terminated path string and flags require a non-symlink directory.
    let raw_fd = unsafe { libc::open(c_path.as_ptr(), flags) };
    if raw_fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw_fd` was returned by `libc::open` and is exclusively owned here.
    let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
    // SAFETY: `libc::stat` is plain data overwritten by `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `fd` is an open directory descriptor and `st` is valid writable storage.
    if unsafe { libc::fstat(fd.as_raw_fd(), &raw mut st) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
    }
    Ok((fd, st))
}

/// Attempts `fchown(fd, uid, -1)` on an already-opened directory FD without symlink TOCTOU risk.
#[cfg(unix)]
fn try_fchown_dir(fd: &OwnedFd, uid: libc::uid_t) -> bool {
    // SAFETY: `fd` is a verified `O_NOFOLLOW` directory descriptor and `u32::MAX` preserves GID.
    unsafe { libc::fchown(fd.as_raw_fd(), uid, libc::gid_t::MAX) == 0 }
}

/// Creates `target` (`0o755` on Unix) and returns `Ok(true)` if newly created or `Ok(false)` if it existed.
fn create_writable_dir(target: &Path) -> Result<bool, ProcessError> {
    #[cfg(unix)]
    let res = DirBuilder::new().mode(0o755).create(target);
    #[cfg(not(unix))]
    let res = fs::create_dir(target);
    match res {
        Ok(()) => Ok(true),
        Err(source) if source.kind() == io::ErrorKind::AlreadyExists => Ok(false),
        Err(source) => Err(ProcessError::WritableDir {
            path: target.to_path_buf(),
            source,
        }),
    }
}

/// Verifies directory ownership/non-symlink status on Unix, applies `fchown`, and returns canonical path.
#[cfg(unix)]
fn validate_and_chown_dir(
    target: &Path,
    created_fresh: bool,
    identity: Option<&IdentitySpec>,
) -> Result<(PathBuf, bool), ProcessError> {
    let (dir_fd, st) = open_dir_nofollow(target).map_err(|source| ProcessError::WritableDir {
        path: target.to_path_buf(),
        source,
    })?;
    if !created_fresh {
        // SAFETY: `geteuid()` always succeeds and takes no arguments.
        let euid = unsafe { libc::geteuid() };
        let target_uid = identity.map(|id| id.uid);
        if st.st_uid != euid && target_uid != Some(st.st_uid) {
            return Err(ProcessError::WritableDir {
                path: target.to_path_buf(),
                source: io::Error::from_raw_os_error(libc::EACCES),
            });
        }
    }
    let canonical = fs::canonicalize(target).map_err(|source| ProcessError::WritableDir {
        path: target.to_path_buf(),
        source,
    })?;
    let canon_meta = fs::metadata(&canonical).map_err(|source| ProcessError::WritableDir {
        path: target.to_path_buf(),
        source,
    })?;
    if canon_meta.dev() != st.st_dev || canon_meta.ino() != st.st_ino {
        return Err(ProcessError::WritableDir {
            path: target.to_path_buf(),
            source: io::Error::from_raw_os_error(libc::ELOOP),
        });
    }
    let chowned = identity.is_some_and(|id| try_fchown_dir(&dir_fd, id.uid));
    Ok((canonical, chowned))
}

/// Canonicalizes `target` on non-Unix platforms where Unix symlink/UID checks do not apply.
#[cfg(not(unix))]
fn validate_and_chown_dir(
    target: &Path,
    _created_fresh: bool,
    _identity: Option<&IdentitySpec>,
) -> Result<(PathBuf, bool), ProcessError> {
    let canonical = fs::canonicalize(target).map_err(|source| ProcessError::WritableDir {
        path: target.to_path_buf(),
        source,
    })?;
    Ok((canonical, false))
}

/// Creates/validates the `--writable` directory and returns its canonical path without mutating env.
pub fn ensure_writable_dir(
    cfg: &WritableDirConfig,
    identity: Option<&IdentitySpec>,
) -> Result<PathBuf, ProcessError> {
    let target = match cfg {
        WritableDirConfig::Default => {
            resolve_default_writable_dir(env::var_os("TMPDIR").as_deref())
        }
        WritableDirConfig::Custom(path) => path.clone(),
    };

    let created_fresh = create_writable_dir(&target)?;
    let (canonical, chowned) = validate_and_chown_dir(&target, created_fresh, identity)?;
    if !chowned {
        probe_dir_writable(&canonical)?;
    }
    Ok(canonical)
}

/// Creates/validates the `--writable` directory and exports its canonical path as `WRITABLE`.
pub fn prepare_writable_dir(
    cfg: &WritableDirConfig,
    identity: Option<&IdentitySpec>,
) -> Result<PathBuf, ProcessError> {
    let dir = ensure_writable_dir(cfg, identity)?;
    // SAFETY: invoked once during single-threaded `nfqws2` startup prior to thread creation or Lua init.
    unsafe {
        env::set_var("WRITABLE", &dir);
    }
    Ok(dir)
}
