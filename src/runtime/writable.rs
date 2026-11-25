//! Writable Lua directory setup and `WRITABLE` environment export (`--writable`).

/// Environment lookup and `WRITABLE` export helpers.
use std::env;
/// C string and OS string conversions for `TMPDIR` resolution and `libc::chown`.
use std::ffi::{CString, OsStr};
/// Filesystem directory creation (`0o755`), canonicalization, and probe file checks.
use std::fs::{self, DirBuilder, OpenOptions};
/// Standard I/O error classification for `AlreadyExists` and non-directory targets.
use std::io;
/// Raw byte access for paths passed to `libc::chown`.
use std::os::unix::ffi::OsStrExt;
/// Unix `mode(0o755)` support for directory creation matching `mkdir(wrdir, 0755)`.
use std::os::unix::fs::DirBuilderExt;
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

/// Resolves the default `--writable` directory path from `TMPDIR` or `/tmp` (`<base>/zapret-rs`).
pub fn resolve_default_writable_dir(tmpdir: Option<&OsStr>) -> PathBuf {
    let base = tmpdir
        .filter(|val| !val.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join(DEFAULT_WRITABLE_SUBDIR)
}

/// Verifies `dir` is writable by atomically creating and removing a unique temporary probe file.
fn probe_dir_writable(dir: &Path) -> Result<(), ProcessError> {
    let seq = PROBE_SEQ.fetch_add(1, Ordering::Relaxed);
    let probe_path = dir.join(format!(".zapret_probe_{}_{}", std::process::id(), seq));
    match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe_path)
    {
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

/// Attempts `chown(dir, uid, -1)` so a dropped-privilege process can write files inside `dir`.
fn try_chown_dir(dir: &Path, uid: libc::uid_t) -> bool {
    let Ok(c_path) = CString::new(dir.as_os_str().as_bytes()) else {
        return false;
    };
    // SAFETY: `c_path` is a NUL-terminated path string and `u32::MAX` (`(gid_t)-1`) preserves GID.
    unsafe { libc::chown(c_path.as_ptr(), uid, libc::gid_t::MAX) == 0 }
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

    if let Err(source) = DirBuilder::new().mode(0o755).create(&target)
        && source.kind() != io::ErrorKind::AlreadyExists
    {
        return Err(ProcessError::WritableDir {
            path: target,
            source,
        });
    }

    let meta = fs::metadata(&target).map_err(|source| ProcessError::WritableDir {
        path: target.clone(),
        source,
    })?;
    if !meta.is_dir() {
        return Err(ProcessError::WritableDir {
            path: target,
            source: io::Error::from_raw_os_error(libc::ENOTDIR),
        });
    }

    let canonical = fs::canonicalize(&target).map_err(|source| ProcessError::WritableDir {
        path: target,
        source,
    })?;

    if let Some(id) = identity
        && try_chown_dir(&canonical, id.uid)
    {
        return Ok(canonical);
    }

    probe_dir_writable(&canonical)?;
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
