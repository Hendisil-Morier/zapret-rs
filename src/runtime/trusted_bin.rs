//! Trusted system binary resolution and executable safety validation.

/// Filesystem metadata lookups and canonicalization avoiding caller-controlled `PATH` lookups.
#[cfg(unix)]
use std::fs;
/// Standard I/O result and error construction for invalid or missing executables.
use std::io;
/// Path component checks and trusted directory construction.
use std::path::{Component, Path, PathBuf};

/// Fixed trusted system binary directories searched instead of caller-controlled `PATH`.
pub const TRUSTED_SYSTEM_BIN_DIRS: &[&str] = &[
    "/usr/sbin",
    "/sbin",
    "/usr/bin",
    "/bin",
    "/run/current-system/sw/sbin",
    "/run/current-system/sw/bin",
    "/usr/local/sbin",
    "/usr/local/bin",
];

/// Resolves a bare executable `name` exclusively within [`TRUSTED_SYSTEM_BIN_DIRS`].
///
/// Never searches `PATH`, protecting root and ambient-capability processes (`CAP_NET_ADMIN`)
/// against unprivileged binary planting.
pub fn resolve_trusted_system_bin(name: &str) -> io::Result<PathBuf>
{
    if name.is_empty() || name.contains('/') || name.contains('\\') || name == "." || name == ".."
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid trusted executable name '{name}'"),
        ));
    }

    #[cfg(unix)]
    {
        for dir in TRUSTED_SYSTEM_BIN_DIRS
        {
            let candidate = Path::new(dir).join(name);
            if validate_unix_candidate(&candidate, true).is_ok()
            {
                return Ok(candidate);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "trusted executable '{name}' not found in system directories ({})",
                TRUSTED_SYSTEM_BIN_DIRS.join(", ")
            ),
        ))
    }

    #[cfg(not(unix))]
    {
        Ok(PathBuf::from(name))
    }
}

/// Validates a configured binary path or bare binary name without ever consulting caller `PATH`.
///
/// Bare names (single normal component) resolve through [`resolve_trusted_system_bin`].
/// Explicit paths must be absolute and point to a non-writable, root-owned executable binary.
pub fn validate_trusted_bin_path(path: &Path) -> io::Result<PathBuf>
{
    let mut comps = path.components();
    if let (Some(Component::Normal(name)), None) = (comps.next(), comps.next())
    {
        let bare = name
            .to_str()
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "executable name is not valid UTF-8")
            })?;
        return resolve_trusted_system_bin(bare);
    }

    if !path.is_absolute()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "refusing relative privileged binary path '{}'; specify an absolute path",
                path.display()
            ),
        ));
    }

    #[cfg(unix)]
    {
        let allow_overflow_uid = is_under_trusted_system_dir(path);
        validate_unix_candidate(path, allow_overflow_uid)?;
    }

    Ok(path.to_path_buf())
}

/// Returns `true` when `path` starts inside one of [`TRUSTED_SYSTEM_BIN_DIRS`].
#[cfg(unix)]
fn is_under_trusted_system_dir(path: &Path) -> bool
{
    TRUSTED_SYSTEM_BIN_DIRS
        .iter()
        .any(|dir| path.starts_with(Path::new(dir)))
}

/// Verifies `candidate` resolves to a regular, executable, non-group/world-writable binary
/// inside safe non-writable directories.
#[cfg(unix)]
fn validate_unix_candidate(candidate: &Path, allow_overflow_uid: bool) -> io::Result<()>
{
    /// Unix file permission mode inspection trait.
    use std::os::unix::fs::PermissionsExt as _;

    let parent = candidate
        .parent()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing parent directory for '{}'", candidate.display()),
            )
        })?;
    let parent_meta = fs::metadata(parent)?;
    if !parent_meta.is_dir()
    {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("parent '{}' is not a directory", parent.display()),
        ));
    }
    check_safe_owner_and_mode(&parent_meta, parent, allow_overflow_uid, false)?;

    let canon = fs::canonicalize(candidate)?;
    let target_meta = fs::metadata(&canon)?;
    if !target_meta.is_file()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("target '{}' is not a regular file", canon.display()),
        ));
    }
    check_safe_owner_and_mode(&target_meta, &canon, allow_overflow_uid, true)?;

    if let Some(canon_parent) = canon.parent()
    {
        let canon_parent_meta = fs::metadata(canon_parent)?;
        if !canon_parent_meta.is_dir()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("canonical parent '{}' is not a directory", canon_parent.display()),
            ));
        }
        check_safe_owner_and_mode(&canon_parent_meta, canon_parent, allow_overflow_uid, false)?;
    }

    // Reject world-writable ancestor directories (e.g., `/tmp`, `/var/tmp`, `/dev/shm`).
    let mut ancestor = canon.parent();
    while let Some(dir) = ancestor
    {
        let dir_meta = fs::metadata(dir)?;
        if (dir_meta
            .permissions()
            .mode()
            & 0o002)
            != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("refusing executable inside world-writable directory '{}'", dir.display()),
            ));
        }
        ancestor = dir.parent();
    }
    Ok(())
}

/// Enforces root ownership (plus unmapped overflow UID `65534` only in FHS system dirs),
/// clears group/world write bits, and requires executable bits when `require_exec` is `true`.
#[cfg(unix)]
fn check_safe_owner_and_mode(
    meta: &fs::Metadata,
    path: &Path,
    allow_overflow_uid: bool,
    require_exec: bool,
) -> io::Result<()>
{
    /// Unix metadata permission mode and owner UID inspection trait.
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    const OVERFLOW_UID: u32 = 65_534;
    let uid = meta.uid();
    let owner_ok = uid == 0 || (allow_overflow_uid && uid == OVERFLOW_UID);
    if !owner_ok
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing non-root-owned executable path '{}' (uid={uid})", path.display()),
        ));
    }

    let mode = meta
        .permissions()
        .mode();
    if (mode & 0o022) != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("refusing group/world-writable path '{}' (mode={mode:o})", path.display()),
        ));
    }
    if require_exec && (mode & 0o111) == 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("path '{}' is not marked executable", path.display()),
        ));
    }
    Ok(())
}
