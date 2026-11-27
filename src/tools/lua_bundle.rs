//! Compile-time bundled `lua/*.lua` scripts, XDG/system path discovery, and fallback extraction.

/// Directory creation, path canonicalization, and unchanged-file checks before overwriting.
use std::fs;
/// Destination filesystem path resolution for discovered and materialized Lua scripts.
use std::path::{Path, PathBuf};

/// User home directory lookup and tilde expansion shared with config path resolution.
use crate::tools::strat::interactive::{expand_tilde, resolve_user_home};
/// Symlink-safe file writer using `O_NOFOLLOW` so pre-existing symlinks are never overwritten.
use crate::tools::strat::toml::write_config_nofollow;

/// Core Lua script library embedded into the binary so installations work without an external repo.
pub const BUNDLED_LUA_SCRIPTS: &[(&str, &str)] = &[
    ("zapret-lib.lua", include_str!("../../lua/zapret-lib.lua")),
    ("zapret-antidpi.lua", include_str!("../../lua/zapret-antidpi.lua")),
    ("zapret-auto.lua", include_str!("../../lua/zapret-auto.lua")),
    ("zapret-obfs.lua", include_str!("../../lua/zapret-obfs.lua")),
    ("zapret-pcap.lua", include_str!("../../lua/zapret-pcap.lua")),
    ("zapret-tests.lua", include_str!("../../lua/zapret-tests.lua")),
];

/// Resolves `$<xdg_env>/zapret-rs` or `~/<home_segments>/zapret-rs`.
pub(crate) fn xdg_zapret_dir(xdg_env: &str, home_segments: &[&str]) -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os(xdg_env).filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(xdg).join("zapret-rs"));
    }
    resolve_user_home().map(|mut h| {
        for seg in home_segments {
            h.push(seg);
        }
        h.push("zapret-rs");
        h
    })
}

/// Returns the default user Lua directory (`$XDG_DATA_HOME/zapret-rs/lua` or `~/.local/share/zapret-rs/lua`).
pub fn default_user_lua_dir() -> Option<PathBuf> {
    xdg_zapret_dir("XDG_DATA_HOME", &[".local", "share"]).map(|d| d.join("lua"))
}

/// Returns candidate directories searched for `zapret-lib.lua` and `zapret-antidpi.lua`.
///
/// Relative CWD directories (`./lua`) are intentionally excluded unless passed via `--lua-dir`.
fn candidate_lua_dirs(explicit_dir: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = explicit_dir {
        return vec![expand_tilde(&dir.to_string_lossy())];
    }
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        dirs.push(parent.join("lua"));
        if let Some(prefix) = parent.parent() {
            dirs.push(prefix.join("share").join("zapret-rs").join("lua"));
        }
        if let Some(grand) = parent.parent().and_then(Path::parent) {
            dirs.push(grand.join("lua"));
        }
    }
    if let Some(user_dir) = default_user_lua_dir() {
        dirs.push(user_dir);
    }
    dirs.extend(
        [
            "/usr/local/share/zapret-rs/lua",
            "/usr/share/zapret-rs/lua",
            "/opt/zapret2/lua",
            "/usr/share/zapret2/lua",
        ]
        .map(PathBuf::from),
    );
    dirs
}

/// Auto-detects the first directory containing both `zapret-lib.lua` and `zapret-antidpi.lua`.
pub fn detect_lua_dir(explicit_dir: Option<&Path>) -> Option<PathBuf> {
    candidate_lua_dirs(explicit_dir).into_iter().find(|dir| {
        dir.join("zapret-lib.lua").is_file() && dir.join("zapret-antidpi.lua").is_file()
    })
}

/// Strips the Windows `\\?\` extended-length prefix from canonicalized paths when present.
pub fn strip_windows_verbatim_prefix(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    if let Some(s) = path.to_str()
        && let Some(stripped) = s.strip_prefix(r"\\?\")
        && !stripped.starts_with("UNC\\")
    {
        return PathBuf::from(stripped);
    }
    path
}

/// Returns canonical paths to `zapret-lib.lua` and `zapret-antidpi.lua` inside `dir`.
fn canonical_pair(dir: &Path) -> Vec<PathBuf> {
    let lib = dir.join("zapret-lib.lua");
    let anti = dir.join("zapret-antidpi.lua");
    vec![
        strip_windows_verbatim_prefix(fs::canonicalize(&lib).unwrap_or(lib)),
        strip_windows_verbatim_prefix(fs::canonicalize(&anti).unwrap_or(anti)),
    ]
}

/// Materializes all [`BUNDLED_LUA_SCRIPTS`] into `dir` without following symlinks.
///
/// Unchanged existing files are left untouched so repeated lookups avoid needless disk writes.
pub fn extract_bundled_lua(dir: &Path) -> Result<Vec<PathBuf>, String> {
    fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create Lua directory '{}': {err}", dir.display()))?;
    let mut written = Vec::with_capacity(BUNDLED_LUA_SCRIPTS.len());
    for &(name, contents) in BUNDLED_LUA_SCRIPTS {
        let dest = dir.join(name);
        if fs::read_to_string(&dest).ok().as_deref() != Some(contents) {
            write_config_nofollow(&dest, contents).map_err(|err| {
                format!("failed to write bundled Lua script '{}': {err}", dest.display())
            })?;
        }
        written.push(dest);
    }
    Ok(written)
}

/// Resolves canonical paths to `zapret-lib.lua` and `zapret-antidpi.lua`.
///
/// When `explicit_dir` is omitted and no on-disk `lua` directory exists, extracts the bundled
/// Lua scripts into [`default_user_lua_dir`] so installed binaries work without an external repo.
pub fn resolve_lua_scripts(explicit_dir: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    if let Some(dir) = detect_lua_dir(explicit_dir) {
        return Ok(canonical_pair(&dir));
    }
    if explicit_dir.is_none()
        && let Some(bundle_dir) = default_user_lua_dir()
        && extract_bundled_lua(&bundle_dir).is_ok()
    {
        return Ok(canonical_pair(&bundle_dir));
    }
    let checked = candidate_lua_dirs(explicit_dir)
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "could not locate zapret-lib.lua and zapret-antidpi.lua (checked: {checked}); pass --lua-dir <PATH>"
    ))
}
