//! Self-installing CLI (`zapret-rs install` / `uninstall`) for binary, bundled Lua, caps, and systemd.

/// Argument forwarding matching multicall CLI runner signatures.
use std::ffi::OsString;
/// Filesystem operations for directory creation, exclusive binary staging, symlink setup, and removal.
use std::fs::{self, OpenOptions};
/// Stream copy between source executable and exclusively created stage file.
use std::io;
/// Unix `O_NOFOLLOW` open flags and executable mode helpers preventing symlink stage races.
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _, symlink};
/// Destination prefix and installed binary/share path construction.
use std::path::{Path, PathBuf};
/// Clean exit status reporting.
use std::process::ExitCode;

/// CLI flag parsing for `install` and `uninstall` subcommands.
use clap::Parser;

/// Linux host integration helpers for capabilities and systemd service installation/removal.
#[cfg(target_os = "linux")]
use crate::tools::installer_sys::{apply_net_caps, install_systemd_service, uninstall_systemd_service};
/// Bundled Lua script extraction into `<prefix>/share/zapret-rs/lua`.
use crate::tools::lua_bundle::extract_bundled_lua;
/// Current invoking user's real home directory resolution (handling `sudo`).
use crate::tools::strat::interactive::resolve_user_home;

/// Compatibility symlink names optionally linked to `zapret-rs` inside `<prefix>/bin`.
pub const SYMLINK_NAMES: &[&str] = &["nfqws2", "strat_finder", "ip2net", "mdig"];

/// Command-line options for `zapret-rs install`.
#[derive(Debug, Parser)]
#[command(
    name = "zapret-rs install",
    version = env!("CARGO_PKG_VERSION"),
    about = "Install zapret-rs binary, bundled Lua scripts, capabilities, and optional systemd unit"
)]
struct InstallCli {
    /// Target prefix (`bin/zapret-rs`, `share/zapret-rs/lua`; defaults to `~/.local` or `/usr/local`).
    #[arg(long = "prefix", value_name = "DIR")]
    prefix: Option<PathBuf>,
    /// Create `nfqws2`, `strat_finder`, `ip2net`, and `mdig` compatibility symlinks in `bin/`.
    #[arg(long = "symlinks")]
    symlinks: bool,
    /// Skip `setcap cap_net_admin,cap_net_raw+ep` on the installed binary.
    #[arg(long = "no-caps")]
    no_caps: bool,
    /// Render, install, and enable `/etc/systemd/system/zapret-rs.service`.
    #[arg(long = "systemd")]
    systemd: bool,
    /// Override source executable path (defaults to the currently running binary).
    #[arg(long = "source-bin", value_name = "PATH")]
    source_bin: Option<PathBuf>,
}

/// Command-line options for `zapret-rs uninstall`.
#[derive(Debug, Parser)]
#[command(
    name = "zapret-rs uninstall",
    version = env!("CARGO_PKG_VERSION"),
    about = "Remove installed zapret-rs binary, symlinks, bundled Lua scripts, and optional systemd unit"
)]
struct UninstallCli {
    /// Target prefix used during installation (defaults to matching `~/.local` or `/usr/local`).
    #[arg(long = "prefix", value_name = "DIR")]
    prefix: Option<PathBuf>,
    /// Stop/disable and remove `/etc/systemd/system/zapret-rs.service` if present.
    #[arg(long = "systemd")]
    systemd: bool,
}

/// Returns effective UID on Unix (used to choose default prefix `/usr/local` vs `~/.local`).
fn current_euid() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        1000
    }
}

/// Chooses the default install prefix (`~/.local` for unprivileged installs, `/usr/local` otherwise).
fn default_install_prefix(prefer_system: bool) -> PathBuf {
    if prefer_system || current_euid() == 0 {
        return PathBuf::from("/usr/local");
    }
    resolve_user_home()
        .map(|h| h.join(".local"))
        .unwrap_or_else(|| PathBuf::from("/usr/local"))
}

/// Verifies `dir` is a non-symlink directory (creating it cleanly when absent).
fn ensure_real_dir(dir: &Path) -> Result<(), String> {
    if let Ok(meta) = fs::symlink_metadata(dir) {
        if meta.file_type().is_symlink() || !meta.file_type().is_dir() {
            return Err(format!(
                "refusing symlink or non-directory installation path '{}'",
                dir.display()
            ));
        }
        return Ok(());
    }
    fs::create_dir_all(dir)
        .map_err(|err| format!("failed to create '{}': {err}", dir.display()))
}

/// Atomically installs executable bytes from `src` to `dst` using `O_CREAT | O_EXCL | O_NOFOLLOW`
/// staging so pre-existing symlinks or stale stage filenames cannot be hijacked.
fn atomic_copy_executable(src: &Path, dst: &Path) -> Result<(), String> {
    let parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("invalid target path '{}'", dst.display()))?;
    ensure_real_dir(parent)?;

    let mut src_file = fs::File::open(src)
        .map_err(|err| format!("failed to open source binary '{}': {err}", src.display()))?;
    let mut staged = None;
    let mut dst_file = None;
    for attempt in 0..32u32 {
        let candidate = parent.join(format!(".zapret-rs.stage.{}.{}", std::process::id(), attempt));
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        opts.mode(0o755).custom_flags(libc::O_NOFOLLOW);
        match opts.open(&candidate) {
            Ok(file) => {
                staged = Some(candidate);
                dst_file = Some(file);
                break;
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create staged binary '{}': {err}",
                    candidate.display()
                ));
            }
        }
    }
    let (Some(staged_path), Some(mut out_file)) = (staged, dst_file) else {
        return Err(format!("could not allocate exclusive stage file in '{}'", parent.display()));
    };

    if let Err(err) = io::copy(&mut src_file, &mut out_file) {
        let _ = fs::remove_file(&staged_path);
        return Err(format!(
            "failed to copy '{}' to '{}': {err}",
            src.display(),
            staged_path.display()
        ));
    }
    #[cfg(unix)]
    if let Err(err) = out_file.set_permissions(fs::Permissions::from_mode(0o755)) {
        let _ = fs::remove_file(&staged_path);
        return Err(format!("failed to chmod '{}': {err}", staged_path.display()));
    }
    drop(out_file);

    fs::rename(&staged_path, dst).map_err(|err| {
        let _ = fs::remove_file(&staged_path);
        format!("failed to install binary '{}': {err}", dst.display())
    })
}

/// Returns `true` when `link_path` is a symlink targeting `zapret-rs`.
fn symlink_points_to_zapret(link_path: &Path, dst_bin: &Path) -> bool {
    let Ok(meta) = fs::symlink_metadata(link_path) else {
        return false;
    };
    if !meta.file_type().is_symlink() {
        return false;
    }
    fs::read_link(link_path).is_ok_and(|target| {
        target == Path::new("zapret-rs")
            || target == dst_bin
            || target.file_name() == Some(std::ffi::OsStr::new("zapret-rs"))
    })
}

/// Installs `zapret-rs`, bundled Lua scripts, optional symlinks, capabilities, and systemd unit.
fn perform_install(cli: &InstallCli) -> Result<(), String> {
    let prefix = cli
        .prefix
        .clone()
        .unwrap_or_else(|| default_install_prefix(cli.systemd));
    let src_bin = match &cli.source_bin {
        Some(path) => path.clone(),
        None => std::env::current_exe()
            .map_err(|err| format!("cannot locate running executable: {err}"))?,
    };
    let bin_dir = prefix.join("bin");
    let dst_bin = bin_dir.join("zapret-rs");
    let dst_is_symlink =
        fs::symlink_metadata(&dst_bin).is_ok_and(|meta| meta.file_type().is_symlink());
    if dst_is_symlink || fs::canonicalize(&src_bin).ok() != fs::canonicalize(&dst_bin).ok() {
        atomic_copy_executable(&src_bin, &dst_bin)?;
    }

    let lua_dir = prefix.join("share").join("zapret-rs").join("lua");
    ensure_real_dir(&lua_dir)?;
    extract_bundled_lua(&lua_dir)?;

    if cli.symlinks {
        #[cfg(unix)]
        for name in SYMLINK_NAMES {
            let link = bin_dir.join(name);
            if let Ok(meta) = fs::symlink_metadata(&link)
                && (meta.file_type().is_symlink() || meta.file_type().is_file())
            {
                fs::remove_file(&link).map_err(|err| {
                    format!("failed to replace '{}': {err}", link.display())
                })?;
            }
            symlink("zapret-rs", &link)
                .map_err(|err| format!("failed to create symlink '{}': {err}", link.display()))?;
        }
    }

    #[cfg(target_os = "linux")]
    if !cli.no_caps {
        apply_net_caps(&dst_bin)?;
    }

    #[cfg(target_os = "linux")]
    if cli.systemd {
        install_systemd_service(&dst_bin)?;
    }

    println!("Installed binary: {}", dst_bin.display());
    println!("Installed Lua:    {}", lua_dir.display());
    if cli.symlinks {
        println!("Created symlinks: {}", SYMLINK_NAMES.join(", "));
    }
    Ok(())
}

/// Removes installed files from `prefix` (preserving `~/.config/zapret-rs` and unrelated binaries).
fn perform_uninstall(cli: &UninstallCli) -> Result<(), String> {
    let prefix = cli.prefix.clone().unwrap_or_else(|| {
        let user_prefix = default_install_prefix(false);
        if user_prefix.join("bin").join("zapret-rs").exists() && current_euid() != 0 {
            user_prefix
        } else {
            default_install_prefix(cli.systemd)
        }
    });
    let bin_dir = prefix.join("bin");
    let main_bin = bin_dir.join("zapret-rs");
    if let Ok(meta) = fs::symlink_metadata(&main_bin)
        && (meta.file_type().is_file() || meta.file_type().is_symlink())
    {
        fs::remove_file(&main_bin)
            .map_err(|err| format!("failed to remove '{}': {err}", main_bin.display()))?;
    }
    for name in SYMLINK_NAMES {
        let target = bin_dir.join(name);
        if symlink_points_to_zapret(&target, &main_bin) {
            fs::remove_file(&target)
                .map_err(|err| format!("failed to remove '{}': {err}", target.display()))?;
        }
    }
    let lua_share = prefix.join("share").join("zapret-rs");
    if let Ok(meta) = fs::symlink_metadata(&lua_share)
        && !meta.file_type().is_symlink()
        && meta.file_type().is_dir()
    {
        fs::remove_dir_all(&lua_share)
            .map_err(|err| format!("failed to remove '{}': {err}", lua_share.display()))?;
    }
    #[cfg(target_os = "linux")]
    if cli.systemd {
        uninstall_systemd_service()?;
    }
    println!("Uninstalled zapret-rs artifacts under {}", prefix.display());
    Ok(())
}

/// Parses `zapret-rs install` CLI flags and executes installation.
pub fn run_install_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match InstallCli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let is_err = err.use_stderr();
            let _ = err.print();
            return if is_err { ExitCode::from(2) } else { ExitCode::SUCCESS };
        }
    };
    match perform_install(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("install error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Parses `zapret-rs uninstall` CLI flags and removes installed artifacts.
pub fn run_uninstall_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match UninstallCli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(err) => {
            let is_err = err.use_stderr();
            let _ = err.print();
            return if is_err { ExitCode::from(2) } else { ExitCode::SUCCESS };
        }
    };
    match perform_uninstall(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("uninstall error: {err}");
            ExitCode::FAILURE
        }
    }
}
