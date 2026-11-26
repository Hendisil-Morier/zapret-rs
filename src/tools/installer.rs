//! Self-installing CLI (`zapret-rs install` / `uninstall`) for binary, bundled Lua, caps, and systemd.

/// Argument forwarding matching multicall CLI runner signatures.
use std::ffi::OsString;
/// Filesystem operations for directory creation, atomic binary staging, symlink setup, and removal.
use std::fs;
/// Unix executable mode (`0o755`) and symlink creation helpers.
#[cfg(unix)]
use std::os::unix::fs::{PermissionsExt as _, symlink};
/// Destination prefix and installed binary/share path construction.
use std::path::{Path, PathBuf};
/// Subprocess execution for `setcap` and `systemctl`, plus clean exit status reporting.
use std::process::{Command, ExitCode};

/// CLI flag parsing for `install` and `uninstall` subcommands.
use clap::Parser;

/// Bundled Lua script extraction into `<prefix>/share/zapret-rs/lua`.
use crate::tools::lua_bundle::extract_bundled_lua;
/// Current invoking user's real home directory resolution (handling `sudo`).
use crate::tools::strat::interactive::resolve_user_home;
/// Symlink-safe unit file write helper using `O_NOFOLLOW`.
use crate::tools::strat::toml::write_config_nofollow;

/// Compatibility symlink names optionally linked to `zapret-rs` inside `<prefix>/bin`.
pub const SYMLINK_NAMES: &[&str] = &["nfqws2", "strat_finder", "ip2net", "mdig"];

/// Systemd unit template embedded so `zapret-rs install --systemd` works outside the repo.
const SYSTEMD_SERVICE_TEMPLATE: &str = include_str!("../../contrib/systemd/zapret-rs.service");
/// Path where `zapret-rs install --systemd` installs the system service unit.
const SYSTEMD_SERVICE_DEST: &str = "/etc/systemd/system/zapret-rs.service";

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

/// Resolves the target operator username and home directory even when invoked via `sudo`.
fn resolve_operator_identity() -> (String, PathBuf) {
    let user = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "root".to_owned());
    let home = resolve_user_home().unwrap_or_else(|| PathBuf::from("/root"));
    (user, home)
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

/// Renders the embedded systemd unit with concrete executable path, operator user, and home dir.
pub fn render_systemd_service(bin_path: &Path, user: &str, home: &Path) -> String {
    SYSTEMD_SERVICE_TEMPLATE
        .replace("/usr/local/bin/zapret-rs", &bin_path.display().to_string())
        .replace("__USER__", user)
        .replace("__HOME__", &home.display().to_string())
}

/// Atomically installs executable bytes from `src` to `dst` with mode `0755`.
fn atomic_copy_executable(src: &Path, dst: &Path) -> Result<(), String> {
    let parent = dst
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| format!("invalid target path '{}'", dst.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create '{}': {err}", parent.display()))?;

    let staged = parent.join(format!(".zapret-rs.stage.{}", std::process::id()));
    fs::copy(src, &staged)
        .map_err(|err| format!("failed to copy '{}' to '{}': {err}", src.display(), staged.display()))?;
    #[cfg(unix)]
    fs::set_permissions(&staged, fs::Permissions::from_mode(0o755))
        .map_err(|err| format!("failed to chmod '{}': {err}", staged.display()))?;
    fs::rename(&staged, dst).map_err(|err| {
        let _ = fs::remove_file(&staged);
        format!("failed to install binary '{}': {err}", dst.display())
    })
}

/// Grants `CAP_NET_ADMIN` + `CAP_NET_RAW` via `setcap`, prepending `sudo` when not root.
#[cfg(target_os = "linux")]
fn apply_net_caps(bin_path: &Path) -> Result<(), String> {
    let status = if current_euid() == 0 {
        Command::new("setcap")
            .arg("cap_net_admin,cap_net_raw+ep")
            .arg(bin_path)
            .status()
    } else {
        Command::new("sudo")
            .args(["--", "setcap", "cap_net_admin,cap_net_raw+ep"])
            .arg(bin_path)
            .status()
    }
    .map_err(|err| format!("failed to execute setcap: {err}"))?;
    if !status.success() {
        return Err(format!("setcap exited with status {status}"));
    }
    Ok(())
}

/// Installs `/etc/systemd/system/zapret-rs.service` and runs `systemctl daemon-reload && enable`.
#[cfg(target_os = "linux")]
fn install_systemd_service(bin_path: &Path) -> Result<(), String> {
    let (user, home) = resolve_operator_identity();
    let unit = render_systemd_service(bin_path, &user, &home);
    write_config_nofollow(Path::new(SYSTEMD_SERVICE_DEST), &unit)
        .map_err(|err| format!("failed to write {SYSTEMD_SERVICE_DEST} (run with sudo): {err}"))?;
    let reload = Command::new("systemctl").args(["daemon-reload"]).status();
    if !reload.as_ref().is_ok_and(|s| s.success()) {
        return Err("systemctl daemon-reload failed".to_owned());
    }
    let enable = Command::new("systemctl")
        .args(["enable", "zapret-rs.service"])
        .status();
    if !enable.as_ref().is_ok_and(|s| s.success()) {
        return Err("systemctl enable zapret-rs.service failed".to_owned());
    }
    Ok(())
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
    if fs::canonicalize(&src_bin).ok() != fs::canonicalize(&dst_bin).ok() {
        atomic_copy_executable(&src_bin, &dst_bin)?;
    }

    let lua_dir = prefix.join("share").join("zapret-rs").join("lua");
    extract_bundled_lua(&lua_dir)?;

    if cli.symlinks {
        #[cfg(unix)]
        for name in SYMLINK_NAMES {
            let link = bin_dir.join(name);
            let _ = fs::remove_file(&link);
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

/// Removes installed files from `prefix` (preserving `~/.config/zapret-rs` user configs).
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
    for name in ["zapret-rs"].into_iter().chain(SYMLINK_NAMES.iter().copied()) {
        let target = bin_dir.join(name);
        if fs::symlink_metadata(&target).is_ok() {
            fs::remove_file(&target)
                .map_err(|err| format!("failed to remove '{}': {err}", target.display()))?;
        }
    }
    let lua_share = prefix.join("share").join("zapret-rs");
    if lua_share.exists() {
        fs::remove_dir_all(&lua_share)
            .map_err(|err| format!("failed to remove '{}': {err}", lua_share.display()))?;
    }
    #[cfg(target_os = "linux")]
    if cli.systemd {
        let _ = Command::new("systemctl")
            .args(["disable", "--now", "zapret-rs.service"])
            .status();
        let unit = Path::new(SYSTEMD_SERVICE_DEST);
        if unit.exists() {
            fs::remove_file(unit)
                .map_err(|err| format!("failed to remove {SYSTEMD_SERVICE_DEST}: {err}"))?;
        }
        let _ = Command::new("systemctl").args(["daemon-reload"]).status();
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
