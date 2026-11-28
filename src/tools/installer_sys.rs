//! Linux capability-target lockdown, trusted `systemctl` integration, and systemd unit rendering.

/// Process identity and capability-tool execution helpers on Linux.
#[cfg(target_os = "linux")]
use std::ffi::{CString, OsStr};
/// Filesystem metadata inspection, permission enforcement, and unit cleanup.
#[cfg(target_os = "linux")]
use std::fs;
/// Byte slice extraction from `OsStr` paths for `libc::chown`.
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
/// Unix file mode bits (`0o750`) for locking down capability-bearing executables.
#[cfg(target_os = "linux")]
use std::os::unix::fs::PermissionsExt as _;
/// Destination executable and home directory path slices used for systemd unit substitution.
use std::path::Path;
/// Owned home directory path buffer returned on Linux when resolving operator identity.
#[cfg(target_os = "linux")]
use std::path::PathBuf;
/// Trusted system command execution for `chown`, `chmod`, `setcap`, `sudo`, and `systemctl`.
#[cfg(target_os = "linux")]
use std::process::Command;

/// Trusted system binary resolution avoiding caller `PATH` hijacking.
#[cfg(target_os = "linux")]
use crate::runtime::resolve_trusted_system_bin;
/// Current invoking user's real home directory resolution (handling `sudo`).
#[cfg(target_os = "linux")]
use crate::tools::strat::interactive::resolve_user_home;
/// Symlink-safe unit file write helper using `O_NOFOLLOW`.
#[cfg(target_os = "linux")]
use crate::tools::strat::toml::write_config_nofollow;

/// Systemd unit template embedded so `zapret-rs install --systemd` works outside the repo.
const SYSTEMD_SERVICE_TEMPLATE: &str = include_str!("../../contrib/systemd/zapret-rs.service");
/// Path where `zapret-rs install --systemd` installs the system service unit.
#[cfg(target_os = "linux")]
const SYSTEMD_SERVICE_DEST: &str = "/etc/systemd/system/zapret-rs.service";

/// Strips ASCII control characters (`\r`, `\n`, `\0`, etc.) from a systemd substitution string.
fn strip_control_chars(raw: &str) -> String
{
    raw.chars().filter(|ch| !ch.is_control()).collect()
}

/// Validates and renders the embedded systemd unit, rejecting newlines, control bytes, or unsafe inputs.
pub fn try_render_systemd_service(bin_path: &Path, user: &str, home: &Path) -> Result<String, String>
{
    let bin_str = bin_path.to_string_lossy();
    let home_str = home.to_string_lossy();
    if user.is_empty()
        || user.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || bin_str.chars().any(char::is_control)
        || home_str.chars().any(char::is_control)
    {
        return Err(
            "systemd unit fields cannot contain control characters or invalid username whitespace".to_owned()
        );
    }
    if !bin_path.is_absolute() || !home.is_absolute()
    {
        return Err("systemd binary and home paths must be absolute".to_owned());
    }
    Ok(SYSTEMD_SERVICE_TEMPLATE
        .replace("/usr/local/bin/zapret-rs", &bin_str)
        .replace("__USER__", user)
        .replace("__HOME__", &home_str))
}

/// Renders the embedded systemd unit with sanitized executable path, operator user, and home dir.
pub fn render_systemd_service(bin_path: &Path, user: &str, home: &Path) -> String
{
    let clean_bin = strip_control_chars(&bin_path.to_string_lossy());
    let clean_user: String = strip_control_chars(user).chars().filter(|ch| !ch.is_whitespace()).collect();
    let clean_home = strip_control_chars(&home.to_string_lossy());
    SYSTEMD_SERVICE_TEMPLATE
        .replace("/usr/local/bin/zapret-rs", &clean_bin)
        .replace("__USER__", &clean_user)
        .replace("__HOME__", &clean_home)
}

/// Resolves the target operator primary GID (`SUDO_GID` when root under `sudo`, else `getgid`).
#[cfg(target_os = "linux")]
fn resolve_operator_gid() -> u32
{
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0
        && let Ok(raw) = std::env::var("SUDO_GID")
        && let Ok(gid) = raw.parse::<u32>()
    {
        return gid;
    }
    // SAFETY: `getgid` takes no arguments and cannot fail.
    unsafe { libc::getgid() }
}

/// Resolves the target operator username and home directory even when invoked via `sudo`.
#[cfg(target_os = "linux")]
fn resolve_operator_identity() -> (String, PathBuf)
{
    let user = std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("USER").ok().filter(|u| !u.is_empty()))
        .unwrap_or_else(|| "root".to_owned());
    let home = resolve_user_home().unwrap_or_else(|| PathBuf::from("/root"));
    (user, home)
}

/// Runs a trusted system binary directly as UID 0 or prefixed with trusted `sudo --`.
#[cfg(target_os = "linux")]
fn run_privileged_bin(tool_name: &str, args: &[&OsStr]) -> Result<(), String>
{
    let tool_bin = resolve_trusted_system_bin(tool_name)
        .map_err(|err| format!("cannot locate trusted {tool_name}: {err}"))?;
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    let status = if unsafe { libc::geteuid() } == 0
    {
        Command::new(&tool_bin).args(args).status()
    }
    else
    {
        let sudo_bin =
            resolve_trusted_system_bin("sudo").map_err(|err| format!("cannot locate trusted sudo: {err}"))?;
        Command::new(&sudo_bin).arg("--").arg(&tool_bin).args(args).status()
    }
    .map_err(|err| format!("failed to execute {tool_name}: {err}"))?;
    if !status.success()
    {
        return Err(format!("{tool_name} exited with status {status}"));
    }
    Ok(())
}

/// Ensures a capability-bearing binary is a regular file owned by `0:operator_gid` with mode `0750`
/// before `setcap` attaches file capabilities.
#[cfg(target_os = "linux")]
fn lock_down_setcap_target(bin_path: &Path) -> Result<(), String>
{
    let meta = fs::symlink_metadata(bin_path)
        .map_err(|err| format!("failed to inspect '{}': {err}", bin_path.display()))?;
    if meta.file_type().is_symlink() || !meta.file_type().is_file()
    {
        return Err(format!("refusing setcap on non-regular or symlink path '{}'", bin_path.display()));
    }

    let op_gid = resolve_operator_gid();
    // SAFETY: `geteuid` takes no arguments and cannot fail.
    if unsafe { libc::geteuid() } == 0
    {
        let c_path = CString::new(bin_path.as_os_str().as_bytes())
            .map_err(|_| format!("invalid NUL byte in '{}'", bin_path.display()))?;
        // SAFETY: `c_path` is a NUL-terminated path and `chown` follows no extra pointers.
        if unsafe { libc::chown(c_path.as_ptr(), 0, op_gid) } < 0
        {
            return Err(format!(
                "failed to chown '{}' to 0:{op_gid}: {}",
                bin_path.display(),
                std::io::Error::last_os_error()
            ));
        }
        fs::set_permissions(bin_path, fs::Permissions::from_mode(0o750))
            .map_err(|err| format!("failed to chmod 0750 '{}': {err}", bin_path.display()))?;
        return Ok(());
    }

    let owner_spec = format!("0:{op_gid}");
    run_privileged_bin("chown", &[OsStr::new(&owner_spec), bin_path.as_os_str()])?;
    run_privileged_bin("chmod", &[OsStr::new("0750"), bin_path.as_os_str()])
}

/// Grants `CAP_NET_ADMIN` + `CAP_NET_RAW` via trusted `setcap` after locking down ownership and `0750` mode.
#[cfg(target_os = "linux")]
pub(crate) fn apply_net_caps(bin_path: &Path) -> Result<(), String>
{
    lock_down_setcap_target(bin_path)?;
    run_privileged_bin("setcap", &[OsStr::new("cap_net_admin,cap_net_raw+ep"), bin_path.as_os_str()])
}

/// Installs `/etc/systemd/system/zapret-rs.service` safely and runs trusted `systemctl daemon-reload && enable`.
#[cfg(target_os = "linux")]
pub(crate) fn install_systemd_service(bin_path: &Path) -> Result<(), String>
{
    let (user, home) = resolve_operator_identity();
    let unit = try_render_systemd_service(bin_path, &user, &home)?;
    write_config_nofollow(Path::new(SYSTEMD_SERVICE_DEST), &unit)
        .map_err(|err| format!("failed to write {SYSTEMD_SERVICE_DEST} (run with sudo): {err}"))?;
    let systemctl_bin = resolve_trusted_system_bin("systemctl")
        .map_err(|err| format!("cannot locate trusted systemctl: {err}"))?;
    let reload = Command::new(&systemctl_bin).args(["daemon-reload"]).status();
    if !reload.as_ref().is_ok_and(|s| s.success())
    {
        return Err("systemctl daemon-reload failed".to_owned());
    }
    let enable = Command::new(&systemctl_bin).args(["enable", "zapret-rs.service"]).status();
    if !enable.as_ref().is_ok_and(|s| s.success())
    {
        return Err("systemctl enable zapret-rs.service failed".to_owned());
    }
    Ok(())
}

/// Stops/disables and removes `/etc/systemd/system/zapret-rs.service` using trusted `systemctl`.
#[cfg(target_os = "linux")]
pub(crate) fn uninstall_systemd_service() -> Result<(), String>
{
    if let Ok(systemctl_bin) = resolve_trusted_system_bin("systemctl")
    {
        let _ = Command::new(&systemctl_bin).args(["disable", "--now", "zapret-rs.service"]).status();
        let unit = Path::new(SYSTEMD_SERVICE_DEST);
        if fs::symlink_metadata(unit).is_ok_and(|meta| meta.file_type().is_file())
        {
            fs::remove_file(unit).map_err(|err| format!("failed to remove {SYSTEMD_SERVICE_DEST}: {err}"))?;
        }
        let _ = Command::new(&systemctl_bin).args(["daemon-reload"]).status();
    }
    Ok(())
}
