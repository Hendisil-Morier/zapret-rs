//! Detached background `nfqws2` / `systemd` daemon launcher so `r` starts persist after TUI exit.

/// Filesystem checks for systemd unit detection and TOML syncing.
use std::fs;
/// Path resolution for `nfqws2` executables and systemd unit paths.
use std::path::{Path, PathBuf};
/// Subprocess spawning for `systemctl` and detached `nfqws2 --daemon` processes.
use std::process::{Command, Stdio};
/// Control-socket polling sleep and timeout constants.
use std::thread;
/// Control-socket startup wait bounds.
use std::time::{Duration, Instant};

/// Validated `nfqws2` TOML parser used before writing/launching daemon config.
use crate::config::AppConfig;
/// Control socket path resolver shared with `nfqws2`.
use crate::control::default_control_socket_path;
/// Trusted system binary resolution preventing `PATH` hijacking on `sudo`/`systemctl`/`nfqws2`.
use crate::runtime::resolve_trusted_system_bin;
/// Symlink-safe TOML writer, `~/` expansion, and non-interactive `sudo` credential probe.
use crate::tools::{expand_tilde, sudo_needs_password, write_config_nofollow};
/// Tab 2 remote attach session and control-socket detector.
use crate::tui::tab2_session::{Tab2Session, attach_to_socket};
/// Live Unix control socket prober.
use crate::tui::remote::detect_control_socket;
/// Mutable TUI application state holding active config, UID, and socket override.
use crate::tui::state::AppState;

/// Maximum time to wait for a newly launched background daemon to bind its control socket.
const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(3);

/// Outcome from attempting to launch an independent background `nfqws2` daemon.
pub(crate) enum DaemonLaunchOutcome {
    /// Background daemon started and TUI attached over its Unix control socket.
    Attached,
    /// `sudo` requires an interactive password prompt via [`ModalPurpose::SudoForDaemon`].
    NeedSudo(String),
    /// Launch or validation failed with a user-facing error message.
    Failed(String),
    /// Neither a systemd unit nor an `nfqws2` binary is available; fall back to in-process mode.
    Unavailable,
}

/// Returns `true` when the `zapret-rs.service` systemd unit is installed on this host.
pub(crate) fn has_systemd_unit() -> bool {
    Path::new("/etc/systemd/system/zapret-rs.service").is_file()
        || Path::new("/usr/lib/systemd/system/zapret-rs.service").is_file()
}

/// Searches sibling of current TUI binary and trusted system directories for `nfqws2`,
/// never consulting caller `PATH`, and falls back to `(current_exe, Some("daemon"))`.
pub(crate) fn resolve_daemon_target() -> Option<(PathBuf, Option<&'static str>)> {
    let bin_name = format!("nfqws2{}", std::env::consts::EXE_SUFFIX);
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join(&bin_name);
        if sibling.is_file() {
            return Some((sibling, None));
        }
    }
    #[cfg(unix)]
    if let Ok(system_bin) = resolve_trusted_system_bin("nfqws2") {
        return Some((system_bin, None));
    }
    std::env::current_exe().ok().map(|exe| (exe, Some("daemon")))
}

/// Resolves the active operator primary GID for `--uid uid:gid` when `uid` matches real UID.
#[cfg(not(windows))]
fn resolve_daemon_gid(uid: u32) -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` and `getgid` take no arguments and cannot fail.
        if unsafe { libc::getuid() } == uid {
            // SAFETY: `getgid` takes no arguments and cannot fail.
            return unsafe { libc::getgid() };
        }
    }
    uid
}

/// Builds `--daemon` CLI arguments with valid `--nft=false`/`--nft` flag syntax (`AppConfig`).
#[cfg(not(windows))]
pub fn build_daemon_common_args(
    cfg_path: &Path,
    sock_path: &Path,
    no_nft: bool,
) -> Vec<std::ffi::OsString> {
    vec![
        "--daemon".into(),
        "--config".into(),
        cfg_path.as_os_str().to_owned(),
        "--control-socket".into(),
        sock_path.as_os_str().to_owned(),
        if no_nft { "--nft=false" } else { "--nft" }.into(),
    ]
}

/// Polls `detect_control_socket` until a live daemon socket appears or `timeout` elapses.
fn wait_for_control_socket(configured: Option<&Path>, timeout: Duration) -> Option<PathBuf> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(sock) = detect_control_socket(configured) {
            return Some(sock);
        }
        if Instant::now() >= deadline {
            return None;
        }
        thread::sleep(Duration::from_millis(50));
    }
}

/// Starts (or restarts if still deactivating) `zapret-rs.service` via trusted `systemctl` and attaches.
fn start_via_systemd(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) -> DaemonLaunchOutcome {
    if state.status.uid != 0 && sudo_needs_password() {
        return DaemonLaunchOutcome::NeedSudo("sudo systemctl restart zapret-rs.service".to_owned());
    }
    let systemctl_bin = match resolve_trusted_system_bin("systemctl") {
        Ok(p) => p,
        Err(err) => return DaemonLaunchOutcome::Failed(format!("cannot locate trusted systemctl: {err}")),
    };
    let output = if state.status.uid == 0 {
        Command::new(&systemctl_bin)
            .args(["restart", "zapret-rs.service"])
            .stdin(Stdio::null())
            .output()
    } else {
        let sudo_bin = match resolve_trusted_system_bin("sudo") {
            Ok(p) => p,
            Err(err) => return DaemonLaunchOutcome::Failed(format!("cannot locate trusted sudo: {err}")),
        };
        Command::new(&sudo_bin)
            .arg("-n")
            .arg("--")
            .arg(&systemctl_bin)
            .args(["restart", "zapret-rs.service"])
            .stdin(Stdio::null())
            .output()
    };
    match output {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return DaemonLaunchOutcome::Failed(if err.is_empty() {
                "systemctl restart zapret-rs.service failed".to_owned()
            } else {
                err
            });
        }
        Err(err) => return DaemonLaunchOutcome::Failed(format!("failed to invoke systemctl: {err}")),
    }

    match wait_for_control_socket(state.run.control_socket_override.as_deref(), DAEMON_START_TIMEOUT) {
        Some(sock) => {
            if attach_to_socket(state, session_tab2, sock) {
                DaemonLaunchOutcome::Attached
            } else {
                DaemonLaunchOutcome::Failed(state.status_banner.clone())
            }
        }
        None => DaemonLaunchOutcome::Failed(
            "zapret-rs.service started, but control socket did not appear in time".to_owned(),
        ),
    }
}

/// Spawns standalone `nfqws2 --daemon` (or `zapret-rs daemon --daemon`) detached and attaches over IPC.
fn start_standalone_daemon(
    bin: &Path,
    subcmd: Option<&str>,
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) -> DaemonLaunchOutcome {
    if state.config.active_toml.trim().is_empty() {
        return DaemonLaunchOutcome::Failed(
            "no active nfqws2.toml loaded (run Strategy Finder or press 'l' to load a file)".to_owned(),
        );
    }
    let cfg_path = expand_tilde(&state.finder.output_path);
    if let Err(err) = AppConfig::from_toml_str(&state.config.active_toml, cfg_path.parent()) {
        return DaemonLaunchOutcome::Failed(format!("invalid nfqws2.toml: {err}"));
    }
    let disk_same = fs::read_to_string(&cfg_path).is_ok_and(|s| s == state.config.active_toml);
    if !disk_same && let Err(err) = write_config_nofollow(&cfg_path, &state.config.active_toml) {
        return DaemonLaunchOutcome::Failed(format!("cannot write {}: {err}", cfg_path.display()));
    }

    let sock_path = state
        .run.control_socket_override
        .clone()
        .unwrap_or_else(default_control_socket_path);
    let nft_flag = if state.finder.no_nft { "--nft=false" } else { "--nft" };
    let sub_prefix = subcmd.map_or_else(String::new, |s| format!("{s} "));

    #[cfg(windows)]
    {
        if !state.status.has_net_caps {
            return DaemonLaunchOutcome::Unavailable;
        }
        let _ = (sub_prefix, nft_flag);
        let mut cmd = Command::new(bin);
        if let Some(sub) = subcmd {
            cmd.arg(sub);
        }
        cmd.args(["--config"])
            .arg(&cfg_path)
            .arg("--control-socket")
            .arg(&sock_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                return DaemonLaunchOutcome::Failed(format!("failed to run {}: {err}", bin.display()));
            }
        };
        let deadline = Instant::now() + DAEMON_START_TIMEOUT;
        while Instant::now() < deadline {
            if let Some(sock) = detect_control_socket(Some(&sock_path)) {
                return if attach_to_socket(state, session_tab2, sock) {
                    DaemonLaunchOutcome::Attached
                } else {
                    DaemonLaunchOutcome::Failed(state.status_banner.clone())
                };
            }
            if let Ok(Some(status)) = child.try_wait() {
                let mut err_buf = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    use std::io::Read as _;
                    let _ = pipe.read_to_string(&mut err_buf);
                }
                let msg = err_buf.trim();
                return DaemonLaunchOutcome::Failed(if msg.is_empty() {
                    format!("Windows daemon exited with {status}")
                } else {
                    msg.to_owned()
                });
            }
            thread::sleep(Duration::from_millis(50));
        }
        DaemonLaunchOutcome::Failed(format!(
            "WinDivert daemon started, but control IPC at {} did not appear",
            sock_path.display()
        ))
    }
    #[cfg(not(windows))]
    {
        let uid_arg = format!("{}:{}", state.status.uid, resolve_daemon_gid(state.status.uid));
        if state.status.uid != 0 && sudo_needs_password() {
            return DaemonLaunchOutcome::NeedSudo(format!(
                "sudo {} {sub_prefix}--daemon --config {} {nft_flag}",
                bin.display(),
                cfg_path.display()
            ));
        }
        let mut cmd = if state.status.uid == 0 {
            let mut direct = Command::new(bin);
            if let Some(sub) = subcmd {
                direct.arg(sub);
            }
            direct
        } else {
            let sudo_bin = match resolve_trusted_system_bin("sudo") {
                Ok(p) => p,
                Err(err) => {
                    return DaemonLaunchOutcome::Failed(format!(
                        "cannot locate trusted sudo: {err}"
                    ));
                }
            };
            let mut s = Command::new(sudo_bin);
            s.args(["-n", "--"]).arg(bin);
            if let Some(sub) = subcmd {
                s.arg(sub);
            }
            s.args(["--uid", &uid_arg]);
            s
        };
        cmd.args(build_daemon_common_args(&cfg_path, &sock_path, state.finder.no_nft))
            .stdin(Stdio::null());

        match cmd.output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => {
                let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
                return DaemonLaunchOutcome::Failed(if err.is_empty() {
                    "nfqws2 --daemon failed to start".to_owned()
                } else {
                    err
                });
            }
            Err(err) => return DaemonLaunchOutcome::Failed(format!("failed to run {}: {err}", bin.display())),
        }

        match wait_for_control_socket(Some(&sock_path), DAEMON_START_TIMEOUT) {
            Some(sock) => {
                if attach_to_socket(state, session_tab2, sock) {
                    DaemonLaunchOutcome::Attached
                } else {
                    DaemonLaunchOutcome::Failed(state.status_banner.clone())
                }
            }
            None => DaemonLaunchOutcome::Failed(format!(
                "nfqws2 started, but control socket {} did not appear",
                sock_path.display()
            )),
        }
    }
}

/// Launches `zapret-rs.service` (when installed) or standalone `nfqws2 --daemon` so quitting TUI detaches.
pub(crate) fn launch_external_daemon(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) -> DaemonLaunchOutcome {
    if has_systemd_unit() {
        return start_via_systemd(state, session_tab2);
    }
    if let Some((bin, subcmd)) = resolve_daemon_target() {
        return start_standalone_daemon(&bin, subcmd, state, session_tab2);
    }
    DaemonLaunchOutcome::Unavailable
}
