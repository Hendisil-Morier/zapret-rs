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

/// Searches sibling of current TUI binary, `/usr/local/bin`, and `PATH` for `nfqws2`.
pub(crate) fn resolve_nfqws2_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe()
        && let Some(dir) = exe.parent()
    {
        let sibling = dir.join("nfqws2");
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    let system_bin = PathBuf::from("/usr/local/bin/nfqws2");
    if system_bin.is_file() {
        return Some(system_bin);
    }
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|dir| dir.join("nfqws2"))
        .find(|cand| cand.is_file())
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

/// Starts `zapret-rs.service` via `systemctl` (using cached `sudo -n` when non-root) and attaches.
fn start_via_systemd(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) -> DaemonLaunchOutcome {
    if state.uid != 0 && sudo_needs_password() {
        return DaemonLaunchOutcome::NeedSudo("sudo systemctl start zapret-rs.service".to_owned());
    }
    let output = if state.uid == 0 {
        Command::new("systemctl")
            .args(["start", "zapret-rs.service"])
            .stdin(Stdio::null())
            .output()
    } else {
        Command::new("sudo")
            .args(["-n", "systemctl", "start", "zapret-rs.service"])
            .stdin(Stdio::null())
            .output()
    };
    match output {
        Ok(out) if out.status.success() => {}
        Ok(out) => {
            let err = String::from_utf8_lossy(&out.stderr).trim().to_owned();
            return DaemonLaunchOutcome::Failed(if err.is_empty() {
                "systemctl start zapret-rs.service failed".to_owned()
            } else {
                err
            });
        }
        Err(err) => return DaemonLaunchOutcome::Failed(format!("failed to invoke systemctl: {err}")),
    }

    match wait_for_control_socket(state.control_socket_override.as_deref(), DAEMON_START_TIMEOUT) {
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

/// Spawns standalone `nfqws2 --daemon` detached from the TUI process and attaches over IPC.
fn start_standalone_daemon(
    bin: &Path,
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) -> DaemonLaunchOutcome {
    if state.active_toml.trim().is_empty() {
        return DaemonLaunchOutcome::Failed(
            "no active nfqws2.toml loaded (run Strategy Finder or press 'l' to load a file)".to_owned(),
        );
    }
    let cfg_path = expand_tilde(&state.output_path);
    if let Err(err) = AppConfig::from_toml_str(&state.active_toml, cfg_path.parent()) {
        return DaemonLaunchOutcome::Failed(format!("invalid nfqws2.toml: {err}"));
    }
    let disk_same = fs::read_to_string(&cfg_path).is_ok_and(|s| s == state.active_toml);
    if !disk_same && let Err(err) = write_config_nofollow(&cfg_path, &state.active_toml) {
        return DaemonLaunchOutcome::Failed(format!("cannot write {}: {err}", cfg_path.display()));
    }

    let sock_path = state
        .control_socket_override
        .clone()
        .unwrap_or_else(default_control_socket_path);
    let nft_flag = if state.no_nft { "--no-nft" } else { "--nft" };
    let uid_arg = state.uid.to_string();

    if state.uid != 0 && sudo_needs_password() {
        return DaemonLaunchOutcome::NeedSudo(format!(
            "sudo {} --daemon --config {} {nft_flag}",
            bin.display(),
            cfg_path.display()
        ));
    }
    let mut cmd = if state.uid == 0 {
        Command::new(bin)
    } else {
        let mut s = Command::new("sudo");
        s.args(["-n", "--"]).arg(bin).args(["--uid", &uid_arg]);
        s
    };
    cmd.args(["--daemon", "--config"])
        .arg(&cfg_path)
        .arg("--control-socket")
        .arg(&sock_path)
        .arg(nft_flag)
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

/// Launches `zapret-rs.service` (when installed) or standalone `nfqws2 --daemon` so quitting TUI detaches.
pub(crate) fn launch_external_daemon(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) -> DaemonLaunchOutcome {
    if has_systemd_unit() {
        return start_via_systemd(state, session_tab2);
    }
    if let Some(bin) = resolve_nfqws2_binary() {
        return start_standalone_daemon(&bin, state, session_tab2);
    }
    DaemonLaunchOutcome::Unavailable
}
