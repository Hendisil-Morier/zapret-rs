//! Strategy Finder scan executors and floating `AuthModal` privilege / `sudo` submission handlers.

/// I/O error kind inspection for detecting `PermissionDenied` from non-interactive `nftables` installs.
use std::io;

/// Symlink-safe TOML writer, `~/` expansion, non-interactive `nftables`, and TOML merge helpers.
use crate::tools::{FirewallHandle, NftFirewallBackend, STRAT_FINDER_NFT_TABLE, merge_nfqws2_toml};
/// Floating authentication modal helpers and silent `sudo` executor.
use crate::tui::modal::{AuthModal, ModalPurpose, run_sudo_silent, zeroize_string};
/// Detached `systemd` / standalone `nfqws2 --daemon` background launcher.
use crate::tui::daemon_launch::{DaemonLaunchOutcome, launch_external_daemon};
/// Terminal RAII session wrapper, external `$EDITOR`, and Tab 1 domain history persistence.
use crate::tui::session::{TerminalSession, drop_fw_tui, save_domains_history};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
use crate::tui::tab2_session::{Tab2Session, attach_to_socket, execute_remote_stop};
/// Navigation and worker event enums.
use crate::tui::types::{FinderStatus, PostCapsAction, ScanUiEvent};
/// Background scan and live local `nfqws2` NFQUEUE worker handles.
use crate::tui::workers::{ActiveScan, start_finder_scan, start_live_daemon};
/// Control socket auto-detection used to probe for an existing daemon before local launch.
use crate::tui::remote::detect_control_socket;

/// Attempts non-interactive `nftables` installation and flags `need_sudo` on `PermissionDenied`.
///
/// The `need_sudo` flag is set rather than propagated directly so the caller can open the auth
/// modal after cleanly unwinding any partially completed setup.
fn install_nft_non_interactive(
    qnum: u16,
    fwmark: u32,
    tcp: &[u16],
    udp: &[u16],
    need_sudo: &mut bool,
) -> io::Result<Box<dyn FirewallHandle>> {
    let res = NftFirewallBackend::default().install_non_interactive(qnum, fwmark, tcp, udp);
    if let Err(ref err) = res
        && err.kind() == io::ErrorKind::PermissionDenied
    {
        *need_sudo = true;
    }
    res
}

/// Attempts to start a strategy scan; opens the floating auth modal if caps or `sudo` auth are missing.
///
/// If `has_net_caps` is unset, opens the capability grant modal with `PostCapsAction::StartScan`
/// so the scan is retried automatically after `setcap` succeeds.
pub(crate) fn try_start_scan(state: &mut AppState, active_scan: &mut Option<ActiveScan>) {
    if !state.has_net_caps {
        state.open_caps_modal_for(Some(PostCapsAction::StartScan));
        return;
    }
    let mut need_sudo = false;
    let res = start_finder_scan(state, |q, m, t, u| {
        install_nft_non_interactive(q, m, t, u, &mut need_sudo)
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForScan, preview));
        return;
    }
    match res {
        Ok(scan) => {
            save_domains_history(state);
            *active_scan = Some(scan);
        }
        Err(err) => state.apply_scan_event(ScanUiEvent::Failed(err)),
    }
}

/// Records a daemon startup failure uniformly across Tab 2 state, banner, and log.
fn record_start_error(state: &mut AppState, err: String) {
    state.run_status = crate::tui::types::RunStatus::Error(err.clone());
    state.status_banner = format!("Start failed: {err}");
    state.push_run_log(format!("[error] {err}"));
}

/// Attaches to an active socket, launches a persistent background daemon, or falls back to local mode.
///
/// Resolution order: detected control socket → external daemon launch → in-process local daemon.
pub(crate) fn try_start_or_attach(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    let detected = detect_control_socket(state.control_socket_override.as_deref());
    state.detected_socket = detected.clone();
    if let Some(sock) = detected {
        attach_to_socket(state, session_tab2, sock);
        return;
    }
    match launch_external_daemon(state, session_tab2) {
        DaemonLaunchOutcome::Attached => {}
        DaemonLaunchOutcome::NeedSudo(preview) => {
            state.modal = Some(AuthModal::open(ModalPurpose::SudoForDaemon, preview));
        }
        DaemonLaunchOutcome::Failed(err) => record_start_error(state, err),
        DaemonLaunchOutcome::Unavailable => try_start_local_daemon(state, session_tab2),
    }
}

/// Starts local in-process `nfqws2`, prompting for capabilities or `sudo` authentication when absent.
///
/// If `has_net_caps` is unset, opens the capability grant modal with `PostCapsAction::StartDaemon`
/// so the launch is retried automatically after `setcap` succeeds.
fn try_start_local_daemon(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    if !state.has_net_caps {
        state.open_caps_modal_for(Some(PostCapsAction::StartDaemon));
        return;
    }
    let mut need_sudo = false;
    let res = start_live_daemon(state, |q, m, t, u| {
        install_nft_non_interactive(q, m, t, u, &mut need_sudo)
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForDaemon, preview));
        return;
    }
    match res {
        Ok(daemon) => *session_tab2 = Some(Tab2Session::Local(daemon)),
        Err(err) => record_start_error(state, err),
    }
}

/// Executes the confirmed floating modal action (`setcap`, `sudo -v`, or remote stop).
///
/// Returns `true` when `setcap` succeeded and the TUI should re-`exec` cleanly with active caps.
pub(crate) fn submit_auth_modal(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session_tab2: &mut Option<Tab2Session>,
) -> bool {
    let Some(modal) = state.modal.as_mut() else {
        return false;
    };
    let purpose = modal.purpose;

    if purpose == ModalPurpose::ConfirmStopDaemon {
        state.modal = None;
        execute_remote_stop(state, session_tab2);
        return false;
    }
    if purpose == ModalPurpose::ConfirmMergeConfig {
        state.modal = None;
        if let Some((prev, new_toml)) = state.pending_merge.take() {
            match merge_nfqws2_toml(&prev, &new_toml) {
                Ok(merged) => {
                    state.set_active_toml(merged);
                    state.status_banner = format!(
                        "Merged into {} profile(s). Press 's' to save.",
                        state.parsed_profiles.len()
                    );
                }
                Err(err) => state.status_banner = format!("Merge failed (kept new scan): {err}"),
            }
        }
        return false;
    }

    let mut pw_buf = if modal.needs_password {
        Some(modal.take_password())
    } else {
        None
    };
    let pw_ref = pw_buf.as_deref();

    let result = match purpose {
        ModalPurpose::GrantCaps => {
            run_sudo_silent(&["--", "setcap", "cap_net_admin,cap_net_raw+ep", &state.exe_path], pw_ref)
        }
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon => {
            run_sudo_silent(&["-v"], pw_ref)
        }
        ModalPurpose::ConfirmStopDaemon
        | ModalPurpose::ConfirmSpeedTest
        | ModalPurpose::ConfirmMergeConfig => Ok(()),
    };

    if let Some(ref mut secret) = pw_buf {
        zeroize_string(secret);
    }

    match result {
        Ok(()) => {
            state.modal = None;
            match purpose {
                ModalPurpose::GrantCaps => {
                    state.has_net_caps = true;
                    state.status_banner = "Capabilities granted.".to_owned();
                    return true;
                }
                ModalPurpose::SudoForScan => try_start_scan(state, active_scan),
                ModalPurpose::SudoForDaemon => try_start_or_attach(state, session_tab2),
                ModalPurpose::ConfirmStopDaemon
                | ModalPurpose::ConfirmSpeedTest
                | ModalPurpose::ConfirmMergeConfig => {}
            }
        }
        Err(msg) => {
            if let Some(modal) = state.modal.as_mut() {
                modal.needs_password = true;
                modal.error = Some(msg);
            }
        }
    }
    false
}

/// Drains active scan events and shuts down finished scan guards.
///
/// Calls `drop_fw_tui` on the scan's firewall guard so raw mode is correctly restored when
/// the `nftables` teardown runs inside the terminal session.
pub(crate) fn poll_active_scan(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session: &mut TerminalSession,
) {
    let Some(scan) = active_scan.as_mut() else {
        return;
    };
    let mut finished = false;
    while let Ok(ev) = scan.rx.try_recv() {
        if matches!(ev, ScanUiEvent::Completed { .. } | ScanUiEvent::Failed(_)) {
            finished = true;
        }
        state.apply_scan_event(ev);
    }
    if finished && let Some(mut done_scan) = active_scan.take() {
        done_scan.shutdown(|g| drop_fw_tui(session, g));
        if state.pending_merge.is_some() && state.modal.is_none() {
            let preview = format!(
                "merge {} new profile(s) into existing {}",
                state.parsed_profiles.len(),
                state.output_path
            );
            state.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmMergeConfig, preview));
        }
    }
}

/// Shuts down an active scan cleanly when requested by Tab 1.
///
/// Drains the firewall guard via `drop_fw_tui` to restore raw mode safely before `nft` cleanup.
pub(crate) fn cancel_active_scan(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session: &mut TerminalSession,
) {
    if let Some(mut scan) = active_scan.take() {
        scan.shutdown(|g| drop_fw_tui(session, g));
        state.finder_status = FinderStatus::Done;
        state.status_banner = "Scan stopped cleanly.".to_owned();
    }
}
