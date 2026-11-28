//! Strategy Finder scan executors and floating `AuthModal` privilege / `sudo` submission handlers.

/// I/O error kind inspection for detecting `PermissionDenied` from non-interactive `nftables` installs.
use std::io;
/// Timestamp tracking when waiting for a running `nfqws2` daemon to stop before scanning.
use std::time::Instant;

/// Linux `nftables` backend for Strategy Finder / live queue rules.
#[cfg(target_os = "linux")]
use crate::tools::NftFirewallBackend;
/// Active OS firewall backend selector for non-Linux targets.
#[cfg(not(target_os = "linux"))]
use crate::tools::active_firewall_backend;
/// Symlink-safe TOML writer, `~/` expansion, `nft` table constant, and TOML merge helpers.
use crate::tools::{FirewallHandle, STRAT_FINDER_NFT_TABLE, merge_nfqws2_toml};
/// Shared stop-wait state machine reused when halting `nfqws2` prior to starting a scan.
use crate::tui::daemon_cycle::{CycleInputs, CyclePhase, CycleStep, next_step};
/// Detached `systemd` / standalone `nfqws2 --daemon` background launcher.
use crate::tui::daemon_launch::{DaemonLaunchOutcome, launch_external_daemon};
/// Floating authentication modal helpers and silent `sudo` executor.
use crate::tui::modal::{AuthModal, ModalPurpose, run_sudo_silent, zeroize_string};
/// Control socket auto-detection used to probe for an existing daemon before local launch.
use crate::tui::remote::detect_control_socket;
/// Terminal RAII session wrapper, external `$EDITOR`, and Tab 1 domain history persistence.
use crate::tui::session::{TerminalSession, drop_fw_tui, save_domains_history};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
use crate::tui::tab2_session::{
    Tab2Session, attach_and_stop_active_daemon, attach_to_socket, execute_remote_stop,
};
/// Navigation and worker event enums.
use crate::tui::types::{FinderStatus, PostCapsAction, ScanUiEvent};
/// Background scan, prerequisite validator, and live local `nfqws2` NFQUEUE worker handles.
use crate::tui::workers::{ActiveScan, start_finder_scan, start_live_daemon, validate_scan_prereqs};

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
) -> io::Result<Box<dyn FirewallHandle>>
{
    #[cfg(target_os = "linux")]
    {
        let res = NftFirewallBackend::default().install_non_interactive(qnum, fwmark, tcp, udp);
        if let Err(ref err) = res
            && err.kind() == io::ErrorKind::PermissionDenied
        {
            *need_sudo = true;
        }
        res
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = need_sudo;
        active_firewall_backend().install(qnum, fwmark, tcp, udp)
    }
}

/// Queued Tab 1 scan launch waiting for an active `nfqws2` daemon to stop and release its queue.
pub(crate) struct PendingScanStart
{
    /// Timestamp when the daemon stop was initiated so a hung daemon aborts cleanly after timeout.
    started: Instant,
}

/// Validates prerequisites, stops any active `nfqws2` daemon, and either scans right away or waits.
///
/// Local in-process daemons tear down synchronously and launch immediately; socket-attached remote
/// daemons return `Some(PendingScanStart)` until [`poll_pending_scan`] sees the socket vanish.
pub(crate) fn begin_scan_stopping_daemon(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) -> Option<PendingScanStart>
{
    if !state
        .status
        .has_net_caps
    {
        state.open_caps_modal_for(Some(PostCapsAction::StartScan));
        return None;
    }
    if let Err(err) = validate_scan_prereqs(state)
    {
        state.apply_scan_event(ScanUiEvent::Failed(err));
        return None;
    }
    if !attach_and_stop_active_daemon(state, session_tab2, session)
    {
        return None;
    }
    if session_tab2.is_none()
        && detect_control_socket(
            state
                .run
                .control_socket_override
                .as_deref(),
        )
        .is_none()
    {
        try_start_scan(state, active_scan);
        return None;
    }
    state
        .finder
        .status = FinderStatus::Scanning;
    state
        .finder
        .progress_label = "Stopping running nfqws2 daemon...".to_owned();
    state.status_banner = "Stopping nfqws2 before strategy scan...".to_owned();
    Some(PendingScanStart { started: Instant::now() })
}

/// Polls an in-flight pre-scan daemon shutdown and launches the scan once the queue is clear.
pub(crate) fn poll_pending_scan(
    pending_scan: &mut Option<PendingScanStart>,
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session_tab2: &Option<Tab2Session>,
)
{
    let Some(pending) = pending_scan.as_ref()
    else
    {
        return;
    };
    let inputs = CycleInputs {
        session_active: session_tab2.is_some(),
        socket_present: detect_control_socket(
            state
                .run
                .control_socket_override
                .as_deref(),
        )
        .is_some(),
        modal_open: false,
        run_errored: false,
        elapsed: pending
            .started
            .elapsed(),
    };
    match next_step(CyclePhase::Stopping, &inputs)
    {
        CycleStep::WaitStop | CycleStep::WaitStart =>
        {}
        CycleStep::StartNow | CycleStep::Finished =>
        {
            *pending_scan = None;
            state.push_run_log("[scan] nfqws2 stopped; starting strategy scan.");
            try_start_scan(state, active_scan);
        }
        CycleStep::Failed(_) =>
        {
            *pending_scan = None;
            let msg = "Strategy scan aborted: nfqws2 did not stop in time.".to_owned();
            state.push_run_log(format!("[error] {msg}"));
            state.apply_scan_event(ScanUiEvent::Failed(msg));
        }
    }
}

/// Attempts to start a strategy scan; opens the floating auth modal if caps or `sudo` auth are missing.
///
/// If `has_net_caps` is unset, opens the capability grant modal with `PostCapsAction::StartScan`
/// so the scan is retried automatically after `setcap` succeeds.
pub(crate) fn try_start_scan(state: &mut AppState, active_scan: &mut Option<ActiveScan>)
{
    if !state
        .status
        .has_net_caps
    {
        state.open_caps_modal_for(Some(PostCapsAction::StartScan));
        return;
    }
    let mut need_sudo = false;
    let res = start_finder_scan(state, |q, m, t, u| install_nft_non_interactive(q, m, t, u, &mut need_sudo));
    if need_sudo
    {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForScan, preview));
        return;
    }
    match res
    {
        Ok(scan) =>
        {
            save_domains_history(state);
            *active_scan = Some(scan);
        }
        Err(err) => state.apply_scan_event(ScanUiEvent::Failed(err)),
    }
}

/// Records a daemon startup failure uniformly across Tab 2 state, banner, and log.
fn record_start_error(state: &mut AppState, err: String)
{
    state
        .run
        .status = crate::tui::types::RunStatus::Error(err.clone());
    state.status_banner = format!("Start failed: {err}");
    state.push_run_log(format!("[error] {err}"));
}

/// Attaches to an active socket, launches a persistent background daemon, or falls back to local mode.
///
/// Resolution order: detected control socket → external daemon launch → in-process local daemon.
pub(crate) fn try_start_or_attach(state: &mut AppState, session_tab2: &mut Option<Tab2Session>)
{
    let detected = detect_control_socket(
        state
            .run
            .control_socket_override
            .as_deref(),
    );
    state
        .run
        .detected_socket = detected.clone();
    if let Some(sock) = detected
    {
        attach_to_socket(state, session_tab2, sock);
        return;
    }
    match launch_external_daemon(state, session_tab2)
    {
        DaemonLaunchOutcome::Attached =>
        {}
        DaemonLaunchOutcome::NeedSudo(preview) =>
        {
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
fn try_start_local_daemon(state: &mut AppState, session_tab2: &mut Option<Tab2Session>)
{
    if !state
        .status
        .has_net_caps
    {
        state.open_caps_modal_for(Some(PostCapsAction::StartDaemon));
        return;
    }
    let mut need_sudo = false;
    let res = start_live_daemon(state, |q, m, t, u| install_nft_non_interactive(q, m, t, u, &mut need_sudo));
    if need_sudo
    {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForDaemon, preview));
        return;
    }
    match res
    {
        Ok(daemon) => *session_tab2 = Some(Tab2Session::Local(daemon)),
        Err(err) => record_start_error(state, err),
    }
}

/// Executes the confirmed floating modal action (`setcap`, `sudo -v`, or remote stop).
///
/// Handles confirmation modals that require no `sudo` invocation; returns `true` when handled.
fn handle_confirmation_modal(
    purpose: ModalPurpose,
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) -> bool
{
    match purpose
    {
        ModalPurpose::ConfirmStopDaemon =>
        {
            state.modal = None;
            execute_remote_stop(state, session_tab2);
            true
        }
        #[cfg(windows)]
        ModalPurpose::GrantCaps =>
        {
            state.modal = None;
            state.pending_caps_action = None;
            true
        }
        ModalPurpose::ConfirmApplyDns =>
        {
            state.modal = None;
            state.status_banner = match crate::tools::apply_dns_preset(
                state
                    .status
                    .dns_preset,
            )
            {
                Ok(msg) =>
                {
                    state.refresh_status_checks();
                    msg
                }
                Err(err) => format!("DNS update failed: {err}"),
            };
            true
        }
        ModalPurpose::ConfirmMergeConfig =>
        {
            state.modal = None;
            if let Some((prev, new_toml)) = state
                .config
                .pending_merge
                .take()
            {
                match merge_nfqws2_toml(&prev, &new_toml)
                {
                    Ok(merged) =>
                    {
                        state.set_active_toml(merged);
                        state.status_banner = format!(
                            "Merged into {} profile(s). Press 's' to save.",
                            state
                                .config
                                .parsed_profiles
                                .len()
                        );
                    }
                    Err(err) => state.status_banner = format!("Merge failed (kept new scan): {err}"),
                }
            }
            true
        }
        _ => false,
    }
}

/// Returns `true` when `setcap` succeeded and the TUI should re-`exec` cleanly with active caps.
pub(crate) fn submit_auth_modal(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    session_tab2: &mut Option<Tab2Session>,
) -> bool
{
    let Some(modal) = state
        .modal
        .as_mut()
    else
    {
        return false;
    };
    let purpose = modal.purpose;

    if handle_confirmation_modal(purpose, state, session_tab2)
    {
        return false;
    }

    let Some(modal) = state
        .modal
        .as_mut()
    else
    {
        return false;
    };
    let mut pw_buf = if modal.needs_password { Some(modal.take_password()) } else { None };
    let pw_ref = pw_buf.as_deref();

    let result = match purpose
    {
        ModalPurpose::GrantCaps =>
        {
            let setcap_cmd = crate::runtime::resolve_trusted_system_bin("setcap")
                .map(|p| {
                    p.display()
                        .to_string()
                })
                .map_err(|err| format!("cannot locate trusted setcap: {err}"));
            match setcap_cmd
            {
                Ok(bin) => run_sudo_silent(
                    &[
                        "--",
                        &bin,
                        "cap_net_admin,cap_net_raw+ep",
                        &state
                            .status
                            .exe_path,
                    ],
                    pw_ref,
                ),
                Err(err) => Err(err),
            }
        }
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon => run_sudo_silent(&["-v"], pw_ref),
        ModalPurpose::ConfirmStopDaemon
        | ModalPurpose::ConfirmSpeedTest
        | ModalPurpose::ConfirmMergeConfig
        | ModalPurpose::ConfirmApplyDns => Ok(()),
    };

    if let Some(ref mut secret) = pw_buf
    {
        zeroize_string(secret);
    }

    match result
    {
        Ok(()) =>
        {
            state.modal = None;
            match purpose
            {
                ModalPurpose::GrantCaps =>
                {
                    state
                        .status
                        .has_net_caps = true;
                    state.status_banner = "Capabilities granted.".to_owned();
                    return true;
                }
                ModalPurpose::SudoForScan => try_start_scan(state, active_scan),
                ModalPurpose::SudoForDaemon => try_start_or_attach(state, session_tab2),
                ModalPurpose::ConfirmStopDaemon
                | ModalPurpose::ConfirmSpeedTest
                | ModalPurpose::ConfirmMergeConfig
                | ModalPurpose::ConfirmApplyDns =>
                {}
            }
        }
        Err(msg) =>
        {
            if let Some(modal) = state
                .modal
                .as_mut()
            {
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
)
{
    let Some(scan) = active_scan.as_mut()
    else
    {
        return;
    };
    let mut finished = false;
    while let Ok(ev) = scan
        .rx
        .try_recv()
    {
        if matches!(ev, ScanUiEvent::Completed { .. } | ScanUiEvent::Failed(_))
        {
            finished = true;
        }
        state.apply_scan_event(ev);
    }
    if finished && let Some(mut done_scan) = active_scan.take()
    {
        done_scan.shutdown(|g| drop_fw_tui(session, g));
        if state
            .config
            .pending_merge
            .is_some()
            && state
                .modal
                .is_none()
        {
            let preview = format!(
                "merge {} new profile(s) into existing {}",
                state
                    .config
                    .parsed_profiles
                    .len(),
                state
                    .finder
                    .output_path
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
)
{
    if let Some(mut scan) = active_scan.take()
    {
        scan.shutdown(|g| drop_fw_tui(session, g));
        state
            .finder
            .status = FinderStatus::Done;
        state.status_banner = "Scan stopped cleanly.".to_owned();
    }
}
