//! Side-effectful TUI action executors bridging Tab 1/2/3 workers, `sudo` modals, and remote attach.

/// Filesystem reading when reloading `nfqws2.toml` from disk.
use std::fs;
/// I/O error classification for detecting missing `sudo` cached credentials.
use std::io;
/// Shared lock-free telemetry counters passed into local and attached workers.
use std::sync::Arc;

/// Wire control request enum sent to an attached daemon socket.
use crate::control::Request;
/// Symlink-safe TOML writer, `~/` expansion, and non-interactive `nftables` helpers.
use crate::tools::{
    NftFirewallBackend, STRAT_FINDER_NFT_TABLE, expand_tilde, write_config_nofollow,
};
/// Floating authentication modal helpers and silent `sudo` executor.
use crate::tui::modal::{AuthModal, ModalPurpose, run_sudo_silent, zeroize_string};
/// Remote daemon socket auto-detection, attachment, and streaming reader handle.
use crate::tui::remote::{
    AttachedDaemon, RemoteEvent, connect_remote_daemon, detect_control_socket,
};
/// Terminal RAII session wrapper and external `$EDITOR` invocation.
use crate::tui::session::{TerminalSession, drop_fw_tui};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Navigation and worker event enums.
use crate::tui::types::{FinderStatus, RunStatus, ScanUiEvent};
/// Background scan and live local `nfqws2` NFQUEUE worker handles.
use crate::tui::workers::{ActiveDaemon, ActiveScan, start_finder_scan, start_live_daemon};

/// Active Tab 2 telemetry source: either an in-process engine or an attached daemon socket.
pub(crate) enum Tab2Session {
    /// In-process `nfqws2` NFQUEUE engine with managed temporary `nftables` guard.
    Local(ActiveDaemon),
    /// Remote `nfqws2` daemon monitored over a Unix domain control socket.
    Remote(AttachedDaemon),
}

impl Tab2Session {
    /// Drains up to 256 pending packet records into `state.inspector` without blocking.
    pub(crate) fn drain_packets(&self, state: &mut AppState) {
        let (desync_rx, pkt_rx) = match self {
            Self::Local(d) => (&d.desync_rx, &d.pkt_rx),
            Self::Remote(r) => (&r.desync_rx, &r.pkt_rx),
        };
        for _ in 0..256 {
            let Ok(rec) = desync_rx.try_recv() else { break };
            state.inspector.push(rec);
        }
        for _ in 0..256 {
            let Ok(rec) = pkt_rx.try_recv() else { break };
            state.inspector.push(rec);
        }
    }
}

/// Attempts to start a strategy scan; opens the floating auth modal if caps or `sudo` auth are missing.
pub(crate) fn try_start_scan(state: &mut AppState, active_scan: &mut Option<ActiveScan>) {
    if !state.has_net_caps {
        state.open_caps_modal();
        return;
    }
    let mut need_sudo = false;
    let res = start_finder_scan(state, |q, m, tcp, udp| {
        let r = NftFirewallBackend::default().install_non_interactive(q, m, tcp, udp);
        if let Err(ref e) = r
            && e.kind() == io::ErrorKind::PermissionDenied
        {
            need_sudo = true;
        }
        r
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForScan, preview));
        return;
    }
    match res {
        Ok(scan) => *active_scan = Some(scan),
        Err(err) => state.apply_scan_event(ScanUiEvent::Failed(err)),
    }
}

/// Attaches to an existing daemon socket when detected, otherwise starts the in-process engine.
pub(crate) fn try_start_or_attach(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    let detected = detect_control_socket(state.control_socket_override.as_deref());
    state.detected_socket = detected.clone();
    if let Some(sock) = detected {
        match connect_remote_daemon(sock, Arc::clone(&state.counters)) {
            Ok((attached, meta)) => {
                state.set_attached(meta);
                *session_tab2 = Some(Tab2Session::Remote(attached));
            }
            Err(err) => {
                state.run_status = RunStatus::Error(err.clone());
                state.status_banner = format!("Attach failed: {err}");
                state.push_run_log(format!("[error] {err}"));
            }
        }
        return;
    }
    try_start_local_daemon(state, session_tab2);
}

/// Starts local in-process `nfqws2`, prompting for capabilities or `sudo` authentication when absent.
fn try_start_local_daemon(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    if !state.has_net_caps {
        state.open_caps_modal();
        return;
    }
    let mut need_sudo = false;
    let res = start_live_daemon(state, |q, m, tcp, udp| {
        let r = NftFirewallBackend::default().install_non_interactive(q, m, tcp, udp);
        if let Err(ref e) = r
            && e.kind() == io::ErrorKind::PermissionDenied
        {
            need_sudo = true;
        }
        r
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForDaemon, preview));
        return;
    }
    match res {
        Ok(daemon) => *session_tab2 = Some(Tab2Session::Local(daemon)),
        Err(err) => {
            state.run_status = RunStatus::Error(err.clone());
            state.status_banner = format!("Start failed: {err}");
            state.push_run_log(format!("[error] {err}"));
        }
    }
}

/// Sends a confirmed `Request::Stop` command to the currently attached daemon socket.
pub(crate) fn execute_remote_stop(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    if let Some(Tab2Session::Remote(remote)) = session_tab2.as_mut() {
        match remote.send_command(&Request::Stop) {
            Ok(()) => {
                remote.stop_requested = true;
                state.status_banner = "Sent stop request to remote daemon.".to_owned();
            }
            Err(err) => {
                state.push_run_log(format!("[error] {err}"));
                state.status_banner = err;
            }
        }
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
    let mut pw_buf = if modal.needs_password { Some(modal.take_password()) } else { None };
    let pw_ref = pw_buf.as_deref();

    let result = match purpose {
        ModalPurpose::GrantCaps => {
            let exe = state.exe_path.clone();
            run_sudo_silent(&["--", "setcap", "cap_net_admin,cap_net_raw+ep", &exe], pw_ref)
        }
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon => run_sudo_silent(&["-v"], pw_ref),
        ModalPurpose::ConfirmStopDaemon => Ok(()),
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
                ModalPurpose::SudoForDaemon => try_start_local_daemon(state, session_tab2),
                ModalPurpose::ConfirmStopDaemon => {}
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
    }
}

/// Drains remote reader notifications and handles clean stop vs unexpected disconnect.
pub(crate) fn poll_tab2_session(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    let Some(sess) = session_tab2.as_mut() else {
        return;
    };
    sess.drain_packets(state);
    let mut disconnected: Option<(bool, Option<String>)> = None;
    if let Tab2Session::Remote(remote) = sess {
        while let Ok(ev) = remote.ev_rx.try_recv() {
            match ev {
                RemoteEvent::InfoLog(msg) => state.push_run_log(msg),
                RemoteEvent::Error(err) => {
                    state.status_banner = err.clone();
                    state.push_run_log(format!("[error] {err}"));
                }
                RemoteEvent::Disconnected(reason) => {
                    disconnected = Some((remote.stop_requested, reason));
                }
            }
        }
    }
    if let Some((was_stop, reason)) = disconnected {
        if let Some(Tab2Session::Remote(mut remote)) = session_tab2.take() {
            remote.detach();
        }
        state.detected_socket = detect_control_socket(state.control_socket_override.as_deref());
        if was_stop {
            state.set_detached(
                "[stop] remote nfqws2 daemon stopped cleanly.".to_owned(),
                "Remote daemon stopped.".to_owned(),
            );
        } else {
            let msg = reason.unwrap_or_else(|| "socket closed".to_owned());
            state.set_detached(
                format!("[error] control connection lost: {msg}"),
                format!("Control connection lost: {msg}"),
            );
        }
    }
}

/// Saves `state.active_toml` cleanly to `state.output_path` without following symlinks.
pub(crate) fn save_toml_to_disk(state: &mut AppState) {
    if state.active_toml.trim().is_empty() {
        state.status_banner = "Nothing to save yet.".to_owned();
        return;
    }
    let path = expand_tilde(&state.output_path);
    match write_config_nofollow(&path, &state.active_toml) {
        Ok(()) => state.status_banner = format!("Saved {}", path.display()),
        Err(err) => state.status_banner = format!("Save failed: {err}"),
    }
}

/// Reloads `state.output_path` from disk and refreshes Tab 3 TOML validation diagnostics.
pub(crate) fn reload_toml_from_disk(state: &mut AppState) {
    let path = expand_tilde(&state.output_path);
    match fs::read_to_string(&path) {
        Ok(text) => {
            state.set_active_toml(text);
            state.status_banner = match &state.toml_error {
                Some(err) => format!("Loaded with TOML error: {}", err.lines().next().unwrap_or(err)),
                None => format!("Loaded {} ({} profiles)", path.display(), state.parsed_profiles.len()),
            };
        }
        Err(err) => state.status_banner = format!("Reload failed ({}): {err}", path.display()),
    }
}

/// Stops an in-process Tab 2 worker cleanly, draining final records into `state.inspector`.
pub(crate) fn stop_local_daemon(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) {
    if let Some(Tab2Session::Local(mut daemon)) = session_tab2.take() {
        daemon.shutdown(|g| drop_fw_tui(session, g));
        while let Ok(rec) = daemon.desync_rx.try_recv() {
            state.inspector.push(rec);
        }
        while let Ok(rec) = daemon.pkt_rx.try_recv() {
            state.inspector.push(rec);
        }
        state.run_status = RunStatus::Stopped;
        state.push_run_log("[stop] nfqws2 stopped and temporary nftables cleaned up.");
        state.status_banner = "nfqws2 stopped cleanly.".to_owned();
    }
}

/// Shuts down an active scan cleanly when requested by Tab 1.
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
