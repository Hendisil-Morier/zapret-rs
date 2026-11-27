//! Tab 2 daemon session lifecycle: active session type, remote IPC control, packet drain, and idle socket polling.

/// Path type passed when connecting to a discovered Unix domain control socket.
use std::path::PathBuf;
/// Shared lock-free telemetry counters injected into local and attached workers.
use std::sync::Arc;
/// MPSC receiver type for draining bounded packet inspector streams from local and remote workers.
use std::sync::mpsc::Receiver;

/// Wire control request enum sent to an attached daemon socket.
use crate::control::Request;
/// Decoded live telemetry packet record type pushed into the inspector.
use crate::telemetry::PacketRecord;
/// Terminal RAII session wrapper used to safely tear down firewall guards during shutdown.
use crate::tui::session::{TerminalSession, drop_fw_tui};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Navigation and worker event enums, including `ActiveTab` and `RunStatus`.
use crate::tui::types::{ActiveTab, RunStatus};
/// Background live `nfqws2` NFQUEUE worker handle.
use crate::tui::workers::ActiveDaemon;
/// Remote daemon socket auto-detection, attachment, streaming reader, and control request types.
use crate::tui::remote::{AttachedDaemon, RemoteEvent, connect_remote_daemon, detect_control_socket};

/// Active Tab 2 telemetry source: either an in-process engine or a socket-attached daemon.
pub(crate) enum Tab2Session {
    /// In-process `nfqws2` NFQUEUE engine with a managed temporary `nftables` guard.
    Local(ActiveDaemon),
    /// Remote `nfqws2` daemon monitored over a Unix domain control socket.
    Remote(AttachedDaemon),
}

/// Drains up to `limit` packet records from `desync_rx` and `pkt_rx` into `state.inspector`.
///
/// Both channels are drained to ensure neither blocks on a full ring when only one source is active.
fn drain_packet_pair(
    state: &mut AppState,
    desync_rx: &Receiver<PacketRecord>,
    pkt_rx: &Receiver<PacketRecord>,
    limit: usize,
) {
    for rx in [desync_rx, pkt_rx] {
        for _ in 0..limit {
            let Ok(rec) = rx.try_recv() else { break };
            state.inspector.push(rec);
        }
    }
}

impl Tab2Session {
    /// Drains up to 256 pending packet records into `state.inspector` without blocking.
    ///
    /// Called on every render tick to keep the inspector panel live regardless of session variant.
    pub(crate) fn drain_packets(&self, state: &mut AppState) {
        let (desync_rx, pkt_rx) = match self {
            Self::Local(d) => {
                d.capture_enabled.store(
                    state.tab == ActiveTab::Run && !state.inspector.paused,
                    std::sync::atomic::Ordering::Relaxed,
                );
                (&d.desync_rx, &d.pkt_rx)
            }
            Self::Remote(r) => (&r.desync_rx, &r.pkt_rx),
        };
        drain_packet_pair(state, desync_rx, pkt_rx, 256);
    }
}

/// Connects to `sock` and populates Tab 2 remote attach state; returns `true` on success.
///
/// On failure, `state.run.auto_reattach` is cleared to prevent an attach retry storm.
pub(crate) fn attach_to_socket(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    sock: PathBuf,
) -> bool {
    match connect_remote_daemon(sock, Arc::clone(&state.run.counters)) {
        Ok((attached, meta)) => {
            state.set_attached(meta);
            *session_tab2 = Some(Tab2Session::Remote(attached));
            true
        }
        Err(err) => {
            state.run.auto_reattach = false;
            state.run.status = RunStatus::Error(err.clone());
            state.status_banner = format!("Attach failed: {err}");
            state.push_run_log(format!("[error] {err}"));
            false
        }
    }
}

/// Sends a confirmed `Request::Stop` command to the currently attached daemon socket.
///
/// Clears `auto_reattach` so the idle-socket poller does not immediately reconnect after the stop.
pub(crate) fn execute_remote_stop(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    if let Some(Tab2Session::Remote(remote)) = session_tab2.as_mut() {
        match remote.send_command(&Request::Stop) {
            Ok(()) => {
                remote.stop_requested = true;
                state.run.auto_reattach = false;
                state.status_banner = "Sent stop request to remote daemon.".to_owned();
            }
            Err(err) => {
                state.push_run_log(format!("[error] {err}"));
                state.status_banner = err;
            }
        }
    }
}

/// Drains remote reader notifications, handles disconnect, and refreshes socket presence when idle.
///
/// When the session is `None` and no scan is active, probes the control socket every 8 ticks
/// (~800 ms) so the UI reflects a newly started daemon without requiring a manual keypress.
pub(crate) fn poll_tab2_session(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    probe_tick: &mut u8,
    scan_active: bool,
) {
    let Some(sess) = session_tab2.as_mut() else {
        if !scan_active {
            *probe_tick = probe_tick.wrapping_add(1);
            if (*probe_tick).is_multiple_of(8) {
                refresh_idle_socket(state, session_tab2);
            }
        }
        return;
    };
    sess.drain_packets(state);
    let mut disconnected: Option<(bool, Option<String>)> = None;
    if let Tab2Session::Remote(remote) = sess {
        while let Ok(ev) = remote.ev_rx.try_recv() {
            match ev {
                RemoteEvent::StatusUpdated(st) => {
                    if let Some(meta) = state.run.remote_meta.as_mut() {
                        meta.profile_names = st.profile_names;
                        meta.config_path = st.config_path;
                    }
                }
                RemoteEvent::InfoLog(msg) => {
                    state.status_banner = msg.clone();
                    state.push_run_log(msg);
                }
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
        state.run.detected_socket = detect_control_socket(state.run.control_socket_override.as_deref());
        if was_stop {
            state.run.auto_reattach = false;
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

/// Periodically checks control socket presence while Tab 2 is idle and re-attaches when enabled.
///
/// If the previously detected socket path has vanished from disk, it is cleared from `state`.
/// If a new socket appears and `auto_reattach` is set, `attach_to_socket` is called immediately.
fn refresh_idle_socket(state: &mut AppState, session_tab2: &mut Option<Tab2Session>) {
    if let Some(existing) = state.run.detected_socket.clone() {
        if std::fs::symlink_metadata(&existing).is_err() {
            state.run.detected_socket = None;
        } else if state.run.auto_reattach {
            attach_to_socket(state, session_tab2, existing);
        }
        return;
    }
    if let Some(found) = detect_control_socket(state.run.control_socket_override.as_deref()) {
        state.run.detected_socket = Some(found.clone());
        if state.run.auto_reattach {
            attach_to_socket(state, session_tab2, found);
        } else if state.run.status == RunStatus::Stopped {
            state.status_banner =
                format!("Daemon socket ready at {}; press 'r' to attach.", found.display());
        }
    }
}

/// Pushes Tab 3's validated `active_toml` to an attached daemon via `reload_config`.
///
/// Rejects the push if `toml_error` is set, the TOML is empty, or no remote session is active.
pub(crate) fn push_config_to_daemon(state: &mut AppState, session_tab2: &Option<Tab2Session>) {
    let Some(Tab2Session::Remote(remote)) = session_tab2.as_ref() else {
        state.status_banner =
            "Not attached to a daemon. Attach on Tab 2 ('r') before pushing config.".to_owned();
        return;
    };
    if let Some(err) = &state.config.toml_error {
        state.status_banner =
            format!("Cannot push invalid TOML: {}", err.lines().next().unwrap_or(err));
        return;
    }
    if state.config.active_toml.trim().is_empty() {
        state.status_banner = "Active TOML is empty; nothing to push.".to_owned();
        return;
    }
    match remote.send_command(&Request::ReloadConfig { toml: state.config.active_toml.clone() }) {
        Ok(()) => {
            let _ = remote.send_command(&Request::Status);
            state.status_banner = "Pushed config to attached nfqws2 daemon.".to_owned();
        }
        Err(err) => {
            state.push_run_log(format!("[error] {err}"));
            state.status_banner = err;
        }
    }
}

/// Stops an in-process Tab 2 worker cleanly, draining final records into `state.inspector`.
///
/// The firewall guard is torn down via `drop_fw_tui` to restore raw mode safely before nft cleanup.
pub(crate) fn stop_local_daemon(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) {
    if let Some(Tab2Session::Local(mut daemon)) = session_tab2.take() {
        daemon.shutdown(|g| drop_fw_tui(session, g));
        drain_packet_pair(state, &daemon.desync_rx, &daemon.pkt_rx, usize::MAX);
        state.run.status = RunStatus::Stopped;
        let engine = crate::tui::tabs::ENGINE_LABEL;
        state.push_run_log(if cfg!(windows) {
            format!("[stop] {engine} stopped cleanly.")
        } else {
            format!("[stop] {engine} stopped and temporary nftables cleaned up.")
        });
        state.status_banner = format!("{engine} stopped cleanly.");
    }
}

/// Attaches to a visible control socket when unattached, then stops whichever daemon is active.
///
/// Returns `false` if a visible control socket could not be attached to (so stop could not proceed).
pub(crate) fn attach_and_stop_active_daemon(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) -> bool {
    if session_tab2.is_none()
        && let Some(sock) = state
            .run.detected_socket
            .clone()
            .or_else(|| detect_control_socket(state.run.control_socket_override.as_deref()))
    {
        state.run.detected_socket = Some(sock.clone());
        if !attach_to_socket(state, session_tab2, sock) {
            return false;
        }
    }
    match session_tab2 {
        Some(Tab2Session::Remote(_)) => execute_remote_stop(state, session_tab2),
        Some(Tab2Session::Local(_)) => stop_local_daemon(state, session_tab2, session),
        None => {}
    }
    true
}
