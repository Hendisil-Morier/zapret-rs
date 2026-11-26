//! Stop-then-start daemon cycle driving the Tab 2 `R` restart (and reused by the speed comparison).

/// Elapsed-time bounds for the stop wait.
use std::time::{Duration, Instant};

/// Live control-socket probe used to know when the old daemon has really gone away.
use crate::tui::remote::detect_control_socket;
/// Daemon start path (attach, systemd, detached `nfqws2`, or in-process) shared with the `r` key.
use crate::tui::actions::try_start_or_attach;
/// Mutable application state receiving banners and run log lines.
use crate::tui::state::AppState;
/// Session type plus the stop and attach helpers for remote and in-process daemons.
use crate::tui::tab2_session::{Tab2Session, attach_to_socket, execute_remote_stop, stop_local_daemon};
/// Terminal wrapper required to tear down an in-process firewall guard while stopping.
use crate::tui::session::TerminalSession;
/// Run lifecycle status inspected to detect a failed start.
use crate::tui::types::RunStatus;

/// Longest the old daemon may take to release its control socket before the cycle gives up.
pub const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Stage of the stop-then-start sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CyclePhase {
    /// Waiting for the previous daemon to exit and its socket to disappear.
    Stopping,
    /// The start request was issued; waiting for the new daemon session or a sudo prompt result.
    Starting,
}

/// Snapshot of everything the transition decision depends on, gathered once per tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CycleInputs {
    /// `true` while Tab 2 still holds an attached or in-process session.
    pub session_active: bool,
    /// `true` while a live daemon control socket is still reachable on disk.
    pub socket_present: bool,
    /// `true` while a sudo or capability popup is waiting for the user.
    pub modal_open: bool,
    /// `true` when the last start attempt left [`RunStatus::Error`] behind.
    pub run_errored: bool,
    /// Time since the cycle began.
    pub elapsed: Duration,
}

/// Decision produced by [`next_step`] for the current phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CycleStep {
    /// Old daemon is still shutting down; check again next tick.
    WaitStop,
    /// Old daemon is gone; issue the start request now.
    StartNow,
    /// Start is pending on the user (sudo popup); check again next tick.
    WaitStart,
    /// New daemon session is established.
    Finished,
    /// Cycle aborted with a user-facing reason.
    Failed(String),
}

/// Pure transition function: maps the current phase and observations to the next action.
pub fn next_step(phase: CyclePhase, i: &CycleInputs) -> CycleStep {
    match phase {
        CyclePhase::Stopping if !i.session_active && !i.socket_present => CycleStep::StartNow,
        CyclePhase::Stopping if i.elapsed >= STOP_TIMEOUT => {
            CycleStep::Failed(format!("Daemon did not stop within {}s.", STOP_TIMEOUT.as_secs()))
        }
        CyclePhase::Stopping => CycleStep::WaitStop,
        CyclePhase::Starting if i.session_active => CycleStep::Finished,
        CyclePhase::Starting if i.modal_open => CycleStep::WaitStart,
        CyclePhase::Starting if i.run_errored => {
            CycleStep::Failed("Daemon failed to start (see Daemon Log).".to_owned())
        }
        CyclePhase::Starting => CycleStep::Failed("Daemon start cancelled.".to_owned()),
    }
}

/// In-flight restart owned by the runner loop.
pub(crate) struct DaemonCycle {
    /// Current stage of the sequence.
    phase: CyclePhase,
    /// Moment the cycle began, used for the stop timeout.
    started: Instant,
}

/// Starts a restart: attaches if only a detached socket is visible, then asks the daemon to stop.
///
/// Returns `None` when a visible daemon cannot be attached to (so it could not be stopped).
pub(crate) fn begin_restart(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) -> Option<DaemonCycle> {
    if session_tab2.is_none()
        && let Some(sock) = state.detected_socket.clone()
        && !attach_to_socket(state, session_tab2, sock)
    {
        return None;
    }
    match session_tab2 {
        Some(Tab2Session::Remote(_)) => execute_remote_stop(state, session_tab2),
        Some(Tab2Session::Local(_)) => stop_local_daemon(state, session_tab2, session),
        None => {}
    }
    state.status_banner = "Restarting daemon...".to_owned();
    Some(DaemonCycle { phase: CyclePhase::Stopping, started: Instant::now() })
}

/// Advances `job` by one tick and clears it when the sequence has finished or failed.
pub(crate) fn poll_daemon_cycle(
    job: &mut Option<DaemonCycle>,
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) {
    let Some(cycle) = job.as_mut() else {
        return;
    };
    loop {
        let inputs = CycleInputs {
            session_active: session_tab2.is_some(),
            socket_present: detect_control_socket(state.control_socket_override.as_deref()).is_some(),
            modal_open: state.modal.is_some(),
            run_errored: matches!(state.run_status, RunStatus::Error(_)),
            elapsed: cycle.started.elapsed(),
        };
        match next_step(cycle.phase, &inputs) {
            CycleStep::WaitStop | CycleStep::WaitStart => return,
            CycleStep::StartNow => {
                cycle.phase = CyclePhase::Starting;
                try_start_or_attach(state, session_tab2);
            }
            CycleStep::Finished => {
                state.status_banner = "Daemon restarted.".to_owned();
                *job = None;
                return;
            }
            CycleStep::Failed(msg) => {
                state.push_run_log(format!("[error] {msg}"));
                state.status_banner = msg;
                *job = None;
                return;
            }
        }
    }
}
