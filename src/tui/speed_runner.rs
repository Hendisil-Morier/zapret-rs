//! Orchestrates Tab 4's before/after speed comparison (`stop -> probe -> start -> settle -> probe`).

/// Channel primitives receiving timed [`SpeedSample`] rows from background `curl` threads.
use std::sync::mpsc::{self, Receiver};
/// Background probe thread spawning.
use std::thread;
/// Elapsed-time checks for daemon stop and rule-settle delays.
use std::time::{Duration, Instant};

/// `curl` probe runner, IP family selector, target descriptor, and timed sample model.
use crate::tools::{CurlProbeBackend, IpFamily, SpeedSample, SpeedTarget, measure};
/// Reused daemon start/stop helpers and stop-timeout constant.
use crate::tui::actions::try_start_or_attach;
use crate::tui::daemon_cycle::STOP_TIMEOUT;
use crate::tui::remote::detect_control_socket;
use crate::tui::session::TerminalSession;
use crate::tui::speed::{Side, SpeedPhase, build_targets, effective_speed_domains};
use crate::tui::state::AppState;
use crate::tui::tab2_session::{Tab2Session, attach_and_stop_active_daemon};
use crate::tui::types::RunStatus;

/// Settle delay after daemon startup so `nftables` rules and conntrack are active before probing.
const SETTLE_DELAY: Duration = Duration::from_millis(500);

/// Internal state of an active Tab 4 before/after speed comparison run.
enum JobPhase {
    /// Waiting for any running daemon to exit so baseline speed reflects `zapret` OFF.
    Stopping { started: Instant },
    /// Measuring each target in background thread with `zapret` OFF.
    ProbingBefore { rx: Receiver<(usize, SpeedSample)> },
    /// Starting `nfqws2` (systemd, detached daemon, or local) and waiting for attachment.
    Starting,
    /// Waiting briefly after start before launching the second probe sweep.
    Settling { started: Instant },
    /// Measuring each target in background thread with `zapret` ON.
    ProbingAfter { rx: Receiver<(usize, SpeedSample)> },
}

/// Active Tab 4 comparison job driven once per tick by the TUI runner loop.
pub(crate) struct SpeedJob {
    /// Current phase of the stop -> measure -> start -> measure sequence.
    phase: JobPhase,
    /// Ordered probe targets (`domains` from Tab 1 + fixed unaffected control target).
    targets: Vec<SpeedTarget>,
    /// Primary IP family selected on Tab 1.
    ipv: IpFamily,
}

/// Spawns a background thread measuring all `targets` sequentially and streaming `(idx, sample)`.
fn spawn_probe_worker(targets: Vec<SpeedTarget>, ipv: IpFamily) -> Receiver<(usize, SpeedSample)> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let backend = CurlProbeBackend::default();
        for (idx, target) in targets.iter().enumerate() {
            let sample = measure(&backend, target, ipv);
            if tx.send((idx, sample)).is_err() {
                break;
            }
        }
    });
    rx
}

/// Drains completed row samples into `state.speed`, returning `true` when the worker channel closed.
fn drain_probe_samples(
    rx: &Receiver<(usize, SpeedSample)>,
    side: Side,
    state: &mut AppState,
) -> bool {
    loop {
        match rx.try_recv() {
            Ok((idx, sample)) => state.speed.record(side, idx, sample),
            Err(mpsc::TryRecvError::Empty) => return false,
            Err(mpsc::TryRecvError::Disconnected) => return true,
        }
    }
}

/// Aborts the active comparison job cleanly and updates the Tab 4 phase and status banner.
fn abort_speed_job(job: &mut Option<SpeedJob>, state: &mut AppState, msg: String) {
    state.speed.phase = SpeedPhase::Done;
    state.push_run_log(format!("[speed] {msg}"));
    state.status_banner = msg;
    *job = None;
}

/// Cancels an in-flight speed test cleanly, dropping the probe receiver and marking [`SpeedPhase::Done`].
pub(crate) fn cancel_speed_test(job: &mut Option<SpeedJob>, state: &mut AppState) {
    if job.take().is_some() || state.speed.phase.is_running() {
        state.speed.phase = SpeedPhase::Done;
        state.push_run_log("[speed] Speed test cancelled by user.");
        state.status_banner = "Speed test cancelled.".to_owned();
    }
}

/// Starts the Tab 4 before/after speed comparison after user confirmation.
///
/// Stops any active daemon first so the `Before` sweep measures unprotected traffic cleanly.
pub(crate) fn begin_speed_test(
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
    session: &mut TerminalSession,
) -> Option<SpeedJob> {
    if !attach_and_stop_active_daemon(state, session_tab2, session) {
        return None;
    }
    let eff = effective_speed_domains(&state.domains_input, &state.active_toml);
    let targets = build_targets(&eff);
    let ipv = state.ip_mode.families().into_iter().next().unwrap_or(IpFamily::V4);
    state.speed.start(&targets);
    state.status_banner = "Speed test: waiting for daemon to stop...".to_owned();
    Some(SpeedJob { phase: JobPhase::Stopping { started: Instant::now() }, targets, ipv })
}

/// Advances the active [`SpeedJob`] by one tick, driving worker spawns and daemon transitions.
pub(crate) fn poll_speed_test(
    job: &mut Option<SpeedJob>,
    state: &mut AppState,
    session_tab2: &mut Option<Tab2Session>,
) {
    let Some(curr) = job.as_mut() else {
        return;
    };
    match &mut curr.phase {
        JobPhase::Stopping { started } => {
            let sock = detect_control_socket(state.control_socket_override.as_deref()).is_some();
            if session_tab2.is_some() || sock {
                if started.elapsed() >= STOP_TIMEOUT {
                    abort_speed_job(
                        job,
                        state,
                        "Speed test aborted: daemon did not stop in time.".to_owned(),
                    );
                }
                return;
            }
            let rx = spawn_probe_worker(curr.targets.clone(), curr.ipv);
            curr.phase = JobPhase::ProbingBefore { rx };
            state.speed.phase = SpeedPhase::ProbingBefore;
            state.status_banner = "Speed test: measuring without zapret...".to_owned();
        }
        JobPhase::ProbingBefore { rx } => {
            if !drain_probe_samples(rx, Side::Before, state) {
                return;
            }
            curr.phase = JobPhase::Starting;
            state.speed.phase = SpeedPhase::Starting;
            state.status_banner = "Speed test: starting nfqws2...".to_owned();
            try_start_or_attach(state, session_tab2);
        }
        JobPhase::Starting => {
            if session_tab2.is_some() {
                curr.phase = JobPhase::Settling { started: Instant::now() };
                state.speed.phase = SpeedPhase::Settling;
                state.status_banner = "Speed test: settling firewall rules...".to_owned();
            } else if state.modal.is_some() {
                // Waiting on user confirmation (`sudo` / capability prompt).
            } else if matches!(state.run_status, RunStatus::Error(_)) {
                abort_speed_job(
                    job,
                    state,
                    "Speed test aborted: daemon failed to start.".to_owned(),
                );
            } else {
                abort_speed_job(job, state, "Speed test cancelled.".to_owned());
            }
        }
        JobPhase::Settling { started } => {
            if started.elapsed() < SETTLE_DELAY {
                return;
            }
            let rx = spawn_probe_worker(curr.targets.clone(), curr.ipv);
            curr.phase = JobPhase::ProbingAfter { rx };
            state.speed.phase = SpeedPhase::ProbingAfter;
            state.status_banner = "Speed test: measuring with zapret...".to_owned();
        }
        JobPhase::ProbingAfter { rx } => {
            if !drain_probe_samples(rx, Side::After, state) {
                return;
            }
            state.speed.phase = SpeedPhase::Done;
            state.status_banner = "Speed comparison complete.".to_owned();
            *job = None;
        }
    }
}
