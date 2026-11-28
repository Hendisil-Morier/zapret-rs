//! Tests for the Tab 2 daemon restart: pure transition table and `R` key mapping.

/// Key event construction for driving `AppState::handle_key`.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Time bounds used to exercise the stop timeout.
use std::time::Duration;

/// Pure state machine under test.
use zapret_rs::tui::daemon_cycle::{CycleInputs, CyclePhase, CycleStep, STOP_TIMEOUT, next_step};
/// Application state and the action it emits for the runner.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, RunStatus};

/// Builds inputs describing a quiet daemon-free system unless fields are overridden.
fn idle_inputs() -> CycleInputs
{
    CycleInputs {
        session_active: false,
        socket_present: false,
        modal_open: false,
        run_errored: false,
        elapsed: Duration::ZERO,
    }
}

#[test]
fn stopping_waits_for_session_and_socket_then_starts()
{
    let waiting = CycleInputs { session_active: true, ..idle_inputs() };
    assert_eq!(next_step(CyclePhase::Stopping, &waiting), CycleStep::WaitStop);

    let socket_left = CycleInputs { socket_present: true, ..idle_inputs() };
    assert_eq!(next_step(CyclePhase::Stopping, &socket_left), CycleStep::WaitStop);

    assert_eq!(next_step(CyclePhase::Stopping, &idle_inputs()), CycleStep::StartNow);
}

#[test]
fn stopping_times_out_with_readable_reason()
{
    let stuck = CycleInputs { session_active: true, elapsed: STOP_TIMEOUT, ..idle_inputs() };
    match next_step(CyclePhase::Stopping, &stuck)
    {
        CycleStep::Failed(msg) => assert!(msg.contains("did not stop"), "got: {msg}"),
        other => panic!("expected timeout failure, got {other:?}"),
    }
}

#[test]
fn starting_distinguishes_success_pending_sudo_error_and_cancel()
{
    let up = CycleInputs { session_active: true, ..idle_inputs() };
    assert_eq!(next_step(CyclePhase::Starting, &up), CycleStep::Finished);

    let sudo = CycleInputs { modal_open: true, ..idle_inputs() };
    assert_eq!(next_step(CyclePhase::Starting, &sudo), CycleStep::WaitStart);

    let broken = CycleInputs { run_errored: true, ..idle_inputs() };
    assert!(
        matches!(next_step(CyclePhase::Starting, &broken), CycleStep::Failed(m) if m.contains("failed to start"))
    );

    assert!(
        matches!(next_step(CyclePhase::Starting, &idle_inputs()), CycleStep::Failed(m) if m.contains("cancelled"))
    );
}

#[test]
fn shift_r_requests_restart_on_tab2_whether_attached_or_not()
{
    let press =
        |state: &mut AppState| state.handle_key(KeyEvent::new(KeyCode::Char('R'), KeyModifiers::SHIFT));
    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Run;
    assert_eq!(press(&mut state), AppAction::RestartDaemon);

    state
        .run
        .status = RunStatus::Attached;
    assert_eq!(press(&mut state), AppAction::RestartDaemon);

    // Other tabs must not trigger a restart.
    state.tab = ActiveTab::Config;
    assert_ne!(press(&mut state), AppAction::RestartDaemon);
}
