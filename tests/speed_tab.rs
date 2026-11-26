//! Tests for Tab 4 (Speed Test) model, target deduplication, deltas, and headless rendering.

/// Keyboard event construction for driving `AppState::handle_key`.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless terminal backend used to assert rendered Tab 4 frames.
use ratatui::{Terminal, backend::TestBackend};

/// Probe outcome and timed sample types shared with Tab 4 rows.
use zapret_rs::tools::{CONTROL_HOST, ProbeOutcome, SpeedSample};
/// Tab 4 model and formatting helpers under test.
use zapret_rs::tui::speed::{
    Change, Side, SpeedPhase, SpeedRow, SpeedState, build_targets, compare, describe_sample,
    format_rate,
};
/// Top-level TUI state, navigation enum, and frame renderer.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, ModalPurpose, draw_app};

/// Builds a successful [`SpeedSample`] with explicit TTFB and throughput.
fn ok_sample(ttfb_ms: u64, bytes_per_sec: u64) -> SpeedSample {
    SpeedSample {
        outcome: ProbeOutcome::Available { http_code: 200, latency_ms: ttfb_ms },
        connect_ms: 20,
        ttfb_ms,
        bytes_per_sec,
    }
}

/// Builds a failed [`SpeedSample`] for testing fixed/regression deltas.
fn blocked_sample() -> SpeedSample {
    SpeedSample { outcome: ProbeOutcome::Timeout, connect_ms: 0, ttfb_ms: 0, bytes_per_sec: 0 }
}

/// Renders `state` into a plain string for substring assertions.
fn render_str(state: &AppState) -> String {
    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| draw_app(f, state)).expect("draw");
    term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
}

#[test]
fn build_targets_deduplicates_tab1_domains_and_appends_control() {
    let targets = build_targets("https://Example.COM/foo, youtube.com example.com");
    let labels: Vec<&str> = targets.iter().map(|t| t.label.as_str()).collect();
    assert_eq!(labels, vec!["example.com", "youtube.com", &format!("control ({CONTROL_HOST})")]);
}

#[test]
fn compare_identifies_fixed_regression_still_blocked_and_metric_deltas() {
    assert_eq!(
        compare(&SpeedRow {
            label: "a".to_owned(),
            before: Some(blocked_sample()),
            after: Some(ok_sample(100, 500_000)),
        }),
        Change::Fixed
    );
    assert_eq!(
        compare(&SpeedRow {
            label: "b".to_owned(),
            before: Some(ok_sample(100, 500_000)),
            after: Some(blocked_sample()),
        }),
        Change::Broke
    );
    assert_eq!(
        compare(&SpeedRow {
            label: "c".to_owned(),
            before: Some(blocked_sample()),
            after: Some(blocked_sample()),
        }),
        Change::StillBlocked
    );
    assert_eq!(
        compare(&SpeedRow {
            label: "d".to_owned(),
            before: Some(ok_sample(100, 10_000_000)),
            after: Some(ok_sample(110, 11_000_000)),
        }),
        Change::Compared("ttfb +10ms  speed +10%".to_owned())
    );
}

#[test]
fn format_rate_and_describe_sample_cover_scales_and_errors() {
    assert_eq!(format_rate(512), "512 B/s");
    assert_eq!(format_rate(12_500), "12 KB/s");
    assert_eq!(format_rate(10_827_906), "10.8 MB/s");
    assert_eq!(describe_sample(&ok_sample(112, 10_827_906)), "112ms  10.8 MB/s");
    assert_eq!(describe_sample(&blocked_sample()), "TIMEOUT");
}

#[test]
fn tab4_key_switches_renders_empty_state_table_and_help_popup() {
    let mut state = AppState::new(None, None, false);
    state.domains_input = "example.com".to_owned();
    state.handle_key(KeyEvent::new(KeyCode::Char('4'), KeyModifiers::NONE));
    assert_eq!(state.tab, ActiveTab::Speed);

    let empty = render_str(&state);
    assert!(empty.contains("4: Speed Test") && empty.contains("No speed measurements recorded yet."));
    assert!(empty.contains("example.com") && empty.contains(CONTROL_HOST));

    state.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
    let help = render_str(&state);
    assert!(help.contains("4: Speed Test") && help.contains("[r] Run Before/After Check"));
    state.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));

    // Populate a comparison row and confirm the table renders it cleanly.
    let mut sp = SpeedState::default();
    let targets = build_targets("example.com");
    sp.start(&targets);
    sp.record(Side::Before, 0, blocked_sample());
    sp.record(Side::After, 0, ok_sample(85, 2_500_000));
    sp.phase = SpeedPhase::Done;
    state.speed = sp;
    let table_screen = render_str(&state);
    assert!(table_screen.contains("FIXED (works with zapret)") && table_screen.contains("2.5 MB/s"));
}

#[test]
fn tab4_run_key_requires_confirmation_then_emits_run_speed_test_action() {
    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Speed;
    state.domains_input = "example.com".to_owned();

    assert_eq!(
        state.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE)),
        AppAction::None
    );
    let modal = state.modal.as_ref().expect("r on Tab 4 must open ConfirmSpeedTest popup");
    assert_eq!(modal.purpose, ModalPurpose::ConfirmSpeedTest);

    let popup = render_str(&state);
    assert!(popup.contains("Confirm Before/After Speed Check"));

    // Confirming closes the modal and returns `AppAction::RunSpeedTest`.
    assert_eq!(
        state.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
        AppAction::RunSpeedTest
    );
    assert!(state.modal.is_none());

    // Pressing Esc cancels instead.
    state.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert!(state.modal.is_some());
    assert_eq!(
        state.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
        AppAction::None
    );
    assert!(state.modal.is_none());
}
