//! Headless `ratatui` `TestBackend` rendering and state-machine tests.

#![cfg(feature = "tui")]

/// Atomic store helpers for testing live packet counter display on Tab 2.
use std::sync::atomic::Ordering;

/// Synthetic keyboard events driven through [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless in-memory `ratatui` terminal backend for deterministic UI rendering tests.
use ratatui::{Terminal, backend::TestBackend};

/// Strategy catalog and report types fed into [`ScanUiEvent::Completed`].
use zapret_rs::tools::{
    CoveredProfile, IpFamily, ProbeOutcome, ProbeProtocol, ScanLevel, ScanReport, StrategyMatch,
    TargetScanResult, TomlRenderOptions, build_catalog, render_nfqws2_toml,
};
/// TUI state, floating modal, frame renderer, and action/event enums under test.
use zapret_rs::tui::{
    ActiveTab, AppAction, AppState, AuthModal, FinderField, FinderStatus, IpMode, ModalPurpose, RunStatus,
    ScanUiEvent, draw_app,
};

/// Creates a plain unmodified [`KeyEvent`] for `code`.
fn key(code: KeyCode) -> KeyEvent
{
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders `state` into a `TestBackend` buffer of size `(width, height)` and returns the plain text.
fn render_to_string(state: &AppState, width: u16, height: u16) -> String
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|f| draw_app(f, state))
        .expect("draw frame");
    let buf = terminal
        .backend()
        .buffer();
    let mut out = String::new();
    for y in 0..height
    {
        for x in 0..width
        {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Drives Strategy Finder form editing and scan trigger controls against `state`.
fn verify_finder_form_editing(state: &mut AppState)
{
    assert_eq!(state.tab, ActiveTab::Finder);
    assert_eq!(state.focused_field(), FinderField::Domains);

    // Enter text edit mode on Domains; typing 'q' and '1' must insert characters, not quit or switch tabs.
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert!(
        state
            .finder
            .editing_text
    );
    for ch in "q1.example.com".chars()
    {
        assert_eq!(state.handle_key(key(KeyCode::Char(ch))), AppAction::None);
    }
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert!(
        !state
            .finder
            .editing_text
    );
    assert_eq!(
        state
            .finder
            .domains_input,
        "q1.example.com"
    );

    state.handle_key(key(KeyCode::Down)); // ProtoHttp
    assert_eq!(state.focused_field(), FinderField::ProtoHttp);
    state.handle_key(key(KeyCode::Char(' ')));
    assert!(
        !state
            .finder
            .proto_http
    );

    state
        .finder
        .focus_idx = 5; // IpMode
    state.handle_key(key(KeyCode::Enter));
    assert_eq!(
        state
            .finder
            .ip_mode,
        IpMode::V6
    );

    state
        .finder
        .focus_idx = 6; // Level
    state.handle_key(key(KeyCode::Enter));
    assert_eq!(
        state
            .finder
            .level,
        ScanLevel::Standard
    );
}

/// Verifies scan config construction, Start/Stop actions, and completion events against `state`.
fn verify_finder_scan_events(state: &mut AppState)
{
    let cfg = state
        .build_scan_config()
        .expect("valid scan config");
    assert_eq!(cfg.domains, vec!["q1.example.com".to_owned()]);
    assert!(
        !cfg.protos
            .contains(&ProbeProtocol::Http)
    );
    assert_eq!(cfg.families, vec![IpFamily::V6]);
    assert_eq!(cfg.level, ScanLevel::Standard);

    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StartScan);
    state
        .finder
        .status = FinderStatus::Scanning;
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::StopScan);

    let spec = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V6)
        .into_iter()
        .next()
        .expect("tls13 strategy");
    let cover = vec![CoveredProfile {
        strategy: spec.clone(),
        domains: vec!["q1.example.com".to_owned()],
        avg_latency_ms: 42,
    }];
    let rendered = render_nfqws2_toml(&cover, &TomlRenderOptions::default());

    state.apply_scan_event(ScanUiEvent::Baseline {
        domain: "q1.example.com".to_owned(),
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V6,
        summary: "TIMEOUT".to_owned(),
        skipped: false,
    });
    state.apply_scan_event(ScanUiEvent::Candidate {
        domain: "q1.example.com".to_owned(),
        index: 1,
        total: 5,
        strategy_id: spec
            .id
            .clone(),
        passed: true,
        summary: "OK (HTTP 200, 42 ms)".to_owned(),
    });
    state.apply_scan_event(ScanUiEvent::Completed {
        report: ScanReport {
            targets: vec![TargetScanResult {
                domain: "q1.example.com".to_owned(),
                proto: ProbeProtocol::Tls13,
                ipv: IpFamily::V6,
                baseline: ProbeOutcome::Timeout,
                skipped_unblocked: false,
                tested_count: 1,
                matches: vec![StrategyMatch { strategy: spec.clone(), latency_ms: 42 }],
            }],
            cover,
            interrupted: false,
        },
        rendered_toml: rendered,
    });

    assert_eq!(
        state
            .finder
            .status,
        FinderStatus::Done
    );
    assert_eq!(
        state
            .config
            .parsed_profiles,
        vec![spec.id]
    );
}

/// Verifies form editing, text-input key isolation (`q`/`1`), toggles, scan event handling,
/// and tab transitions across all three views.
#[test]
fn tui_state_machine_handles_form_editing_scan_events_and_navigation()
{
    let mut state = AppState::new(None, None, false);
    verify_finder_form_editing(&mut state);
    verify_finder_scan_events(&mut state);

    // Press 'a' to switch to Run tab, start daemon, reset counters, and quit.
    assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Run);
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StartDaemon);

    state
        .run
        .status = RunStatus::Running;
    state
        .run
        .counters
        .total
        .store(12, Ordering::Relaxed);
    assert_eq!(state.handle_key(key(KeyCode::Char('c'))), AppAction::None);
    assert_eq!(
        state
            .run
            .counters
            .snapshot()
            .0,
        0
    );
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StopDaemon);
    state
        .status
        .has_net_caps = false;
    assert_eq!(state.handle_key(key(KeyCode::Char('g'))), AppAction::None);
    assert!(
        state
            .modal
            .is_some(),
        "'g' must open the floating capability modal"
    );
    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(
        state
            .modal
            .is_none(),
        "Esc must dismiss the floating modal"
    );
    assert_eq!(state.handle_key(key(KeyCode::Char('q'))), AppAction::Quit);
}

/// Verifies the floating capability/sudo modal masks passwords, renders cleanly in `TestBackend`,
/// submits on `Enter`, and zeroizes its password buffer on `take_password`.
#[test]
fn tui_floating_auth_modal_masks_password_renders_and_submits()
{
    let mut state = AppState::new(None, None, false);
    state.modal = Some(AuthModal::with_password_prompt(
        ModalPurpose::GrantCaps,
        "sudo setcap cap_net_admin,cap_net_raw+ep ./target/release/zapret-rs".to_owned(),
        true,
    ));

    for ch in "s3cr3t".chars()
    {
        assert_eq!(state.handle_key(key(KeyCode::Char(ch))), AppAction::None);
    }
    let screen = render_to_string(&state, 100, 30);
    assert!(screen.contains("Grant Network Capabilities"));
    assert!(screen.contains("******_"), "password must be masked as asterisks");
    assert!(!screen.contains("s3cr3t"), "plaintext password must never be rendered");

    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitModal);
    let modal = state
        .modal
        .as_mut()
        .expect("modal still open until runner submits");
    assert_eq!(modal.take_password(), "s3cr3t");
    assert_eq!(modal.password_len(), 0, "take_password must clear internal buffer");
}

/// Verifies all three tabs render cleanly without panicking at standard (`120x36`) and compact (`80x24`) sizes.
#[test]
fn tui_renders_all_three_tabs_cleanly_in_headless_test_backend()
{
    let mut state = AppState::new(None, None, false);
    state
        .finder
        .domains_input = "example.com".to_owned();
    state
        .run
        .counters
        .total
        .store(99, Ordering::Relaxed);
    state
        .run
        .counters
        .passed
        .store(86, Ordering::Relaxed);
    state
        .run
        .counters
        .reassembled
        .store(4, Ordering::Relaxed);
    state
        .run
        .counters
        .modified
        .store(7, Ordering::Relaxed);
    state
        .run
        .counters
        .desynced
        .store(2, Ordering::Relaxed);

    for &(w, h) in &[(120u16, 36u16), (80, 24)]
    {
        state.tab = ActiveTab::Finder;
        let finder_screen = render_to_string(&state, w, h);
        assert!(finder_screen.contains("Strategy Setup"));
        assert!(finder_screen.contains("Scan Progress"));
        assert!(finder_screen.contains("example.com"));

        state.tab = ActiveTab::Run;
        let run_screen = render_to_string(&state, w, h);
        assert!(run_screen.contains("Live nfqws2 Controller"));
        assert!(run_screen.contains("99"));

        state.tab = ActiveTab::Config;
        let cfg_screen = render_to_string(&state, w, h);
        let expected_filter_title = state
            .filter_preview()
            .0
            .trim();
        assert!(cfg_screen.contains(expected_filter_title));
        assert!(cfg_screen.contains("table inet zapret_strat_finder {"));

        state.tab = ActiveTab::Hostlist;
        let host_screen = render_to_string(&state, w, h);
        assert!(host_screen.contains("Auto Hostlist") && host_screen.contains("Blacklist"));
    }
}

/// Verifies `H` and `L` cycle across all seven top-level tabs with cyclic wrap-around.
#[test]
fn tui_h_and_l_cycle_top_level_tabs_cyclically()
{
    let mut state = AppState::new(None, None, false);
    assert_eq!(state.tab, ActiveTab::Finder);
    assert_eq!(state.handle_key(key(KeyCode::Char('H'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Settings);
    assert_eq!(state.handle_key(key(KeyCode::Char('H'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Hostlist);
    assert_eq!(state.handle_key(key(KeyCode::Char('L'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Settings);
    assert_eq!(state.handle_key(key(KeyCode::Char('L'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Finder);
    assert_eq!(state.handle_key(key(KeyCode::Char('L'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Run);
}
