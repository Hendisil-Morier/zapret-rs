//! Integration tests for Tab 5 (`Status`) operational component checks, navigation, and rendering.

#![cfg(feature = "tui")]

/// Keyboard event helpers for switching to Tab 5 and navigating component rows.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless terminal backend verifying Tab 5 layout and rendering without a TTY.
use ratatui::{Terminal, backend::TestBackend};

/// TUI application state, tab enum, and root renderer under test.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, draw_app};

#[test]
fn tab5_status_populates_checks_navigates_and_renders() {
    let mut state = AppState::new(None, None, false);
    assert!(state.status_checks.is_empty());

    assert_eq!(
        state.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE)),
        AppAction::None
    );
    assert_eq!(state.tab, ActiveTab::Status);
    assert_eq!(state.status_checks.len(), 9);
    assert_eq!(state.status_selected, 0);

    let names: Vec<&str> = state.status_checks.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        [
            "Privileges",
            "Packet Driver",
            "Lua Scripts",
            "Probe (curl)",
            "DNS Resolver",
            "Config",
            "Daemon & IPC",
            "Strategy Scan",
            "Speed Test",
        ]
    );

    state.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(state.status_selected, 1);
    state.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(state.status_selected, 0);
    state.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert_eq!(state.status_checks.len(), 9);

    // Cycling DNS preset ('n') and opening confirm modal ('a') work cleanly.
    let initial_preset = state.dns_preset;
    state.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));
    assert_ne!(state.dns_preset, initial_preset);
    state.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
    assert_eq!(
        state.modal.as_ref().map(|m| m.purpose),
        Some(zapret_rs::tui::ModalPurpose::ConfirmApplyDns)
    );
    state.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
    assert!(state.modal.is_none());

    let backend = TestBackend::new(120, 34);
    let mut term = Terminal::new(backend).expect("create test terminal");
    term.draw(|f| draw_app(f, &state)).expect("render Tab 5");

    let rendered: String = term
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("Operational Component Status"));
    assert!(rendered.contains("Component Details"));
    assert!(rendered.contains("Packet Driver"));
    assert!(!rendered.contains("[r] Refresh"));
    assert!(!rendered.contains("[d] Debug Report"));
}

#[test]
fn tab5_debug_report_exports_checks_logs_and_curl_exit_hints() {
    use zapret_rs::tools::ProbeOutcome;
    use zapret_rs::tui::debug_report::debug_report_path;

    let dns_err = ProbeOutcome::Failed {
        code: 6,
        detail: "Could not resolve host".to_owned(),
    };
    assert!(dns_err.summary().contains("DNS resolve failed"));

    let write_err = ProbeOutcome::Failed {
        code: 23,
        detail: "Failed writing body".to_owned(),
    };
    assert!(write_err.summary().contains("output write error"));

    let dir = std::env::temp_dir().join(format!("zapret-debug-export-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("nfqws2.toml");

    let mut state = AppState::new(Some(cfg_path), None, false);
    state.push_finder_log("[worker] test-filter");
    state.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));
    state.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));

    let report_file = debug_report_path(&state.output_path);
    let body = std::fs::read_to_string(&report_file).expect("read exported debug report");
    assert!(body.contains("=== zapret-rs Debug Report ==="));
    assert!(body.contains("=== Operational Component Checks ==="));
    assert!(body.contains("=== Speed Test Results ==="));
    assert!(body.contains("=== Strategy Finder Results ==="));
    assert!(body.contains("=== Active Config (nfqws2.toml) ==="));
    assert!(body.contains("[worker] test-filter"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tab5_debug_report_includes_speed_finder_and_active_config() {
    use std::path::PathBuf;
    use zapret_rs::tools::{
        CoveredProfile, IpFamily, ProbeOutcome, ProbeProtocol, SpeedSample, StrategyMatch,
        StrategySpec, TargetScanResult,
    };
    use zapret_rs::tui::RemoteDaemonMeta;
    use zapret_rs::tui::debug_report::format_debug_report;
    use zapret_rs::tui::speed::{SpeedPhase, SpeedRow};

    let mut state = AppState::new(None, None, false);
    state.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));

    // Switch back to Tab 1 and populate scan, speed, config, and attached daemon metadata.
    state.handle_key(KeyEvent::new(KeyCode::Char('1'), KeyModifiers::NONE));
    state.domains_input = "example.com".to_owned();
    state.speed.phase = SpeedPhase::Done;
    state.speed.rows.push(SpeedRow {
        label: "example.com".to_owned(),
        before: Some(SpeedSample {
            outcome: ProbeOutcome::Timeout,
            connect_ms: 0,
            ttfb_ms: 0,
            bytes_per_sec: 0,
        }),
        after: Some(SpeedSample {
            outcome: ProbeOutcome::Available { http_code: 200, latency_ms: 140 },
            connect_ms: 35,
            ttfb_ms: 140,
            bytes_per_sec: 512_000,
        }),
    });

    let strat = StrategySpec {
        id: "tls13:ipv4:fake_badsum".to_owned(),
        family: "fake",
        weight: 45,
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V4,
        actions: Vec::new(),
    };
    state.targets.push(TargetScanResult {
        domain: "example.com".to_owned(),
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V4,
        baseline: ProbeOutcome::Timeout,
        skipped_unblocked: false,
        tested_count: 17,
        matches: vec![StrategyMatch { strategy: strat.clone(), latency_ms: 140 }],
    });
    state.cover.push(CoveredProfile {
        strategy: strat,
        domains: vec!["example.com".to_owned()],
        avg_latency_ms: 140,
    });
    state.set_active_toml("qnum = 200\nfirmware_test = true\n".to_owned());
    state.remote_meta = Some(RemoteDaemonMeta {
        socket_path: PathBuf::from("/tmp/test.sock"),
        daemon_version: "1.4.0".to_owned(),
        pid: 4242,
        qnum: 200,
        fwmark: 0x4000_0000,
        intercept: true,
        profile_names: vec!["profile_0".to_owned()],
        config_path: None,
    });

    // Switching back to Tab 5 must refresh status checks with the updated Speed Test & Scan rows.
    state.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));
    let speed_check = state
        .status_checks
        .iter()
        .find(|c| c.name == "Speed Test")
        .expect("Speed Test status row");
    assert!(speed_check.summary.contains("1 fixed"));

    let report = format_debug_report(&state);
    assert!(report.contains("Daemon Info : pid=4242 ver=1.4.0 qnum=200 intercept=true profiles=[profile_0]"));
    assert!(report.contains("DNS Preset  : Cloudflare"));
    assert!(report.contains("example.com: before=[TIMEOUT] after=[conn 35ms ttfb 140ms  512 KB/s] result=FIXED"));
    assert!(report.contains("example.com (tls13/ipv4): baseline=TIMEOUT tested=17 matches=1 best=tls13:ipv4:fake_badsum (140 ms)"));
    assert!(report.contains("tls13:ipv4:fake_badsum: domains=[example.com] avg=140 ms"));
    assert!(report.contains("qnum = 200"));
}
