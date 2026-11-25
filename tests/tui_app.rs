//! Headless `ratatui` `TestBackend` rendering, state-machine, and `zapret-rs` binary CLI tests.

#![cfg(feature = "tui")]

/// Subprocess checks for the compiled `zapret-rs` TUI binary (`--version`, `--help`).
use std::process::Command;
/// Atomic store helpers for testing live packet counter display on Tab 2.
use std::sync::atomic::Ordering;

/// Synthetic keyboard events driven through [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless in-memory `ratatui` terminal backend for deterministic UI rendering tests.
use ratatui::{Terminal, backend::TestBackend};

/// Packet interception types used to test live packet inspector decoding.
use zapret_rs::intercepter::{Decision, QueuedPacket};
/// Wire packet builders used to construct realistic IPv4+TCP HTTP packets.
use zapret_rs::packet::{
    DissectedPacket, IPPROTO_TCP, Ipv4Header, ReconstructOptions, TH_ACK, TH_PUSH, TcpHeader,
    reconstruct_packet,
};
/// Strategy catalog and report types fed into [`ScanUiEvent::Completed`].
use zapret_rs::tools::{
    CoveredProfile, IpFamily, ProbeOutcome, ProbeProtocol, ScanLevel, ScanReport, StrategyMatch,
    TargetScanResult, TomlRenderOptions, build_catalog, render_nfqws2_toml,
};
/// TUI state, packet inspector, floating modal, frame renderer, and action/event enums under test.
use zapret_rs::tui::{
    ActiveTab, AppAction, AppState, AuthModal, FinderField, FinderStatus, IpMode, ModalPurpose,
    PacketVerdict, RunStatus, ScanUiEvent, VerdictFilter, build_packet_record, draw_app,
    format_hex_dump,
};

/// Creates a plain unmodified [`KeyEvent`] for `code`.
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders `state` into a `TestBackend` buffer of size `(width, height)` and returns the plain text.
fn render_to_string(state: &AppState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| draw_app(f, state)).expect("draw frame");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height {
        for x in 0..width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Verifies form editing, text-input key isolation (`q`/`1`), toggles, scan event handling,
/// and tab transitions across all three views.
#[test]
fn tui_state_machine_handles_form_editing_scan_events_and_navigation() {
    let mut state = AppState::new(None, None, false);
    assert_eq!(state.tab, ActiveTab::Finder);
    assert_eq!(state.focused_field(), FinderField::Domains);

    // Enter text edit mode on Domains; typing 'q' and '1' must insert characters, not quit or switch tabs.
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert!(state.editing_text);
    for ch in "q1.example.com".chars() {
        assert_eq!(state.handle_key(key(KeyCode::Char(ch))), AppAction::None);
    }
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert!(!state.editing_text);
    assert_eq!(state.domains_input, "q1.example.com");

    // Toggle HTTP off, cycle IP mode to V6, cycle ScanLevel to Standard.
    state.handle_key(key(KeyCode::Down)); // ProtoHttp
    assert_eq!(state.focused_field(), FinderField::ProtoHttp);
    state.handle_key(key(KeyCode::Char(' ')));
    assert!(!state.proto_http);

    state.focus_idx = 5; // IpMode
    state.handle_key(key(KeyCode::Enter));
    assert_eq!(state.ip_mode, IpMode::V6);

    state.focus_idx = 6; // Level
    state.handle_key(key(KeyCode::Enter));
    assert_eq!(state.level, ScanLevel::Standard);

    // Build scan config from form state and verify fields.
    let cfg = state.build_scan_config().expect("valid scan config");
    assert_eq!(cfg.domains, vec!["q1.example.com".to_owned()]);
    assert!(!cfg.protos.contains(&ProbeProtocol::Http));
    assert_eq!(cfg.families, vec![IpFamily::V6]);
    assert_eq!(cfg.level, ScanLevel::Standard);

    // Trigger scan start and feed synthetic ScanUiEvents.
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StartScan);
    state.finder_status = FinderStatus::Scanning;
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
        strategy_id: spec.id.clone(),
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

    assert_eq!(state.finder_status, FinderStatus::Done);
    assert_eq!(state.parsed_profiles, vec![spec.id]);

    // Press 'a' to switch to Run tab, start daemon, reset counters, and quit.
    assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Run);
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StartDaemon);

    state.run_status = RunStatus::Running;
    state.counters.total.store(12, Ordering::Relaxed);
    assert_eq!(state.handle_key(key(KeyCode::Char('c'))), AppAction::None);
    assert_eq!(state.counters.snapshot().0, 0);
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::StopDaemon);
    state.has_net_caps = false;
    assert_eq!(state.handle_key(key(KeyCode::Char('g'))), AppAction::None);
    assert!(state.modal.is_some(), "'g' must open the floating capability modal");
    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(state.modal.is_none(), "Esc must dismiss the floating modal");
    assert_eq!(state.handle_key(key(KeyCode::Char('q'))), AppAction::Quit);
}

/// Verifies the floating capability/sudo modal masks passwords, renders cleanly in `TestBackend`,
/// submits on `Enter`, and zeroizes its password buffer on `take_password`.
#[test]
fn tui_floating_auth_modal_masks_password_renders_and_submits() {
    let mut state = AppState::new(None, None, false);
    state.modal = Some(AuthModal::with_password_prompt(
        ModalPurpose::GrantCaps,
        "sudo setcap cap_net_admin,cap_net_raw+ep ./target/release/zapret-rs".to_owned(),
        true,
    ));

    for ch in "s3cr3t".chars() {
        assert_eq!(state.handle_key(key(KeyCode::Char(ch))), AppAction::None);
    }
    let screen = render_to_string(&state, 100, 30);
    assert!(screen.contains("Grant Network Capabilities"));
    assert!(screen.contains("******_"), "password must be masked as asterisks");
    assert!(!screen.contains("s3cr3t"), "plaintext password must never be rendered");

    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitModal);
    let modal = state.modal.as_mut().expect("modal still open until runner submits");
    assert_eq!(modal.take_password(), "s3cr3t");
    assert_eq!(modal.password_len(), 0, "take_password must clear internal buffer");
}

/// Verifies all three tabs render cleanly without panicking at standard (`120x36`) and compact (`80x24`) sizes.
#[test]
fn tui_renders_all_three_tabs_cleanly_in_headless_test_backend() {
    let mut state = AppState::new(None, None, false);
    state.domains_input = "example.com".to_owned();
    state.counters.total.store(99, Ordering::Relaxed);
    state.counters.passed.store(90, Ordering::Relaxed);
    state.counters.modified.store(7, Ordering::Relaxed);
    state.counters.dropped.store(2, Ordering::Relaxed);

    for &(w, h) in &[(120u16, 36u16), (80, 24)] {
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
        assert!(cfg_screen.contains("Temporary nftables Script"));
        assert!(cfg_screen.contains("table inet zapret_strat_finder {"));
        assert!(cfg_screen.contains("System & Privilege Diagnostics"));
    }
}

/// Verifies the compiled `zapret-rs` binary handles `--version` and `--help` cleanly without a TTY.
#[test]
fn zapret_rs_tui_binary_cli_version_and_help() {
    let bin = env!("CARGO_BIN_EXE_zapret-rs");

    let ver = Command::new(bin).arg("--version").output().expect("run zapret-rs --version");
    assert!(ver.status.success());
    assert_eq!(
        String::from_utf8_lossy(&ver.stdout).trim(),
        format!("zapret-rs {}", env!("CARGO_PKG_VERSION"))
    );

    let help = Command::new(bin).arg("--help").output().expect("run zapret-rs --help");
    assert!(help.status.success());
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--config"));
    assert!(help_text.contains("--lua-dir"));
    assert!(help_text.contains("--no-nft"));
}

/// Verifies live packet inspector decoding (HTTP Host, TCP flags, verdicts, hex dump),
/// filtering (`f`), pausing (`p`), and floating packet detail rendering (`d` / `Esc`).
#[test]
fn tui_packet_inspector_decodes_filters_pauses_and_renders_detail_modal() {
    let http_payload = b"GET / HTTP/1.1\r\nHost: store.steampowered.com\r\n\r\n".to_vec();
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4, header_len: 5, tos: 0, total_len: 0, id: 1, frag_off: 0,
            ttl: 64, protocol: IPPROTO_TCP, checksum: 0,
            src: [192, 168, 1, 10], dst: [104, 18, 2, 3], options: Vec::new(),
        }),
        ip6: None,
        tcp: Some(TcpHeader {
            s_port: 51234, d_port: 80, seq: 1000, ack: 2000, reserved: 0, data_offset: 5,
            flags: TH_PUSH | TH_ACK, window: 64240, checksum: 0, urgent_ptr: 0, options: Vec::new(),
        }),
        udp: None,
        icmp: None,
        payload: Some(http_payload),
        ..DissectedPacket::default()
    };
    let wire = reconstruct_packet(&dis, &ReconstructOptions::default()).expect("wire packet");
    let qpkt = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("eth0"), payload: &wire };

    let rec_drop = build_packet_record(1, &qpkt, &Decision::Drop);
    assert_eq!(rec_drop.direction, "OUT");
    assert_eq!(rec_drop.proto, "TCP");
    assert_eq!(rec_drop.src, "192.168.1.10:51234");
    assert_eq!(rec_drop.dst, "104.18.2.3:80");
    assert_eq!(rec_drop.verdict, PacketVerdict::Drop);
    assert!(rec_drop.info.contains("HTTP Host=store.steampowered.com"));

    let dump = format_hex_dump(&rec_drop.payload_preview);
    assert!(dump[0].starts_with("0000: 47 45 54 20"));
    assert!(dump[0].contains("|GET / HTTP/1.1"));

    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Run;
    state.inspector.push(rec_drop);
    // Push 400 `PASS` packets after the `DROP` packet to ensure high-volume `PASS` traffic never
    // evicts desynced packets from `MOD+DROP` / `DROP` views.
    for seq in 2..=401 {
        state.inspector.push(build_packet_record(seq, &qpkt, &Decision::Pass));
    }
    assert_eq!(state.inspector.packets.len(), 300);
    assert_eq!(state.inspector.desync_packets.len(), 1);

    // Filter to MOD+DROP -> packet #1 is still preserved and visible!
    assert_eq!(state.handle_key(key(KeyCode::Char('f'))), AppAction::None);
    assert_eq!(state.inspector.filter, VerdictFilter::ModifiedOrDropped);
    assert_eq!(state.inspector.selected_record().map(|r| r.seq), Some(1));

    // Pause capture -> subsequent pushed packets are ignored until resumed.
    assert_eq!(state.handle_key(key(KeyCode::Char('p'))), AppAction::None);
    assert!(state.inspector.paused);
    state.inspector.push(build_packet_record(500, &qpkt, &Decision::Drop));
    assert_eq!(state.inspector.desync_packets.len(), 1);

    // Open detail popup with 'd', verify it renders headers + hex dump, then close with Esc.
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::None);
    assert!(state.inspector.detail_open);
    let screen = render_to_string(&state, 110, 32);
    assert!(screen.contains("Packet #1 Detail [DROP]"));
    assert!(screen.contains("store.steampowered.com"));
    assert!(screen.contains("0000: 47 45 54 20"));

    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(!state.inspector.detail_open);
}

/// Verifies Tab 3 `e`/`Enter` triggers `AppAction::EditConfig`, starter TOML parses cleanly,
/// and invalid vs valid TOML updates the Config tab validation badge.
#[test]
fn config_tab_edit_action_and_toml_validation_badge() {
    let mut state = AppState::new(None, None, false);
    state.has_net_caps = true;
    state.tab = ActiveTab::Config;
    assert_eq!(state.handle_key(key(KeyCode::Char('e'))), AppAction::EditConfig);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::EditConfig);

    // Invalid TOML populates `toml_error` and displays `[INVALID:` on Tab 3.
    state.set_active_toml("qnum = [broken".to_owned());
    assert!(state.toml_error.is_some());
    assert!(state.parsed_profiles.is_empty());
    let bad_screen = render_to_string(&state, 120, 32);
    assert!(bad_screen.contains("[INVALID:"));

    // Valid starter TOML clears `toml_error` and renders `[VALID:`.
    let starter = zapret_rs::tui::editor::build_starter_toml(200, 0x4000_0000, "");
    state.set_active_toml(starter);
    assert!(state.toml_error.is_none());
    let ok_screen = render_to_string(&state, 120, 32);
    assert!(ok_screen.contains("[VALID:"));
    assert!(ok_screen.contains("[e/Enter] Edit ($EDITOR)"));
}
