//! Integration tests for mouse click and scroll-wheel handling across all TUI tabs.

/// Mouse event construction for driving [`handle_mouse_event`].
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
/// Terminal frame bounds matching `ratatui::TestBackend` test dimensions.
use ratatui::layout::Rect;

/// Shared packet snapshot type used when testing Tab 2 packet selection by click.
use zapret_rs::telemetry::{PacketRecord, PacketVerdict};
/// Tab 4 sample builders for testing Speed Test table clicks and wheel scrolls.
use zapret_rs::tools::{ProbeOutcome, SpeedSample, control_target, domain_target};
/// Mouse handler under test.
use zapret_rs::tui::mouse::handle_mouse_event;
/// TUI state, tab, and panel focus enums under test.
use zapret_rs::tui::types::{ActiveTab, ConfigFocus, FinderField, FinderFocus, RunFocus};
use zapret_rs::tui::{AppState, speed::Side};

/// Standard 120x32 terminal area used across headless mouse tests.
const AREA: Rect = Rect { x: 0, y: 0, width: 120, height: 32 };

/// Builds a synthetic left mouse button down event at `(x, y)`.
fn click(x: u16, y: u16) -> MouseEvent {
    MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column: x, row: y, modifiers: KeyModifiers::NONE }
}

/// Builds a synthetic mouse scroll event at `(x, y)`.
fn scroll(x: u16, y: u16, down: bool) -> MouseEvent {
    let kind = if down { MouseEventKind::ScrollDown } else { MouseEventKind::ScrollUp };
    MouseEvent { kind, column: x, row: y, modifiers: KeyModifiers::NONE }
}

/// Builds a dummy packet record for Tab 2 inspector mouse tests.
fn dummy_pkt(seq: u64) -> PacketRecord {
    PacketRecord {
        seq,
        direction: "OUT".to_owned(),
        proto: "TCP".to_owned(),
        src: "10.0.0.2:5000".to_owned(),
        dst: "1.1.1.1:443".to_owned(),
        ttl: 64,
        fwmark: 0,
        iface: "eth0".to_owned(),
        payload_len: 100,
        tcp_detail: None,
        info: "TLS SNI=example.org".to_owned(),
        verdict: PacketVerdict::Desync,
        profile: Some("tls".to_owned()),
        payload_preview: Vec::new(),
    }
}

#[test]
fn mouse_clicks_switch_header_tabs_and_trigger_footer_help_and_theme() {
    let mut state = AppState::new(None, None, false);
    assert_eq!(state.tab, ActiveTab::Finder);

    // Header row y = 1: tabs at x=1 (Finder), 24 (Run), 42 (Config), 62 (Speed).
    handle_mouse_event(&mut state, click(26, 1), AREA);
    assert_eq!(state.tab, ActiveTab::Run);
    handle_mouse_event(&mut state, click(45, 1), AREA);
    assert_eq!(state.tab, ActiveTab::Config);
    handle_mouse_event(&mut state, click(64, 1), AREA);
    assert_eq!(state.tab, ActiveTab::Speed);
    handle_mouse_event(&mut state, click(3, 1), AREA);
    assert_eq!(state.tab, ActiveTab::Finder);

    // Footer row y = 31: `[t] <theme>` around x = 12, `[?] Keys` at x = 3.
    let prev_theme = state.theme.name;
    handle_mouse_event(&mut state, click(12, 31), AREA);
    assert_ne!(state.theme.name, prev_theme);

    handle_mouse_event(&mut state, click(3, 31), AREA);
    assert!(state.help_open);
    handle_mouse_event(&mut state, click(3, 31), AREA);
    assert!(!state.help_open);
}

#[test]
fn mouse_interacts_with_finder_run_config_and_speed_panels() {
    let mut state = AppState::new(None, None, false);

    // Tab 1: click ProtoHttp row (body starts at y=3, inner row 0=y=4 -> ProtoHttp is y=5).
    assert!(state.finder.proto_http);
    handle_mouse_event(&mut state, click(10, 5), AREA);
    assert_eq!(state.focused_field(), FinderField::ProtoHttp);
    assert!(!state.finder.proto_http);

    // Tab 1 right-bottom Live Scan Log scroll wheel focuses Log and increments offset.
    for i in 0..8 {
        state.push_finder_log(format!("line {i}"));
    }
    handle_mouse_event(&mut state, scroll(80, 26, false), AREA);
    assert_eq!(state.focus.finder, FinderFocus::Log);
    assert_eq!(state.focus.finder_log_scroll, 3);

    // Tab 2: inspector rows start at y = 3(body)+7(ctrl)+3(metrics)+2(border+hdr) = 15.
    state.tab = ActiveTab::Run;
    state.inspector.push(dummy_pkt(1));
    state.inspector.push(dummy_pkt(2));
    handle_mouse_event(&mut state, click(20, 16), AREA);
    assert_eq!(state.focus.run, RunFocus::Inspector);
    assert_eq!(state.inspector.selected, 1);
    // Clicking already-selected row opens detail; next click closes it.
    handle_mouse_event(&mut state, click(20, 16), AREA);
    assert!(state.inspector.detail_open);
    handle_mouse_event(&mut state, click(20, 16), AREA);
    assert!(!state.inspector.detail_open);

    // Tab 3: scroll wheel in left TOML, top-right nft, bottom-right AutoHostlist focuses & scrolls.
    state.tab = ActiveTab::Config;
    handle_mouse_event(&mut state, scroll(20, 10, true), AREA);
    assert_eq!((state.focus.config, state.config.toml_scroll), (ConfigFocus::Toml, 3));
    handle_mouse_event(&mut state, scroll(90, 10, true), AREA);
    assert_eq!((state.focus.config, state.focus.nft_scroll), (ConfigFocus::Nft, 3));
    handle_mouse_event(&mut state, scroll(90, 25, true), AREA);
    assert_eq!((state.focus.config, state.focus.autolist_scroll), (ConfigFocus::AutoHostlist, 3));

    // Tab 4: click row 1 in Comparison Table (y = 3(body)+4(hdr)+2(border+table_hdr) + 1 = 10).
    state.tab = ActiveTab::Speed;
    state.speed.start(&[domain_target("example.com"), control_target()]);
    state.speed.record(
        Side::Before,
        0,
        SpeedSample {
            outcome: ProbeOutcome::Timeout,
            connect_ms: 0,
            ttfb_ms: 0,
            bytes_per_sec: 0,
        },
    );
    handle_mouse_event(&mut state, click(20, 10), AREA);
    assert_eq!(state.speed.selected, 1);
    handle_mouse_event(&mut state, scroll(20, 10, false), AREA);
    assert_eq!(state.speed.selected, 0);
}
