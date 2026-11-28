//! Unit tests for Tab 2 Packet Inspector advanced `/` query filtering.

/// Keyboard events and key codes used to drive [`PacketInspectorState::handle_key_with_binds`].
use crossterm::event::{KeyCode, KeyEvent};

/// Shared packet snapshot and outcome classification types.
use zapret_rs::telemetry::{PacketRecord, PacketVerdict};
/// Default keymap passed into inspector key handler tests.
use zapret_rs::tui::Keybinds;
/// Packet inspector state, verdict filter, and query matcher under test.
use zapret_rs::tui::inspect::{PacketInspectorState, VerdictFilter, matches_query};

/// Sends one unmodified key press to `insp` using the default keybinding map.
fn send_key(insp: &mut PacketInspectorState, code: KeyCode) -> Option<String>
{
    insp.handle_key_with_binds(KeyEvent::from(code), &Keybinds::default())
}

/// Builds a synthetic [`PacketRecord`] for filter unit tests (`flow = (dir, proto, src, dst)`).
fn sample_pkt(
    seq: u64,
    flow: (&str, &str, &str, &str),
    verdict: PacketVerdict,
    info: &str,
    profile: Option<&str>,
) -> PacketRecord
{
    let (dir, proto, src, dst) = flow;
    PacketRecord {
        seq,
        direction: dir.to_owned(),
        proto: proto.to_owned(),
        src: src.to_owned(),
        dst: dst.to_owned(),
        ttl: 64,
        fwmark: 0,
        iface: "eth0".to_owned(),
        payload_len: 120,
        tcp_detail: None,
        info: info.to_owned(),
        verdict,
        profile: profile.map(str::to_owned),
        payload_preview: Vec::new(),
    }
}

#[test]
fn matches_query_supports_bare_terms_field_prefixes_and_negation()
{
    let tls_desync = sample_pkt(
        1,
        ("OUT", "TCP", "10.0.0.2:51000", "1.1.1.1:443"),
        PacketVerdict::Desync,
        "TLS SNI=youtube.com",
        Some("tls-split"),
    );
    let quic_pass = sample_pkt(
        2,
        ("OUT", "UDP", "10.0.0.2:52000", "8.8.8.8:443"),
        PacketVerdict::Pass,
        "QUIC Initial",
        None,
    );
    let dns_in = sample_pkt(
        3,
        ("IN", "UDP", "8.8.8.8:53", "10.0.0.2:41000"),
        PacketVerdict::Pass,
        "DNS response",
        None,
    );

    assert!(matches_query(&tls_desync, ""));
    assert!(matches_query(&tls_desync, "youtube"));
    assert!(matches_query(&tls_desync, "proto:tcp port:443 dir:out"));
    assert!(matches_query(&tls_desync, "profile:tls-split v:desync"));
    assert!(!matches_query(&tls_desync, "!youtube"));
    assert!(!matches_query(&quic_pass, "proto:tcp"));
    assert!(matches_query(&quic_pass, "port:443 !proto:tcp"));
    assert!(matches_query(&dns_in, "dir:in port:53 host:8.8.8.8"));
    assert!(!matches_query(&dns_in, "port:443"));
}

#[test]
fn inspector_slash_key_edits_applies_and_clears_query_with_verdict_filter()
{
    let mut insp = PacketInspectorState::default();
    insp.push(sample_pkt(
        1,
        ("OUT", "TCP", "10.0.0.2:50000", "1.1.1.1:443"),
        PacketVerdict::Desync,
        "TLS SNI=example.org",
        Some("yt"),
    ));
    insp.push(sample_pkt(
        2,
        ("OUT", "TCP", "10.0.0.2:50001", "9.9.9.9:80"),
        PacketVerdict::Desync,
        "HTTP Host=blocked.test",
        Some("http"),
    ));
    insp.push(sample_pkt(
        3,
        ("OUT", "UDP", "10.0.0.2:50002", "8.8.8.8:443"),
        PacketVerdict::Pass,
        "QUIC Initial",
        None,
    ));

    assert_eq!(insp.visible_packets().len(), 3);
    assert!(send_key(&mut insp, KeyCode::Char('/')).is_some());
    assert!(insp.filter_editing);

    for ch in "port:443".chars()
    {
        send_key(&mut insp, KeyCode::Char(ch));
    }
    assert_eq!(insp.filter_query, "port:443");
    assert_eq!(insp.visible_packets().len(), 2);

    send_key(&mut insp, KeyCode::Enter);
    assert!(!insp.filter_editing);
    assert_eq!(insp.visible_packets().len(), 2);

    // Combine query with VerdictFilter (`f` -> DesyncOnly).
    send_key(&mut insp, KeyCode::Char('f'));
    assert_eq!(insp.filter, VerdictFilter::DesyncOnly);
    let hits = insp.visible_packets();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].seq, 1);

    // Re-open with `/` and press Esc to clear the query.
    send_key(&mut insp, KeyCode::Char('/'));
    send_key(&mut insp, KeyCode::Esc);
    assert!(!insp.filter_editing);
    assert!(insp.filter_query.is_empty());
    assert_eq!(insp.visible_packets().len(), 2);
}

#[test]
fn app_state_guards_global_keys_during_filter_editing_and_renders_query_in_title()
{
    use crossterm::event::{KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use zapret_rs::tui::{AppAction, AppState, draw_app, types::ActiveTab};

    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Run;

    // Enter `/` filter edit mode and type characters that collide with global bindings (`q`, `t`, `?`, `1`).
    assert_eq!(state.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE)), AppAction::None);
    assert!(state.inspector.filter_editing);
    for ch in "qt?1".chars()
    {
        assert_eq!(state.handle_key(KeyEvent::new(KeyCode::Char(ch), KeyModifiers::NONE)), AppAction::None);
    }
    assert_eq!(state.tab, ActiveTab::Run);
    assert!(!state.help_open);
    assert_eq!(state.inspector.filter_query, "qt?1");

    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| draw_app(f, &state)).expect("draw");
    let rendered: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(rendered.contains("/: qt?1_"), "expected active filter cursor in title");
}
