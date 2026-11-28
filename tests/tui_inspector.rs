//! TUI packet inspector, Config tab validation, multicall CLI dispatch, and firewall preview tests.

#![cfg(feature = "tui")]

/// Subprocess checks for the compiled `zapret-rs` binary (`--version`, `--help`, symlinks).
use std::process::Command;

/// Synthetic keyboard events driven through [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless in-memory `ratatui` terminal backend for deterministic UI rendering tests.
use ratatui::{Terminal, backend::TestBackend};

/// Packet outcome classification used to test `REASM` vs `DESYNC` inspector badges.
use zapret_rs::desync::PacketOutcome;
/// Packet interception types used to test live packet inspector decoding.
use zapret_rs::intercepter::QueuedPacket;
/// Wire packet builders used to construct realistic IPv4+TCP HTTP packets.
use zapret_rs::packet::{
    DissectedPacket, IPPROTO_TCP, Ipv4Header, ReconstructOptions, TH_ACK, TH_PUSH, TcpHeader,
    reconstruct_packet,
};
/// TUI state, packet inspector, frame renderer, and action/verdict enums under test.
use zapret_rs::tui::{
    ActiveTab, AppAction, AppState, PacketVerdict, VerdictFilter, build_packet_record, draw_app,
    format_hex_dump,
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

/// Verifies the compiled `zapret-rs` binary handles `--version` and `--help` cleanly without a TTY.
#[test]
fn zapret_rs_tui_binary_cli_version_and_help()
{
    let bin = env!("CARGO_BIN_EXE_zapret-rs");

    let ver = Command::new(bin)
        .arg("--version")
        .output()
        .expect("run zapret-rs --version");
    assert!(
        ver.status
            .success()
    );
    assert_eq!(
        String::from_utf8_lossy(&ver.stdout).trim(),
        format!("zapret-rs {}", env!("CARGO_PKG_VERSION"))
    );

    let help = Command::new(bin)
        .arg("--help")
        .output()
        .expect("run zapret-rs --help");
    assert!(
        help.status
            .success()
    );
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(help_text.contains("--config"));
    assert!(help_text.contains("--lua-dir"));
    assert!(help_text.contains("--no-nft"));
}

/// Builds a synthetic outbound HTTP packet and checks decoded inspector record and hex dump fields.
fn build_and_verify_sample_http_packet() -> (Vec<u8>, zapret_rs::telemetry::PacketRecord)
{
    let http_payload = b"GET / HTTP/1.1\r\nHost: store.steampowered.com\r\n\r\n".to_vec();
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 1,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: [192, 168, 1, 10],
            dst: [104, 18, 2, 3],
            options: Vec::new(),
        }),
        ip6: None,
        tcp: Some(TcpHeader {
            s_port: 51234,
            d_port: 80,
            seq: 1000,
            ack: 2000,
            reserved: 0,
            data_offset: 5,
            flags: TH_PUSH | TH_ACK,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        udp: None,
        icmp: None,
        payload: Some(http_payload),
        ..DissectedPacket::default()
    };
    let wire = reconstruct_packet(&dis, &ReconstructOptions::default()).expect("wire packet");
    let qpkt = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("eth0"), payload: &wire };

    let desync_outcome = PacketOutcome::Desync(Some("tls13:ipv4:multisplit:2".to_owned()));
    let rec_desync = build_packet_record(1, &qpkt, &desync_outcome);
    assert_eq!(rec_desync.direction, "OUT");
    assert_eq!(rec_desync.proto, "TCP");
    assert_eq!(rec_desync.src, "192.168.1.10:51234");
    assert_eq!(rec_desync.dst, "104.18.2.3:80");
    assert_eq!(rec_desync.verdict, PacketVerdict::Desync);
    assert_eq!(
        rec_desync
            .profile
            .as_deref(),
        Some("tls13:ipv4:multisplit:2")
    );
    assert!(
        rec_desync
            .info
            .contains("HTTP Host=store.steampowered.com")
    );
    assert!(
        rec_desync
            .info
            .contains("(tls13:ipv4:multisplit:2)")
    );

    let dump = format_hex_dump(&rec_desync.payload_preview);
    assert!(dump[0].starts_with("0000: 47 45 54 20"));
    assert!(dump[0].contains("|GET / HTTP/1.1"));
    (wire, rec_desync)
}

/// Seeds 400 `PASS` and 1 `REASM` packet onto `state.inspector` and verifies ring-buffer retention.
fn seed_and_verify_inspector_buffers(
    state: &mut AppState,
    qpkt: &QueuedPacket<'_>,
    rec_desync: zapret_rs::telemetry::PacketRecord,
)
{
    state
        .inspector
        .push(rec_desync);
    state
        .inspector
        .push(build_packet_record(2, qpkt, &PacketOutcome::Reasm));
    for seq in 3..=402
    {
        state
            .inspector
            .push(build_packet_record(seq, qpkt, &PacketOutcome::Pass));
    }
    assert_eq!(
        state
            .inspector
            .packets
            .len(),
        300
    );
    assert_eq!(
        state
            .inspector
            .desync_packets
            .len(),
        1
    );
    assert_eq!(
        state
            .inspector
            .reasm_packets
            .len(),
        1
    );
}

/// Verifies opening and dismissing the packet detail modal via `d` and `Esc`.
fn assert_inspector_detail_modal(state: &mut AppState)
{
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::None);
    assert!(
        state
            .inspector
            .detail_open
    );
    let screen = render_to_string(state, 110, 32);
    for expected in [
        "Packet #1 Detail [DESYNC]",
        "Profile : tls13:ipv4:multisplit:2",
        "store.steampowered.com",
        "0000: 47 45 54 20",
    ]
    {
        assert!(screen.contains(expected), "missing '{expected}' in detail modal");
    }

    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(
        !state
            .inspector
            .detail_open
    );
}

/// Verifies live packet inspector filtering (`f`), pausing (`p`), and detail rendering (`d` / `Esc`).
#[test]
fn tui_packet_inspector_decodes_filters_pauses_and_renders_detail_modal()
{
    let (wire, rec_desync) = build_and_verify_sample_http_packet();
    let qpkt = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("eth0"), payload: &wire };
    let desync_outcome = PacketOutcome::Desync(Some("tls13:ipv4:multisplit:2".to_owned()));

    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Run;
    seed_and_verify_inspector_buffers(&mut state, &qpkt, rec_desync);

    assert_eq!(state.handle_key(key(KeyCode::Char('f'))), AppAction::None);
    assert_eq!(
        state
            .inspector
            .filter,
        VerdictFilter::DesyncOnly
    );
    assert_eq!(
        state
            .inspector
            .selected_record()
            .map(|r| r.seq),
        Some(1)
    );

    assert_eq!(state.handle_key(key(KeyCode::Char('p'))), AppAction::None);
    assert!(
        state
            .inspector
            .paused
    );
    state
        .inspector
        .push(build_packet_record(500, &qpkt, &desync_outcome));
    assert_eq!(
        state
            .inspector
            .desync_packets
            .len(),
        1
    );

    assert_inspector_detail_modal(&mut state);

    assert_eq!(state.handle_key(key(KeyCode::Char('f'))), AppAction::None);
    assert_eq!(
        state
            .inspector
            .filter,
        VerdictFilter::ReasmOnly
    );
    assert_eq!(
        state
            .inspector
            .selected_record()
            .map(|r| r.seq),
        Some(2)
    );
}

/// Verifies Tab 3 `e`/`Enter` triggers `AppAction::EditConfig`, starter TOML parses cleanly,
/// and invalid vs valid TOML updates the Config tab validation badge.
#[test]
fn config_tab_edit_action_and_toml_validation_badge()
{
    let mut state = AppState::new(None, None, false);
    state
        .status
        .has_net_caps = true;
    state.tab = ActiveTab::Config;
    assert_eq!(state.handle_key(key(KeyCode::Char('e'))), AppAction::EditConfig);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::EditConfig);

    state.set_active_toml("qnum = [broken".to_owned());
    assert!(
        state
            .config
            .toml_error
            .is_some()
    );
    assert!(
        state
            .config
            .parsed_profiles
            .is_empty()
    );
    let bad_screen = render_to_string(&state, 120, 32);
    assert!(bad_screen.contains("[INVALID:"));

    let starter = zapret_rs::tui::editor::build_starter_toml(200, 0x4000_0000, "");
    state.set_active_toml(starter);
    assert!(
        state
            .config
            .toml_error
            .is_none()
    );
    let ok_screen = render_to_string(&state, 120, 32);
    assert!(ok_screen.contains("[VALID:") && ok_screen.contains("[?] Keys"));
    state.handle_key(key(KeyCode::Char('?')));
    let help_screen = render_to_string(&state, 120, 32);
    assert!(
        help_screen.contains("Keybindings")
            && help_screen.contains("[?]")
            && help_screen.contains("[e/Enter] Edit ($EDITOR)")
    );
    state.handle_key(key(KeyCode::Esc));
    assert!(!state.help_open);
}

/// Verifies `zapret-rs` routes both explicit subcommands and `argv[0]` symlinks to each applet.
#[test]
fn zapret_rs_multicall_subcommands_and_symlink_dispatch()
{
    let bin = env!("CARGO_BIN_EXE_zapret-rs");

    for (sub, expected_ver) in
        [("daemon", "nfqws2"), ("scan", "strat_finder"), ("ip2net", "ip2net"), ("mdig", "mdig")]
    {
        let out = Command::new(bin)
            .args([sub, "--version"])
            .output()
            .expect("subcommand --version");
        assert!(
            out.status
                .success(),
            "{sub} --version failed: {out:?}"
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains(expected_ver), "{sub} version output mismatch: {stdout}");
    }

    #[cfg(unix)]
    {
        let dir = std::env::temp_dir().join(format!("zapret-rs-sym-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create symlink temp dir");
        for name in ["nfqws2", "ip2net", "mdig", "strat_finder"]
        {
            let link = dir.join(name);
            std::os::unix::fs::symlink(bin, &link).expect("symlink applet");
            let out = Command::new(&link)
                .arg("--version")
                .output()
                .expect("run symlinked applet");
            assert!(
                out.status
                    .success(),
                "{name} symlink --version failed: {out:?}"
            );
            let stdout = String::from_utf8_lossy(&out.stdout);
            assert!(stdout.contains(name), "{name} symlink stdout mismatch: {stdout}");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Verifies OS firewall backends own their Tab 3 panel titles, filter previews, and unsupported fallback.
#[test]
fn firewall_backends_supply_distinct_preview_titles_and_unsupported_error()
{
    use zapret_rs::tools::{
        FirewallBackend, NftFirewallBackend, UnsupportedFirewallBackend, active_firewall_backend,
    };

    let nft = NftFirewallBackend::default();
    assert_eq!(nft.preview_title(), " Temporary nftables Script ");
    assert!(
        nft.preview_filter(200, 0x4000_0000, &[443], &[])
            .contains("queue num 200")
    );

    let unsupported = UnsupportedFirewallBackend;
    assert_eq!(unsupported.preview_title(), " Packet Filter Preview ");
    assert!(
        unsupported
            .preview_filter(200, 0x4000_0000, &[443], &[])
            .contains("not implemented")
    );
    let Err(err) = unsupported.install(200, 0x4000_0000, &[443], &[])
    else
    {
        panic!("unsupported backend should not install firewall rules");
    };
    assert_eq!(err.kind(), std::io::ErrorKind::Unsupported);

    let active = active_firewall_backend();
    #[cfg(target_os = "linux")]
    assert_eq!(active.preview_title(), " Temporary nftables Script ");
    #[cfg(windows)]
    assert_eq!(active.preview_title(), " WinDivert Filter ");
}
