//! Integration tests for TUI control-socket attach mode, remote telemetry, modals, and errors.

#![cfg(feature = "tui")]

use std::fs;
use std::io::BufReader;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use zapret_rs::control::{
    CONTROL_PROTOCOL_VERSION, ControlCommand, ControlErrorCode, ControlServer, ControlServerConfig,
    DaemonStatusMeta, Request, Response, TelemetryHub, read_message, write_message,
};
use zapret_rs::desync::PacketOutcome;
use zapret_rs::intercepter::QueuedPacket;
use zapret_rs::telemetry::{PacketCounters, PacketVerdict, build_packet_record};
use zapret_rs::tui::remote::RemoteEvent;
use zapret_rs::tui::{
    ActiveTab, AppAction, AppState, ModalPurpose, RunStatus, connect_remote_daemon,
    detect_control_socket, draw_app,
};

fn temp_dir_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_tui_attach_{label}_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

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

fn sample_pkt(seq: u64, outcome: PacketOutcome) -> zapret_rs::telemetry::PacketRecord {
    let mut raw = vec![0u8; 40];
    raw[0] = 0x45;
    raw[3] = 40;
    raw[8] = 64;
    raw[9] = 6;
    raw[12..16].copy_from_slice(&[192, 168, 1, 23]);
    raw[16..20].copy_from_slice(&[93, 184, 216, 34]);
    raw[20..22].copy_from_slice(&51234u16.to_be_bytes());
    raw[22..24].copy_from_slice(&443u16.to_be_bytes());
    raw[32] = 0x50;
    raw[33] = 0x18;
    let qp = QueuedPacket { packet_id: seq as u32, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw };
    build_packet_record(seq, &qp, &outcome)
}

#[test]
fn attach_streams_telemetry_renders_attached_handles_keys_and_disconnect() {
    let dir = temp_dir_path("attach");
    let sock = dir.join("control.sock");
    let daemon_counters = Arc::new(PacketCounters::default());
    daemon_counters.total.store(10, Ordering::Relaxed);
    daemon_counters.desynced.store(2, Ordering::Relaxed);

    let meta = DaemonStatusMeta {
        version: "1.0.1".to_owned(),
        pid: 99123,
        qnum: 205,
        fwmark: 0x4000_0000,
        intercept: true,
        profile_names: vec!["tls13:multisplit:2".to_owned()],
        config_path: Some("/etc/zapret-rs/nfqws2.toml".to_owned()),
    };
    let hub = TelemetryHub::new(Arc::clone(&daemon_counters), meta, 20);
    let srv = ControlServer::start(ControlServerConfig::new(sock.clone(), "1.0.1"), Arc::clone(&hub))
        .expect("start server");

    assert_eq!(detect_control_socket(Some(&sock)), Some(sock.clone()));

    let mut state = AppState::new(None, None, false);
    state.has_net_caps = false; // Unprivileged TUI can attach without caps.
    state.tab = ActiveTab::Run;

    let (mut attached, rmeta) =
        connect_remote_daemon(sock.clone(), Arc::clone(&state.counters)).expect("attach");
    assert_eq!(rmeta.pid, 99123);
    assert_eq!(rmeta.qnum, 205);
    state.set_attached(rmeta);
    assert_eq!(state.counters.snapshot().0, 10);

    // Stream REASM and DESYNC packets from the daemon hub into TUI channels.
    hub.publish_packet(sample_pkt(11, PacketOutcome::Reasm));
    hub.publish_packet(sample_pkt(12, PacketOutcome::Desync(Some("tls13:multisplit:2".to_owned()))));

    let deadline = Instant::now() + Duration::from_secs(2);
    let mut got_reasm = false;
    let mut got_desync = false;
    while Instant::now() < deadline && !(got_reasm && got_desync) {
        while let Some(rec) = attached.try_recv_desync() {
            if rec.verdict == PacketVerdict::Reasm {
                got_reasm = true;
            }
            if rec.verdict == PacketVerdict::Desync {
                got_desync = true;
            }
            state.inspector.push(rec);
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(got_reasm && got_desync, "expected both REASM and DESYNC records in attach stream");

    let screen = render_to_string(&state, 120, 36);
    assert!(screen.contains("ATTACHED"), "header/controller must show ATTACHED");
    assert!(screen.contains("PID 99123"), "must show remote daemon PID");
    assert!(screen.contains("tls13:multisplit:2"));
    assert!(screen.contains("REASM") && screen.contains("DESYNC"));
    assert!(screen.contains("[x] Detach") && screen.contains("[S] Stop Daemon"));

    // Keys on Tab 2 in Attached state: 'l' reloads remote lists, 'x' detaches, 'S' confirms stop.
    assert_eq!(state.handle_key(key(KeyCode::Char('l'))), AppAction::ReloadRemoteLists);
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::DetachDaemon);

    assert_eq!(state.handle_key(key(KeyCode::Char('S'))), AppAction::None);
    let modal = state.modal.as_ref().expect("'S' must open ConfirmStopDaemon popup");
    assert_eq!(modal.purpose, ModalPurpose::ConfirmStopDaemon);
    let popup_screen = render_to_string(&state, 120, 36);
    assert!(popup_screen.contains("Confirm Stop Daemon"));
    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(state.modal.is_none());

    assert_eq!(state.handle_key(key(KeyCode::Char('S'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitModal);

    // Send a stop command through `AttachedDaemon` and see the hub receive it.
    attached.send_command(&Request::Stop).expect("send stop");
    let cmd_deadline = Instant::now() + Duration::from_secs(2);
    let mut saw_stop = false;
    while Instant::now() < cmd_deadline {
        if let Some(ControlCommand::Stop { reply }) = hub.try_recv_command() {
            let _ = reply.send(Ok("stopping".to_owned()));
            saw_stop = true;
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    assert!(saw_stop, "server hub must forward Stop command");

    // Shutting down server simulates connection loss -> reader emits Disconnected without panic.
    srv.shutdown();
    let mut saw_dc = None;
    let dc_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < dc_deadline {
        if let Some(RemoteEvent::Disconnected(reason)) = attached.try_recv_event() {
            saw_dc = Some(reason);
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(saw_dc.is_some(), "reader must report Disconnected when server shuts down");
    state.set_detached(
        "[error] control connection lost".to_owned(),
        "Control connection lost".to_owned(),
    );
    assert_eq!(state.run_status, RunStatus::Stopped);

    attached.detach();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn attach_reports_readable_error_on_protocol_version_mismatch() {
    let dir = temp_dir_path("mismatch");
    let sock = dir.join("fake.sock");
    let listener = UnixListener::bind(&sock).expect("bind fake server");

    let srv_thread = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let req: Option<Request> = read_message(&mut reader).expect("read hello");
        assert!(matches!(req, Some(Request::Hello { version: CONTROL_PROTOCOL_VERSION })));
        write_message(
            &mut stream,
            &Response::Error {
                code: ControlErrorCode::UnsupportedVersion,
                message: "server supports version 99".to_owned(),
            },
        )
        .expect("write version error");
    });

    let counters = Arc::new(PacketCounters::default());
    let err = connect_remote_daemon(sock, counters)
        .err()
        .expect("version mismatch must fail");
    assert!(err.contains("mismatch") && err.contains("99"), "got unreadable error: {err}");

    srv_thread.join().expect("fake server join");
    let _ = fs::remove_dir_all(&dir);
}
