//! Integration tests for Unix control socket server security, lifecycle, and fanout isolation.

use std::fs;
use std::io::BufReader;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::thread;
use std::time::{Duration, Instant};

use zapret_rs::control::{
    CONTROL_PROTOCOL_VERSION, ControlCommand, ControlErrorCode, ControlServer, ControlServerConfig,
    ControlServerError, DaemonStatusMeta, Request, Response, TelemetryHub, current_euid,
    read_message, write_message,
};
use zapret_rs::desync::PacketOutcome;
use zapret_rs::intercepter::QueuedPacket;
use zapret_rs::telemetry::{PacketCounters, build_packet_record};

fn temp_dir_path(label: &str) -> std::path::PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_ctl_{label}_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn sample_meta() -> DaemonStatusMeta {
    DaemonStatusMeta {
        version: "1.0.1".to_owned(),
        pid: std::process::id(),
        qnum: 200,
        fwmark: 0x4000_0000,
        intercept: false,
        profile_names: vec!["tls13:multisplit".to_owned()],
        config_path: None,
    }
}

fn sample_record(seq: u64, outcome: PacketOutcome) -> zapret_rs::telemetry::PacketRecord {
    let mut raw = vec![0u8; 40];
    raw[0] = 0x45;
    raw[3] = 40;
    raw[8] = 64;
    raw[9] = 6;
    raw[12..16].copy_from_slice(&[10, 0, 0, 1]);
    raw[16..20].copy_from_slice(&[1, 1, 1, 1]);
    raw[20..22].copy_from_slice(&44444u16.to_be_bytes());
    raw[22..24].copy_from_slice(&443u16.to_be_bytes());
    raw[32] = 0x50;
    raw[33] = 0x18;
    let qp = QueuedPacket { packet_id: seq as u32, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw };
    build_packet_record(seq, &qp, &outcome)
}

#[test]
fn socket_permissions_0600_handshake_status_and_clean_unlink() {
    let dir = temp_dir_path("mode0600");
    let sock = dir.join("control.sock");
    let counters = Arc::new(PacketCounters::default());
    counters.total.store(42, Ordering::Relaxed);
    let hub = TelemetryHub::new(counters, sample_meta(), 20);

    let srv = ControlServer::start(ControlServerConfig::new(sock.clone(), "1.0.1"), Arc::clone(&hub))
        .expect("start server");

    let mode = fs::symlink_metadata(&sock).expect("stat socket").permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "control socket must be created with 0600 mode");

    let mut client = UnixStream::connect(&sock).expect("connect");
    let mut reader = BufReader::new(client.try_clone().expect("clone"));

    // Commands before hello are rejected.
    write_message(&mut client, &Request::Status).expect("write status before hello");
    let first: Response = read_message(&mut reader).expect("read").expect("reply");
    assert!(matches!(first, Response::Error { code: ControlErrorCode::HandshakeRequired, .. }));

    write_message(&mut client, &Request::Hello { version: CONTROL_PROTOCOL_VERSION })
        .expect("write hello");
    let hello: Response = read_message(&mut reader).expect("read").expect("reply");
    assert!(matches!(hello, Response::HelloOk { version: CONTROL_PROTOCOL_VERSION, .. }));

    write_message(&mut client, &Request::Status).expect("write status");
    let status: Response = read_message(&mut reader).expect("read").expect("reply");
    match status {
        Response::Status(st) => {
            assert_eq!(st.qnum, 200);
            assert_eq!(st.counters.total, 42);
            assert_eq!(st.profile_names, vec!["tls13:multisplit".to_owned()]);
        }
        other => panic!("unexpected status reply: {other:?}"),
    }

    drop(reader);
    drop(client);
    srv.shutdown();
    assert!(!sock.exists(), "socket file must be unlinked on shutdown");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stale_socket_is_replaced_while_live_socket_and_symlink_fail() {
    let dir = temp_dir_path("stale_live");

    // 1. Stale socket created by a dead listener is replaced.
    let stale_sock = dir.join("stale.sock");
    let stale_listener = UnixListener::bind(&stale_sock).expect("bind stale");
    drop(stale_listener);
    let hub1 = TelemetryHub::new(Arc::new(PacketCounters::default()), sample_meta(), 20);
    let srv1 = ControlServer::start(ControlServerConfig::new(stale_sock.clone(), "1.0.1"), hub1)
        .expect("stale socket must be replaced");

    // 2. Active socket owned by `srv1` makes starting another server fail clearly.
    let hub2 = TelemetryHub::new(Arc::new(PacketCounters::default()), sample_meta(), 20);
    let err = ControlServer::start(ControlServerConfig::new(stale_sock.clone(), "1.0.1"), hub2)
        .err()
        .expect("live socket must fail startup");
    assert!(matches!(err, ControlServerError::AlreadyRunning(_)), "got {err}");
    srv1.shutdown();

    // 3. Symlink at socket path is refused.
    let target = dir.join("target.txt");
    fs::write(&target, b"keep").expect("write target");
    let link = dir.join("link.sock");
    symlink(&target, &link).expect("symlink");
    let hub3 = TelemetryHub::new(Arc::new(PacketCounters::default()), sample_meta(), 20);
    let sym_err = ControlServer::start(ControlServerConfig::new(link, "1.0.1"), hub3)
        .err()
        .expect("symlink must be refused");
    assert!(matches!(sym_err, ControlServerError::SymlinkNotAllowed(_)), "got {sym_err}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn unauthorized_peer_uid_is_closed_before_any_reply() {
    let dir = temp_dir_path("peeruid");
    let sock = dir.join("control.sock");
    let hub = TelemetryHub::new(Arc::new(PacketCounters::default()), sample_meta(), 20);

    let mut cfg = ControlServerConfig::new(sock.clone(), "1.0.1");
    cfg.expected_uid = Some(current_euid().wrapping_add(1));

    let srv = ControlServer::start(cfg, hub).expect("start server");
    let mut client = UnixStream::connect(&sock).expect("connect");
    client.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let _ = write_message(&mut client, &Request::Hello { version: CONTROL_PROTOCOL_VERSION });

    let mut reader = BufReader::new(client);
    match read_message::<_, Response>(&mut reader) {
        Ok(None) | Err(zapret_rs::control::CodecError::Io(_)) => {}
        other => panic!("unauthorized peer must receive zero replies, got {other:?}"),
    }

    srv.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn slow_subscriber_is_disconnected_without_blocking_healthy_clients_and_commands_route() {
    let dir = temp_dir_path("fanout");
    let sock = dir.join("control.sock");
    let hub = TelemetryHub::new(Arc::new(PacketCounters::default()), sample_meta(), 20);

    let mut cfg = ControlServerConfig::new(sock.clone(), "1.0.1");
    cfg.client_queue_cap = 32;
    cfg.client_sndbuf = Some(4096);
    let srv = ControlServer::start(cfg, Arc::clone(&hub)).expect("start server");

    // Slow client subscribes then stops reading completely.
    let mut slow = UnixStream::connect(&sock).expect("connect slow");
    let mut slow_reader = BufReader::new(slow.try_clone().expect("clone slow"));
    write_message(&mut slow, &Request::Hello { version: CONTROL_PROTOCOL_VERSION }).expect("hello slow");
    assert!(matches!(read_message::<_, Response>(&mut slow_reader).expect("r"), Some(Response::HelloOk { .. })));
    write_message(&mut slow, &Request::Subscribe { pass_sample_rate: None }).expect("sub slow");
    assert!(matches!(read_message::<_, Response>(&mut slow_reader).expect("r"), Some(Response::Ack { .. })));
    assert!(matches!(read_message::<_, Response>(&mut slow_reader).expect("r"), Some(Response::Counters(_))));

    // Fast client subscribes and drains packets on a reader thread.
    let mut fast = UnixStream::connect(&sock).expect("connect fast");
    let mut fast_reader = BufReader::new(fast.try_clone().expect("clone fast"));
    write_message(&mut fast, &Request::Hello { version: CONTROL_PROTOCOL_VERSION }).expect("hello fast");
    assert!(matches!(read_message::<_, Response>(&mut fast_reader).expect("r"), Some(Response::HelloOk { .. })));
    write_message(&mut fast, &Request::Subscribe { pass_sample_rate: None }).expect("sub fast");
    assert!(matches!(read_message::<_, Response>(&mut fast_reader).expect("r"), Some(Response::Ack { .. })));
    assert!(matches!(read_message::<_, Response>(&mut fast_reader).expect("r"), Some(Response::Counters(_))));

    fast.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let fast_thread = thread::spawn(move || {
        let mut received = 0usize;
        while let Ok(Some(resp)) = read_message::<_, Response>(&mut fast_reader) {
            if matches!(resp, Response::Packet(_)) {
                received += 1;
                if received >= 100 {
                    break;
                }
            }
        }
        received
    });

    // Pump non-PASS records so slow client fills socket buffer + 32-slot queue while fast drains.
    for seq in 1..=350u64 {
        hub.publish_packet(sample_record(seq, PacketOutcome::Desync(Some("p".to_owned()))));
        if seq.is_multiple_of(8) {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let got = fast_thread.join().expect("fast reader");
    assert!(got >= 100, "healthy subscriber must keep receiving packets (got {got})");
    // Slow client must eventually hit EOF or reset once its queued bytes drain.
    slow.set_read_timeout(Some(Duration::from_secs(2))).expect("slow timeout");
    let mut saw_disconnect = false;
    for _ in 0..350 {
        match read_message::<_, Response>(&mut slow_reader) {
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => {
                saw_disconnect = true;
                break;
            }
        }
    }
    assert!(saw_disconnect, "stalled subscriber must be disconnected cleanly");

    // Verify command forwarding works end to end from a healthy authenticated client.
    let mut cmd_client = UnixStream::connect(&sock).expect("connect cmd client");
    let mut cmd_reader = BufReader::new(cmd_client.try_clone().expect("clone cmd client"));
    cmd_client.set_read_timeout(Some(Duration::from_secs(2))).expect("cmd timeout");
    write_message(&mut cmd_client, &Request::Hello { version: CONTROL_PROTOCOL_VERSION })
        .expect("hello cmd");
    assert!(matches!(
        read_message::<_, Response>(&mut cmd_reader).expect("hello reply"),
        Some(Response::HelloOk { .. })
    ));

    let cmd_hub = Arc::clone(&hub);
    let responder = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(cmd) = cmd_hub.try_recv_command() {
                match cmd {
                    ControlCommand::ReloadLists { reply } => {
                        let _ = reply.send(Ok("reloaded 1 list".to_owned()));
                        break;
                    }
                    ControlCommand::Stop { reply } => {
                        let _ = reply.send(Ok("stopping".to_owned()));
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(5));
        }
    });

    write_message(&mut cmd_client, &Request::ReloadLists).expect("reload_lists");
    match read_message::<_, Response>(&mut cmd_reader).expect("read reply") {
        Some(Response::Ack { op, message }) if op == "reload_lists" => {
            assert_eq!(message.as_deref(), Some("reloaded 1 list"));
        }
        other => panic!("unexpected response after reload_lists: {other:?}"),
    }
    responder.join().expect("responder");

    drop(cmd_client);
    drop(slow);
    drop(fast);
    srv.shutdown();
    let _ = fs::remove_dir_all(&dir);
}
