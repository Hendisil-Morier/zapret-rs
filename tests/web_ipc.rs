//! Integration tests bridging `ControlServer` daemon IPC to `zapret-rs web` HTTP/SSE routes.
#![cfg(unix)]

/// Buffered SSE stream reader verifying incremental event delivery over HTTP.
use std::io::{BufRead, BufReader, Read, Write};
/// Loopback HTTP client sockets.
use std::net::{SocketAddr, TcpStream};
/// Shared telemetry hub and graceful test thread shutdown flags.
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
/// Command handler thread spawning and timeouts.
use std::thread;
use std::time::{Duration, Instant};

/// Control server and telemetry hub under test.
use zapret_rs::control::{
    ControlCommand, ControlServer, ControlServerConfig, DaemonStatusMeta, TelemetryHub,
};
/// Packet outcome types forwarded across SSE.
use zapret_rs::desync::PacketOutcome;
use zapret_rs::intercepter::QueuedPacket;
use zapret_rs::telemetry::{PacketCounters, build_packet_record};
/// Web HTTP/SSE server under test.
use zapret_rs::tools::{WebAuth, WebConfig, start_web_server};

fn raw_http(addr: SocketAddr, req: &str) -> (u16, String)
{
    let mut s = TcpStream::connect(addr).expect("connect web");
    s.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    s.write_all(req.as_bytes()).expect("write");
    let mut out = String::new();
    s.read_to_string(&mut out).expect("read");
    let status = out
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .expect("status");
    (status, out)
}

fn sample_packet(seq: u64) -> zapret_rs::telemetry::PacketRecord
{
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
    build_packet_record(seq, &qp, &PacketOutcome::Modify(Some("tls13:multisplit:1".to_owned())))
}

/// Spawns a mock control command handler thread answering reload and stop actions.
fn spawn_mock_daemon_loop(
    hub: Arc<TelemetryHub>,
    stop_flag: Arc<AtomicBool>,
    reload_seen: Arc<AtomicBool>,
    stop_seen: Arc<AtomicBool>,
) -> thread::JoinHandle<()>
{
    thread::spawn(move || {
        while !stop_flag.load(Ordering::Acquire)
        {
            while let Some(cmd) = hub.try_recv_command()
            {
                match cmd
                {
                    ControlCommand::ReloadLists { reply } =>
                    {
                        reload_seen.store(true, Ordering::Release);
                        let _ = reply.send(Ok("reloaded 2 domains".to_owned()));
                    }
                    ControlCommand::Stop { reply } =>
                    {
                        stop_seen.store(true, Ordering::Release);
                        let _ = reply.send(Ok("stopping daemon".to_owned()));
                    }
                    ControlCommand::ReloadConfig { reply, .. } =>
                    {
                        let _ = reply.send(Ok("ok".to_owned()));
                    }
                }
            }
            thread::sleep(Duration::from_millis(15));
        }
    })
}

/// Verifies `/api/events` SSE status and packet event delivery from the live control bridge.
fn verify_sse_status_and_packet_stream(addr: SocketAddr, hub: &TelemetryHub)
{
    let mut sse = TcpStream::connect(addr).expect("connect sse");
    sse.set_read_timeout(Some(Duration::from_secs(3))).expect("timeout");
    sse.write_all(
        b"GET /api/events HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bridge-token\r\n\r\n",
    )
    .expect("write sse");
    let mut sse_reader = BufReader::new(sse);
    let mut collected = String::new();
    let sse_deadline = Instant::now() + Duration::from_secs(3);
    let mut line = String::new();
    while Instant::now() < sse_deadline
    {
        line.clear();
        sse_reader.read_line(&mut line).expect("read sse header");
        collected.push_str(&line);
        if collected.contains("event: status") && collected.contains("tls13:multisplit:1")
        {
            break;
        }
    }
    assert!(collected.contains("text/event-stream"));
    assert!(collected.contains("event: status"));

    hub.publish_packet(sample_packet(9));
    collected.clear();
    let pkt_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < pkt_deadline
    {
        line.clear();
        sse_reader.read_line(&mut line).expect("read sse packet");
        collected.push_str(&line);
        if collected.contains("event: packet") && collected.contains("tls13:multisplit:1")
        {
            break;
        }
    }
    assert!(collected.contains("event: packet"));
}

#[test]
fn web_bridge_streams_status_sse_and_executes_daemon_actions()
{
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_web_ipc_{}_{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("control.sock");

    let counters = Arc::new(PacketCounters::default());
    counters.total.store(120, Ordering::Relaxed);
    counters.modified.store(7, Ordering::Relaxed);
    let meta = DaemonStatusMeta {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        qnum: 200,
        fwmark: 0x4000_0000,
        intercept: true,
        profile_names: vec!["tls13:multisplit:1".to_owned()],
        config_path: None,
    };
    let hub = TelemetryHub::new(Arc::clone(&counters), meta, 20);
    let ctl_srv = ControlServer::start(
        ControlServerConfig::new(sock.clone(), env!("CARGO_PKG_VERSION")),
        Arc::clone(&hub),
    )
    .expect("start control server");

    let stop_flag = Arc::new(AtomicBool::new(false));
    let reload_seen = Arc::new(AtomicBool::new(false));
    let stop_seen = Arc::new(AtomicBool::new(false));
    let cmd_thread = spawn_mock_daemon_loop(
        Arc::clone(&hub),
        Arc::clone(&stop_flag),
        Arc::clone(&reload_seen),
        Arc::clone(&stop_seen),
    );

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let (auth, _) = WebAuth::new(bind, Some("bridge-token".to_owned()), false).expect("auth");
    let mut web =
        start_web_server(WebConfig { bind, auth, control_socket: Some(sock), config: None, lua_dir: None })
            .expect("start web server");
    let addr = web.addr();

    let deadline = Instant::now() + Duration::from_secs(3);
    let status_body = loop
    {
        let (st, resp) = raw_http(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bridge-token\r\n\r\n",
        );
        assert_eq!(st, 200);
        if resp.contains("\"connected\":true")
        {
            break resp;
        }
        assert!(Instant::now() < deadline, "IPC bridge failed to attach: {resp}");
        thread::sleep(Duration::from_millis(30));
    };
    assert!(status_body.contains("\"qnum\":200"));
    assert!(status_body.contains("tls13:multisplit:1"));
    assert!(status_body.contains("\"total\":120"));

    verify_sse_status_and_packet_stream(addr, &hub);

    let (st_rel, out_rel) = raw_http(
        addr,
        "POST /api/daemon/reload-lists HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bridge-token\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert_eq!(st_rel, 200);
    assert!(out_rel.contains("reloaded 2 domains"));
    assert!(reload_seen.load(Ordering::Acquire));

    let (st_stop, out_stop) = raw_http(
        addr,
        "POST /api/daemon/stop HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer bridge-token\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert_eq!(st_stop, 200);
    assert!(out_stop.contains("stopping daemon"));
    assert!(stop_seen.load(Ordering::Acquire));

    stop_flag.store(true, Ordering::Release);
    web.shutdown();
    ctl_srv.shutdown();
    let _ = cmd_thread.join();
    let _ = std::fs::remove_dir_all(&dir);
}
