//! Integration tests for `zapret-rs web` Config editor, Domain hostlist, and Scan routes.

/// Raw loopback TCP HTTP helper without external HTTP client dependencies.
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
/// Temporary directory creation and file verification.
use std::fs;

/// Web server launcher and auth helpers under test.
use zapret_rs::tools::{WebAuth, WebConfig, start_web_server};

fn raw_http(addr: SocketAddr, req: &str) -> (u16, String) {
    let mut s = TcpStream::connect(addr).expect("connect web");
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

#[test]
fn config_editor_rejects_invalid_toml_writes_valid_and_manages_domains() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_web_ops_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("nfqws2.toml");
    let initial_toml = "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"inline_doms\"\nhostlist_domains = [\"example.com\"]\n";
    fs::write(&cfg_path, initial_toml).expect("write initial toml");

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let (auth, _) = WebAuth::new(bind, Some("ops-token".to_owned()), false).expect("auth");
    let mut web = start_web_server(WebConfig {
        bind,
        auth,
        control_socket: Some(dir.join("missing.sock")),
        config: Some(cfg_path.clone()),
        lua_dir: None,
    })
    .expect("start web");
    let addr = web.addr();

    // GET /api/config returns file contents and valid profile count.
    let (st_get, body_get) = raw_http(
        addr,
        "GET /api/config HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\n\r\n",
    );
    assert_eq!(st_get, 200);
    assert!(body_get.contains("\"valid\":true") && body_get.contains("\"profiles\":1"));

    // POST invalid TOML returns 400 and never overwrites original disk file.
    let bad_body = serde_json::json!({ "toml": "unknown_field = 123\n", "apply": false }).to_string();
    let req_bad = format!(
        "POST /api/config HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{bad_body}",
        bad_body.len()
    );
    assert_eq!(raw_http(addr, &req_bad).0, 400);
    assert_eq!(fs::read_to_string(&cfg_path).expect("read"), initial_toml);

    // POST valid TOML saves cleanly.
    let valid_toml = "qnum = 201\nfwmark = 0x40000000\n";
    let ok_body = serde_json::json!({ "toml": valid_toml, "apply": false }).to_string();
    let req_ok = format!(
        "POST /api/config HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{ok_body}",
        ok_body.len()
    );
    let (st_ok, out_ok) = raw_http(addr, &req_ok);
    assert_eq!(st_ok, 200);
    assert!(out_ok.contains("\"ok\":true"));
    assert_eq!(fs::read_to_string(&cfg_path).expect("read updated"), valid_toml);

    // Blacklist (`hostlist_exclude`) updates profiles in nfqws2.toml; autohostlist is gated off.
    let add_body = "{\"domain\":\"Bank.Example.com\",\"action\":\"add\",\"list\":\"exclude\"}";
    let req_add = format!(
        "POST /api/domains HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{add_body}",
        add_body.len()
    );
    let (st_add, out_add) = raw_http(addr, &req_add);
    assert_eq!(st_add, 400, "no profiles in valid_toml yet returns clear 400");
    assert!(out_add.contains("no [[profiles]]"));

    // Restore a config with one profile and blacklist + test conditional autohostlist gating.
    let with_prof = "qnum = 201\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"p1\"\n";
    let save_prof = serde_json::json!({ "toml": with_prof, "apply": false }).to_string();
    let req_prof = format!(
        "POST /api/config HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{save_prof}",
        save_prof.len()
    );
    assert_eq!(raw_http(addr, &req_prof).0, 200);

    let (st_ex, out_ex) = raw_http(addr, &req_add);
    assert_eq!(st_ex, 200);
    assert!(out_ex.contains("bank.example.com"));
    assert!(fs::read_to_string(&cfg_path).expect("read").contains("hostlist_exclude_domains"));

    let auto_off = "{\"domain\":\"blocked.test\",\"action\":\"add\",\"list\":\"auto\"}";
    let req_auto_off = format!(
        "POST /api/domains HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{auto_off}",
        auto_off.len()
    );
    assert_eq!(raw_http(addr, &req_auto_off).0, 400, "autohostlist edit refused when hostlist_auto unset");

    let bad_dom = "{\"domain\":\"bad domain!!\",\"action\":\"add\",\"list\":\"exclude\"}";
    let req_bad_dom = format!(
        "POST /api/domains HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{bad_dom}",
        bad_dom.len()
    );
    assert_eq!(raw_http(addr, &req_bad_dom).0, 400);

    let rm_body = "{\"domain\":\"bank.example.com\",\"action\":\"remove\",\"list\":\"exclude\"}";
    let req_rm = format!(
        "POST /api/domains HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{rm_body}",
        rm_body.len()
    );
    assert_eq!(raw_http(addr, &req_rm).0, 200);
    let (st_doms, out_doms) = raw_http(
        addr,
        "GET /api/domains HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\n\r\n",
    );
    assert_eq!(st_doms, 200);
    assert!(out_doms.contains("\"exclude_domains\":[]"));

    // Scan status starts idle.
    let (st_scan, out_scan) = raw_http(
        addr,
        "GET /api/scan HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer ops-token\r\n\r\n",
    );
    assert_eq!(st_scan, 200);
    assert!(out_scan.contains("\"status\":\"idle\""));

    web.shutdown();
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn config_apply_pushes_reload_config_to_attached_daemon() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};
    use zapret_rs::control::{
        ControlCommand, ControlServer, ControlServerConfig, DaemonStatusMeta, TelemetryHub,
    };
    use zapret_rs::telemetry::PacketCounters;

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_web_apply_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let sock = dir.join("control.sock");
    let cfg_path = dir.join("nfqws2.toml");

    let hub = TelemetryHub::new(
        Arc::new(PacketCounters::default()),
        DaemonStatusMeta {
            version: "1.4.2".to_owned(),
            pid: std::process::id(),
            qnum: 200,
            fwmark: 0x4000_0000,
            intercept: true,
            profile_names: vec![],
            config_path: None,
        },
        20,
    );
    let ctl = ControlServer::start(ControlServerConfig::new(sock.clone(), "1.4.2"), Arc::clone(&hub))
        .expect("start ctl");

    let stop_loop = Arc::new(AtomicBool::new(false));
    let seen_reload = Arc::new(AtomicBool::new(false));
    let (s_flag, r_flag, h_loop) = (Arc::clone(&stop_loop), Arc::clone(&seen_reload), Arc::clone(&hub));
    let t = thread::spawn(move || {
        while !s_flag.load(Ordering::Acquire) {
            while let Some(cmd) = h_loop.try_recv_command() {
                if let ControlCommand::ReloadConfig { reply, .. } = cmd {
                    r_flag.store(true, Ordering::Release);
                    let _ = reply.send(Ok("applied 1 profile(s)".to_owned()));
                }
            }
            thread::sleep(Duration::from_millis(15));
        }
    });

    let bind: SocketAddr = "127.0.0.1:0".parse().expect("loopback");
    let (auth, _) = WebAuth::new(bind, Some("apply-tok".to_owned()), false).expect("auth");
    let mut web = start_web_server(WebConfig {
        bind,
        auth,
        control_socket: Some(sock),
        config: Some(cfg_path),
        lua_dir: None,
    })
    .expect("start web");
    let addr = web.addr();

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let (_, body) = raw_http(
            addr,
            "GET /api/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer apply-tok\r\n\r\n",
        );
        if body.contains("\"connected\":true") {
            break;
        }
        assert!(Instant::now() < deadline, "daemon did not attach in time");
        thread::sleep(Duration::from_millis(25));
    }

    let apply_body = serde_json::json!({
        "toml": "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"p1\"\n",
        "apply": true
    })
    .to_string();
    let req = format!(
        "POST /api/config HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer apply-tok\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{apply_body}",
        apply_body.len()
    );
    let (st, out) = raw_http(addr, &req);
    assert_eq!(st, 200);
    assert!(out.contains("applied 1 profile(s)"));
    assert!(seen_reload.load(Ordering::Acquire));

    stop_loop.store(true, Ordering::Release);
    web.shutdown();
    ctl.shutdown();
    let _ = t.join();
    let _ = fs::remove_dir_all(&dir);
}
