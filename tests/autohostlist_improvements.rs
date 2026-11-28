//! Integration tests for improved autohostlist DPI detection, cooldown coalescing, sibling rollups, and active confirmation.

/// Shared interior mutability for hostlist file handles under test.
use std::cell::RefCell;
/// Localhost loopback TCP servers used to verify non-blocking active DPI confirmation.
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
/// Filesystem paths and temporary workspace cleanup.
use std::path::PathBuf;
/// Reference counting for autohostlist file wrappers and capturing packet senders.
use std::rc::Rc;
/// Background mock listener thread join handles.
use std::thread;
/// Short probe timeouts and poll backoff during asynchronous confirmation checks.
use std::time::{Duration, Instant};

/// Configuration models parsed from TOML test fixtures.
use zapret_rs::config::{AppConfig, L7Payload, L7Proto};
/// Connection tracking flow entry types for incoming TCP trigger unit verification.
use zapret_rs::conntrack::CtrackEntry;
/// Desync engine and background endpoint probe helper under test.
use zapret_rs::desync::{DesyncEngine, probe_endpoint_for_dpi};
/// Packet capture metadata fed into `DesyncEngine::process_packet`.
use zapret_rs::intercepter::QueuedPacket;
/// Autohostlist promotion, fail pool, parent domain resolver, and incoming trigger helpers.
use zapret_rs::lists::{
    AutoHostlistAction, AutoHostlistRecordCtx, AutoHostlistSettings, HostFailPool, HostlistCollection,
    HostlistFile, HostlistRef, check_tcp_incoming_trigger, record_autohost_failure, safe_parent_domain,
};
/// Packet wire headers, TCP flag masks, and IPv4/TCP packet constructor.
use zapret_rs::packet::{
    DissectedPacket, IPPROTO_TCP, Ipv4Header, ReconstructOptions, TH_ACK, TH_FIN, TH_PUSH, TH_RST, TH_SYN,
    TcpHeader, reconstruct_packet,
};
/// TLS fatal alert and HTTP DPI block detectors.
use zapret_rs::protocol::{http_reply_looks_like_dpi_block, is_tls_fatal_alert};

/// Creates a clean temporary test directory under `std::env::temp_dir()`.
fn clean_temp_dir(label: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-ah-imp-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

/// Builds a minimal IPv4/TCP wire packet for end-to-end engine simulation.
fn build_tcp4(addrs: ([u8; 4], [u8; 4], u16, u16), seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8>
{
    let (src, dst, sp, dp) = addrs;
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
            src,
            dst,
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: sp,
            d_port: dp,
            seq,
            ack,
            reserved: 0,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("reconstruct tcp4")
}

/// Verifies `rseq == 0` RST, TLS Fatal Alert, premature FIN, HTTP 451, and `<meta refresh>` triggers.
#[test]
fn incoming_dpi_triggers_cover_rseq0_rst_tls_alert_early_fin_451_and_meta_refresh()
{
    let settings = AutoHostlistSettings::default();

    // 1. Forged `TH_RST` at exact `server.seq0` (`rseq == 0`), while `SYN+ACK` at `rseq == 0` stays `None`.
    let mut synack_entry = CtrackEntry::new(None).expect("entry");
    synack_entry.hostname_ah_check = true;
    synack_entry.pos.server.seq0 = 7000;
    synack_entry.pos.server.seq_last = 7000;
    assert_eq!(
        check_tcp_incoming_trigger(&mut synack_entry, TH_SYN | TH_ACK, None, L7Payload::Empty, &settings),
        None
    );
    let mut rst0 = CtrackEntry::new(None).expect("entry");
    rst0.hostname_ah_check = true;
    rst0.pos.server.seq0 = 7000;
    rst0.pos.server.seq_last = 7000;
    assert_eq!(check_tcp_incoming_trigger(&mut rst0, TH_RST, None, L7Payload::Empty, &settings), Some(true));

    // 2. Plaintext TLS Fatal Alert (`0x15 0x03 0x03 0x00 0x02 0x02 0x28`), ignoring warning/ciphertext alerts.
    let fatal_alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28];
    let warning_alert = [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00];
    let encrypted_alert = [0x15, 0x03, 0x03, 0x00, 0x16, 0x02, 0x28];
    assert!(is_tls_fatal_alert(&fatal_alert));
    assert!(!is_tls_fatal_alert(&warning_alert));
    assert!(!is_tls_fatal_alert(&encrypted_alert));

    let mut tls_alert_entry = CtrackEntry::new(None).expect("entry");
    tls_alert_entry.hostname_ah_check = true;
    tls_alert_entry.l7proto = L7Proto::Tls;
    tls_alert_entry.pos.server.seq0 = 7000;
    tls_alert_entry.pos.server.seq_last = 7001;
    assert_eq!(
        check_tcp_incoming_trigger(
            &mut tls_alert_entry,
            TH_ACK | TH_PUSH,
            Some(&fatal_alert),
            L7Payload::Unknown,
            &settings
        ),
        Some(true)
    );

    // 3. Premature empty `TH_FIN` when server sent 0 payload packets after client TLS ClientHello.
    let mut fin_entry = CtrackEntry::new(None).expect("entry");
    fin_entry.hostname_ah_check = true;
    fin_entry.l7proto = L7Proto::Tls;
    fin_entry.pos.client.pdcounter = 1;
    fin_entry.pos.server.pdcounter = 0;
    fin_entry.pos.server.seq0 = 7000;
    fin_entry.pos.server.seq_last = 7001;
    assert_eq!(
        check_tcp_incoming_trigger(&mut fin_entry, TH_FIN | TH_ACK, None, L7Payload::Empty, &settings),
        Some(true)
    );

    let mut normal_fin = CtrackEntry::new(None).expect("entry");
    normal_fin.hostname_ah_check = true;
    normal_fin.l7proto = L7Proto::Tls;
    normal_fin.pos.client.pdcounter = 1;
    normal_fin.pos.server.pdcounter = 1;
    normal_fin.pos.server.seq0 = 7000;
    normal_fin.pos.server.seq_last = 7001;
    assert_eq!(
        check_tcp_incoming_trigger(&mut normal_fin, TH_FIN | TH_ACK, None, L7Payload::Empty, &settings),
        None
    );

    // 4. HTTP 451 + off-SLD HTML `<meta http-equiv="refresh">` block pages, while same-SLD refresh stays allowed.
    let http_451 = b"HTTP/1.1 451 Unavailable For Legal Reasons\r\nContent-Length: 0\r\n\r\n";
    let meta_block = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><head><meta http-equiv=\"refresh\" content=\"0;url=http://block.isp.invalid/deny\"></head></html>";
    let meta_same =
        b"HTTP/1.1 200 OK\r\n\r\n<meta http-equiv=\"refresh\" content=\"0;url=https://cdn.example.com/\">";
    assert!(http_reply_looks_like_dpi_block(http_451, "example.com", false));
    assert!(http_reply_looks_like_dpi_block(meta_block, "example.com", false));
    assert!(!http_reply_looks_like_dpi_block(meta_same, "www.example.com", false));
}

/// Verifies burst cooldown coalescing and public-suffix-safe sibling subdomain promotion.
#[test]
fn cooldown_coalesces_parallel_bursts_and_siblings_promote_safely()
{
    assert_eq!(safe_parent_domain("cdn1.blocked.example"), Some("blocked.example"));
    assert_eq!(safe_parent_domain("cdn1.blocked.co.uk"), Some("blocked.co.uk"));
    assert_eq!(safe_parent_domain("blocked.co.uk"), None);
    assert_eq!(safe_parent_domain("user1.github.io"), None);
    assert_eq!(safe_parent_domain("192.0.2.1"), None);

    let dir = clean_temp_dir("cooldown-sib");
    let auto_path = dir.join("auto.txt");
    std::fs::write(&auto_path, "!exempt.example\n").expect("seed auto");
    let autolist = Rc::new(RefCell::new(HostlistFile::from_path(auto_path.clone())));
    autolist.borrow_mut().load_initial().expect("load auto");
    let hostlists = HostlistCollection {
        include: vec![HostlistRef { file: Rc::clone(&autolist), is_autolist: true }],
        exclude: Vec::new(),
    };
    let mut fail_pool = HostFailPool::new();
    let settings = AutoHostlistSettings {
        fail_threshold: 2,
        fail_cooldown_sec: 2,
        sibling_threshold: 2,
        ..AutoHostlistSettings::default()
    };

    let mut record = |host: &str, now_sec: i64| -> AutoHostlistAction {
        let mut ctx = AutoHostlistRecordCtx {
            settings: &settings,
            fail_pool: &mut fail_pool,
            hostlists: &hostlists,
            autolist_file: &autolist,
            debug_log: None,
            profile_n: 1,
            profile_name: "auto",
            client_label: "127.0.0.1:1234",
            l7proto: L7Proto::Tls,
            now_sec,
        };
        record_autohost_failure(&mut ctx, host, false)
    };

    // Rapid retry inside 2s cooldown is coalesced; at t+2 it counts and promotes `single.example`.
    assert_eq!(record("single.example", 100), AutoHostlistAction::FailCounted(1));
    assert_eq!(record("single.example", 101), AutoHostlistAction::Ignored);
    assert_eq!(record("single.example", 102), AutoHostlistAction::AddedToList);

    // Distinct failing siblings `cdn1.multi.example` + `cdn2.multi.example` promote `multi.example` immediately.
    assert_eq!(record("cdn1.multi.example", 200), AutoHostlistAction::FailCounted(1));
    assert_eq!(record("cdn2.multi.example", 200), AutoHostlistAction::AddedToList);

    // Exempt parent `exempt.example` must NOT be promoted via failing children or sibling rollup.
    assert_eq!(record("a.exempt.example", 300), AutoHostlistAction::FailCounted(1));
    assert_eq!(record("b.exempt.example", 300), AutoHostlistAction::FailCounted(1));
    assert_eq!(record("a.exempt.example", 302), AutoHostlistAction::SkippedDuplicateOrExempt);

    // Shared PaaS `github.io` must NOT collapse `a.github.io` + `b.github.io`.
    assert_eq!(record("a.github.io", 400), AutoHostlistAction::FailCounted(1));
    assert_eq!(record("b.github.io", 400), AutoHostlistAction::FailCounted(1));

    let content = std::fs::read_to_string(&auto_path).expect("read autolist");
    let _ = std::fs::remove_dir_all(&dir);
    assert!(content.contains("single.example\n"));
    assert!(content.contains("multi.example\n"));
    assert!(!content.contains("\nexempt.example\n"));
    assert!(!content.contains("github.io\n"));
}

/// Verifies `probe_endpoint_for_dpi` and end-to-end `DesyncEngine` background `confirm_block` promotion.
#[test]
fn background_active_confirmation_verifies_tls_and_http_blocks_and_healthy_origins()
{
    let dir = clean_temp_dir("confirm");
    let auto_path = dir.join("auto.txt");

    // Server 1: TLS Fatal Alert emitter (`handshake_failure` level 2).
    let alert_srv = TcpListener::bind(("127.0.0.1", 0)).expect("bind alert listener");
    let alert_port = alert_srv.local_addr().expect("addr").port();
    let alert_handle = thread::spawn(move || {
        for mut s in alert_srv.incoming().take(2).flatten()
        {
            let mut discard = [0u8; 1024];
            let _ = s.read(&mut discard);
            let _ = s.write_all(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        }
    });

    // Server 2: Healthy TLS ServerHello responder.
    let ok_srv = TcpListener::bind(("127.0.0.1", 0)).expect("bind ok listener");
    let ok_port = ok_srv.local_addr().expect("addr").port();
    let ok_handle = thread::spawn(move || {
        if let Ok((mut s, _)) = ok_srv.accept()
        {
            let mut discard = [0u8; 1024];
            let _ = s.read(&mut discard);
            let mut sh = [0u8; 64];
            sh[0] = 0x16;
            sh[1] = 0x03;
            sh[2] = 0x03;
            sh[3] = 0x00;
            sh[4] = 59;
            sh[5] = 0x02;
            sh[6] = 0x00;
            sh[7] = 0x00;
            sh[8] = 55;
            sh[9] = 0x03;
            sh[10] = 0x03;
            let _ = s.write_all(&sh);
        }
    });

    // Server 3: HTTP 451 censor emitter.
    let http_srv = TcpListener::bind(("127.0.0.1", 0)).expect("bind http451 listener");
    let http_port = http_srv.local_addr().expect("addr").port();
    let http_handle = thread::spawn(move || {
        if let Ok((mut s, _)) = http_srv.accept()
        {
            let mut discard = [0u8; 1024];
            let _ = s.read(&mut discard);
            let _ = s.write_all(b"HTTP/1.1 451 Unavailable For Legal Reasons\r\nContent-Length: 0\r\n\r\n");
        }
    });

    let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let timeout = Duration::from_secs(2);
    assert_eq!(
        probe_endpoint_for_dpi(loopback, alert_port, "dpi.example", false, L7Proto::Tls, 0, timeout),
        Some(true)
    );
    assert_eq!(
        probe_endpoint_for_dpi(loopback, ok_port, "ok.example", false, L7Proto::Tls, 0, timeout),
        Some(false)
    );
    assert_eq!(
        probe_endpoint_for_dpi(loopback, http_port, "censored.example", false, L7Proto::Http, 0, timeout),
        Some(true)
    );

    // Closed port returns `None` (`Inconclusive`) instead of misclassifying offline reachability.
    let closed_srv = TcpListener::bind(("127.0.0.1", 0)).expect("ephemeral");
    let closed_port = closed_srv.local_addr().expect("addr").port();
    drop(closed_srv);
    assert_eq!(
        probe_endpoint_for_dpi(loopback, closed_port, "down.example", false, L7Proto::Tls, 0, timeout),
        None
    );

    // End-to-end `DesyncEngine`: single passive failure (`fail_threshold = 3`) promotes via background confirmation!
    let toml = format!(
        "[[profiles]]\nfilter_tcp = [\"{alert_port}\"]\nhostlist_auto = \"{}\"\nhostlist_auto_fail_threshold = 3\nhostlist_auto_confirm = true\n",
        auto_path.display()
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine");

    let client = [10, 0, 0, 2];
    let server = [127, 0, 0, 1];
    let syn = build_tcp4((client, server, 41000, alert_port), 1000, 0, TH_SYN, &[]);
    let synack = build_tcp4((server, client, alert_port, 41000), 2000, 1001, TH_SYN | TH_ACK, &[]);
    let ch = zapret_rs::protocol::tls_mod(
        &zapret_rs::protocol::FakeTlsMod {
            sni: "confirmed.example".to_owned(),
            mod_flags: zapret_rs::protocol::FAKE_TLS_MOD_SNI,
        },
        None,
        &zapret_rs::config::FAKE_TLS_CLIENTHELLO_DEFAULT,
    )
    .expect("client hello");
    let ch_pkt = build_tcp4((client, server, 41000, alert_port), 1001, 2001, TH_ACK | TH_PUSH, &ch);
    let rst_pkt =
        build_tcp4((server, client, alert_port, 41000), 2001, 1001 + ch.len() as u32, TH_RST | TH_ACK, &[]);

    for (id, raw) in [(1, &syn), (2, &synack), (3, &ch_pkt), (4, &rst_pkt)]
    {
        let _ = engine.process_packet(&QueuedPacket {
            packet_id: id,
            mark: 0,
            ifin: None,
            ifout: None,
            payload: raw,
        });
    }

    // Drain asynchronous confirmation results via normal packet tick until `confirmed.example` lands on disk.
    let tick_pkt = build_tcp4((client, server, 41001, alert_port), 1000, 0, TH_SYN, &[]);
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline
    {
        let _ = engine.process_packet(&QueuedPacket {
            packet_id: 99,
            mark: 0,
            ifin: None,
            ifout: None,
            payload: &tick_pkt,
        });
        if std::fs::read_to_string(&auto_path).is_ok_and(|s| s.contains("confirmed.example"))
        {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }

    let promoted = std::fs::read_to_string(&auto_path).unwrap_or_default();
    drop(engine);
    let _ = alert_handle.join();
    let _ = ok_handle.join();
    let _ = http_handle.join();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(promoted.contains("confirmed.example"), "expected confirmed.example in {promoted}");
}
