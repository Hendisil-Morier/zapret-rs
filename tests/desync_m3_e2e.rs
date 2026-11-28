//! End-to-end Milestone 3 integration tests covering TLS/QUIC reassembly, DNS IPCache,
//! autohostlists (TCP retrans RST, HTTP redirect, UDP stall), RELATED ICMP, and list reloads.

/// Shared mock [`PacketSender`] and wire packet builder fixtures.
mod common;

/// Interior mutability for sharing [`CapturingSender`] with `DesyncEngine`.
use std::cell::RefCell;
/// Temporary directory creation and autohostlist disk verification helpers.
use std::fs;
/// Destination IP parsing when asserting emitted RST endpoints.
use std::net::IpAddr;
/// Fixture path construction for unmodified `zapret2/files/fake/` binaries.
use std::path::{Path, PathBuf};
/// Single-thread reference counting for mock sender injection.
use std::rc::Rc;

/// TOML configuration parser initializing profiles, hostlists, ipsets, and IPCache settings.
use zapret_rs::config::AppConfig;
/// Stateful desync engine orchestrating L7 probes, reassembly, hostlists, and Lua callbacks.
use zapret_rs::desync::DesyncEngine;
/// Kernel queue packet wrapper and verdict enum under test.
use zapret_rs::intercepter::{Decision, QueuedPacket};
/// Protocol numbers, ICMP error codes, and TCP header flags used to build synthetic traffic.
use zapret_rs::packet::constants::{
    ICMP_DEST_UNREACH, ICMP_UNREACH_PORT, IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP, TH_ACK, TH_PUSH, TH_RST,
    TH_SYN,
};
/// Packet structures, dissector, and checksum-computing wire reconstructor.
use zapret_rs::packet::{
    DissectedPacket, IcmpHeader, Ipv4Header, ReconstructOptions, TcpHeader, UdpHeader, dissect_packet,
    reconstruct_packet,
};
/// Abstract packet transmitter coerced from [`CapturingSender`].
use zapret_rs::rawsend::PacketSender;

/// Mock sender and basic IPv4 TCP/UDP builders reused across scenarios.
use common::{CapturingSender, build_ipv4_tcp, build_ipv4_udp};

/// Reads a binary fixture file from `tests/fixtures/fake/`.
fn fake_fixture(name: &str) -> Vec<u8>
{
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake")).join(name);
    fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Returns a clean temporary directory under `std::env::temp_dir()`.
fn clean_temp_dir(label: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-m3-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

/// Constructs a base IPv4 header with `ttl = 64` for test packet assembly.
fn ipv4_base(src: [u8; 4], dst: [u8; 4], protocol: u8) -> Ipv4Header
{
    Ipv4Header {
        version: 4,
        header_len: 5,
        tos: 0,
        total_len: 0,
        id: 0x1001,
        frag_off: 0,
        ttl: 64,
        protocol,
        checksum: 0,
        src,
        dst,
        options: Vec::new(),
    }
}

/// Constructs an IPv4/TCP segment with explicit sequence, acknowledgment, flags, and payload.
#[allow(clippy::too_many_arguments)]
fn build_tcp4(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8>
{
    let dis = DissectedPacket {
        ip: Some(ipv4_base(src, dst, IPPROTO_TCP)),
        tcp: Some(TcpHeader {
            s_port: sport,
            d_port: dport,
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
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid TCP packet")
}

/// Constructs an IPv4/UDP datagram with explicit source/destination endpoints.
fn build_udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8>
{
    let dis = DissectedPacket {
        ip: Some(ipv4_base(src, dst, IPPROTO_UDP)),
        udp: Some(UdpHeader { s_port: sport, d_port: dport, len: 0, checksum: 0 }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid UDP packet")
}

/// Builds an outgoing `QueuedPacket` on `eth0`.
const fn out_pkt(id: u32, payload: &[u8]) -> QueuedPacket<'_>
{
    QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("eth0"), payload }
}

/// Builds an incoming `QueuedPacket` on `eth0`.
const fn in_pkt(id: u32, payload: &[u8]) -> QueuedPacket<'_>
{
    QueuedPacket { packet_id: id, mark: 0, ifin: Some("eth0"), ifout: None, payload }
}

/// Completes a tracked 2-way SYN / SYN+ACK exchange starting at `(seq=1000, server_seq=2000)`.
fn send_handshake(engine: &DesyncEngine, c: [u8; 4], s: [u8; 4], cp: u16, sp: u16, base_id: u32)
{
    let syn = build_tcp4(c, s, cp, sp, 1000, 0, TH_SYN, &[]);
    let synack = build_tcp4(s, c, sp, cp, 2000, 1001, TH_SYN | TH_ACK, &[]);
    assert_eq!(engine.process_packet(&out_pkt(base_id, &syn)), Decision::Pass);
    assert_eq!(engine.process_packet(&in_pkt(base_id + 1, &synack)), Decision::Pass);
}

/// Verifies 2-segment TCP TLS ClientHello reassembly, SNI hostlist matching, and ordered replay.
#[test]
fn tcp_tls_client_hello_reassembly_replays_delayed_pieces_with_sni()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let toml = r#"
        lua_init = [{ inline = """
            _G.replays = {}
            function inspect_tls(ctx, desync)
                table.insert(_G.replays, {
                    replay = desync.replay, piece = desync.replay_piece,
                    count = desync.replay_piece_count, last = desync.replay_piece_last,
                    offset = desync.reasm_offset, len = #desync.reasm_data,
                    l7proto = desync.l7proto, l7payload = desync.l7payload,
                    tracked = (desync.track ~= nil),
                })
                if desync.replay_piece == 2 then
                    desync.dis.ip.ip_ttl = 33
                    return VERDICT_MODIFY
                end
                return VERDICT_PASS
            end
        """ }]
        [[profiles]]
        filter_tcp = ["443"]
        filter_l7 = ["tls"]
        hostlist_domains = ["iana.org"]
        [[profiles.actions]]
        func = "inspect_tls"
        payload = ["tls_client_hello"]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::with_sender(&cfg, Rc::clone(&sender) as Rc<RefCell<dyn PacketSender>>)
        .expect("engine init");

    let ch = fake_fixture("tls_clienthello_iana_org.bin");
    let split = 30usize;
    let (c, s) = ([10, 0, 0, 2], [93, 184, 216, 34]);
    send_handshake(&engine, c, s, 42000, 443, 1);

    let seg1 = build_tcp4(c, s, 42000, 443, 1001, 2001, TH_ACK | TH_PUSH, &ch[..split]);
    let seg2 = build_tcp4(c, s, 42000, 443, 1001 + split as u32, 2001, TH_ACK | TH_PUSH, &ch[split..]);

    assert_eq!(
        engine.process_packet_traced(&out_pkt(3, &seg1)),
        (Decision::Drop, zapret_rs::desync::PacketOutcome::Reasm)
    );
    assert!(
        sender
            .borrow()
            .packets
            .is_empty(),
        "piece 1 must wait"
    );

    assert_eq!(
        engine.process_packet_traced(&out_pkt(4, &seg2)),
        (Decision::Drop, zapret_rs::desync::PacketOutcome::Modify(Some("profile #1".to_owned())))
    );
    {
        let captured = &sender
            .borrow()
            .packets;
        assert_eq!(captured.len(), 2, "both delayed segments must flush via sender");
        assert_eq!(
            dissect_packet(&captured[0].data, false)
                .ip
                .expect("ip")
                .ttl,
            64
        );
        assert_eq!(
            dissect_packet(&captured[1].data, false)
                .ip
                .expect("ip")
                .ttl,
            33
        );
    }

    // Non-matching 2-segment ClientHello (`www.google.com` vs `hostlist_domains = ["iana.org"]`)
    // must classify both segments as `Reasm` (reassembled pass-through, not `Desync`).
    let gch = fake_fixture("tls_clienthello_www_google_com.bin");
    send_handshake(&engine, c, s, 42001, 443, 10);
    let g1 = build_tcp4(c, s, 42001, 443, 1001, 2001, TH_ACK, &gch[..split]);
    let g2 = build_tcp4(c, s, 42001, 443, 1001 + split as u32, 2001, TH_ACK | TH_PUSH, &gch[split..]);
    assert_eq!(
        engine.process_packet_traced(&out_pkt(12, &g1)),
        (Decision::Drop, zapret_rs::desync::PacketOutcome::Reasm)
    );
    assert_eq!(
        engine.process_packet_traced(&out_pkt(13, &g2)),
        (Decision::Drop, zapret_rs::desync::PacketOutcome::Reasm)
    );

    engine
        .runtime()
        .lua()
        .globals()
        .set("expected_len", ch.len())
        .expect("set expected_len");
    engine
        .runtime()
        .exec_str(
            r#"
            assert(#_G.replays == 2)
            assert(_G.replays[1].replay and _G.replays[1].piece == 1 and _G.replays[1].count == 2)
            assert(_G.replays[1].last == false and _G.replays[1].offset == 0)
            assert(_G.replays[1].len == expected_len and _G.replays[1].tracked)
            assert(_G.replays[1].l7proto == "tls" and _G.replays[1].l7payload == "tls_client_hello")
            assert(_G.replays[2].piece == 2 and _G.replays[2].last == true and _G.replays[2].offset == 30)
            assert(_G.replays[2].len == expected_len)
            "#,
        )
        .expect("Lua replay assertions pass");
}

/// Verifies QUIC Initial decryption, SNI hostlist match, `decrypt_data`, and `ct_new_postnat_fix`.
#[test]
fn quic_initial_decrypt_hostlist_match_and_postnat_fix_drop()
{
    let toml = r#"
        lua_init = [{ inline = """
            function check_quic(ctx, desync)
                assert(desync.l7proto == "quic")
                assert(desync.l7payload == "quic_initial")
                assert(type(desync.decrypt_data) == "string" and #desync.decrypt_data > 40)
                _G.quic_matched = true
                return VERDICT_DROP
            end
        """ }]
        [[profiles]]
        filter_udp = ["443"]
        filter_l7 = ["quic"]
        hostlist_domains = ["google.com"]
        [[profiles.actions]]
        func = "check_quic"
        payload = ["quic_initial"]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine init");

    let quic_raw = fake_fixture("quic_initial_www_google_com.bin");
    let udp = build_ipv4_udp(51000, 443, &quic_raw);
    let Decision::Replace(postnat) = engine.process_packet(&out_pkt(1, &udp))
    else
    {
        panic!("packet 1 VERDICT_DROP must trigger ct_new_postnat_fix Replace");
    };
    assert_eq!(postnat.len(), udp.len());
    assert_eq!(postnat[8], 1, "postnat fix rewrites ip_ttl = 1");
    assert_eq!(postnat[9], 255, "postnat fix rewrites ip_p = 255");
    engine
        .runtime()
        .exec_str("assert(_G.quic_matched == true)")
        .expect("QUIC action ran");
}

/// Verifies DNS IN A response populates IPCache so a bare TCP SYN matches a hostlist profile.
#[test]
fn dns_a_response_populates_ipcache_for_subsequent_tcp_syn()
{
    let toml = r#"
        ipcache_hostname = true
        ipcache_lifetime = 3600
        lua_init = [
            { inline = "function mark_dns(ctx, desync) _G.dns_hits = (_G.dns_hits or 0) + 1; return VERDICT_PASS end" }
        ]
        [[profiles]]
        filter_tcp = ["80"]
        hostlist_domains = ["cached.example"]
        [[profiles.actions]]
        func = "mark_dns"
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine init");

    let mut dns_resp = vec![0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    dns_resp.extend_from_slice(b"\x06cached\x07example\x00\x00\x01\x00\x01");
    dns_resp.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 60, 0, 4, 203, 0, 113, 10]);
    let dns_pkt = build_udp4([8, 8, 8, 8], [10, 0, 0, 2], 53, 55555, &dns_resp);
    assert_eq!(engine.process_packet(&in_pkt(1, &dns_pkt)), Decision::Pass);

    let syn = build_tcp4([10, 0, 0, 2], [203, 0, 113, 10], 40000, 80, 1, 0, TH_SYN, &[]);
    assert_eq!(engine.process_packet(&out_pkt(2, &syn)), Decision::Pass);
    engine
        .runtime()
        .exec_str("assert(_G.dns_hits == 1)")
        .expect("DNS IPCache hit");
}

/// Verifies autohostlist triggers: TCP retrans synthetic RST, HTTP 302 redirect append, and UDP stall append.
#[test]
fn autohostlist_tcp_retrans_rst_http_redirect_and_udp_stall()
{
    let dir = clean_temp_dir("auto");
    let (auto_tcp, auto_udp, debug_log) =
        (dir.join("auto_tcp.txt"), dir.join("auto_udp.txt"), dir.join("auto_debug.log"));
    let sender = Rc::new(RefCell::new(CapturingSender::default()));

    let toml = format!(
        r#"
        hostlist_auto_debug = "{dbg}"
        lua_init = [
            {{ inline = "function count_hit(ctx, desync) _G.auto_hits = (_G.auto_hits or 0) + 1; return VERDICT_PASS end" }}
        ]
        [[profiles]]
        filter_tcp = ["80"]
        hostlist_auto = "{tcp}"
        hostlist_auto_fail_threshold = 2
        hostlist_auto_fail_cooldown = 0
        hostlist_auto_retrans_threshold = 2
        hostlist_auto_retrans_reset = true
        hostlist_auto_incoming_maxseq = 4096
        [[profiles.actions]]
        func = "count_hit"
        [[profiles]]
        filter_udp = ["443"]
        hostlist_auto = "{udp}"
        hostlist_auto_fail_threshold = 1
        hostlist_auto_udp_out = 3
        hostlist_auto_udp_in = 0
        [[profiles.actions]]
        func = "count_hit"
        "#,
        dbg = debug_log.display(),
        tcp = auto_tcp.display(),
        udp = auto_udp.display(),
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid TOML");
    let engine = DesyncEngine::with_sender(&cfg, Rc::clone(&sender) as Rc<RefCell<dyn PacketSender>>)
        .expect("engine init");

    let (c, s) = ([10, 0, 0, 2], [198, 51, 100, 20]);
    let get_req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";

    // Flow 1: GET + 2 retransmissions => synthetic RST injected, fail counter 1/2.
    send_handshake(&engine, c, s, 30001, 80, 1);
    let get1 = build_tcp4(c, s, 30001, 80, 1001, 2001, TH_ACK | TH_PUSH, get_req);
    for id in 3..=5
    {
        assert_eq!(engine.process_packet(&out_pkt(id, &get1)), Decision::Pass);
    }
    let sent = &sender
        .borrow()
        .packets;
    assert_eq!(sent.len(), 1, "retrans_threshold=2 must inject one synthetic RST");
    assert_eq!(
        dissect_packet(&sent[0].data, false)
            .tcp
            .expect("tcp")
            .flags
            & TH_RST,
        TH_RST
    );
    assert_eq!(
        sent[0].dst,
        "10.0.0.2"
            .parse::<IpAddr>()
            .expect("ip")
    );

    // Flow 2: HTTP 302 off-SLD redirect => fail 2/2 promotes blocked.example to disk.
    send_handshake(&engine, c, s, 30002, 80, 6);
    let redir_req = build_tcp4(c, s, 30002, 80, 1001, 2001, TH_ACK | TH_PUSH, get_req);
    let reply = b"HTTP/1.1 302 Found\r\nLocation: http://block.isp.invalid/\r\n\r\n";
    let reply_pkt = build_tcp4(s, c, 80, 30002, 2001, 1001 + get_req.len() as u32, TH_ACK | TH_PUSH, reply);
    assert_eq!(engine.process_packet(&out_pkt(8, &redir_req)), Decision::Pass);
    assert_eq!(engine.process_packet(&in_pkt(9, &reply_pkt)), Decision::Pass);

    let disk_tcp = fs::read_to_string(&auto_tcp).expect("read auto_tcp");
    let disk_dbg = fs::read_to_string(&debug_log).expect("read debug log");
    assert!(disk_tcp.contains("blocked.example") && disk_dbg.contains("blocked.example"));

    // Flow 3: promoted host now triggers profile action.
    send_handshake(&engine, c, s, 30003, 80, 10);
    let req3 = build_tcp4(c, s, 30003, 80, 1001, 2001, TH_ACK | TH_PUSH, get_req);
    assert_eq!(engine.process_packet(&out_pkt(12, &req3)), Decision::Pass);
    engine
        .runtime()
        .exec_str("assert((_G.auto_hits or 0) >= 1)")
        .expect("promoted domain hit");

    // UDP stall: 3 outgoing QUIC Initial packets without reply promote www.google.com.
    let udp = build_udp4(c, [142, 250, 1, 1], 49000, 443, &fake_fixture("quic_initial_www_google_com.bin"));
    for id in 13..16
    {
        let _ = engine.process_packet(&out_pkt(id, &udp));
    }
    let disk_udp = fs::read_to_string(&auto_udp).expect("read auto_udp");
    let _ = fs::remove_dir_all(&dir);
    assert!(disk_udp.contains("www.google.com"), "auto_udp missing host: {disk_udp}");
}

/// Verifies RELATED ICMPv4 inheritance of parent flow state and `reload_lists()` hot-reload.
#[test]
fn related_icmp_inheritance_and_reload_lists()
{
    let dir = clean_temp_dir("icmp-reload");
    let hl_path = dir.join("hosts.txt");
    fs::write(&hl_path, "first.example\n").expect("write initial hostlist");

    let toml = format!(
        r#"
        lua_init = [{{ inline = """
            function on_pkt(ctx, desync)
                if desync.l7payload == "ipv4" then
                    assert(desync.profile_n == 1 and desync.track ~= nil)
                    _G.icmp_inherited = true
                else
                    _G.tcp_hits = (_G.tcp_hits or 0) + 1
                end
                return VERDICT_PASS
            end
        """ }}]
        [[profiles]]
        filter_tcp = ["443"]
        hostlist = ["{}"]
        [[profiles.actions]]
        in_range = "a"
        out_range = "a"
        func = "on_pkt"
        "#,
        hl_path.display()
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine init");

    let (c, s) = ([10, 0, 0, 2], [93, 184, 216, 34]);
    let syn = build_tcp4(c, s, 43000, 443, 999, 0, TH_SYN, &[]);
    let first = build_ipv4_tcp(43000, 443, b"GET / HTTP/1.1\r\nHost: first.example\r\n\r\n");
    let _ = engine.process_packet(&out_pkt(1, &syn));
    let _ = engine.process_packet(&out_pkt(2, &first));

    let icmp_dis = DissectedPacket {
        ip: Some(ipv4_base([192, 0, 2, 1], c, IPPROTO_ICMP)),
        icmp: Some(IcmpHeader {
            icmp_type: ICMP_DEST_UNREACH,
            icmp_code: ICMP_UNREACH_PORT,
            checksum: 0,
            data: 0,
        }),
        payload: Some(syn),
        ..DissectedPacket::default()
    };
    let icmp_pkt = reconstruct_packet(&icmp_dis, &ReconstructOptions::default()).expect("icmp");
    assert_eq!(engine.process_packet(&in_pkt(3, &icmp_pkt)), Decision::Pass);

    let syn2 = build_tcp4(c, s, 43001, 443, 500, 0, TH_SYN, &[]);
    let second = build_ipv4_tcp(43001, 443, b"GET / HTTP/1.1\r\nHost: second.example\r\n\r\n");
    let _ = engine.process_packet(&out_pkt(4, &syn2));
    let _ = engine.process_packet(&out_pkt(5, &second));

    fs::write(&hl_path, "first.example\nsecond.example\n").expect("update hostlist");
    engine.reload_lists();
    let _ = engine.process_packet(&out_pkt(6, &second));
    let _ = fs::remove_dir_all(&dir);

    engine
        .runtime()
        .exec_str("assert(_G.icmp_inherited == true and _G.tcp_hits == 2)")
        .expect("RELATED ICMP inherited flow and reload_lists picked up second.example");
}
