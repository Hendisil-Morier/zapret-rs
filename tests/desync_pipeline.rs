//! Integration tests verifying [`DesyncEngine`] profile matching, verdict reconstruction,
//! and baseline L7 payload classification.
#![cfg(target_os = "linux")]

/// Shared synthetic packet builders for integration tests.
mod common;

/// Configuration schema parsing and baseline L7 payload enum.
use zapret_rs::config::{AppConfig, L7Payload};
/// Core desync engine, verdict aggregator, and baseline payload classifier.
use zapret_rs::desync::{DesyncEngine, aggregate_verdict, classify_baseline_payload};
/// NFQUEUE packet metadata, decision enum, and fwmark dispatch guard.
use zapret_rs::intercepter::{Decision, QueuedPacket, dispatch_packet};
/// Packet checksum helpers for validating modified packet checksums.
use zapret_rs::packet::checksum::{ipv4_header_checksum, tcp_ipv4_checksum};
/// Wire protocol and verdict constants used across synthetic packets and assertions.
use zapret_rs::packet::constants::{
    DEFAULT_MSS, ICMP_DEST_UNREACH, ICMP_ECHO, ICMP6_PACKET_TOO_BIG, IP6_BASE_LEN, IPPROTO_ICMP,
    IPPROTO_ICMPV6, VERDICT_DROP, VERDICT_MODIFY, VERDICT_PASS, VERDICT_PRESERVE_NEXT,
};
/// Wire packet dissection and reconstruction helpers for synthetic ICMP/ESP test frames.
use zapret_rs::packet::{
    DissectedPacket, IcmpHeader, Ipv4Header, Ipv6Header, ReconstructOptions, dissect_packet,
    reconstruct_packet,
};

/// Shared packet generators imported from `tests/common/mod.rs`.
use common::{build_ipv4_tcp, build_ipv4_udp, build_ipv6_tcp};

/// Verifies profile matching, first-match precedence, and `dispatch_packet` fwmark suppression.
#[test]
fn profile_matching_first_match_and_fwmark_loop_guard()
{
    let toml = r#"
        fwmark = 0x40000000
        lua_init = [
            { inline = """
                function drop_tcp_443(ctx, desync)
                    return VERDICT_DROP
                end
                function pass_udp_53(ctx, desync)
                    _G.udp_hit = true
                    return VERDICT_PASS
                end
                function fallback_drop(ctx, desync)
                    _G.fallback_hit = true
                    return VERDICT_DROP
                end
            """ }
        ]

        [[profiles]]
        name = "https"
        filter_tcp = ["443"]
        actions = [{ func = "drop_tcp_443" }]

        [[profiles]]
        name = "dns"
        filter_udp = ["53"]
        actions = [{ func = "pass_udp_53" }]

        [[profiles]]
        name = "fallback"
        actions = [{ func = "fallback_drop" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML config");
    let engine = DesyncEngine::new(&cfg).expect("engine should initialize");

    // 1) TCP 443 matches profile 1 first and returns Drop (not fallback).
    let raw_443 = build_ipv4_tcp(51000, 443, b"hello");
    let pkt_443 = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_443 };
    assert_eq!(engine.process_packet(&pkt_443), Decision::Drop);

    // 2) Packet carrying `desync_fwmark` is bypassed by `dispatch_packet` before reaching engine.
    let pkt_marked = QueuedPacket { mark: 0x4000_0001, ..pkt_443.clone() };
    let decision = dispatch_packet(&pkt_marked, cfg.fwmark, &mut |p| engine.process_packet(p));
    assert_eq!(decision, Decision::Pass);

    // 3) UDP 53 matches profile 2 (not fallback), returns Pass, sets `_G.udp_hit`, never touches fallback.
    let raw_53 = build_ipv4_udp(40000, 53, b"\x12\x34dns");
    let pkt_53 = QueuedPacket { packet_id: 2, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_53 };
    assert_eq!(engine.process_packet(&pkt_53), Decision::Pass);
    engine
        .runtime()
        .exec_str(
            r#"
            assert(_G.udp_hit == true, "UDP profile should execute")
            assert(_G.fallback_hit == nil, "first matching profile must stop profile scan")
            "#,
        )
        .expect("Lua globals check should succeed");
}

/// Verifies `desync` fields, `%`/`#` blob substitution, `\%` escapes, and verdict aggregation precedence.
#[test]
fn desync_table_fields_blob_substitution_and_verdict_precedence()
{
    let toml = r##"
        lua_init = [
            { inline = """
                function inspect_and_modify(ctx, desync)
                    assert(desync.profile_n == 1)
                    assert(desync.profile_name == "tls_test")
                    assert(desync.cookie == "cook-42")
                    assert(desync.outgoing == true)
                    assert(desync.ifin == nil)
                    assert(desync.ifout == "eth1")
                    assert(desync.fwmark == 0x1234)
                    assert(desync.target.port == 443)
                    assert(#desync.target.ip == 4)
                    assert(desync.l7payload == "unknown")
                    assert(desync.l7proto == "unknown")
                    assert(desync.tcp_mss == DEFAULT_MSS)
                    assert(desync.replay == false)
                    assert(desync.reasm_offset == 0)
                    assert(desync.track == nil)
                    assert(desync.func == "inspect_and_modify")
                    assert(desync.func_n == 1)
                    assert(desync.func_instance == "inspect_and_modify_1_1")
                    assert(desync.arg.blob == fake_default_tls)
                    assert(desync.arg.len == tostring(#fake_default_tls))
                    assert(desync.arg.escaped == "%literal")
                    desync.dis.ip.ip_ttl = 9
                    return VERDICT_MODIFY
                end
                function emit_pass(ctx, desync)
                    assert(desync.func == "emit_pass")
                    assert(desync.func_n == 2)
                    return VERDICT_PASS
                end
                function emit_drop(ctx, desync)
                    return VERDICT_DROP
                end
            """ }
        ]

        [[profiles]]
        name = "tls_test"
        cookie = "cook-42"
        filter_tcp = ["443"]

        [[profiles.actions]]
        func = "inspect_and_modify"
        args = { blob = "%fake_default_tls", len = "#fake_default_tls", escaped = "\\%literal" }

        [[profiles.actions]]
        func = "emit_pass"
    "##;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML config");
    let engine = DesyncEngine::new(&cfg).expect("engine should initialize");
    assert_eq!(
        engine
            .runtime()
            .config()
            .qnum,
        u32::from(cfg.qnum),
        "runtime mirrors queue number"
    );
    assert_eq!(DEFAULT_MSS, 1220);

    let raw = build_ipv4_tcp(44444, 443, b"client_hello_bytes");
    let pkt = QueuedPacket { packet_id: 10, mark: 0x1234, ifin: None, ifout: Some("eth1"), payload: &raw };

    // MODIFY + PASS => Replace with ttl=9.
    let Decision::Replace(modified) = engine.process_packet(&pkt)
    else
    {
        panic!("expected Decision::Replace from MODIFY + PASS");
    };
    let dis = dissect_packet(&modified, false);
    assert_eq!(
        dis.ip
            .as_ref()
            .expect("ip")
            .ttl,
        9
    );

    // Pure `aggregate_verdict` truth table checks including VERDICT_PRESERVE_NEXT.
    assert_eq!(aggregate_verdict(VERDICT_PASS, VERDICT_MODIFY), VERDICT_MODIFY);
    assert_eq!(aggregate_verdict(VERDICT_MODIFY, VERDICT_PASS), VERDICT_MODIFY);
    assert_eq!(aggregate_verdict(VERDICT_MODIFY, VERDICT_DROP), VERDICT_DROP);
    assert_eq!(aggregate_verdict(VERDICT_DROP, VERDICT_MODIFY), VERDICT_DROP);
    assert_eq!(
        aggregate_verdict(VERDICT_PASS, VERDICT_MODIFY | VERDICT_PRESERVE_NEXT),
        VERDICT_MODIFY | VERDICT_PRESERVE_NEXT
    );
    assert_eq!(
        aggregate_verdict(VERDICT_MODIFY | VERDICT_PRESERVE_NEXT, VERDICT_DROP),
        VERDICT_DROP | VERDICT_PRESERVE_NEXT
    );
}

/// Verifies `VERDICT_MODIFY` updates wire checksums and `VERDICT_PRESERVE_NEXT` preserves IPv6 `next` fields.
#[test]
fn verdict_modify_reconstructs_checksums_and_preserves_ipv6_next()
{
    let toml = r#"
        lua_init = [
            { inline = """
                function tamper_ipv4(ctx, desync)
                    desync.dis.ip.ip_ttl = 7
                    desync.dis.tcp.th_win = 4321
                    desync.dis.payload = "MODIFIED_PAYLOAD"
                    return VERDICT_MODIFY
                end
                function tamper_ipv6_preserve(ctx, desync)
                    desync.dis.ip6.exthdr[1].next = 253
                    return bitor(VERDICT_MODIFY, VERDICT_PRESERVE_NEXT)
                end
            """ }
        ]

        [[profiles]]
        name = "v4_tamper"
        filter_l3 = ["ipv4"]
        filter_tcp = ["80"]
        actions = [{ func = "tamper_ipv4" }]

        [[profiles]]
        name = "v6_preserve"
        filter_l3 = ["ipv6"]
        filter_tcp = ["80"]
        actions = [{ func = "tamper_ipv6_preserve" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine should init");

    // 1) IPv4 VERDICT_MODIFY updates fields and computes valid RFC checksums.
    let raw_v4 = build_ipv4_tcp(55000, 80, b"GET / HTTP/1.1\r\n\r\n");
    let pkt_v4 = QueuedPacket { packet_id: 20, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_v4 };
    let Decision::Replace(mod_v4) = engine.process_packet(&pkt_v4)
    else
    {
        panic!("expected Decision::Replace for IPv4 tamper");
    };
    let dis_v4 = dissect_packet(&mod_v4, false);
    let ip = dis_v4
        .ip
        .as_ref()
        .expect("ip");
    let tcp = dis_v4
        .tcp
        .as_ref()
        .expect("tcp");
    assert_eq!(ip.ttl, 7);
    assert_eq!(tcp.window, 4321);
    assert_eq!(
        dis_v4
            .payload
            .as_deref(),
        Some(b"MODIFIED_PAYLOAD".as_slice())
    );
    assert_eq!(
        ip.checksum,
        ipv4_header_checksum(&mod_v4[..dis_v4.l3_len]).expect("valid ipv4 header"),
        "reconstructed IPv4 header checksum must match RFC 1071"
    );
    let expected_tcp_sum = tcp_ipv4_checksum(
        ip.src,
        ip.dst,
        &mod_v4[dis_v4.l3_len..dis_v4.l3_len + dis_v4.l4_len],
        &mod_v4[dis_v4.l3_len + dis_v4.l4_len..],
    );
    assert_eq!(tcp.checksum, expected_tcp_sum, "reconstructed TCP checksum must match RFC 793 computation");

    // 2) IPv6 VERDICT_MODIFY | VERDICT_PRESERVE_NEXT keeps custom exthdr[1].next = 253 at wire byte 40.
    let raw_v6 = build_ipv6_tcp(55001, 80, b"GET / HTTP/1.1\r\n\r\n");
    let pkt_v6 = QueuedPacket { packet_id: 21, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_v6 };
    let Decision::Replace(mod_v6) = engine.process_packet(&pkt_v6)
    else
    {
        panic!("expected Decision::Replace for IPv6 preserve");
    };
    assert_eq!(
        mod_v6[IP6_BASE_LEN], 253,
        "first extension header Next Header byte must remain 253 under VERDICT_PRESERVE_NEXT"
    );
}

/// Verifies `classify_baseline_payload` across TCP, UDP, ICMP, attached-IP ICMP, and raw IP packets.
#[test]
fn classify_baseline_payload_covers_all_milestone2_tags()
{
    let tcp_empty = dissect_packet(&build_ipv4_tcp(1234, 80, b""), false);
    assert_eq!(classify_baseline_payload(&tcp_empty), L7Payload::Empty);

    let tcp_data = dissect_packet(&build_ipv4_tcp(1234, 80, b"abc"), false);
    assert_eq!(classify_baseline_payload(&tcp_data), L7Payload::Unknown);

    let udp_data = dissect_packet(&build_ipv4_udp(1234, 53, b"q"), false);
    assert_eq!(classify_baseline_payload(&udp_data), L7Payload::Unknown);

    // Regular ICMP Echo Request -> Icmp.
    let icmp_echo = reconstruct_packet(
        &DissectedPacket {
            ip: Some(Ipv4Header {
                version: 4,
                header_len: 5,
                tos: 0,
                total_len: 0,
                id: 1,
                frag_off: 0,
                ttl: 64,
                protocol: IPPROTO_ICMP,
                checksum: 0,
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                options: Vec::new(),
            }),
            icmp: Some(IcmpHeader { icmp_type: ICMP_ECHO, icmp_code: 0, checksum: 0, data: 0x0001_0001 }),
            payload: Some(b"ping".to_vec()),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMP echo must reconstruct");
    assert_eq!(classify_baseline_payload(&dissect_packet(&icmp_echo, false)), L7Payload::Icmp);

    // ICMPv4 Dest Unreachable with attached IPv4 packet -> Ipv4.
    let inner_v4 = build_ipv4_tcp(3333, 443, b"inner");
    let icmp_unreach = reconstruct_packet(
        &DissectedPacket {
            ip: Some(Ipv4Header {
                version: 4,
                header_len: 5,
                tos: 0,
                total_len: 0,
                id: 2,
                frag_off: 0,
                ttl: 64,
                protocol: IPPROTO_ICMP,
                checksum: 0,
                src: [10, 0, 0, 254],
                dst: [10, 0, 0, 1],
                options: Vec::new(),
            }),
            icmp: Some(IcmpHeader { icmp_type: ICMP_DEST_UNREACH, icmp_code: 3, checksum: 0, data: 0 }),
            payload: Some(inner_v4),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMP unreach must reconstruct");
    assert_eq!(classify_baseline_payload(&dissect_packet(&icmp_unreach, false)), L7Payload::Ipv4);

    // ICMPv6 Packet Too Big with attached IPv6 packet -> Ipv6.
    let inner_v6 = build_ipv6_tcp(4444, 443, b"inner6");
    let icmp6_ptb = reconstruct_packet(
        &DissectedPacket {
            ip6: Some(Ipv6Header {
                flow: 0x6000_0000,
                payload_len: None,
                next_header: IPPROTO_ICMPV6,
                hop_limit: 64,
                src: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                dst: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                exthdr: Vec::new(),
            }),
            icmp: Some(IcmpHeader { icmp_type: ICMP6_PACKET_TOO_BIG, icmp_code: 0, checksum: 0, data: 1280 }),
            payload: Some(inner_v6),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMPv6 PTB must reconstruct");
    assert_eq!(classify_baseline_payload(&dissect_packet(&icmp6_ptb, false)), L7Payload::Ipv6);

    // Non-TCP/UDP/ICMP raw IP protocol (ESP = 50) -> Unknown.
    let raw_esp = reconstruct_packet(
        &DissectedPacket {
            ip: Some(Ipv4Header {
                version: 4,
                header_len: 5,
                tos: 0,
                total_len: 0,
                id: 3,
                frag_off: 0,
                ttl: 64,
                protocol: 50,
                checksum: 0,
                src: [10, 0, 0, 1],
                dst: [10, 0, 0, 2],
                options: Vec::new(),
            }),
            payload: Some(b"esp_bytes".to_vec()),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ESP packet must reconstruct");
    assert_eq!(classify_baseline_payload(&dissect_packet(&raw_esp, false)), L7Payload::Unknown);
}
