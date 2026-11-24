//! End-to-end integration tests for [`DesyncEngine`], Lua desync context bindings,
//! verdict aggregation, wire reconstruction, and `zapret-lib.lua` orchestration.

/// Interior mutability and single-thread sharing for recording mocked [`PacketSender`] packets.
use std::cell::RefCell;
/// Standard IP address type for checking captured destination addresses.
use std::net::IpAddr;
/// Single-thread reference counting for passing mocked senders into [`DesyncEngine`].
use std::rc::Rc;

/// Configuration schema parsing for TOML profiles and blobs.
use zapret_rs::config::{AppConfig, L7Payload};
/// Core desync engine, verdict aggregator, and baseline payload classifier.
use zapret_rs::desync::{DesyncEngine, aggregate_verdict, classify_baseline_payload};
/// NFQUEUE packet metadata, decision enum, and fwmark dispatch guard.
use zapret_rs::intercepter::{Decision, QueuedPacket, dispatch_packet};
/// Lua error type for checking missing function validation at startup.
use zapret_rs::lua::LuaEngineError;
/// Packet checksum helpers for validating modified packet checksums.
use zapret_rs::packet::checksum::{ipv4_header_checksum, tcp_ipv4_checksum};
/// Wire protocol and verdict constants used across synthetic packets and assertions.
use zapret_rs::packet::constants::{
    DEFAULT_MSS, ICMP_DEST_UNREACH, ICMP_ECHO, ICMP6_PACKET_TOO_BIG, IP6_BASE_LEN,
    IPPROTO_HOPOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, TH_ACK, TH_PUSH,
    VERDICT_DROP, VERDICT_MODIFY, VERDICT_PASS, VERDICT_PRESERVE_NEXT,
};
/// Wire packet dissection and reconstruction helpers for synthetic test frames.
use zapret_rs::packet::{
    DissectedPacket, IcmpHeader, Ipv4Header, Ipv6ExtHeader, Ipv6Header, ReconstructOptions,
    TcpHeader, UdpHeader, dissect_packet, reconstruct_packet,
};
/// Raw packet sender trait implemented by the local test capture sink.
use zapret_rs::rawsend::{PacketSender, RawSendError};

/// Path to `zapret2`'s unmodified `zapret-lib.lua`.
const ZAPRET_LIB_LUA: &str = "/home/morier/Documents/projects/zapret2/lua/zapret-lib.lua";

/// One packet captured from Lua `rawsend` / `rawsend_dissect` during desync execution.
#[derive(Debug, Clone)]
struct CapturedPacket {
    /// Destination IP passed to `PacketSender::send`.
    dst: IpAddr,
    /// Effective firewall mark applied to the outgoing socket.
    fwmark: u32,
    /// Optional outgoing interface override.
    ifout: Option<String>,
    /// Serialized L3/L4 wire bytes.
    data: Vec<u8>,
}

/// Mock [`PacketSender`] recording injected packets without `CAP_NET_RAW`.
#[derive(Default)]
struct CapturingSender {
    /// Ordered list of injected packets.
    packets: Vec<CapturedPacket>,
}

impl PacketSender for CapturingSender {
    /// Records one outgoing raw packet into `self.packets`.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError> {
        self.packets.push(CapturedPacket {
            dst,
            fwmark,
            ifout: ifout.map(str::to_owned),
            data: packet.to_vec(),
        });
        Ok(())
    }
}

/// Builds a valid IPv4 + TCP wire packet with RFC-compliant checksums.
fn build_ipv4_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x1234,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: [10, 0, 0, 2],
            dst: [93, 184, 216, 34],
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: src_port,
            d_port: dst_port,
            seq: 1000,
            ack: 2000,
            reserved: 0,
            data_offset: 5,
            flags: TH_ACK | TH_PUSH,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv4 TCP packet must reconstruct")
}

/// Builds a valid IPv4 + UDP wire packet with RFC-compliant checksums.
fn build_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x2222,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_UDP,
            checksum: 0,
            src: [10, 0, 0, 2],
            dst: [8, 8, 8, 8],
            options: Vec::new(),
        }),
        udp: Some(UdpHeader {
            s_port: src_port,
            d_port: dst_port,
            len: 0,
            checksum: 0,
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv4 UDP packet must reconstruct")
}

/// Builds a valid IPv6 + Hop-by-Hop + TCP wire packet.
fn build_ipv6_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let dis = DissectedPacket {
        ip6: Some(Ipv6Header {
            flow: 0x6000_0001,
            payload_len: None,
            next_header: IPPROTO_HOPOPTS,
            hop_limit: 64,
            src: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            exthdr: vec![Ipv6ExtHeader {
                header_type: IPPROTO_HOPOPTS,
                next_header: IPPROTO_TCP,
                data: vec![0; 6],
            }],
        }),
        tcp: Some(TcpHeader {
            s_port: src_port,
            d_port: dst_port,
            seq: 500,
            ack: 1,
            reserved: 0,
            data_offset: 5,
            flags: TH_ACK,
            window: 32768,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv6 TCP packet must reconstruct")
}

/// Verifies profile matching, first-match precedence, and `dispatch_packet` fwmark suppression.
#[test]
fn profile_matching_first_match_and_fwmark_loop_guard() {
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
    let pkt_443 = QueuedPacket {
        packet_id: 1,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_443,
    };
    assert_eq!(engine.process_packet(&pkt_443), Decision::Drop);

    // 2) Packet carrying `desync_fwmark` is bypassed by `dispatch_packet` before reaching engine.
    let pkt_marked = QueuedPacket {
        mark: 0x4000_0001,
        ..pkt_443.clone()
    };
    let decision = dispatch_packet(&pkt_marked, cfg.fwmark, &mut |p| engine.process_packet(p));
    assert_eq!(decision, Decision::Pass);

    // 3) UDP 53 matches profile 2 (not fallback), returns Pass, sets `_G.udp_hit`, never touches fallback.
    let raw_53 = build_ipv4_udp(40000, 53, b"\x12\x34dns");
    let pkt_53 = QueuedPacket {
        packet_id: 2,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_53,
    };
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
fn desync_table_fields_blob_substitution_and_verdict_precedence() {
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
        engine.runtime().config().qnum,
        u32::from(cfg.qnum),
        "runtime mirrors queue number"
    );
    assert_eq!(DEFAULT_MSS, 1220);

    let raw = build_ipv4_tcp(44444, 443, b"client_hello_bytes");
    let pkt = QueuedPacket {
        packet_id: 10,
        mark: 0x1234,
        ifin: None,
        ifout: Some("eth1"),
        payload: &raw,
    };

    // MODIFY + PASS => Replace with ttl=9.
    let Decision::Replace(modified) = engine.process_packet(&pkt) else {
        panic!("expected Decision::Replace from MODIFY + PASS");
    };
    let dis = dissect_packet(&modified, false);
    assert_eq!(dis.ip.as_ref().expect("ip").ttl, 9);

    // Pure `aggregate_verdict` truth table checks including VERDICT_PRESERVE_NEXT.
    assert_eq!(
        aggregate_verdict(VERDICT_PASS, VERDICT_MODIFY),
        VERDICT_MODIFY
    );
    assert_eq!(
        aggregate_verdict(VERDICT_MODIFY, VERDICT_PASS),
        VERDICT_MODIFY
    );
    assert_eq!(
        aggregate_verdict(VERDICT_MODIFY, VERDICT_DROP),
        VERDICT_DROP
    );
    assert_eq!(
        aggregate_verdict(VERDICT_DROP, VERDICT_MODIFY),
        VERDICT_DROP
    );
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
fn verdict_modify_reconstructs_checksums_and_preserves_ipv6_next() {
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
    let pkt_v4 = QueuedPacket {
        packet_id: 20,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_v4,
    };
    let Decision::Replace(mod_v4) = engine.process_packet(&pkt_v4) else {
        panic!("expected Decision::Replace for IPv4 tamper");
    };
    let dis_v4 = dissect_packet(&mod_v4, false);
    let ip = dis_v4.ip.as_ref().expect("ip");
    let tcp = dis_v4.tcp.as_ref().expect("tcp");
    assert_eq!(ip.ttl, 7);
    assert_eq!(tcp.window, 4321);
    assert_eq!(dis_v4.payload.as_deref(), Some(b"MODIFIED_PAYLOAD".as_slice()));
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
    assert_eq!(
        tcp.checksum, expected_tcp_sum,
        "reconstructed TCP checksum must match RFC 793 computation"
    );

    // 2) IPv6 VERDICT_MODIFY | VERDICT_PRESERVE_NEXT keeps custom exthdr[1].next = 253 at wire byte 40.
    let raw_v6 = build_ipv6_tcp(55001, 80, b"GET / HTTP/1.1\r\n\r\n");
    let pkt_v6 = QueuedPacket {
        packet_id: 21,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_v6,
    };
    let Decision::Replace(mod_v6) = engine.process_packet(&pkt_v6) else {
        panic!("expected Decision::Replace for IPv6 preserve");
    };
    assert_eq!(
        mod_v6[IP6_BASE_LEN], 253,
        "first extension header Next Header byte must remain 253 under VERDICT_PRESERVE_NEXT"
    );
}

/// Verifies `raw_packet(ctx)`, re-entrant `rawsend_dissect`, `VERDICT_DROP`, and post-call `ctx` invalidation.
#[test]
fn reentrant_rawsend_dissect_and_stashed_ctx_invalidation() {
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let toml = r#"
        fwmark = 0x40000000
        lua_init = [
            { inline = """
                function send_fake_and_drop(ctx, desync)
                    local raw = raw_packet(ctx)
                    assert(raw == _G.expected_raw, "raw_packet(ctx) must return exact wire bytes")
                    desync.dis.ip.ip_ttl = 1
                    assert(rawsend_dissect(desync.dis, { fwmark = 0x10, ifout = desync.ifout }))
                    _G.leaked_ctx = ctx
                    return VERDICT_DROP
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["443"]
        actions = [{ func = "send_fake_and_drop" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let sender_trait: Rc<RefCell<dyn PacketSender>> = Rc::clone(&sender) as _;
    let engine = DesyncEngine::with_sender(&cfg, sender_trait)
        .expect("engine with mock sender should init");

    let raw = build_ipv4_tcp(41234, 443, b"tls_hello");
    let lua_expected = engine
        .runtime()
        .lua()
        .create_string(&raw)
        .expect("Lua byte string");
    engine
        .runtime()
        .lua()
        .globals()
        .set("expected_raw", lua_expected)
        .expect("set expected_raw");

    let pkt = QueuedPacket {
        packet_id: 30,
        mark: 0,
        ifin: None,
        ifout: Some("wlan0"),
        payload: &raw,
    };
    assert_eq!(engine.process_packet(&pkt), Decision::Drop);

    let captured = &sender.borrow().packets;
    assert_eq!(captured.len(), 1);
    assert_eq!(
        captured[0].dst,
        "93.184.216.34".parse::<IpAddr>().expect("valid IPv4 dst")
    );
    assert_eq!(captured[0].fwmark, 0x4000_0010);
    assert_eq!(captured[0].ifout.as_deref(), Some("wlan0"));
    let sent_dis = dissect_packet(&captured[0].data, false);
    assert_eq!(sent_dis.ip.as_ref().expect("ip").ttl, 1);

    // Calling raw_packet on the leaked ctx after return must error with "ctx is invalid".
    let leaked_err = engine
        .runtime()
        .exec_str("raw_packet(_G.leaked_ctx)")
        .expect_err("leaked ctx must be invalidated after action returns");
    assert!(
        leaked_err.to_string().contains("ctx is invalid"),
        "unexpected error: {leaked_err}"
    );
}

/// Verifies `zapret2/lua/zapret-lib.lua`'s `desync_orchestrator_example` with `execution_plan` and cutoffs.
#[test]
fn zapret_lib_orchestrator_runs_execution_plan_once_and_allows_cutoffs() {
    let toml = format!(
        r#"
        lua_init = [
            "{ZAPRET_LIB_LUA}",
            {{ inline = """
                function custom_step_1(ctx, desync)
                    _G.step1_calls = (_G.step1_calls or 0) + 1
                    assert(desync.arg.blob == fake_default_http)
                    instance_cutoff(ctx)
                    return VERDICT_PASS
                end
                function custom_step_2(ctx, desync)
                    _G.step2_calls = (_G.step2_calls or 0) + 1
                    desync.dis.payload = "ORCH_DONE"
                    return VERDICT_MODIFY
                end
                function test_cutoffs(ctx, desync)
                    instance_cutoff(ctx)
                    instance_cutoff(ctx, true)
                    lua_cutoff(ctx)
                    lua_cutoff(ctx, false)
                    local plan = execution_plan(ctx)
                    assert(#plan == 0)
                    return VERDICT_PASS
                end
            """ }}
        ]

        [[profiles]]
        name = "orch_profile"
        filter_tcp = ["80"]

        [[profiles.actions]]
        func = "desync_orchestrator_example"

        [[profiles.actions]]
        func = "custom_step_1"
        args = {{ blob = "%fake_default_http" }}

        [[profiles.actions]]
        func = "custom_step_2"

        [[profiles]]
        name = "cutoff_profile"
        filter_tcp = ["8080"]
        actions = [{{ func = "test_cutoffs" }}]
    "#
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine with zapret-lib.lua should initialize");

    // 1) Orchestrator cancels native calls to custom_step_1/2, replays each exactly once, and modifies packet.
    let raw_80 = build_ipv4_tcp(45000, 80, b"GET / HTTP/1.1\r\n\r\n");
    let pkt_80 = QueuedPacket {
        packet_id: 40,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_80,
    };
    let Decision::Replace(mod_80) = engine.process_packet(&pkt_80) else {
        panic!("expected Decision::Replace from orchestrated replay");
    };
    let dis_80 = dissect_packet(&mod_80, false);
    assert_eq!(dis_80.payload.as_deref(), Some(b"ORCH_DONE".as_slice()));

    engine
        .runtime()
        .exec_str(
            r#"
            assert(_G.step1_calls == 1, "custom_step_1 must execute once, not twice")
            assert(_G.step2_calls == 1, "custom_step_2 must execute once, not twice")
            "#,
        )
        .expect("call counts verified");

    // 2) Direct instance_cutoff / lua_cutoff calls work cleanly; lua_cutoff(nil) errors "missing ctx".
    let raw_8080 = build_ipv4_tcp(45001, 8080, b"hi");
    let pkt_8080 = QueuedPacket {
        packet_id: 41,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &raw_8080,
    };
    assert_eq!(engine.process_packet(&pkt_8080), Decision::Pass);

    let nil_err = engine
        .runtime()
        .exec_str("lua_cutoff(nil)")
        .expect_err("lua_cutoff(nil) must reject missing ctx");
    assert!(
        nil_err.to_string().contains("missing ctx"),
        "unexpected error: {nil_err}"
    );
}

/// Verifies missing desync functions fail startup and runtime/verdict errors degrade to `Decision::Pass`.
#[test]
fn startup_missing_function_fails_and_runtime_errors_degrade_to_pass() {
    let missing_cfg = AppConfig::from_toml_str(
        r#"
        [[profiles]]
        actions = [{ func = "does_not_exist" }]
        "#,
        None,
    )
    .expect("TOML parses cleanly");
    let err = match DesyncEngine::new(&missing_cfg) {
        Ok(_) => panic!("expected MissingFunction error"),
        Err(err) => err,
    };
    assert!(matches!(err, LuaEngineError::MissingFunction(ref name) if name == "does_not_exist"));

    let toml = r#"
        lua_init = [
            { inline = """
                function act_error(ctx, desync) error("boom") end
                function act_str(ctx, desync) return "bad" end
                function act_float(ctx, desync) return 1.5 end
                function act_range(ctx, desync) return 99 end
                function act_multi(ctx, desync) return VERDICT_PASS, VERDICT_DROP end
                function act_ok(ctx, desync) return VERDICT_PASS end
                function act_corrupt_dis(ctx, desync)
                    desync.dis = "not_a_table"
                    return VERDICT_MODIFY
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["1001"]
        actions = [{ func = "act_error" }]

        [[profiles]]
        filter_tcp = ["1002"]
        actions = [{ func = "act_str" }]

        [[profiles]]
        filter_tcp = ["1003"]
        actions = [{ func = "act_float" }]

        [[profiles]]
        filter_tcp = ["1004"]
        actions = [{ func = "act_range" }]

        [[profiles]]
        filter_tcp = ["1005"]
        actions = [{ func = "act_multi" }]

        [[profiles]]
        filter_tcp = ["1006"]
        actions = [{ func = "act_ok", args = { bad = "%missing_blob" } }]

        [[profiles]]
        filter_tcp = ["1007"]
        actions = [{ func = "act_corrupt_dis" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("all functions defined");

    for port in 1001..=1007 {
        let raw = build_ipv4_tcp(40000, port, b"payload");
        let pkt = QueuedPacket {
            packet_id: u32::from(port),
            mark: 0,
            ifin: None,
            ifout: Some("eth0"),
            payload: &raw,
        };
        assert_eq!(
            engine.process_packet(&pkt),
            Decision::Pass,
            "error case on port {port} must degrade safely to Decision::Pass"
        );
    }
}

/// Verifies `classify_baseline_payload` across TCP, UDP, ICMP, attached-IP ICMP, and raw IP packets.
#[test]
fn classify_baseline_payload_covers_all_milestone2_tags() {
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
            icmp: Some(IcmpHeader {
                icmp_type: ICMP_ECHO,
                icmp_code: 0,
                checksum: 0,
                data: 0x0001_0001,
            }),
            payload: Some(b"ping".to_vec()),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMP echo must reconstruct");
    assert_eq!(
        classify_baseline_payload(&dissect_packet(&icmp_echo, false)),
        L7Payload::Icmp
    );

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
            icmp: Some(IcmpHeader {
                icmp_type: ICMP_DEST_UNREACH,
                icmp_code: 3,
                checksum: 0,
                data: 0,
            }),
            payload: Some(inner_v4),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMP unreach must reconstruct");
    assert_eq!(
        classify_baseline_payload(&dissect_packet(&icmp_unreach, false)),
        L7Payload::Ipv4
    );

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
            icmp: Some(IcmpHeader {
                icmp_type: ICMP6_PACKET_TOO_BIG,
                icmp_code: 0,
                checksum: 0,
                data: 1280,
            }),
            payload: Some(inner_v6),
            ..DissectedPacket::default()
        },
        &ReconstructOptions::default(),
    )
    .expect("ICMPv6 PTB must reconstruct");
    assert_eq!(
        classify_baseline_payload(&dissect_packet(&icmp6_ptb, false)),
        L7Payload::Ipv6
    );

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
    assert_eq!(
        classify_baseline_payload(&dissect_packet(&raw_esp, false)),
        L7Payload::Unknown
    );
}
