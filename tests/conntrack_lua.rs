//! Integration tests for `desync.track`, `lua_state`, `PacketRange` cutoffs, and `conntrack_feed`.

/// Shared mock [`PacketSender`] fixture.
mod common;

/// Interior mutability and single-thread sharing for injecting `CapturingSender`.
use std::cell::RefCell;
/// Single-thread reference counting for passing `CapturingSender` into [`DesyncEngine`].
use std::rc::Rc;

/// Application config parser for loading inline TOML profiles.
use zapret_rs::config::AppConfig;
/// Core desync engine dispatching tracked flows through Lua actions.
use zapret_rs::desync::DesyncEngine;
/// Intercepted packet metadata and kernel verdict enum.
use zapret_rs::intercepter::{Decision, QueuedPacket};
/// Packet constants for building synthetic TCP packets with handshake options.
use zapret_rs::packet::constants::{IPPROTO_TCP, TCP_KIND_MSS, TH_ACK, TH_PUSH, TH_SYN};
/// Wire packet types and reconstructor for building valid synthetic IPv4 TCP packets.
use zapret_rs::packet::{
    DissectedPacket, Ipv4Header, ReconstructOptions, TcpHeader, TcpOption, dissect_packet, reconstruct_packet,
};
/// Raw packet sender trait object coerced from [`common::CapturingSender`].
use zapret_rs::rawsend::PacketSender;

/// Shared mock sender recording outgoing packets.
use common::CapturingSender;

/// Builds a valid IPv4 + TCP packet between client (`10.0.0.2:41000`) and server (`93.184.216.34:443`).
#[allow(clippy::too_many_arguments)]
fn build_tcp4_pkt(
    from_server: bool,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: Vec<TcpOption>,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8>
{
    let (src, dst, s_port, d_port) = if from_server
    {
        ([93, 184, 216, 34], [10, 0, 0, 2], 443, 41000)
    }
    else
    {
        ([10, 0, 0, 2], [93, 184, 216, 34], 41000, 443)
    };
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x2222,
            frag_off: 0,
            ttl,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src,
            dst,
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port,
            d_port,
            seq,
            ack,
            reserved: 0,
            data_offset: 5,
            flags,
            window,
            checksum: 0,
            urgent_ptr: 0,
            options,
        }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid synthetic TCP packet")
}

/// Extension helper rewriting TCP destination port `443` to `80` with fixed checksums for test readability.
trait PortRewrite
{
    fn replace_port_443_to_80(self) -> Vec<u8>;
}

impl PortRewrite for Vec<u8>
{
    fn replace_port_443_to_80(self) -> Vec<u8>
    {
        let mut dis = dissect_packet(&self, false);
        if let Some(tcp) = dis
            .tcp
            .as_mut()
        {
            tcp.d_port = 80;
        }
        reconstruct_packet(&dis, &ReconstructOptions::default()).expect("rewrite port 80")
    }
}

/// Sends SYN, SYNACK, and 4 outgoing payloads over port 443 to trigger instance and lua cutoffs.
fn run_443_cutoff_sequence(engine: &DesyncEngine)
{
    let syn = build_tcp4_pkt(
        false,
        1000,
        0,
        TH_SYN,
        4096,
        vec![TcpOption { kind: TCP_KIND_MSS, data: Some(vec![0x05, 0xB4]) }],
        &[],
        64,
    );
    let synack = build_tcp4_pkt(
        true,
        2000,
        1001,
        TH_SYN | TH_ACK,
        4096,
        vec![TcpOption { kind: TCP_KIND_MSS, data: Some(vec![0x05, 0x78]) }],
        &[],
        55,
    );
    let d1 = build_tcp4_pkt(false, 1001, 2001, TH_ACK | TH_PUSH, 4096, vec![], b"payload1", 64);
    let d2 = build_tcp4_pkt(false, 1009, 2001, TH_ACK | TH_PUSH, 4096, vec![], b"payload2", 64);
    let d3 = build_tcp4_pkt(false, 1017, 2001, TH_ACK | TH_PUSH, 4096, vec![], b"payload3", 64);
    let d4 = build_tcp4_pkt(false, 1025, 2001, TH_ACK | TH_PUSH, 4096, vec![], b"payload4", 64);

    let out_pkt =
        |id, raw| QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("eth0"), payload: raw };
    let in_pkt =
        |id, raw| QueuedPacket { packet_id: id, mark: 0, ifin: Some("eth0"), ifout: None, payload: raw };

    assert_eq!(engine.process_packet(&out_pkt(1, &syn)), Decision::Pass);
    assert_eq!(engine.process_packet(&in_pkt(2, &synack)), Decision::Pass);
    assert_eq!(engine.process_packet(&out_pkt(3, &d1)), Decision::Pass);
    assert_eq!(engine.process_packet(&out_pkt(4, &d2)), Decision::Pass);
    assert_eq!(engine.process_packet(&out_pkt(5, &d3)), Decision::Drop);
    assert_eq!(engine.process_packet(&out_pkt(6, &d4)), Decision::Pass); // stopped by lua_out_cutoff
}

/// Verifies `desync.track` fields (`incoming_ttl`, aliasing, `lua_state`, `tcp_mss`), ranges, and cutoffs.
#[test]
fn desync_engine_exposes_track_lua_state_ranges_and_cutoffs()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let toml = r#"
        lua_init = [
            { inline = """
                _G.act1_calls = 0
                _G.act2_calls = 0
                _G.seen_vals = {}
                function inspect_and_cut_inst(ctx, desync)
                    assert(desync.track ~= nil)
                    assert(desync.track.incoming_ttl == 55)
                    assert(desync.track.l7proto == "unknown")
                    assert(desync.track.pos.dt >= 0)
                    assert(desync.track.pos.direct == desync.track.pos.client)
                    assert(desync.track.pos.reverse == desync.track.pos.server)
                    assert(desync.track.pos.client.tcp.mss == 1460)
                    assert(desync.tcp_mss == 1400)
                    assert(desync.reasm_data == "payload1" or desync.reasm_data == "payload2")
                    local st = desync.track.lua_state
                    st.count = (st.count or 0) + 1
                    _G.act1_calls = _G.act1_calls + 1
                    table.insert(_G.seen_vals, st.count)
                    instance_cutoff(ctx) -- cut off act1 on d1 so d2 skips it
                    return VERDICT_PASS
                end
                function cut_lua_at_d3(ctx, desync)
                    _G.act2_calls = _G.act2_calls + 1
                    lua_cutoff(ctx, true) -- cut off remaining outgoing traffic
                    return VERDICT_DROP
                end
                function auto_latched(ctx, desync)
                    _G.auto_calls = (_G.auto_calls or 0) + 1
                    return VERDICT_PASS
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["443"]
        [[profiles.actions]]
        out_range = "d1-d2"
        func = "inspect_and_cut_inst"
        [[profiles.actions]]
        out_range = "d3-d4"
        func = "cut_lua_at_d3"

        [[profiles]]
        filter_tcp = ["80"]
        [[profiles.actions]]
        out_range = "n1-n2"
        func = "auto_latched"
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("config parses");
    let sender_trait: Rc<RefCell<dyn PacketSender>> = Rc::clone(&sender) as _;
    let engine = DesyncEngine::with_sender(&cfg, sender_trait).expect("engine builds");

    run_443_cutoff_sequence(&engine);
    let out_pkt =
        |id, raw| QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("eth0"), payload: raw };

    engine
        .runtime()
        .exec_str(
            r#"
        assert(_G.act1_calls == 1, "instance_cutoff should stop d2")
        assert(_G.act2_calls == 1, "lua_cutoff should run once on d3 and stop d4")
        assert(#_G.seen_vals == 1 and _G.seen_vals[1] == 1)
    "#,
        )
        .expect("cutoff assertions pass");

    // Verify auto-cutoff latch on port 80 when n3 passes out_range="n1-n2".
    let syn80 = build_tcp4_pkt(false, 500, 0, TH_SYN, 4096, vec![], &[], 64).replace_port_443_to_80();
    let ack80 = build_tcp4_pkt(false, 501, 1, TH_ACK, 4096, vec![], &[], 64).replace_port_443_to_80();
    let ack80_3 = build_tcp4_pkt(false, 501, 1, TH_ACK, 4096, vec![], b"x", 64).replace_port_443_to_80();
    let _ = engine.process_packet(&out_pkt(10, &syn80));
    let _ = engine.process_packet(&out_pkt(11, &ack80));
    let _ = engine.process_packet(&out_pkt(12, &ack80_3));
    let (e80, _) = engine
        .runtime()
        .conntrack()
        .borrow()
        .double_search(&dissect_packet(&syn80, false))
        .expect("80 tracked");
    assert!(
        e80.borrow()
            .lua_out_cutoff
    );
}

/// Verifies `conntrack_feed` creates tracked state from Lua dissect/raw packets and propagates `ctx.ctrack`.
#[test]
fn lua_conntrack_feed_creates_and_propagates_ctrack_mid_profile()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let toml = r#"
        lua_init = [
            { inline = """
                _G.step1 = 0
                _G.step2 = 0
                function feed_step(ctx, desync)
                    assert(desync.track == nil)
                    _G.step1 = _G.step1 + 1
                    local t, out = conntrack_feed({
                        ip = desync.dis.ip,
                        tcp = {
                            th_sport = 41000, th_dport = 443,
                            th_seq = 900, th_ack = 0,
                            th_off = 5, th_flags = TH_SYN, th_win = 4096
                        }
                    })
                    assert(t ~= nil and out == true)
                    return VERDICT_PASS
                end
                function post_feed_step(ctx, desync)
                    _G.step2 = _G.step2 + 1
                    return VERDICT_DROP
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["443"]
        [[profiles.actions]]
        out_range = "a"
        func = "feed_step"
        [[profiles.actions]]
        out_range = "n1-n1"
        func = "post_feed_step"
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("config parses");
    let sender_trait: Rc<RefCell<dyn PacketSender>> = Rc::clone(&sender) as _;
    let engine = DesyncEngine::with_sender(&cfg, sender_trait).expect("engine builds");

    // Mid-stream packet is untracked until step 1 invokes `conntrack_feed`.
    let mid = build_tcp4_pkt(false, 901, 1, TH_ACK | TH_PUSH, 4096, vec![], b"mid", 64);
    let decision = engine.process_packet(&QueuedPacket {
        packet_id: 99,
        mark: 0,
        ifin: None,
        ifout: Some("eth0"),
        payload: &mid,
    });
    assert_eq!(decision, Decision::Drop);
    engine
        .runtime()
        .exec_str("assert(_G.step1 == 1 and _G.step2 == 1)")
        .expect("mid-profile propagation");

    // Raw-string conntrack_feed and invalid type error handling.
    engine
        .runtime()
        .set_blob("raw_syn", &build_tcp4_pkt(false, 123, 0, TH_SYN, 4096, vec![], &[], 64))
        .unwrap();
    engine
        .runtime()
        .exec_str(
            r#"
        local t, out = conntrack_feed(raw_syn)
        assert(t ~= nil and out == true and t.pos.client.tcp.seq0 == 123)
    "#,
        )
        .expect("raw string conntrack_feed succeeds");
    assert!(
        engine
            .runtime()
            .exec_str("conntrack_feed(42)")
            .is_err()
    );
}
