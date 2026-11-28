//! Integration tests verifying `LuaRuntime` against `zapret2`'s unmodified `zapret-lib.lua`
//! and `zapret-tests.lua`, plus mocked `rawsend` / `rawsend_dissect` packet capture assertions.

/// Interior mutability and single-thread sharing for capturing mocked `PacketSender` packets.
use std::cell::RefCell;
/// Standard IP address enum for checking injected destination addresses.
use std::net::IpAddr;
/// Filesystem paths pointing to the sibling `zapret2` Lua suite.
use std::path::Path;
/// Single-thread reference counting for passing [`CapturingSender`] into [`LuaRuntime`].
use std::rc::Rc;

/// Embedded `zapret2`-compatible LuaJIT runtime and config struct.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// Dissected packet checksums and protocol constants used to verify mocked raw sends.
use zapret_rs::packet::checksum::udp_ipv4_checksum;
/// Protocol constants used when validating captured packets.
use zapret_rs::packet::constants::{
    IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IPIP,
    IPPROTO_TCP, IPPROTO_UDP,
};
/// Packet dissector used to verify captured `rawsend_dissect` wire bytes.
use zapret_rs::packet::dissecter::dissect_packet;
/// Raw socket sender trait and error type implemented by [`CapturingSender`].
use zapret_rs::rawsend::{PacketSender, RawSendError};

/// Path to `zapret2`'s unmodified `zapret-lib.lua`.
const ZAPRET_LIB_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-lib.lua");
/// Path to `zapret2`'s unmodified `zapret-tests.lua`.
const ZAPRET_TESTS_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-tests.lua");

/// One packet injection call captured by [`CapturingSender`].
#[derive(Debug, Clone)]
struct CapturedPacket
{
    /// Destination IP passed to `PacketSender::send`.
    dst: IpAddr,
    /// Effective firewall mark (`opts.fwmark | config.desync_fwmark`).
    fwmark: u32,
    /// Optional outgoing interface name (`opts.ifout`).
    ifout: Option<String>,
    /// Exact serialized L3 wire packet bytes.
    data: Vec<u8>,
}

/// Mock [`PacketSender`] recording every packet emitted by Lua `rawsend` / `rawsend_dissect`.
#[derive(Default)]
struct CapturingSender
{
    /// Ordered log of transmitted packets.
    packets: Vec<CapturedPacket>,
}

impl PacketSender for CapturingSender
{
    /// Records an outgoing raw packet without opening a `CAP_NET_RAW` socket.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>
    {
        self.packets.push(CapturedPacket {
            dst,
            fwmark,
            ifout: ifout.map(str::to_owned),
            data: packet.to_vec(),
        });
        Ok(())
    }
}

/// Creates a [`LuaRuntime`] preloaded with unmodified `zapret-lib.lua` and `zapret-tests.lua`.
fn runtime_with_zapret_tests(sender: Rc<RefCell<CapturingSender>>) -> LuaRuntime
{
    let config = LuaConfig { desync_fwmark: 0x4000_0000, ..LuaConfig::default() };
    let rt = LuaRuntime::with_sender(config, sender).expect("LuaRuntime should initialize");
    rt.exec_file(Path::new(ZAPRET_LIB_LUA)).expect("zapret-lib.lua should load cleanly");
    rt.exec_file(Path::new(ZAPRET_TESTS_LUA)).expect("zapret-tests.lua should load cleanly");
    rt
}

/// Verifies `harden_lua` removes dangerous OS, I/O, FFI-load, and debug primitives.
#[test]
fn lua_security_hardening_removes_dangerous_globals()
{
    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    rt.exec_str(
        r#"
        assert(os.execute == nil, "os.execute must be nil")
        assert(io.popen == nil, "io.popen must be nil")
        assert(package.loadlib == nil, "package.loadlib must be nil")
        assert(debug == nil, "debug must be nil")
        assert(package.loaded.debug == nil, "package.loaded.debug must be nil")
        assert(NFQWS2_COMPAT_VER == 6, "compat version must equal 6")
        "#,
    )
    .expect("hardening assertions must pass");
}

/// Runs `zapret2`'s unmodified `test_bin`, `test_bop`, `test_random`, and `test_ipstr` suites.
#[test]
fn zapret_tests_binary_crypto_random_and_ipstr_pass()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = runtime_with_zapret_tests(sender);
    rt.exec_str(
        r#"
        test_bin()
        test_bop()
        test_random()
        test_ipstr()
        "#,
    )
    .expect("zapret-tests binary/bop/random/ipstr tests must pass");
}

/// Runs `zapret2`'s unmodified `test_dissect` (20 randomized rounds) and `test_csum` suites.
#[test]
fn zapret_tests_dissect_and_checksum_suites_pass()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = runtime_with_zapret_tests(sender);
    rt.exec_str(
        r#"
        test_dissect()
        test_csum()
        "#,
    )
    .expect("zapret-tests dissect and csum suites must pass");
}

/// Runs `zapret2`'s unmodified `test_get_source_ip` and `test_ifaddrs` suites.
#[test]
fn zapret_tests_network_topology_suites_pass()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = runtime_with_zapret_tests(sender);
    rt.exec_str(
        r#"
        test_get_source_ip()
        test_ifaddrs()
        "#,
    )
    .expect("zapret-tests get_source_ip and ifaddrs suites must pass");
}

/// Verifies `rawsend` and `rawsend_dissect` across repeats, fwmarks, interfaces, `badsum`,
/// IPv4/IPv6 `ipfrag2` (with HOPOPTS/DSTOPTS and `ip6_preserve_next`), ICMP, and IPIP via mock sender.
#[test]
fn lua_rawsend_and_rawsend_dissect_emit_valid_wire_packets()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = runtime_with_zapret_tests(Rc::clone(&sender));

    rt.exec_str(
        r#"
        local payload = string.rep("A", 160)
        local ip4 = {
            ip_tos = 0,
            ip_id = 0x1234,
            ip_off = 0,
            ip_ttl = 64,
            ip_p = IPPROTO_UDP,
            ip_src = pton("10.1.1.1"),
            ip_dst = pton("10.1.1.2"),
        }
        local udp = { uh_sport = 40000, uh_dport = 443 }
        local dis4 = { ip = ip4, udp = udp, payload = payload }

        -- 1) rawsend_dissect with repeats, fwmark, ifout (3 packets)
        assert(rawsend_dissect(dis4, { repeats = 3, fwmark = 0x50EA, ifout = "eth9" }))

        -- 2) rawsend_dissect with badsum (1 packet)
        assert(rawsend_dissect(dis4, { fwmark = 0x1 }, { badsum = true }))

        -- 3) rawsend direct bytes (2 packets)
        local raw_udp = reconstruct_dissect(dis4)
        assert(rawsend(raw_udp, { repeats = 2, fwmark = 0x20 }))

        -- 4) IPv4 UDP ipfrag2 (2 fragments)
        local frags4 = ipfrag2(dis4, { ipfrag_pos_udp = 80 })
        assert(#frags4 == 2)
        for _, f in ipairs(frags4) do
            assert(rawsend_dissect(f))
        end

        -- 5) IPv6 UDP with HOPOPTS + two DSTOPTS + ipfrag2 + custom ipfrag_next + ip6_preserve_next (2 fragments)
        local ip6 = {
            ip6_flow = 0x6000AE38,
            ip6_hlim = 64,
            ip6_src = pton("fd00::1"),
            ip6_dst = pton("fd00::2"),
            exthdr = {
                { type = IPPROTO_HOPOPTS, data = "\x00\x00\x00\x00\x00\x00" },
            },
        }
        insert_ip6_exthdr(ip6, nil, IPPROTO_DSTOPTS, "\x00\x00\x00\x00\x00\x00")
        insert_ip6_exthdr(ip6, nil, IPPROTO_DSTOPTS, "\x00\x00\x00\x00\x00\x00")
        local dis6 = { ip6 = ip6, udp = udp, payload = payload }
        fix_ip_proto(dis6)
        local frags6 = ipfrag2(dis6, { ipfrag_pos_udp = 72, ipfrag_next = IPPROTO_TCP })
        assert(#frags6 == 2)
        for _, f in ipairs(frags6) do
            assert(rawsend_dissect(f, { fwmark = 0x409A }, { ip6_preserve_next = true }))
        end

        -- 6) ICMPv4 and ICMPv6 (2 packets)
        local icmp4 = { icmp_type = ICMP_ECHO, icmp_code = 0, icmp_data = 0x12340001 }
        assert(rawsend_dissect({ ip = {
            ip_tos = 0, ip_id = 1, ip_off = 0, ip_ttl = 64, ip_p = IPPROTO_ICMP,
            ip_src = pton("10.1.1.1"), ip_dst = pton("10.1.1.2"),
        }, icmp = icmp4, payload = "ping4" }))

        local icmp6 = { icmp_type = ICMP6_ECHO_REQUEST, icmp_code = 0, icmp_data = 0x12340002 }
        assert(rawsend_dissect({ ip6 = {
            ip6_flow = 0x60000000, ip6_hlim = 64,
            ip6_src = pton("fd00::1"), ip6_dst = pton("fd00::2"),
        }, icmp = icmp6, payload = "ping6" }))

        -- 7) IPv4 IPIP and IPv6 IPIP (2 packets)
        local dis_ipip4 = { ip = {
            ip_tos = 0, ip_id = 2, ip_off = 0, ip_ttl = 64, ip_p = IPPROTO_IPIP,
            ip_src = pton("10.1.1.1"), ip_dst = pton("10.1.1.2"),
        }, payload = raw_udp }
        assert(rawsend_dissect(dis_ipip4))

        local dis_ipip6 = { ip6 = {
            ip6_flow = 0x6000583F, ip6_hlim = 64,
            ip6_src = pton("fd00::1"), ip6_dst = pton("fd00::2"),
        }, payload = raw_udp }
        assert(rawsend_dissect(dis_ipip6, nil, { ip6_last_proto = IPPROTO_IPIP }))
        "#,
    )
    .expect("Lua rawsend scenarios must execute without error");

    let captured = &sender.borrow().packets;
    assert_eq!(captured.len(), 14, "expected 3+1+2+2+2+2+2 = 14 packets");

    // Verify first 3 repeated IPv4 UDP packets: fwmark OR'd with desync_fwmark, ifout, valid UDP checksum.
    let expected_v4_dst: IpAddr = "10.1.1.2".parse().expect("valid IPv4");
    let expected_v6_dst: IpAddr = "fd00::2".parse().expect("valid IPv6");
    for pkt in &captured[0..3]
    {
        assert_eq!(pkt.dst, expected_v4_dst);
        assert_eq!(pkt.fwmark, 0x4000_50EA);
        assert_eq!(pkt.ifout.as_deref(), Some("eth9"));
        let dis = dissect_packet(&pkt.data, false);
        assert_eq!(dis.l4proto, IPPROTO_UDP);
        assert_eq!(dis.payload.as_ref().expect("pl").len(), 160);
    }

    // Verify `badsum = true` corrupted the UDP checksum compared to the valid packet.
    let good_udp_sum = dissect_packet(&captured[0].data, false).udp.expect("good").checksum;
    let bad_udp = dissect_packet(&captured[3].data, false).udp.expect("bad");
    assert_ne!(bad_udp.checksum, good_udp_sum);
    assert_ne!(bad_udp.checksum, 0);
    // Double-check against pure Rust RFC checksum helper.
    let expected_good_sum =
        udp_ipv4_checksum([10, 1, 1, 1], [10, 1, 1, 2], &captured[0].data[20..28], &captured[0].data[28..]);
    assert_eq!(good_udp_sum, expected_good_sum);

    // Verify direct `rawsend` repeats.
    for pkt in &captured[4..6]
    {
        assert_eq!(pkt.fwmark, 0x4000_0020);
        assert_eq!(pkt.data, captured[0].data);
    }

    // Verify IPv4 UDP fragments (indices 6, 7).
    let f4_1 = dissect_packet(&captured[6].data, false);
    let f4_2 = dissect_packet(&captured[7].data, false);
    assert_eq!(f4_1.frag_off, Some(0));
    assert_eq!(f4_2.frag_off, Some(80));

    // Verify IPv6 UDP fragments (indices 8, 9): HOPOPTS, DSTOPTS, FRAGMENT, DSTOPTS2, plus forged TCP next on frag 2.
    let f6_1 = dissect_packet(&captured[8].data, false);
    let f6_2 = dissect_packet(&captured[9].data, false);
    assert_eq!(captured[8].dst, expected_v6_dst);
    assert_eq!(captured[8].fwmark, 0x4000_409A);
    assert_eq!(f6_1.frag_off, Some(0));
    let exts_1 = &f6_1.ip6.as_ref().expect("ip6").exthdr;
    assert_eq!(exts_1[0].header_type, IPPROTO_HOPOPTS);
    assert_eq!(exts_1[1].header_type, IPPROTO_DSTOPTS);
    assert_eq!(exts_1[2].header_type, IPPROTO_FRAGMENT);
    assert_eq!(exts_1[3].header_type, IPPROTO_DSTOPTS);
    assert_eq!(f6_2.frag_off, Some(72));
    assert_eq!(f6_2.l4proto, IPPROTO_TCP);

    // Verify ICMPv4, ICMPv6, IPv4 IPIP, IPv6 IPIP (indices 10..14).
    assert_eq!(dissect_packet(&captured[10].data, false).l4proto, IPPROTO_ICMP);
    assert_eq!(dissect_packet(&captured[11].data, false).l4proto, IPPROTO_ICMPV6);
    assert_eq!(dissect_packet(&captured[12].data, false).l4proto, IPPROTO_IPIP);
    assert_eq!(dissect_packet(&captured[13].data, false).l4proto, IPPROTO_IPIP);
}
