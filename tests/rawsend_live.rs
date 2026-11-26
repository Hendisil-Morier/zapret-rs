//! Live kernel `SOCK_RAW` loopback injection and `ipfrag2` integration tests (run in `unshare -r -n` or as root).
#![cfg(target_os = "linux")]

/// Error kind matching for expected kernel checksum-drop timeouts on `recv_from`.
use std::io::ErrorKind;
/// Standard IP addresses and UDP loopback sockets used to capture kernel-delivered packets.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
/// Path resolution for loading `zapret2/lua/zapret-lib.lua`.
use std::path::Path;
/// Socket read timeout configuration for loopback delivery and negative-drop checks.
use std::time::Duration;

/// LuaJIT runtime configuration and wrapper.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// Wire protocol constants used to construct IPv4/IPv6 loopback test datagrams.
use zapret_rs::packet::constants::{
    IP_DF, IPPROTO_DSTOPTS, IPPROTO_HOPOPTS, IPPROTO_NONE, IPPROTO_UDP, IPV6_DEFAULT_FLOW,
};
/// Packet reconstruction options and wire serializer.
use zapret_rs::packet::reconstruct::{ReconstructOptions, reconstruct_packet};
/// Dissected L3/L4 header containers.
use zapret_rs::packet::types::{
    DissectedPacket, Ipv4Header, Ipv6ExtHeader, Ipv6Header, UdpHeader,
};
/// Raw socket sender trait, Linux `RawSender`, and error variants.
use zapret_rs::rawsend::{PacketSender, RawSendError, RawSender};

/// Builds a wire-encoded IPv4 UDP loopback datagram (`127.0.0.1` -> `127.0.0.1`).
fn build_loopback_udp4(src_port: u16, dst_port: u16, payload: &[u8], badsum: bool) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x4242,
            frag_off: IP_DF,
            ttl: 64,
            protocol: IPPROTO_UDP,
            checksum: 0,
            src: Ipv4Addr::LOCALHOST.octets(),
            dst: Ipv4Addr::LOCALHOST.octets(),
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
    reconstruct_packet(
        &dis,
        &ReconstructOptions {
            badsum,
            ..ReconstructOptions::default()
        },
    )
    .expect("valid loopback IPv4 UDP packet should reconstruct")
}

/// Builds a wire-encoded IPv6 UDP loopback datagram (`::1` -> `::1`) with optional extension headers.
fn build_loopback_udp6(
    src_port: u16,
    dst_port: u16,
    exthdr: Vec<Ipv6ExtHeader>,
    payload: &[u8],
    badsum: bool,
) -> Vec<u8> {
    let dis = DissectedPacket {
        ip6: Some(Ipv6Header {
            flow: IPV6_DEFAULT_FLOW,
            payload_len: None,
            next_header: IPPROTO_NONE,
            hop_limit: 64,
            src: Ipv6Addr::LOCALHOST.octets(),
            dst: Ipv6Addr::LOCALHOST.octets(),
            exthdr,
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
    reconstruct_packet(
        &dis,
        &ReconstructOptions {
            badsum,
            ..ReconstructOptions::default()
        },
    )
    .expect("valid loopback IPv6 UDP packet should reconstruct")
}

/// Asserts that `sock` receives a datagram matching `expected_payload` from `(expected_ip, expected_port)`.
fn assert_udp_received(
    sock: &UdpSocket,
    expected_payload: &[u8],
    expected_ip: IpAddr,
    expected_port: u16,
) {
    let mut buf = [0u8; 512];
    let (n, peer) = sock
        .recv_from(&mut buf)
        .expect("kernel should deliver raw-injected UDP datagram to loopback socket");
    assert_eq!(&buf[..n], expected_payload);
    assert_eq!(peer, SocketAddr::new(expected_ip, expected_port));
}

/// Asserts that `sock` times out without receiving a datagram (e.g., after an invalid checksum).
fn assert_udp_timed_out(sock: &UdpSocket) {
    let mut buf = [0u8; 512];
    let err = sock
        .recv_from(&mut buf)
        .expect_err("corrupted UDP checksum datagram should be dropped by the kernel");
    assert!(
        matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut),
        "expected read timeout on dropped datagram, got {err}"
    );
}

/// Verifies `RawSender::preinit`, IPv4/IPv6 loopback delivery, kernel bad-checksum drops, and `SO_BINDTODEVICE` `bind_fix4`/`bind_fix6` transitions.
#[test]
#[ignore = "requires CAP_NET_RAW (run in root or unshare -r -n)"]
fn raw_sender_preinit_and_loopback_udp_delivery() {
    let udp4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind IPv4 loopback UDP socket");
    udp4.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set IPv4 read timeout");
    let v4_port = udp4.local_addr().expect("IPv4 local_addr").port();

    let udp6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind IPv6 loopback UDP socket");
    udp6.set_read_timeout(Some(Duration::from_millis(400)))
        .expect("set IPv6 read timeout");
    let v6_port = udp6.local_addr().expect("IPv6 local_addr").port();

    let mut sender = RawSender::new(true, true);
    sender
        .preinit()
        .expect("RawSender::preinit should open AF_INET and AF_INET6 raw sockets");

    // 1. Valid IPv4 UDP packet bound to `"lo"` delivers cleanly.
    let v4_payload_a = b"rawsend-live-v4-a";
    let v4_pkt_a = build_loopback_udp4(41001, v4_port, v4_payload_a, false);
    sender
        .send(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x4000_0000, Some("lo"), &v4_pkt_a)
        .expect("IPv4 send on lo should succeed");
    assert_udp_received(&udp4, v4_payload_a, IpAddr::V4(Ipv4Addr::LOCALHOST), 41001);

    // 2. Corrupted IPv4 UDP checksum is dropped by the kernel.
    let v4_bad = build_loopback_udp4(41001, v4_port, b"rawsend-badsum-v4", true);
    sender
        .send(IpAddr::V4(Ipv4Addr::LOCALHOST), 0x4000_0000, Some("lo"), &v4_bad)
        .expect("IPv4 raw socket sendto accepts bad-csum datagram for wire injection");
    assert_udp_timed_out(&udp4);

    // 3. Switching `ifout` from `Some("lo")` back to `None` clears `SO_BINDTODEVICE` (`bind_fix4`),
    //    and embedded NUL triggers `InvalidInterfaceName`.
    let v4_payload_b = b"rawsend-live-v4-cleared-bind";
    let v4_pkt_b = build_loopback_udp4(41002, v4_port, v4_payload_b, false);
    sender
        .send(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, None, &v4_pkt_b)
        .expect("IPv4 send after clearing SO_BINDTODEVICE should succeed");
    assert_udp_received(&udp4, v4_payload_b, IpAddr::V4(Ipv4Addr::LOCALHOST), 41002);

    let bad_if4 = sender.send(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, Some("bad\0if"), &v4_pkt_b);
    assert!(matches!(bad_if4, Err(RawSendError::InvalidInterfaceName(_))));

    // 4. Valid IPv6 UDP packet bound to `"lo"` delivers cleanly.
    let v6_payload_a = b"rawsend-live-v6-a";
    let v6_pkt_a = build_loopback_udp6(42001, v6_port, Vec::new(), v6_payload_a, false);
    sender
        .send(IpAddr::V6(Ipv6Addr::LOCALHOST), 0x4000_0000, Some("lo"), &v6_pkt_a)
        .expect("IPv6 send on lo should succeed");
    assert_udp_received(&udp6, v6_payload_a, IpAddr::V6(Ipv6Addr::LOCALHOST), 42001);

    // 5. Corrupted IPv6 UDP checksum is dropped by the kernel.
    let v6_bad = build_loopback_udp6(42001, v6_port, Vec::new(), b"rawsend-badsum-v6", true);
    sender
        .send(IpAddr::V6(Ipv6Addr::LOCALHOST), 0x4000_0000, Some("lo"), &v6_bad)
        .expect("IPv6 raw socket sendto accepts bad-csum datagram for wire injection");
    assert_udp_timed_out(&udp6);

    // 6. Switching `ifout` from `Some("lo")` back to `None` clears `SO_BINDTODEVICE` (`bind_fix6`),
    //    and embedded NUL triggers `InvalidInterfaceName`.
    let v6_payload_b = b"rawsend-live-v6-cleared-bind";
    let v6_pkt_b = build_loopback_udp6(42002, v6_port, Vec::new(), v6_payload_b, false);
    sender
        .send(IpAddr::V6(Ipv6Addr::LOCALHOST), 0, None, &v6_pkt_b)
        .expect("IPv6 send after clearing SO_BINDTODEVICE should succeed");
    assert_udp_received(&udp6, v6_payload_b, IpAddr::V6(Ipv6Addr::LOCALHOST), 42002);

    let bad_if6 = sender.send(IpAddr::V6(Ipv6Addr::LOCALHOST), 0, Some("bad\0if"), &v6_pkt_b);
    assert!(matches!(bad_if6, Err(RawSendError::InvalidInterfaceName(_))));
}

/// Verifies Lua `rawsend` and `rawsend_dissect` + `ipfrag2` deliver reassembled IPv4 and IPv6 packets (with `HOPOPTS` + `DSTOPTS` + `ipfrag_next = IPPROTO_TCP` + `ip6_preserve_next = true`) through the kernel.
#[test]
#[ignore = "requires CAP_NET_RAW (run in root or unshare -r -n)"]
fn lua_live_rawsend_and_ipfrag2_deliver_through_kernel() {
    let udp4 = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind IPv4 loopback UDP socket");
    udp4.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set IPv4 read timeout");
    let v4_port = udp4.local_addr().expect("IPv4 local_addr").port();

    let udp6 = UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)).expect("bind IPv6 loopback UDP socket");
    udp6.set_read_timeout(Some(Duration::from_millis(500)))
        .expect("set IPv6 read timeout");
    let v6_port = udp6.local_addr().expect("IPv6 local_addr").port();

    let cfg = LuaConfig {
        desync_fwmark: 0x4000_0000,
        bind_fix4: true,
        bind_fix6: true,
        ..LuaConfig::default()
    };
    let rt = LuaRuntime::new(cfg).expect("LuaRuntime::new should initialize");
    let zapret_lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("lua/zapret-lib.lua");
    assert!(
        zapret_lib.exists(),
        "expected zapret-lib.lua at {}",
        zapret_lib.display()
    );
    rt.exec_file(&zapret_lib)
        .expect("loading zapret-lib.lua should succeed");

    // 1. Direct Lua `rawsend` delivers a loopback IPv4 UDP packet.
    let direct_payload = b"lua-direct-rawsend-payload";
    let direct_v4 = build_loopback_udp4(43001, v4_port, direct_payload, false);
    rt.set_blob("direct_v4", &direct_v4)
        .expect("set direct_v4 blob");
    rt.exec_str(r#"assert(rawsend(direct_v4, { ifout = "lo", fwmark = 0x10 }) == true)"#)
        .expect("Lua rawsend should return true");
    assert_udp_received(&udp4, direct_payload, IpAddr::V4(Ipv4Addr::LOCALHOST), 43001);

    // 2. Lua `ipfrag2` + `rawsend_dissect` splits and kernel-reassembles an IPv4 UDP packet.
    let frag4_payload = b"0123456789abcdef0123456789ABCDEF";
    let frag4_pkt = build_loopback_udp4(43002, v4_port, frag4_payload, false);
    rt.set_blob("frag4_pkt", &frag4_pkt)
        .expect("set frag4_pkt blob");
    rt.exec_str(
        r#"
        local d = dissect(frag4_pkt)
        local frags = ipfrag2(d, { ipfrag_pos_udp = 16 })
        assert(frags and #frags == 2, "expected 2 IPv4 fragments")
        assert(rawsend_dissect(frags[1], { ifout = "lo" }) == true)
        assert(rawsend_dissect(frags[2], { ifout = "lo" }) == true)
        "#,
    )
    .expect("Lua IPv4 ipfrag2 + rawsend_dissect should succeed");
    assert_udp_received(&udp4, frag4_payload, IpAddr::V4(Ipv4Addr::LOCALHOST), 43002);

    // 3. Lua `ipfrag2` + `rawsend_dissect` splits an IPv6 packet with HOPOPTS + DSTOPTS,
    //    rewrites fragment 2's next header to IPPROTO_TCP, and preserves it via `ip6_preserve_next = true`.
    //    RFC 8200 / Linux reassembly uses fragment 1's Next Header and delivers the full UDP payload.
    let frag6_payload = b"ipv6-frag-payload-0123456789abcd";
    let padn_6 = vec![1, 4, 0, 0, 0, 0];
    let frag6_pkt = build_loopback_udp6(
        43003,
        v6_port,
        vec![
            Ipv6ExtHeader {
                header_type: IPPROTO_HOPOPTS,
                next_header: IPPROTO_DSTOPTS,
                data: padn_6.clone(),
            },
            Ipv6ExtHeader {
                header_type: IPPROTO_DSTOPTS,
                next_header: IPPROTO_UDP,
                data: padn_6,
            },
        ],
        frag6_payload,
        false,
    );
    rt.set_blob("frag6_pkt", &frag6_pkt)
        .expect("set frag6_pkt blob");
    rt.exec_str(
        r#"
        local d = dissect(frag6_pkt)
        local frags = ipfrag2(d, { ipfrag_pos_udp = 16, ipfrag_next = IPPROTO_TCP })
        assert(frags and #frags == 2, "expected 2 IPv6 fragments")
        assert(#frags[2].ip6.exthdr == 3, "expected HOPOPTS + DSTOPTS + FRAGMENT")
        assert(frags[2].ip6.exthdr[3].type == IPPROTO_FRAGMENT)
        assert(frags[2].ip6.exthdr[3].next == IPPROTO_TCP)
        local w2 = reconstruct_dissect(frags[2], { ip6_preserve_next = true })
        -- 40B base + 8B HOPOPTS + 8B DSTOPTS = byte offset 56 for FRAGMENT header; byte 0 is `next`.
        assert(string.byte(w2, 57) == IPPROTO_TCP, "expected preserved TCP next header on wire")
        assert(rawsend_dissect(frags[1], { ifout = "lo" }, { ip6_preserve_next = true }) == true)
        assert(rawsend_dissect(frags[2], { ifout = "lo" }, { ip6_preserve_next = true }) == true)
        "#,
    )
    .expect("Lua IPv6 ipfrag2 + rawsend_dissect should succeed");
    assert_udp_received(&udp6, frag6_payload, IpAddr::V6(Ipv6Addr::LOCALHOST), 43003);
}
