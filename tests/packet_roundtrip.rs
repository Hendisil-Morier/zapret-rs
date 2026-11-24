//! Integration tests for full L3/L4 packet dissection, reconstruction, options, and fragmentation.

/// Standard IP address enums for verifying `extract_dst`.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Protocol constants used to construct and assert dissected packets.
use zapret_rs::packet::constants::{
    IP_DF, IPPROTO_AH, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_ICMP,
    IPPROTO_ICMPV6, IPPROTO_NONE, IPPROTO_ROUTING, IPPROTO_TCP, IPPROTO_UDP, IPV6_DEFAULT_FLOW,
    TCP_KIND_NOOP, TCP_KIND_TS, TH_ACK, TH_PUSH,
};
/// Packet dissection, destination extraction, and header inspection functions.
use zapret_rs::packet::{dissect_packet, extract_dst, find_ipv6_exthdr};
/// Packet error variants for negative reconstruction and destination checks.
use zapret_rs::packet::error::PacketError;
/// Packet reconstruction options and packet/header constructors.
use zapret_rs::packet::reconstruct::{ReconstructOptions, reconstruct_packet};
/// Parsed L3/L4 packet and header types.
use zapret_rs::packet::types::{
    DissectedPacket, IcmpHeader, Ipv4Header, Ipv6ExtHeader, Ipv6Header, TcpHeader, TcpOption,
    UdpHeader,
};

/// Builds a baseline IPv4 header suitable for full packet round-trip tests.
fn sample_ipv4(protocol: u8, options: Vec<u8>) -> Ipv4Header {
    Ipv4Header {
        version: 4,
        header_len: 5,
        tos: 0x02,
        total_len: 0,
        id: 0x4321,
        frag_off: IP_DF,
        ttl: 64,
        protocol,
        checksum: 0,
        src: [10, 0, 0, 1],
        dst: [10, 0, 0, 2],
        options,
    }
}

/// Builds a baseline IPv6 header with optional extension headers.
fn sample_ipv6(exthdr: Vec<Ipv6ExtHeader>) -> Ipv6Header {
    Ipv6Header {
        flow: IPV6_DEFAULT_FLOW | 0x12345,
        payload_len: None,
        next_header: IPPROTO_NONE,
        hop_limit: 64,
        src: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        dst: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        exthdr,
    }
}

/// Verifies IPv4 + TCP roundtrip including non-4-byte-aligned IPv4 options zero-padding and TCP options.
#[test]
fn ipv4_tcp_with_unaligned_ip_options_roundtrips_cleanly() {
    let mut dis = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_TCP, vec![1, 2, 3, 4, 5])), // padded to 8 bytes
        tcp: Some(TcpHeader {
            s_port: 12345,
            d_port: 443,
            seq: 0x1122_3344,
            ack: 0x5566_7788,
            reserved: 3,
            data_offset: 5,
            flags: TH_PUSH | TH_ACK,
            window: 32768,
            checksum: 0,
            urgent_ptr: 0,
            options: vec![
                TcpOption {
                    kind: TCP_KIND_NOOP,
                    data: None,
                },
                TcpOption {
                    kind: TCP_KIND_TS,
                    data: Some(vec![0, 0, 0, 10, 0, 0, 0, 20]),
                },
            ],
        }),
        payload: Some(b"GET / HTTP/1.1\r\n\r\n".to_vec()),
        ..DissectedPacket::default()
    };

    let wire1 = reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("IPv4 TCP reconstruction should succeed");
    let parsed = dissect_packet(&wire1, false);
    assert_eq!(parsed.l4proto, IPPROTO_TCP);
    assert_eq!(parsed.l3_len, 28);
    assert_eq!(parsed.l4_len, 32);
    assert_eq!(parsed.ip.as_ref().expect("ip present").options, vec![1, 2, 3, 4, 5, 0, 0, 0]);
    assert_eq!(parsed.payload.as_deref(), Some(&b"GET / HTTP/1.1\r\n\r\n"[..]));

    // Reconstructing the dissected packet must be byte-for-byte identical.
    dis.ip = parsed.ip.clone();
    let wire2 = reconstruct_packet(&parsed, &ReconstructOptions::default())
        .expect("second reconstruction should succeed");
    assert_eq!(wire1, wire2);
}

/// Verifies IPv6 + HOPOPTS/ROUTING/DSTOPTS/AH + UDP roundtrip and extension-header offset lookup.
#[test]
fn ipv6_extension_headers_and_udp_roundtrip() {
    let dis = DissectedPacket {
        ip6: Some(sample_ipv6(vec![
            Ipv6ExtHeader {
                header_type: IPPROTO_HOPOPTS,
                next_header: IPPROTO_NONE,
                data: vec![1, 2, 3, 4, 5, 6],
            },
            Ipv6ExtHeader {
                header_type: IPPROTO_ROUTING,
                next_header: IPPROTO_NONE,
                data: vec![0; 14],
            },
            Ipv6ExtHeader {
                header_type: IPPROTO_DSTOPTS,
                next_header: IPPROTO_NONE,
                data: vec![7; 6],
            },
            Ipv6ExtHeader {
                header_type: IPPROTO_AH,
                next_header: IPPROTO_NONE,
                data: vec![9; 10], // 2 + 10 = 12 bytes (multiple of 4)
            },
        ])),
        udp: Some(UdpHeader {
            s_port: 50000,
            d_port: 443,
            len: 0,
            checksum: 0,
        }),
        payload: Some(b"quic-initial".to_vec()),
        ..DissectedPacket::default()
    };

    let wire = reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("IPv6 exthdr reconstruction should succeed");
    assert_eq!(find_ipv6_exthdr(&wire, IPPROTO_HOPOPTS), Some(40));
    assert_eq!(find_ipv6_exthdr(&wire, IPPROTO_ROUTING), Some(48));
    assert_eq!(find_ipv6_exthdr(&wire, IPPROTO_DSTOPTS), Some(64));
    assert_eq!(find_ipv6_exthdr(&wire, IPPROTO_AH), Some(72));
    assert_eq!(find_ipv6_exthdr(&wire, IPPROTO_FRAGMENT), None);

    let parsed = dissect_packet(&wire, false);
    assert_eq!(parsed.l4proto, IPPROTO_UDP);
    assert_eq!(parsed.l3_len, 84);
    assert_eq!(parsed.l4_len, 8);
    assert_eq!(parsed.ip6.as_ref().expect("ip6 present").exthdr.len(), 4);
    assert_eq!(parsed.payload.as_deref(), Some(&b"quic-initial"[..]));

    let wire2 = reconstruct_packet(&parsed, &ReconstructOptions::default())
        .expect("re-reconstruction should succeed");
    assert_eq!(wire, wire2);
}

/// Verifies `no_payload_check = false` rejects truncated IPv6 packets while `true` still parses L3.
#[test]
fn dissect_packet_respects_no_payload_check_on_truncated_ipv6() {
    let dis = DissectedPacket {
        ip6: Some(sample_ipv6(vec![Ipv6ExtHeader {
            header_type: IPPROTO_HOPOPTS,
            next_header: IPPROTO_NONE,
            data: vec![0; 6],
        }])),
        udp: Some(UdpHeader {
            s_port: 1234,
            d_port: 5678,
            len: 0,
            checksum: 0,
        }),
        payload: Some(b"payload-bytes".to_vec()),
        ..DissectedPacket::default()
    };
    let wire = reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid packet");
    // Truncate inside the UDP header (40 base + 8 hopopts + 5 partial UDP).
    let truncated = &wire[..53];

    let strict = dissect_packet(truncated, false);
    assert!(strict.ip6.is_none());
    assert!(strict.payload.is_none());

    let lenient = dissect_packet(truncated, true);
    assert!(lenient.ip6.is_some());
    assert_eq!(lenient.l4proto, IPPROTO_UDP);
    assert!(lenient.udp.is_none());
    assert_eq!(lenient.payload.as_deref(), Some(&wire[48..53]));
}

/// Verifies ICMPv4 and ICMPv6 packets reconstruct and dissect accurately with valid checksums.
#[test]
fn icmp_v4_and_v6_roundtrip() {
    let v4 = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_ICMP, Vec::new())),
        icmp: Some(IcmpHeader {
            icmp_type: 8,
            icmp_code: 0,
            checksum: 0,
            data: 0x0001_0002,
        }),
        payload: Some(b"echo4".to_vec()),
        ..DissectedPacket::default()
    };
    let w4 = reconstruct_packet(&v4, &ReconstructOptions::default()).expect("icmp4");
    let d4 = dissect_packet(&w4, false);
    assert_eq!(d4.l4proto, IPPROTO_ICMP);
    assert_eq!(d4.icmp.as_ref().expect("icmp").data, 0x0001_0002);

    let v6 = DissectedPacket {
        ip6: Some(sample_ipv6(Vec::new())),
        icmp: Some(IcmpHeader {
            icmp_type: 128,
            icmp_code: 0,
            checksum: 0,
            data: 0x0003_0004,
        }),
        payload: Some(b"echo6".to_vec()),
        ..DissectedPacket::default()
    };
    let w6 = reconstruct_packet(&v6, &ReconstructOptions::default()).expect("icmp6");
    let d6 = dissect_packet(&w6, false);
    assert_eq!(d6.l4proto, IPPROTO_ICMPV6);
    assert_eq!(d6.icmp.as_ref().expect("icmp6").data, 0x0003_0004);
}

/// Verifies `extract_dst` across IPv4, IPv6, truncated buffers, and unsupported versions.
#[test]
fn extract_dst_handles_valid_and_invalid_packets() {
    let v4 = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_UDP, Vec::new())),
        udp: Some(UdpHeader {
            s_port: 1,
            d_port: 2,
            len: 0,
            checksum: 0,
        }),
        payload: Some(Vec::new()),
        ..DissectedPacket::default()
    };
    let w4 = reconstruct_packet(&v4, &ReconstructOptions::default()).expect("v4");
    assert_eq!(extract_dst(&w4), Ok(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

    let v6 = DissectedPacket {
        ip6: Some(sample_ipv6(Vec::new())),
        udp: Some(UdpHeader {
            s_port: 1,
            d_port: 2,
            len: 0,
            checksum: 0,
        }),
        payload: Some(Vec::new()),
        ..DissectedPacket::default()
    };
    let w6 = reconstruct_packet(&v6, &ReconstructOptions::default()).expect("v6");
    assert_eq!(
        extract_dst(&w6),
        Ok(IpAddr::V6(Ipv6Addr::from([
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        ])))
    );

    assert_eq!(extract_dst(&[]), Err(PacketError::Truncated));
    assert_eq!(extract_dst(&[0x55; 20]), Err(PacketError::UnsupportedVersion(5)));
    assert_eq!(extract_dst(&w6[..39]), Err(PacketError::Truncated));
}
