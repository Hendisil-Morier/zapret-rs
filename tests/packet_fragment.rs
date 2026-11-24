//! Integration tests for `ReconstructOptions`, IPv6 `next` preservation, and IPv4/IPv6 fragment slicing.

/// Protocol constants used to construct and assert fragmented and option-controlled packets.
use zapret_rs::packet::constants::{
    IP_DF, IP_MF, IPPROTO_FRAGMENT, IPPROTO_HOPOPTS, IPPROTO_IPIP, IPPROTO_NONE, IPPROTO_TCP,
    IPPROTO_UDP, IPV6_DEFAULT_FLOW, TH_ACK,
};
/// Packet dissection function used to verify reconstructed packets and non-first fragments.
use zapret_rs::packet::dissecter::dissect_packet;
/// Packet reconstruction options and raw wire constructor.
use zapret_rs::packet::reconstruct::{ReconstructOptions, reconstruct_packet};
/// Parsed L3/L4 packet and header types.
use zapret_rs::packet::types::{
    DissectedPacket, IcmpHeader, Ipv4Header, Ipv6ExtHeader, Ipv6Header, TcpHeader, UdpHeader,
};

/// Builds a baseline IPv4 header suitable for fragmentation and reconstruction-option tests.
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

/// Verifies `ReconstructOptions` flags: `keepsum`, `badsum`, `ip6_last_proto`, and `ip6_preserve_next`.
#[test]
fn reconstruct_options_control_checksums_and_ipv6_next_headers() {
    let tcp_pkt = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_TCP, Vec::new())),
        tcp: Some(TcpHeader {
            s_port: 1000,
            d_port: 80,
            seq: 1,
            ack: 2,
            reserved: 0,
            data_offset: 5,
            flags: TH_ACK,
            window: 1024,
            checksum: 0x1357,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: Some(b"abc".to_vec()),
        ..DissectedPacket::default()
    };

    let kept = reconstruct_packet(
        &tcp_pkt,
        &ReconstructOptions {
            keepsum: true,
            ..ReconstructOptions::default()
        },
    )
    .expect("keepsum should succeed");
    assert_eq!(dissect_packet(&kept, false).tcp.expect("tcp").checksum, 0x1357);

    let good = reconstruct_packet(&tcp_pkt, &ReconstructOptions::default()).expect("good sum");
    let bad = reconstruct_packet(
        &tcp_pkt,
        &ReconstructOptions {
            badsum: true,
            ..ReconstructOptions::default()
        },
    )
    .expect("badsum");
    assert_ne!(
        dissect_packet(&good, false).tcp.expect("good").checksum,
        dissect_packet(&bad, false).tcp.expect("bad").checksum
    );

    // UDP badsum must never produce checksum 0x0000.
    let udp_pkt = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_UDP, Vec::new())),
        udp: Some(UdpHeader {
            s_port: 5000,
            d_port: 53,
            len: 0,
            checksum: 0,
        }),
        payload: Some(b"dns".to_vec()),
        ..DissectedPacket::default()
    };
    for _ in 0..16 {
        let bad_udp = reconstruct_packet(
            &udp_pkt,
            &ReconstructOptions {
                badsum: true,
                ..ReconstructOptions::default()
            },
        )
        .expect("badsum udp");
        let parsed = dissect_packet(&bad_udp, false).udp.expect("udp");
        assert_ne!(parsed.checksum, 0);
    }

    // `ip6_last_proto` and `ip6_preserve_next` for IP-in-IP encapsulation without L4 headers.
    let mut ipip_dis = DissectedPacket {
        ip6: Some(sample_ipv6(vec![Ipv6ExtHeader {
            header_type: IPPROTO_HOPOPTS,
            next_header: 0xAA,
            data: vec![0; 6],
        }])),
        payload: Some(vec![1, 2, 3, 4]),
        ..DissectedPacket::default()
    };
    let wire_ipip = reconstruct_packet(
        &ipip_dis,
        &ReconstructOptions {
            ip6_last_proto: Some(IPPROTO_IPIP),
            ..ReconstructOptions::default()
        },
    )
    .expect("ip6_last_proto should succeed");
    assert_eq!(dissect_packet(&wire_ipip, false).l4proto, IPPROTO_IPIP);

    // Preserving explicit `next` in extension header when `ip6_preserve_next = true`.
    ipip_dis.ip6.as_mut().expect("ip6").next_header = IPPROTO_HOPOPTS;
    let preserved = reconstruct_packet(
        &ipip_dis,
        &ReconstructOptions {
            ip6_preserve_next: true,
            ip6_last_proto: Some(IPPROTO_IPIP),
            ..ReconstructOptions::default()
        },
    )
    .expect("ip6_preserve_next should succeed");
    assert_eq!(preserved[40], 0xAA);
}

/// Verifies IPv4 and IPv6 fragmentation slicing during reconstruction and non-first fragment dissection.
#[test]
fn ipv4_and_ipv6_fragment_slicing_and_dissect_roundtrip() {
    let payload = vec![0x41u8; 40];

    // IPv4 fragment 1 (offset 0, MF=1, payload slice = 16 bytes) and fragment 2 (offset 16 bytes).
    let mut v4_frag1 = DissectedPacket {
        ip: Some(sample_ipv4(IPPROTO_UDP, Vec::new())),
        udp: Some(UdpHeader {
            s_port: 1111,
            d_port: 2222,
            len: 0,
            checksum: 0,
        }),
        payload: Some(payload.clone()),
        ..DissectedPacket::default()
    };
    v4_frag1.ip.as_mut().expect("ip").frag_off = IP_MF;
    v4_frag1.ip.as_mut().expect("ip").total_len = 20 + 16;

    let mut v4_frag2 = v4_frag1.clone();
    v4_frag2.ip.as_mut().expect("ip").frag_off = 16 >> 3;
    v4_frag2.ip.as_mut().expect("ip").total_len = 20 + (8 + 40 - 16);

    let f1_bytes = reconstruct_packet(&v4_frag1, &ReconstructOptions::default()).expect("v4 f1");
    let f2_bytes = reconstruct_packet(&v4_frag2, &ReconstructOptions::default()).expect("v4 f2");
    assert_eq!(f1_bytes.len(), 36);
    assert_eq!(f2_bytes.len(), 52);

    let f2_dis = dissect_packet(&f2_bytes, false);
    assert_eq!(f2_dis.frag_off, Some(16));
    assert!(f2_dis.udp.is_none());

    // IPv6 fragment 2 starting at offset 24 with custom trailing `next` preserved via `ip6_preserve_next`.
    let mut v6_frag2 = DissectedPacket {
        ip6: Some(sample_ipv6(vec![
            Ipv6ExtHeader {
                header_type: IPPROTO_HOPOPTS,
                next_header: IPPROTO_FRAGMENT,
                data: vec![0; 6],
            },
            Ipv6ExtHeader {
                header_type: IPPROTO_FRAGMENT,
                next_header: IPPROTO_TCP,
                data: vec![0, 24, 0, 0, 0, 99],
            },
        ])),
        icmp: Some(IcmpHeader {
            icmp_type: 128,
            icmp_code: 0,
            checksum: 0,
            data: 1,
        }),
        payload: Some(payload),
        ..DissectedPacket::default()
    };
    // Full unfragmentable extra headers = 16 bytes; fragmentable part = 48 - 24 = 24 bytes -> ip6_plen = 40.
    v6_frag2.ip6.as_mut().expect("ip6").next_header = IPPROTO_HOPOPTS;
    v6_frag2.ip6.as_mut().expect("ip6").payload_len = Some(16 + 24);

    let v6_f2_bytes = reconstruct_packet(
        &v6_frag2,
        &ReconstructOptions {
            ip6_preserve_next: true,
            ..ReconstructOptions::default()
        },
    )
    .expect("v6 f2");
    assert_eq!(v6_f2_bytes.len(), 80);

    let v6_f2_dis = dissect_packet(&v6_f2_bytes, false);
    assert_eq!(v6_f2_dis.frag_off, Some(24));
    assert_eq!(v6_f2_dis.l4proto, IPPROTO_TCP);
    assert!(v6_f2_dis.icmp.is_none());

    // Re-reconstructing the dissected non-first fragment preserves payload bytes verbatim.
    let rebuilt = reconstruct_packet(&v6_f2_dis, &ReconstructOptions::default())
        .expect("rebuilding dissected fragment");
    assert_eq!(rebuilt, v6_f2_bytes);
}
