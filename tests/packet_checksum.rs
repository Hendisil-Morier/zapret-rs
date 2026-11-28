//! Integration tests for RFC 1071 / RFC 768 Internet checksum accumulation and header fixups.

/// Byte-level checksum accumulator and IPv4/TCP/UDP/ICMP checksum computation and fixup APIs.
use zapret_rs::packet::checksum::{
    ChecksumAccumulator, fix_icmp_checksum, fix_ipv4_checksum, fix_tcp_checksum, fix_udp_checksum,
    icmp_ipv4_checksum, icmp_ipv6_checksum, ipv4_header_checksum, tcp_ipv4_checksum, tcp_ipv6_checksum,
    udp_ipv4_checksum, udp_ipv6_checksum,
};
/// Packet error type for negative checksum validation assertions.
use zapret_rs::packet::error::PacketError;

/// Verifies the classic RFC 1071 IPv4 header checksum vector (`0xb861`) and round-trip zero check.
#[test]
fn ipv4_header_checksum_matches_rfc1071_vector_and_verifies_zero()
{
    let mut header: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x12, 0x34, 0xc0, 0xa8, 0x00, 0x01, 0xc0,
        0xa8, 0x00, 0xc7,
    ];

    // Existing checksum field bytes (0x1234) must be ignored during computation.
    let csum = ipv4_header_checksum(&header).expect("valid IPv4 header");
    assert_eq!(csum, 0xb861);

    fix_ipv4_checksum(&mut header).expect("fix_ipv4_checksum should succeed");
    assert_eq!(&header[10..12], &[0xb8, 0x61]);

    // Summing the entire header including the computed checksum must fold to 0xFFFF -> inverted 0.
    let mut acc = ChecksumAccumulator::new();
    acc.update(&header);
    assert_eq!(acc.finalize(), 0);
}

/// Verifies that splitting odd-length slices across multiple `update` calls equals one contiguous update.
#[test]
fn checksum_accumulator_handles_odd_length_split_slices()
{
    let payload = b"hello world! odd bytes 123";

    let mut whole = ChecksumAccumulator::new();
    whole.update(payload);

    let mut split = ChecksumAccumulator::new();
    split.update(&payload[..5]);
    split.update(&payload[5..12]);
    split.update(&[]);
    split.update(&payload[12..13]);
    split.update(&payload[13..]);

    assert_eq!(whole.finalize(), split.finalize());
}

/// Verifies TCPv4 and TCPv6 checksum fixups, stale-checksum overwrite, and odd-length payloads.
#[test]
fn tcp_v4_and_v6_checksum_fixups_validate_against_pseudo_header_sums()
{
    let ip4: [u8; 20] = [
        0x45, 0x00, 0x00, 0x2d, 0x00, 0x01, 0x40, 0x00, 64, 6, 0x00, 0x00, 192, 168, 1, 10, 93, 184, 216, 34,
    ];
    let payload = b"hello"; // odd length (5 bytes)
    let mut tcp = [
        0xd4, 0x31, 0x01, 0xbb, 0x00, 0x00, 0x03, 0xe8, 0x00, 0x00, 0x07, 0xd0, 0x50, 0x18, 0xff, 0xff, 0xde,
        0xad, 0x00, 0x00,
    ];

    let expected4 = tcp_ipv4_checksum([192, 168, 1, 10], [93, 184, 216, 34], &tcp, payload);
    fix_tcp_checksum(&ip4, &mut tcp, payload).expect("fix_tcp_checksum v4 should succeed");
    assert_eq!(u16::from_be_bytes([tcp[16], tcp[17]]), expected4);
    assert_ne!(expected4, 0xdead);

    let mut ip6 = [0u8; 40];
    ip6[0] = 0x60;
    ip6[6] = 6;
    ip6[7] = 64;
    let src6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    ip6[8..24].copy_from_slice(&src6);
    ip6[24..40].copy_from_slice(&dst6);

    let expected6 = tcp_ipv6_checksum(src6, dst6, &tcp, payload);
    fix_tcp_checksum(&ip6, &mut tcp, payload).expect("fix_tcp_checksum v6 should succeed");
    assert_eq!(u16::from_be_bytes([tcp[16], tcp[17]]), expected6);
}

/// Verifies UDPv4/UDPv6 checksums and RFC 768 conversion of `0x0000` checksums to `0xFFFF`.
#[test]
fn udp_checksum_enforces_rfc768_nonzero_mapping_for_v4_and_v6()
{
    // Craft an IPv4 + UDP header where the 1's-complement sum equals 0xFFFF (so !sum == 0x0000 -> 0xFFFF).
    let src4 = [0, 0, 0, 1];
    let dst4 = [0, 0, 0, 2];
    let mut udp = [0u8; 8];
    udp[0..2].copy_from_slice(&1000u16.to_be_bytes());
    udp[2..4].copy_from_slice(&2000u16.to_be_bytes());
    udp[4..6].copy_from_slice(&10u16.to_be_bytes());

    let prelim = udp_ipv4_checksum(src4, dst4, &udp, &[0, 0]);
    let fix_payload = prelim.to_be_bytes();
    let mapped = udp_ipv4_checksum(src4, dst4, &udp, &fix_payload);
    assert_eq!(mapped, 0xFFFF);

    let src6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    let prelim6 = udp_ipv6_checksum(src6, dst6, &udp, &[0, 0]);
    let mapped6 = udp_ipv6_checksum(src6, dst6, &udp, &prelim6.to_be_bytes());
    assert_eq!(mapped6, 0xFFFF);

    let mut ip4 = [0u8; 20];
    ip4[0] = 0x45;
    ip4[9] = 17;
    ip4[12..16].copy_from_slice(&src4);
    ip4[16..20].copy_from_slice(&dst4);
    fix_udp_checksum(&ip4, &mut udp, &fix_payload).expect("fix_udp_checksum should succeed");
    assert_eq!(u16::from_be_bytes([udp[6], udp[7]]), 0xFFFF);
}

/// Verifies ICMPv4 (no pseudo-header) and ICMPv6 (IPv6 pseudo-header) checksum calculation and fixup.
#[test]
fn icmp_v4_and_v6_checksum_fixups_differ_by_pseudo_header()
{
    let payload = b"ping-data-odd";
    let mut icmp = [8, 0, 0x99, 0x99, 0x12, 0x34, 0x00, 0x01];

    let mut ip4 = [0u8; 20];
    ip4[0] = 0x45;
    ip4[9] = 1;
    let expected4 = icmp_ipv4_checksum(&icmp, payload);
    fix_icmp_checksum(&ip4, &mut icmp, payload).expect("fix_icmp_checksum v4 should succeed");
    assert_eq!(u16::from_be_bytes([icmp[2], icmp[3]]), expected4);

    let mut ip6 = [0u8; 40];
    ip6[0] = 0x60;
    ip6[6] = 58;
    let src6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst6 = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    ip6[8..24].copy_from_slice(&src6);
    ip6[24..40].copy_from_slice(&dst6);

    icmp[0] = 128;
    let expected6 = icmp_ipv6_checksum(src6, dst6, &icmp, payload);
    fix_icmp_checksum(&ip6, &mut icmp, payload).expect("fix_icmp_checksum v6 should succeed");
    assert_eq!(u16::from_be_bytes([icmp[2], icmp[3]]), expected6);
    assert_ne!(expected6, icmp_ipv4_checksum(&icmp, payload));
}

/// Verifies that malformed, truncated, wrong-version, or oversized headers fail with `InvalidChecksumHeader`.
#[test]
fn checksum_fixups_reject_invalid_headers()
{
    let mut short_ip4 = [0x45u8; 19];
    assert_eq!(fix_ipv4_checksum(&mut short_ip4).unwrap_err(), PacketError::InvalidChecksumHeader);

    let mut wrong_ver = [0x65u8; 20];
    assert_eq!(fix_ipv4_checksum(&mut wrong_ver).unwrap_err(), PacketError::InvalidChecksumHeader);

    let mut oversized = [0x45u8; 64];
    assert_eq!(fix_ipv4_checksum(&mut oversized).unwrap_err(), PacketError::InvalidChecksumHeader);

    let valid_ip4 = [0x45u8; 20];
    let mut bad_tcp = [0u8; 20];
    bad_tcp[12] = 0x40; // data offset = 16 bytes (< 20)
    assert_eq!(
        fix_tcp_checksum(&valid_ip4, &mut bad_tcp, b"").unwrap_err(),
        PacketError::InvalidChecksumHeader
    );

    let mut short_udp = [0u8; 7];
    assert_eq!(
        fix_udp_checksum(&valid_ip4, &mut short_udp, b"").unwrap_err(),
        PacketError::InvalidChecksumHeader
    );

    let mut short_icmp = [0u8; 7];
    assert_eq!(
        fix_icmp_checksum(&valid_ip4, &mut short_icmp, b"").unwrap_err(),
        PacketError::InvalidChecksumHeader
    );
}
