/// Packet dissection function under test for IPv4 TCP packets.
use zapret_rs::packet::dissecter::parse_ipv4_tcp;
/// Typed packet parsing error variants for negative test assertions.
use zapret_rs::packet::error::PacketError;
/// Parsed TCP option representation used to verify option decoding.
use zapret_rs::packet::types::TcpOption;

/// Builds a synthetic IPv4 + TCP packet with the provided 4-byte-aligned TCP options and payload.
fn build_ipv4_tcp(tcp_options: &[u8], payload: &[u8]) -> Vec<u8>
{
    assert_eq!(tcp_options.len() % 4, 0);
    let tcp_len = 20 + tcp_options.len();
    let total_len = (20 + tcp_len + payload.len()) as u16;
    let data_offset = (tcp_len / 4) as u8;

    let mut pkt = Vec::with_capacity(total_len as usize);

    // IPv4 header (20 bytes)
    pkt.push(0x45); // version 4, header_len 5 (20 bytes)
    pkt.push(0x00); // tos
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0x1234u16.to_be_bytes()); // id
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // frag_off (Don't Fragment)
    pkt.push(64); // ttl
    pkt.push(6); // protocol = TCP
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&[192, 168, 1, 10]); // src
    pkt.extend_from_slice(&[93, 184, 216, 34]); // dst

    // TCP header (20 bytes + options)
    pkt.extend_from_slice(&54321u16.to_be_bytes()); // s_port
    pkt.extend_from_slice(&443u16.to_be_bytes()); // d_port
    pkt.extend_from_slice(&1000u32.to_be_bytes()); // seq
    pkt.extend_from_slice(&2000u32.to_be_bytes()); // ack
    pkt.push(data_offset << 4); // data_offset + reserved (0)
    pkt.push(0x18); // flags (PSH | ACK)
    pkt.extend_from_slice(&65535u16.to_be_bytes()); // window
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // checksum
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // urgent_ptr
    pkt.extend_from_slice(tcp_options);
    pkt.extend_from_slice(payload);

    pkt
}

/// Asserts IPv4 header fields parsed from `build_ipv4_tcp`.
fn assert_sample_ipv4_fields(ip: &zapret_rs::packet::Ipv4Header)
{
    assert_eq!(ip.version, 4);
    assert_eq!(ip.header_len, 5);
    assert_eq!(ip.tos, 0);
    assert_eq!(ip.total_len, 45);
    assert_eq!(ip.id, 0x1234);
    assert_eq!(ip.frag_off, 0x4000);
    assert_eq!(ip.ttl, 64);
    assert_eq!(ip.protocol, 6);
    assert_eq!(ip.checksum, 0);
    assert_eq!(ip.src, [192, 168, 1, 10]);
    assert_eq!(ip.dst, [93, 184, 216, 34]);
    assert!(
        ip.options
            .is_empty()
    );
}

/// Asserts TCP header fields parsed from `build_ipv4_tcp`.
fn assert_sample_tcp_fields(tcp: &zapret_rs::packet::TcpHeader)
{
    assert_eq!(tcp.s_port, 54321);
    assert_eq!(tcp.d_port, 443);
    assert_eq!(tcp.seq, 1000);
    assert_eq!(tcp.ack, 2000);
    assert_eq!(tcp.data_offset, 5);
    assert_eq!(tcp.reserved, 0);
    assert_eq!(tcp.flags, 0x18);
    assert_eq!(tcp.window, 65535);
    assert_eq!(tcp.checksum, 0);
    assert_eq!(tcp.urgent_ptr, 0);
    assert!(
        tcp.options
            .is_empty()
    );
}

/// Verifies that all IPv4 header fields, TCP header fields, empty options, and payload bytes parse accurately.
#[test]
fn parse_ipv4_tcp_parses_valid_packet_fields_and_payload()
{
    let pkt = build_ipv4_tcp(&[], b"hello");
    let dis = parse_ipv4_tcp(&pkt).expect("valid IPv4 TCP packet should parse");

    assert_sample_ipv4_fields(&dis.ip);
    assert_sample_tcp_fields(&dis.tcp);

    assert_eq!(dis.payload, b"hello");
}

/// Verifies that trailing link-layer padding bytes past `ip.total_len` are excluded from the parsed payload.
#[test]
fn parse_ipv4_tcp_trims_trailing_ethernet_padding()
{
    let mut pkt = build_ipv4_tcp(&[], b"hello");
    pkt.extend_from_slice(&[0u8; 14]);

    let dis = parse_ipv4_tcp(&pkt).expect("packet with trailing padding should parse");
    assert_eq!(
        dis.ip
            .total_len,
        45
    );
    assert_eq!(dis.payload, b"hello");
}

/// Verifies that 16 zero bytes inside an MD5 TCP option are preserved while trailing END padding is stripped.
#[test]
fn parse_ipv4_tcp_preserves_md5_zero_bytes_and_strips_trailing_end_padding()
{
    let mut tcp_options = Vec::with_capacity(20);
    tcp_options.extend_from_slice(&[19, 18]);
    tcp_options.extend_from_slice(&[0u8; 16]);
    tcp_options.extend_from_slice(&[0, 0]);

    let pkt = build_ipv4_tcp(&tcp_options, b"tls");
    let dis = parse_ipv4_tcp(&pkt).expect("packet with MD5 option and END padding should parse");

    assert_eq!(
        dis.tcp
            .data_offset,
        10
    );
    assert_eq!(
        dis.tcp
            .options,
        vec![TcpOption { kind: 19, data: Some(vec![0u8; 16]) }]
    );
    assert_eq!(dis.payload, b"tls");
}

/// Verifies that 1-byte NOOP options and a multi-byte Timestamp option decode into the expected `TcpOption` sequence.
#[test]
fn parse_ipv4_tcp_parses_noop_and_timestamp_options()
{
    let tcp_options = [1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2];
    let pkt = build_ipv4_tcp(&tcp_options, b"data");
    let dis = parse_ipv4_tcp(&pkt).expect("packet with NOOP and Timestamp options should parse");

    assert_eq!(
        dis.tcp
            .options,
        vec![
            TcpOption { kind: 1, data: None },
            TcpOption { kind: 1, data: None },
            TcpOption { kind: 8, data: Some(vec![0, 0, 0, 1, 0, 0, 0, 2]) },
        ]
    );
    assert_eq!(dis.payload, b"data");
}

/// Verifies that a non-IPv4 version nibble returns `PacketError::UnsupportedVersion`.
#[test]
fn parse_ipv4_tcp_rejects_unsupported_ip_version()
{
    let mut pkt = build_ipv4_tcp(&[], b"");
    pkt[0] = 0x65;

    assert_eq!(parse_ipv4_tcp(&pkt).unwrap_err(), PacketError::UnsupportedVersion(6));
}

/// Verifies that an IPv4 header length below 20 bytes returns `PacketError::InvalidHeaderLen`.
#[test]
fn parse_ipv4_tcp_rejects_invalid_ipv4_header_length()
{
    let mut pkt = build_ipv4_tcp(&[], b"");
    pkt[0] = 0x44;

    assert_eq!(parse_ipv4_tcp(&pkt).unwrap_err(), PacketError::InvalidHeaderLen(16));
}

/// Verifies that a TCP data offset below 20 bytes returns `PacketError::InvalidHeaderLen`.
#[test]
fn parse_ipv4_tcp_rejects_invalid_tcp_data_offset()
{
    let mut pkt = build_ipv4_tcp(&[], b"");
    pkt[32] = 0x40;

    assert_eq!(parse_ipv4_tcp(&pkt).unwrap_err(), PacketError::InvalidHeaderLen(16));
}

/// Verifies that a non-TCP IPv4 protocol number returns `PacketError::UnsupportedProtocol`.
#[test]
fn parse_ipv4_tcp_rejects_non_tcp_protocol()
{
    let mut pkt = build_ipv4_tcp(&[], b"");
    pkt[9] = 17;

    assert_eq!(parse_ipv4_tcp(&pkt).unwrap_err(), PacketError::UnsupportedProtocol(17));
}

/// Verifies that short buffers and impossible `ip.total_len` values return `PacketError::Truncated`.
#[test]
fn parse_ipv4_tcp_rejects_truncated_buffers_and_impossible_total_len()
{
    let base_pkt = build_ipv4_tcp(&[], b"hello");

    assert_eq!(parse_ipv4_tcp(&base_pkt[..10]).unwrap_err(), PacketError::Truncated);

    let mut oversized_total_len = base_pkt.clone();
    oversized_total_len[2..4].copy_from_slice(&100u16.to_be_bytes());
    assert_eq!(parse_ipv4_tcp(&oversized_total_len).unwrap_err(), PacketError::Truncated);

    let mut undersized_ip_len = base_pkt.clone();
    undersized_ip_len[2..4].copy_from_slice(&12u16.to_be_bytes());
    assert_eq!(parse_ipv4_tcp(&undersized_ip_len).unwrap_err(), PacketError::Truncated);

    let mut cut_tcp_len = base_pkt;
    cut_tcp_len[2..4].copy_from_slice(&30u16.to_be_bytes());
    assert_eq!(parse_ipv4_tcp(&cut_tcp_len).unwrap_err(), PacketError::Truncated);
}
