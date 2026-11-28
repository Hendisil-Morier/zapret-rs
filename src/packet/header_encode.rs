//! Standalone wire-format header serializers for IPv4, IPv6, TCP, UDP, and ICMP.

/// Packet result alias.
use crate::packet::byte_reader::PEResult;
/// IPv4 header checksum fixup helper.
use crate::packet::checksum::fix_ipv4_checksum;
/// Protocol numbers, header base sizes, TCP option kinds, and option length limits.
use crate::packet::constants::{
    ICMP_BASE_LEN, IP_BASE_LEN, IP6_BASE_LEN, IPPROTO_AH, MAX_IP4_OPTIONS_LEN, MAX_TCP_OPTIONS_LEN,
    RECONSTRUCT_MAX_SIZE, TCP_BASE_LEN, TCP_KIND_END, TCP_KIND_NOOP, UDP_BASE_LEN,
};
/// Typed packet reconstruction errors.
use crate::packet::error::PacketError;
/// Header container types being serialized to wire bytes.
use crate::packet::types::{IcmpHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};

/// Reconstructs a wire-format IPv4 header with zero-padded options and a valid IPv4 header checksum.
pub fn reconstruct_ipv4_header(ip: &Ipv4Header) -> PEResult<Vec<u8>>
{
    if ip
        .options
        .len()
        > MAX_IP4_OPTIONS_LEN
    {
        return Err(PacketError::OptionsTooLong(
            ip.options
                .len(),
        ));
    }
    let padded_opt_len = (ip
        .options
        .len()
        + 3)
        & !3;
    let total_hdr_len = IP_BASE_LEN + padded_opt_len;
    let ihl = (total_hdr_len / 4) as u8;

    let mut buf = Vec::with_capacity(total_hdr_len);
    buf.push(0x40 | (ihl & 0x0F));
    buf.push(ip.tos);
    buf.extend_from_slice(
        &ip.total_len
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &ip.id
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &ip.frag_off
            .to_be_bytes(),
    );
    buf.push(ip.ttl);
    buf.push(ip.protocol);
    buf.extend_from_slice(&0u16.to_be_bytes());
    buf.extend_from_slice(&ip.src);
    buf.extend_from_slice(&ip.dst);
    buf.extend_from_slice(&ip.options);
    buf.resize(total_hdr_len, 0);

    fix_ipv4_checksum(&mut buf)?;
    Ok(buf)
}

/// Reconstructs a wire-format IPv6 base header plus extension headers, updating `Next Header` links unless `preserve_next` is true.
pub fn reconstruct_ipv6_header(ip6: &Ipv6Header, last_proto: u8, preserve_next: bool) -> PEResult<Vec<u8>>
{
    let mut buf = Vec::with_capacity(
        IP6_BASE_LEN
            + ip6
                .exthdr
                .len()
                * 8,
    );
    buf.extend_from_slice(
        &ip6.flow
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &ip6.payload_len
            .unwrap_or(0)
            .to_be_bytes(),
    );
    buf.push(ip6.next_header);
    buf.push(ip6.hop_limit);
    buf.extend_from_slice(&ip6.src);
    buf.extend_from_slice(&ip6.dst);

    let mut last_next_offset = 6usize;

    for ext in &ip6.exthdr
    {
        let data_len = ext
            .data
            .len();
        if data_len < 6
        {
            return Err(PacketError::InvalidExtHeader);
        }

        let len_byte = if ext.header_type == IPPROTO_AH
        {
            if data_len >= 1024 || ((data_len + 2) & 3) != 0
            {
                return Err(PacketError::InvalidExtHeader);
            }
            (((data_len + 2) >> 2) - 2) as u8
        }
        else
        {
            if data_len >= 2048 || ((data_len + 2) & 7) != 0
            {
                return Err(PacketError::InvalidExtHeader);
            }
            (((data_len + 2) >> 3) - 1) as u8
        };

        let cur_offset = buf.len();
        if cur_offset + 2 + data_len > RECONSTRUCT_MAX_SIZE
        {
            return Err(PacketError::PayloadTooLarge(cur_offset + 2 + data_len));
        }

        buf.push(ext.next_header);
        buf.push(len_byte);
        buf.extend_from_slice(&ext.data);

        if !preserve_next
        {
            buf[last_next_offset] = ext.header_type;
        }
        last_next_offset = cur_offset;
    }

    if !preserve_next
    {
        buf[last_next_offset] = last_proto;
    }

    if ip6
        .payload_len
        .is_none()
    {
        let plen =
            u16::try_from(buf.len() - IP6_BASE_LEN).map_err(|_| PacketError::PayloadTooLarge(buf.len()))?;
        buf[4..6].copy_from_slice(&plen.to_be_bytes());
    }

    Ok(buf)
}

/// Reconstructs a wire-format TCP header, encoding options and padding to a 4-byte boundary.
pub fn reconstruct_tcp_header(tcp: &TcpHeader) -> PEResult<Vec<u8>>
{
    let mut opt_buf = Vec::new();
    for opt in &tcp.options
    {
        match opt.kind
        {
            TCP_KIND_END | TCP_KIND_NOOP =>
            {
                if opt_buf.len() >= MAX_TCP_OPTIONS_LEN
                {
                    return Err(PacketError::OptionsTooLong(opt_buf.len() + 1));
                }
                opt_buf.push(opt.kind);
            }
            kind =>
            {
                let data = opt
                    .data
                    .as_deref()
                    .unwrap_or(&[]);
                let opt_len = 2 + data.len();
                if opt_buf.len() + opt_len > MAX_TCP_OPTIONS_LEN
                {
                    return Err(PacketError::OptionsTooLong(opt_buf.len() + opt_len));
                }
                opt_buf.push(kind);
                opt_buf.push(opt_len as u8);
                opt_buf.extend_from_slice(data);
            }
        }
    }

    let pad = (4 - (opt_buf.len() & 3)) & 3;
    if opt_buf.len() + pad > MAX_TCP_OPTIONS_LEN
    {
        return Err(PacketError::OptionsTooLong(opt_buf.len() + pad));
    }
    opt_buf.resize(opt_buf.len() + pad, 0);

    let total_len = TCP_BASE_LEN + opt_buf.len();
    let data_offset = (total_len / 4) as u8;

    let mut buf = Vec::with_capacity(total_len);
    buf.extend_from_slice(
        &tcp.s_port
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &tcp.d_port
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &tcp.seq
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &tcp.ack
            .to_be_bytes(),
    );
    buf.push((data_offset << 4) | (tcp.reserved & 0x0F));
    buf.push(tcp.flags);
    buf.extend_from_slice(
        &tcp.window
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &tcp.checksum
            .to_be_bytes(),
    );
    buf.extend_from_slice(
        &tcp.urgent_ptr
            .to_be_bytes(),
    );
    buf.extend_from_slice(&opt_buf);

    Ok(buf)
}

/// Reconstructs a wire-format 8-byte UDP header.
pub fn reconstruct_udp_header(udp: &UdpHeader) -> [u8; UDP_BASE_LEN]
{
    let mut buf = [0u8; UDP_BASE_LEN];
    buf[0..2].copy_from_slice(
        &udp.s_port
            .to_be_bytes(),
    );
    buf[2..4].copy_from_slice(
        &udp.d_port
            .to_be_bytes(),
    );
    buf[4..6].copy_from_slice(
        &udp.len
            .to_be_bytes(),
    );
    buf[6..8].copy_from_slice(
        &udp.checksum
            .to_be_bytes(),
    );
    buf
}

/// Reconstructs a wire-format 8-byte unified ICMPv4/ICMPv6 header.
pub fn reconstruct_icmp_header(icmp: &IcmpHeader) -> [u8; ICMP_BASE_LEN]
{
    let mut buf = [0u8; ICMP_BASE_LEN];
    buf[0] = icmp.icmp_type;
    buf[1] = icmp.icmp_code;
    buf[2..4].copy_from_slice(
        &icmp
            .checksum
            .to_be_bytes(),
    );
    buf[4..8].copy_from_slice(
        &icmp
            .data
            .to_be_bytes(),
    );
    buf
}
