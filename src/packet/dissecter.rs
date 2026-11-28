//! IPv4, TCP, UDP, and ICMP header parsers and full L3/L4 packet dissection.

/// Bounds-checked big-endian reader and shared packet result type.
use crate::packet::byte_reader::{ByteReader, PEResult};
/// Protocol numbers, header base lengths, TCP option kinds, and IPv4 fragmentation masks.
use crate::packet::constants::{
    ICMP_BASE_LEN, IP_BASE_LEN, IP_MF, IP_OFFMASK, IP6_BASE_LEN, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP,
    IPPROTO_UDP, TCP_BASE_LEN, TCP_KIND_END, TCP_KIND_NOOP, UDP_BASE_LEN,
};
/// Typed packet dissection error variants.
use crate::packet::error::PacketError;
/// IPv6 extension-header chain walker and base header decoder.
use crate::packet::ipv6_ext::{dissect_ipv6_base, walk_ipv6_exthdrs};
/// Parsed L3/L4 header and packet container structs.
use crate::packet::types::{
    DissectedPacket, Dissecter, IcmpHeader, Ipv4Header, TcpHeader, TcpOption, UdpHeader,
};
/// Bit-nibble extractors and wire bounds validators.
use crate::packet::validate::{
    check_icmp_header, check_ipv4_header, check_ipv4_payload, check_ipv6_header, check_ipv6_payload,
    check_tcp_header, check_udp_header, check_udp_payload, lower_4bits, upper_4bits,
};

/// Parses an IPv4 header from a [`ByteReader`] while strictly enforcing version 4 and IHL >= 20.
pub fn parse_ipv4_header(r: &mut ByteReader<'_>) -> PEResult<Ipv4Header>
{
    let ver_ihl = r.read_u8()?;

    let version = upper_4bits(ver_ihl);
    if version != 4
    {
        return Err(PacketError::UnsupportedVersion(version));
    }

    let header_len = lower_4bits(ver_ihl);
    let ip_bytes_len = (header_len as usize) * 4;

    if ip_bytes_len < IP_BASE_LEN
    {
        return Err(PacketError::InvalidHeaderLen(ip_bytes_len));
    }

    Ok(Ipv4Header {
        version,
        header_len,

        tos: r.read_u8()?,
        total_len: r.read_u16()?,

        id: r.read_u16()?,
        frag_off: r.read_u16()?,
        ttl: r.read_u8()?,

        protocol: r.read_u8()?,
        checksum: r.read_u16()?,

        src: r.read_array::<4>()?,
        dst: r.read_array::<4>()?,

        options: r
            .read_bytes(ip_bytes_len - IP_BASE_LEN)?
            .to_vec(),
    })
}

/// Parses a TCP header from a [`ByteReader`] and decodes its options past byte 20.
fn parse_tcp_header(reader: &mut ByteReader<'_>) -> PEResult<TcpHeader>
{
    let s_port = reader.read_u16()?;
    let d_port = reader.read_u16()?;

    let seq = reader.read_u32()?;
    let ack = reader.read_u32()?;

    let off_res = reader.read_u8()?;
    let data_offset = upper_4bits(off_res);
    let reserved = lower_4bits(off_res);

    let tcp_bytes_len = (data_offset as usize) * 4;
    if tcp_bytes_len < TCP_BASE_LEN
    {
        return Err(PacketError::InvalidHeaderLen(tcp_bytes_len));
    }

    let flags = reader.read_u8()?;
    let window = reader.read_u16()?;
    let checksum = reader.read_u16()?;
    let urgent_ptr = reader.read_u16()?;
    let option_bytes = reader.read_bytes(tcp_bytes_len - TCP_BASE_LEN)?;

    Ok(TcpHeader {
        s_port,
        d_port,
        seq,
        ack,
        data_offset,
        reserved,
        flags,
        window,
        checksum,
        urgent_ptr,
        options: parse_tcp_option(option_bytes),
    })
}

/// Parses an IPv4 + TCP packet buffer into [`Dissecter`], trimming trailing link-layer padding.
pub fn parse_ipv4_tcp(raw: &[u8]) -> PEResult<Dissecter>
{
    let mut reader = ByteReader::new(raw);

    let ip = parse_ipv4_header(&mut reader)?;
    reader.truncate(ip.total_len as usize)?;

    if ip.protocol != IPPROTO_TCP
    {
        return Err(PacketError::UnsupportedProtocol(ip.protocol));
    }

    let tcp = parse_tcp_header(&mut reader)?;
    let payload = reader
        .remaining()
        .to_vec();

    Ok(Dissecter { ip, tcp, payload })
}

/// Parses variable-length TCP options past byte 20, stripping only trailing END padding bytes.
fn parse_tcp_option(input: &[u8]) -> Vec<TcpOption>
{
    let mut reader = ByteReader::new(input);
    let mut option = Vec::new();

    while let Ok(kind) = reader.read_u8()
    {
        if kind == TCP_KIND_END || kind == TCP_KIND_NOOP
        {
            option.push(TcpOption { kind, data: None });
        }
        else
        {
            let Ok(len) = reader.read_u8()
            else
            {
                break;
            };
            let Some(data_len) = (len as usize).checked_sub(2)
            else
            {
                break;
            };

            let Ok(data) = reader.read_bytes(data_len)
            else
            {
                break;
            };

            option.push(TcpOption { kind, data: Some(data.to_vec()) });
        }
    }

    // Strip trailing END padding while preserving any END bytes embedded between other options.
    while option
        .last()
        .is_some_and(|opt| opt.kind == TCP_KIND_END)
    {
        option.pop();
    }

    option
}

/// Parses standalone IPv4 header bytes matching `zapret2`'s `lua_push_iphdr`.
pub fn dissect_ipv4_header(raw: &[u8]) -> Option<Ipv4Header>
{
    if raw.len() < IP_BASE_LEN
    {
        return None;
    }
    let version = upper_4bits(raw[0]);
    let header_len = lower_4bits(raw[0]);
    let ihl_bytes = (header_len as usize) * 4;
    let options = if ihl_bytes > IP_BASE_LEN && ihl_bytes <= raw.len()
    {
        raw[IP_BASE_LEN..ihl_bytes].to_vec()
    }
    else
    {
        Vec::new()
    };

    Some(Ipv4Header {
        version,
        header_len,
        tos: raw[1],
        total_len: u16::from_be_bytes([raw[2], raw[3]]),
        id: u16::from_be_bytes([raw[4], raw[5]]),
        frag_off: u16::from_be_bytes([raw[6], raw[7]]),
        ttl: raw[8],
        protocol: raw[9],
        checksum: u16::from_be_bytes([raw[10], raw[11]]),
        src: raw[12..16]
            .try_into()
            .ok()?,
        dst: raw[16..20]
            .try_into()
            .ok()?,
        options,
    })
}

/// Parses standalone TCP header bytes (clamping options to `raw.len()`) matching `lua_push_tcphdr`.
pub fn dissect_tcp_header(raw: &[u8]) -> Option<TcpHeader>
{
    if raw.len() < TCP_BASE_LEN
    {
        return None;
    }
    let data_offset = upper_4bits(raw[12]);
    let reserved = lower_4bits(raw[12]);
    let tcp_len = ((data_offset as usize) * 4).min(raw.len());
    let options =
        if tcp_len > TCP_BASE_LEN { parse_tcp_option(&raw[TCP_BASE_LEN..tcp_len]) } else { Vec::new() };

    Some(TcpHeader {
        s_port: u16::from_be_bytes([raw[0], raw[1]]),
        d_port: u16::from_be_bytes([raw[2], raw[3]]),
        seq: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
        ack: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
        reserved,
        data_offset,
        flags: raw[13],
        window: u16::from_be_bytes([raw[14], raw[15]]),
        checksum: u16::from_be_bytes([raw[16], raw[17]]),
        urgent_ptr: u16::from_be_bytes([raw[18], raw[19]]),
        options,
    })
}

/// Parses standalone 8-byte UDP header bytes matching `lua_push_udphdr`.
pub fn dissect_udp_header(raw: &[u8]) -> Option<UdpHeader>
{
    if raw.len() < UDP_BASE_LEN
    {
        return None;
    }
    Some(UdpHeader {
        s_port: u16::from_be_bytes([raw[0], raw[1]]),
        d_port: u16::from_be_bytes([raw[2], raw[3]]),
        len: u16::from_be_bytes([raw[4], raw[5]]),
        checksum: u16::from_be_bytes([raw[6], raw[7]]),
    })
}

/// Parses standalone 8-byte ICMPv4/ICMPv6 header bytes matching `lua_push_icmphdr`.
pub fn dissect_icmp_header(raw: &[u8]) -> Option<IcmpHeader>
{
    if raw.len() < ICMP_BASE_LEN
    {
        return None;
    }
    Some(IcmpHeader {
        icmp_type: raw[0],
        icmp_code: raw[1],
        checksum: u16::from_be_bytes([raw[2], raw[3]]),
        data: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
    })
}

/// Dissects a complete L3/L4 packet into [`DissectedPacket`], matching `zapret2`'s `proto_dissect_l3l4`.
pub fn dissect_packet(raw: &[u8], no_payload_check: bool) -> DissectedPacket
{
    let mut dis = DissectedPacket::default();
    let pkt: &[u8];
    let is_frag: bool;

    if check_ipv4_header(raw) && (no_payload_check || check_ipv4_payload(raw))
    {
        let Some(ip) = dissect_ipv4_header(raw)
        else
        {
            return dis;
        };
        let iplen = (ip.total_len as usize).min(raw.len());
        pkt = &raw[..iplen];
        let ihl_bytes = (ip.header_len as usize) * 4;
        is_frag = (ip.frag_off & (IP_OFFMASK | IP_MF)) != 0;
        if is_frag
        {
            dis.frag_off = Some((ip.frag_off & IP_OFFMASK) << 3);
        }
        dis.l4proto = ip.protocol;
        dis.l3_len = ihl_bytes;
        dis.ip = Some(ip);
    }
    else if check_ipv6_header(raw) && (no_payload_check || check_ipv6_payload(raw))
    {
        let plen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
        let iplen = (IP6_BASE_LEN + plen).min(raw.len());
        pkt = &raw[..iplen];
        let walk = walk_ipv6_exthdrs(pkt);
        if !walk.chain_valid
        {
            return dis;
        }
        is_frag = walk.frag;
        if is_frag
        {
            dis.frag_off = Some(walk.frag_off);
        }
        dis.l4proto = walk.l4_proto;
        dis.l3_len = walk.l3_len;
        dis.ip6 = Some(dissect_ipv6_base(pkt, walk.exthdrs));
    }
    else
    {
        return dis;
    }

    let mut rem = &pkt[dis.l3_len..];
    dis.transport_len = rem.len();

    if !is_frag
    {
        if dis.l4proto == IPPROTO_TCP && check_tcp_header(rem)
        {
            if let Some(tcp) = dissect_tcp_header(rem)
            {
                let l4_len = (tcp.data_offset as usize) * 4;
                dis.l4_len = l4_len;
                dis.tcp = Some(tcp);
                rem = &rem[l4_len..];
            }
        }
        else if dis.l4proto == IPPROTO_UDP
            && check_udp_header(rem)
            && (no_payload_check || check_udp_payload(rem))
        {
            if let Some(udp) = dissect_udp_header(rem)
            {
                dis.l4_len = UDP_BASE_LEN;
                dis.udp = Some(udp);
                rem = &rem[UDP_BASE_LEN..];
            }
        }
        else if (dis.l4proto == IPPROTO_ICMP || dis.l4proto == IPPROTO_ICMPV6)
            && check_icmp_header(rem)
            && let Some(icmp) = dissect_icmp_header(rem)
        {
            dis.l4_len = ICMP_BASE_LEN;
            dis.icmp = Some(icmp);
            rem = &rem[ICMP_BASE_LEN..];
        }
    }

    dis.payload = Some(rem.to_vec());
    dis
}
