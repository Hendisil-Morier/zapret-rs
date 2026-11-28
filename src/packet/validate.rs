//! Wire-level L3/L4 header bounds checks and destination address extraction.

/// Destination IP address representation returned by [`extract_dst`].
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Shared packet result alias.
use crate::packet::byte_reader::PEResult;
/// Header minimum sizes for IPv4, IPv6, TCP, UDP, and ICMP.
use crate::packet::constants::{ICMP_BASE_LEN, IP_BASE_LEN, IP6_BASE_LEN, TCP_BASE_LEN, UDP_BASE_LEN};
/// Typed error returned when destination extraction receives malformed headers.
use crate::packet::error::PacketError;

/// Extracts the high 4 bits of a packed header byte (e.g., IP version or TCP data offset).
pub(crate) fn upper_4bits(input: u8) -> u8
{
    input >> 4
}

/// Extracts the low 4 bits of a packed header byte (e.g., IPv4 IHL or TCP reserved bits).
pub(crate) fn lower_4bits(input: u8) -> u8
{
    input & 0x0F
}

/// Validates that `raw` starts with a well-formed IPv4 header whose declared lengths fit inside `raw`.
pub fn check_ipv4_header(raw: &[u8]) -> bool
{
    if raw.len() < IP_BASE_LEN
    {
        return false;
    }
    if upper_4bits(raw[0]) != 4
    {
        return false;
    }
    let ip_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    let ihl_bytes = (lower_4bits(raw[0]) as usize) * 4;
    ihl_bytes >= IP_BASE_LEN && ip_len >= ihl_bytes && raw.len() >= ihl_bytes
}

/// Validates that `raw` holds at least the full `ip_len` declared in its IPv4 header.
pub fn check_ipv4_payload(raw: &[u8]) -> bool
{
    if raw.len() < IP_BASE_LEN
    {
        return false;
    }
    let ip_len = u16::from_be_bytes([raw[2], raw[3]]) as usize;
    raw.len() >= ip_len
}

/// Validates that `raw` starts with a 40-byte IPv6 base header (`version == 6`).
pub fn check_ipv6_header(raw: &[u8]) -> bool
{
    raw.len() >= IP6_BASE_LEN && (raw[0] & 0xF0) == 0x60
}

/// Validates that `raw` holds at least `40 + ip6_plen` bytes.
pub fn check_ipv6_payload(raw: &[u8]) -> bool
{
    if raw.len() < IP6_BASE_LEN
    {
        return false;
    }
    let plen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    raw.len() >= IP6_BASE_LEN + plen
}

/// Validates that `raw` holds a complete TCP header including its variable-length options.
pub fn check_tcp_header(raw: &[u8]) -> bool
{
    if raw.len() < TCP_BASE_LEN
    {
        return false;
    }
    let off = (upper_4bits(raw[12]) as usize) * 4;
    off >= TCP_BASE_LEN && raw.len() >= off
}

/// Validates that `raw` holds at least an 8-byte UDP header.
pub fn check_udp_header(raw: &[u8]) -> bool
{
    raw.len() >= UDP_BASE_LEN
}

/// Validates that `raw` holds at least the full length declared in `uh_ulen`.
pub fn check_udp_payload(raw: &[u8]) -> bool
{
    if raw.len() < UDP_BASE_LEN
    {
        return false;
    }
    let ulen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    ulen >= UDP_BASE_LEN && raw.len() >= ulen
}

/// Validates that `raw` holds at least an 8-byte ICMPv4/ICMPv6 base header.
pub fn check_icmp_header(raw: &[u8]) -> bool
{
    raw.len() >= ICMP_BASE_LEN
}

/// Extracts the destination [`IpAddr`] from a raw IPv4 or IPv6 packet, matching `extract_dst`.
pub fn extract_dst(raw: &[u8]) -> PEResult<IpAddr>
{
    if check_ipv4_header(raw)
    {
        let dst: [u8; 4] = raw[16..20]
            .try_into()
            .map_err(|_| PacketError::Truncated)?;
        Ok(IpAddr::V4(Ipv4Addr::from(dst)))
    }
    else if check_ipv6_header(raw)
    {
        let dst: [u8; 16] = raw[24..40]
            .try_into()
            .map_err(|_| PacketError::Truncated)?;
        Ok(IpAddr::V6(Ipv6Addr::from(dst)))
    }
    else if !raw.is_empty()
    {
        let ver = upper_4bits(raw[0]);
        if ver != 4 && ver != 6
        {
            Err(PacketError::UnsupportedVersion(ver))
        }
        else
        {
            Err(PacketError::Truncated)
        }
    }
    else
    {
        Err(PacketError::Truncated)
    }
}
