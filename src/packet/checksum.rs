//! RFC 1071 / RFC 768 Internet checksum calculation and header fixup routines for IPv4, IPv6, TCP, UDP, and ICMP.

/// Packet result alias and typed error variants.
use crate::packet::byte_reader::PEResult;
/// IPv4/IPv6 header sizes and protocol numbers.
use crate::packet::constants::{IP_BASE_LEN, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};
/// Error variant returned when an invalid header is passed for checksum calculation.
use crate::packet::error::PacketError;
/// Layer-3 and layer-4 header structure validators.
use crate::packet::validate::{check_icmp_header, check_ipv6_header, check_tcp_header, check_udp_header};

/// Decoded L3 endpoint addresses used to construct transport pseudo-headers.
enum L3ChecksumTarget
{
    /// IPv4 source and destination addresses.
    V4
    {
        /// Source IPv4 address octets.
        src: [u8; 4],
        /// Destination IPv4 address octets.
        dst: [u8; 4],
    },
    /// IPv6 source and destination addresses.
    V6
    {
        /// Source IPv6 address bytes.
        src: [u8; 16],
        /// Destination IPv6 address bytes.
        dst: [u8; 16],
    },
}

/// Incremental RFC 1071 one's-complement 16-bit big-endian checksum accumulator.
#[derive(Debug, Clone, Copy, Default)]
pub struct ChecksumAccumulator
{
    /// Unfolded 64-bit sum of big-endian 16-bit words.
    sum: u64,
    /// Trailing unmatched high byte from an odd-length input slice.
    odd_byte: Option<u8>,
}

impl ChecksumAccumulator
{
    /// Creates an empty checksum accumulator initialized to zero.
    pub fn new() -> Self
    {
        Self::default()
    }

    /// Feeds arbitrary bytes into the one's-complement sum, handling odd-length slice boundaries.
    pub fn update(&mut self, bytes: &[u8])
    {
        let rest = if let Some(prev) = self
            .odd_byte
            .take()
        {
            if let Some((&first, tail)) = bytes.split_first()
            {
                self.sum += u64::from(u16::from_be_bytes([prev, first]));
                tail
            }
            else
            {
                self.odd_byte = Some(prev);
                return;
            }
        }
        else
        {
            bytes
        };

        let (chunks, remainder) = rest.as_chunks::<2>();
        for &chunk in chunks
        {
            self.sum += u64::from(u16::from_be_bytes(chunk));
        }

        if let Some(&last) = remainder.first()
        {
            self.odd_byte = Some(last);
        }
    }

    /// Feeds a 16-bit host-order integer in big-endian byte order.
    pub fn update_u16(&mut self, value: u16)
    {
        self.update(&value.to_be_bytes());
    }

    /// Feeds a 32-bit host-order integer in big-endian byte order.
    pub fn update_u32(&mut self, value: u32)
    {
        self.update(&value.to_be_bytes());
    }

    /// Folds carries into 16 bits and returns the inverted one's-complement checksum in host order.
    pub fn finalize(self) -> u16
    {
        let mut sum = self.sum;
        if let Some(last) = self.odd_byte
        {
            sum += u64::from(u16::from_be_bytes([last, 0]));
        }
        while (sum >> 16) != 0
        {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Adds the IPv4 transport pseudo-header (`src`, `dst`, `proto`, `transport_len`) to `acc`.
fn add_ipv4_pseudo_header(
    acc: &mut ChecksumAccumulator,
    src: [u8; 4],
    dst: [u8; 4],
    proto: u8,
    transport_len: usize,
)
{
    acc.update(&src);
    acc.update(&dst);
    acc.update_u32((transport_len as u32).wrapping_add(u32::from(proto)));
}

/// Adds the IPv6 transport pseudo-header (`src`, `dst`, `transport_len`, `proto`) to `acc`.
fn add_ipv6_pseudo_header(
    acc: &mut ChecksumAccumulator,
    src: [u8; 16],
    dst: [u8; 16],
    proto: u8,
    transport_len: usize,
)
{
    acc.update(&src);
    acc.update(&dst);
    acc.update_u32((transport_len as u32).wrapping_add(u32::from(proto)));
}

/// Feeds a header slice while treating the 2-byte checksum field at `csum_offset` as zeroes.
fn update_header_zeroing_csum(acc: &mut ChecksumAccumulator, hdr: &[u8], csum_offset: usize)
{
    if hdr.len() >= csum_offset + 2
    {
        acc.update(&hdr[..csum_offset]);
        acc.update(&[0, 0]);
        acc.update(&hdr[csum_offset + 2..]);
    }
    else
    {
        acc.update(hdr);
    }
}

/// Checks that `header` starts with an IPv4 header whose `ihl` fits inside `header`,
/// without requiring `ip_len` to be populated yet (matching `ip4_fix_checksum`).
fn is_valid_ipv4_header_for_csum(header: &[u8]) -> bool
{
    if header.len() < IP_BASE_LEN || (header[0] >> 4) != 4
    {
        return false;
    }
    let ihl_bytes = ((header[0] & 0x0F) as usize) * 4;
    ihl_bytes >= IP_BASE_LEN && header.len() >= ihl_bytes
}

/// Inspects `ip_hdr` as either an IPv4 or IPv6 header and returns its source and destination addresses.
fn detect_l3_addrs(ip_hdr: &[u8]) -> PEResult<L3ChecksumTarget>
{
    if is_valid_ipv4_header_for_csum(ip_hdr)
    {
        let src: [u8; 4] = ip_hdr[12..16]
            .try_into()
            .map_err(|_| PacketError::InvalidChecksumHeader)?;
        let dst: [u8; 4] = ip_hdr[16..20]
            .try_into()
            .map_err(|_| PacketError::InvalidChecksumHeader)?;
        Ok(L3ChecksumTarget::V4 { src, dst })
    }
    else if check_ipv6_header(ip_hdr)
    {
        let src: [u8; 16] = ip_hdr[8..24]
            .try_into()
            .map_err(|_| PacketError::InvalidChecksumHeader)?;
        let dst: [u8; 16] = ip_hdr[24..40]
            .try_into()
            .map_err(|_| PacketError::InvalidChecksumHeader)?;
        Ok(L3ChecksumTarget::V6 { src, dst })
    }
    else
    {
        Err(PacketError::InvalidChecksumHeader)
    }
}

/// Computes the RFC 1071 IPv4 header checksum over `ip_hl * 4` bytes, ignoring bytes `10..12`.
pub fn ipv4_header_checksum(header: &[u8]) -> PEResult<u16>
{
    if !is_valid_ipv4_header_for_csum(header)
    {
        return Err(PacketError::InvalidChecksumHeader);
    }
    let ihl_bytes = ((header[0] & 0x0F) as usize) * 4;
    let mut acc = ChecksumAccumulator::new();
    update_header_zeroing_csum(&mut acc, &header[..ihl_bytes], 10);
    Ok(acc.finalize())
}

/// Validates an IPv4 header buffer (`<= 60` bytes) and writes its updated checksum at bytes `10..12`.
pub fn fix_ipv4_checksum(header: &mut [u8]) -> PEResult<()>
{
    if header.len() > 60
    {
        return Err(PacketError::InvalidChecksumHeader);
    }
    let csum = ipv4_header_checksum(header)?;
    header[10..12].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

/// Computes the TCP checksum for an IPv4 packet (`tcp_hdr` + `payload`), ignoring `th_sum`.
pub fn tcp_ipv4_checksum(src: [u8; 4], dst: [u8; 4], tcp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    add_ipv4_pseudo_header(&mut acc, src, dst, IPPROTO_TCP, tcp_hdr.len() + payload.len());
    update_header_zeroing_csum(&mut acc, tcp_hdr, 16);
    acc.update(payload);
    acc.finalize()
}

/// Computes the TCP checksum for an IPv6 packet (`tcp_hdr` + `payload`), ignoring `th_sum`.
pub fn tcp_ipv6_checksum(src: [u8; 16], dst: [u8; 16], tcp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    add_ipv6_pseudo_header(&mut acc, src, dst, IPPROTO_TCP, tcp_hdr.len() + payload.len());
    update_header_zeroing_csum(&mut acc, tcp_hdr, 16);
    acc.update(payload);
    acc.finalize()
}

/// Validates L3 (`ip_hdr`) and L4 (`tcp_hdr`) headers and updates `th_sum` in `tcp_hdr[16..18]`.
pub fn fix_tcp_checksum(ip_hdr: &[u8], tcp_hdr: &mut [u8], payload: &[u8]) -> PEResult<()>
{
    if !check_tcp_header(tcp_hdr)
    {
        return Err(PacketError::InvalidChecksumHeader);
    }
    let csum = match detect_l3_addrs(ip_hdr)?
    {
        L3ChecksumTarget::V4 { src, dst } => tcp_ipv4_checksum(src, dst, tcp_hdr, payload),
        L3ChecksumTarget::V6 { src, dst } => tcp_ipv6_checksum(src, dst, tcp_hdr, payload),
    };
    tcp_hdr[16..18].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

/// Computes the UDP checksum for an IPv4 packet, converting `0x0000` to `0xFFFF` per RFC 768.
pub fn udp_ipv4_checksum(src: [u8; 4], dst: [u8; 4], udp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    add_ipv4_pseudo_header(&mut acc, src, dst, IPPROTO_UDP, udp_hdr.len() + payload.len());
    update_header_zeroing_csum(&mut acc, udp_hdr, 6);
    acc.update(payload);
    let csum = acc.finalize();
    if csum == 0 { 0xFFFF } else { csum }
}

/// Computes the UDP checksum for an IPv6 packet, converting `0x0000` to `0xFFFF` per RFC 768 / RFC 2460.
pub fn udp_ipv6_checksum(src: [u8; 16], dst: [u8; 16], udp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    add_ipv6_pseudo_header(&mut acc, src, dst, IPPROTO_UDP, udp_hdr.len() + payload.len());
    update_header_zeroing_csum(&mut acc, udp_hdr, 6);
    acc.update(payload);
    let csum = acc.finalize();
    if csum == 0 { 0xFFFF } else { csum }
}

/// Validates L3 (`ip_hdr`) and L4 (`udp_hdr`) headers and updates `uh_sum` in `udp_hdr[6..8]`.
pub fn fix_udp_checksum(ip_hdr: &[u8], udp_hdr: &mut [u8], payload: &[u8]) -> PEResult<()>
{
    if !check_udp_header(udp_hdr)
    {
        return Err(PacketError::InvalidChecksumHeader);
    }
    let csum = match detect_l3_addrs(ip_hdr)?
    {
        L3ChecksumTarget::V4 { src, dst } => udp_ipv4_checksum(src, dst, udp_hdr, payload),
        L3ChecksumTarget::V6 { src, dst } => udp_ipv6_checksum(src, dst, udp_hdr, payload),
    };
    udp_hdr[6..8].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}

/// Computes the ICMPv4 checksum over `icmp_hdr` + `payload` without a pseudo-header.
pub fn icmp_ipv4_checksum(icmp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    update_header_zeroing_csum(&mut acc, icmp_hdr, 2);
    acc.update(payload);
    acc.finalize()
}

/// Computes the ICMPv6 checksum over the IPv6 pseudo-header, `icmp_hdr`, and `payload`.
pub fn icmp_ipv6_checksum(src: [u8; 16], dst: [u8; 16], icmp_hdr: &[u8], payload: &[u8]) -> u16
{
    let mut acc = ChecksumAccumulator::new();
    add_ipv6_pseudo_header(&mut acc, src, dst, IPPROTO_ICMPV6, icmp_hdr.len() + payload.len());
    update_header_zeroing_csum(&mut acc, icmp_hdr, 2);
    acc.update(payload);
    acc.finalize()
}

/// Validates L3 (`ip_hdr`) and L4 (`icmp_hdr`) headers and updates `icmp_cksum` in `icmp_hdr[2..4]`.
pub fn fix_icmp_checksum(ip_hdr: &[u8], icmp_hdr: &mut [u8], payload: &[u8]) -> PEResult<()>
{
    if !check_icmp_header(icmp_hdr)
    {
        return Err(PacketError::InvalidChecksumHeader);
    }
    let csum = match detect_l3_addrs(ip_hdr)?
    {
        L3ChecksumTarget::V4 { .. } => icmp_ipv4_checksum(icmp_hdr, payload),
        L3ChecksumTarget::V6 { src, dst } => icmp_ipv6_checksum(src, dst, icmp_hdr, payload),
    };
    icmp_hdr[2..4].copy_from_slice(&csum.to_be_bytes());
    Ok(())
}
