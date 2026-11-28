//! Full-packet wire reconstruction orchestrating L3/L4 serialization, checksums, and fragmentation.

/// Random number generation trait for intentional `--badsum` checksum corruption (`rand 0.10`).
use rand::RngExt;

/// Packet result alias.
use crate::packet::byte_reader::PEResult;
/// Protocol checksum computation and fixup helpers.
use crate::packet::checksum::{fix_icmp_checksum, fix_ipv4_checksum, fix_tcp_checksum, fix_udp_checksum};
/// Protocol numbers, header base sizes, and packet size limits.
use crate::packet::constants::{
    ICMP_BASE_LEN, IP6_BASE_LEN, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_NONE, IPPROTO_TCP, IPPROTO_UDP,
    RECONSTRUCT_MAX_SIZE, UDP_BASE_LEN,
};
/// Typed packet reconstruction errors.
use crate::packet::error::PacketError;
/// IPv4 and IPv6 fragmentation slicing finalizers.
use crate::packet::fragment::{finalize_ipv4_packet, finalize_ipv6_packet};
/// Standalone L3 and L4 header encoders.
use crate::packet::header_encode::{
    reconstruct_icmp_header, reconstruct_ipv4_header, reconstruct_ipv6_header, reconstruct_tcp_header,
    reconstruct_udp_header,
};
/// Dissected packet container struct.
use crate::packet::types::DissectedPacket;

/// Optional flags controlling checksums and IPv6 Next-Header chaining during reconstruction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReconstructOptions
{
    /// Preserve existing L4 checksums instead of recomputing them.
    pub keepsum: bool,
    /// Intentionally corrupt the L4 checksum (after recomputing, unless `keepsum` is true).
    pub badsum: bool,
    /// Keep existing `next` fields inside IPv6 extension headers instead of auto-linking them.
    pub ip6_preserve_next: bool,
    /// Override the trailing protocol identifier after IPv6 extension headers (`None` = auto).
    pub ip6_last_proto: Option<u8>,
}

/// Determines the IPv6 trailing protocol number automatically from present L4 headers.
fn auto_ipv6_last_proto(dis: &DissectedPacket) -> u8
{
    if dis
        .tcp
        .is_some()
    {
        IPPROTO_TCP
    }
    else if dis
        .udp
        .is_some()
    {
        IPPROTO_UDP
    }
    else if dis
        .icmp
        .is_some()
    {
        if dis
            .ip
            .is_some()
        {
            IPPROTO_ICMP
        }
        else if dis
            .ip6
            .is_some()
        {
            IPPROTO_ICMPV6
        }
        else
        {
            IPPROTO_NONE
        }
    }
    else
    {
        IPPROTO_NONE
    }
}

/// Applies non-zero random checksum corruption for `badsum` across TCP, UDP, and ICMP headers.
fn apply_badsum(l4_buf: &mut [u8], csum_offset: usize, forbid_zero: bool)
{
    let mut rng = rand::rng();
    let old = u16::from_be_bytes([l4_buf[csum_offset], l4_buf[csum_offset + 1]]);
    let corrupted = if forbid_zero
    {
        loop
        {
            let candidate = rng.random_range(1u16..=0xFFFF);
            if candidate != old
            {
                break candidate;
            }
        }
    }
    else
    {
        old ^ rng.random_range(1u16..=0xFFFF)
    };
    l4_buf[csum_offset..csum_offset + 2].copy_from_slice(&corrupted.to_be_bytes());
}

/// Appends payload bytes into `buf` after validating the 65535-byte payload limit and `RECONSTRUCT_MAX_SIZE`.
fn append_checked_payload(buf: &mut Vec<u8>, payload: &[u8]) -> PEResult<()>
{
    if payload.len() > 0xFFFF
    {
        return Err(PacketError::PayloadTooLarge(payload.len()));
    }
    if buf.len() + payload.len() > RECONSTRUCT_MAX_SIZE
    {
        return Err(PacketError::PayloadTooLarge(buf.len() + payload.len()));
    }
    buf.extend_from_slice(payload);
    Ok(())
}

/// Appends the L4 header matching `dis` (`TCP`, `UDP`, or `ICMP`), returning the protocol tag.
fn append_l4_header(dis: &DissectedPacket, buf: &mut Vec<u8>) -> PEResult<u8>
{
    if let Some(tcp) = &dis.tcp
    {
        let tcp_bytes = reconstruct_tcp_header(tcp)?;
        if buf.len() + tcp_bytes.len() > RECONSTRUCT_MAX_SIZE
        {
            return Err(PacketError::PayloadTooLarge(buf.len() + tcp_bytes.len()));
        }
        buf.extend_from_slice(&tcp_bytes);
        return Ok(IPPROTO_TCP);
    }
    if let Some(udp) = &dis.udp
    {
        if buf.len() + UDP_BASE_LEN > RECONSTRUCT_MAX_SIZE
        {
            return Err(PacketError::PayloadTooLarge(buf.len() + UDP_BASE_LEN));
        }
        buf.extend_from_slice(&reconstruct_udp_header(udp));
        return Ok(IPPROTO_UDP);
    }
    if let Some(icmp) = &dis.icmp
    {
        if buf.len() + ICMP_BASE_LEN > RECONSTRUCT_MAX_SIZE
        {
            return Err(PacketError::PayloadTooLarge(buf.len() + ICMP_BASE_LEN));
        }
        buf.extend_from_slice(&reconstruct_icmp_header(icmp));
        return Ok(IPPROTO_ICMP);
    }
    Ok(0)
}

/// Computes L4 checksums and optional bad-checksum sabotage across the serialized packet buffer.
fn apply_l4_checksums(
    l4_kind: u8,
    buf: &mut [u8],
    l3_len: usize,
    l4_end: usize,
    opts: &ReconstructOptions,
) -> PEResult<()>
{
    let (ip_hdr, rest) = buf.split_at_mut(l3_len);
    let (l4_hdr, pl) = rest.split_at_mut(l4_end - l3_len);
    match l4_kind
    {
        IPPROTO_TCP =>
        {
            fix_tcp_checksum(ip_hdr, l4_hdr, pl)?;
            if opts.badsum
            {
                apply_badsum(l4_hdr, 16, false);
            }
        }
        IPPROTO_UDP =>
        {
            let udp_len = u16::try_from(pl.len() + UDP_BASE_LEN)
                .map_err(|_| PacketError::PayloadTooLarge(pl.len() + UDP_BASE_LEN))?;
            l4_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
            fix_udp_checksum(ip_hdr, l4_hdr, pl)?;
            if opts.badsum
            {
                apply_badsum(l4_hdr, 6, true);
            }
        }
        IPPROTO_ICMP =>
        {
            fix_icmp_checksum(ip_hdr, l4_hdr, pl)?;
            if opts.badsum
            {
                apply_badsum(l4_hdr, 2, false);
            }
        }
        _ =>
        {}
    }
    Ok(())
}

/// Reconstructs a full wire-format L3/L4 packet from a [`DissectedPacket`] and [`ReconstructOptions`],
/// matching `zapret2`'s `lua_reconstruct_dissect`.
pub fn reconstruct_packet(dis: &DissectedPacket, opts: &ReconstructOptions) -> PEResult<Vec<u8>>
{
    let is_frag_dissect = dis
        .frag_off
        .is_some();
    let has_l4 = dis
        .tcp
        .is_some()
        || dis
            .udp
            .is_some()
        || dis
            .icmp
            .is_some();
    let last_proto_opt = opts
        .ip6_last_proto
        .unwrap_or(IPPROTO_NONE);
    let effective_preserve_next =
        opts.ip6_preserve_next || is_frag_dissect || (last_proto_opt == IPPROTO_NONE && !has_l4);
    let effective_last_proto =
        if last_proto_opt == IPPROTO_NONE { auto_ipv6_last_proto(dis) } else { last_proto_opt };

    let mut buf = if let Some(ip) = &dis.ip
    {
        reconstruct_ipv4_header(ip)?
    }
    else if let Some(ip6) = &dis.ip6
    {
        reconstruct_ipv6_header(ip6, effective_last_proto, effective_preserve_next)?
    }
    else
    {
        return Err(PacketError::MissingNetworkHeader);
    };

    let l3_len = buf.len();
    let is_v4 = dis
        .ip
        .is_some();
    let payload = dis
        .payload
        .as_deref()
        .unwrap_or(&[]);

    if is_frag_dissect
    {
        append_checked_payload(&mut buf, payload)?;
        if is_v4
        {
            let total_len = u16::try_from(buf.len()).map_err(|_| PacketError::PayloadTooLarge(buf.len()))?;
            buf[2..4].copy_from_slice(&total_len.to_be_bytes());
            fix_ipv4_checksum(&mut buf[..l3_len])?;
        }
        else
        {
            let plen = u16::try_from(buf.len() - IP6_BASE_LEN)
                .map_err(|_| PacketError::PayloadTooLarge(buf.len()))?;
            buf[4..6].copy_from_slice(&plen.to_be_bytes());
        }
        return Ok(buf);
    }

    let l4_kind = append_l4_header(dis, &mut buf)?;
    let l4_end = buf.len();
    append_checked_payload(&mut buf, payload)?;

    if !opts.keepsum && l4_kind != 0
    {
        apply_l4_checksums(l4_kind, &mut buf, l3_len, l4_end, opts)?;
    }

    if is_v4
    {
        finalize_ipv4_packet(&mut buf, l3_len)?;
    }
    else
    {
        finalize_ipv6_packet(&mut buf)?;
    }

    Ok(buf)
}
