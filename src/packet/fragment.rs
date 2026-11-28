//! IPv4 and IPv6 fragmentation slicing and L3 length/checksum finalization.

/// Packet result alias.
use crate::packet::byte_reader::PEResult;
/// IPv4 header checksum fixup routine.
use crate::packet::checksum::fix_ipv4_checksum;
/// IPv4/IPv6 base sizes, protocol numbers, and fragmentation masks.
use crate::packet::constants::{
    IP_MF, IP_OFFMASK, IP6_BASE_LEN, IP6F_MORE_FRAG, IP6F_OFF_MASK, IPPROTO_FRAGMENT,
};
/// Typed error variants returned for invalid fragment offsets or lengths.
use crate::packet::error::PacketError;
/// IPv6 extension header offset lookup helper.
use crate::packet::ipv6_ext::find_ipv6_exthdr;

/// Finalizes IPv4 fragmentation slicing and updates `ip_len` and the IPv4 header checksum.
pub(crate) fn finalize_ipv4_packet(buf: &mut Vec<u8>, l3_len: usize) -> PEResult<()>
{
    let ip_off = u16::from_be_bytes([buf[6], buf[7]]);
    if (ip_off & (IP_OFFMASK | IP_MF)) != 0
    {
        let iplen = u16::from_be_bytes([buf[2], buf[3]]) as usize;
        let off = ((ip_off & IP_OFFMASK) as usize) << 3;
        let frag_start = l3_len + off;
        if iplen < l3_len || iplen > buf.len()
        {
            return Err(PacketError::InvalidFragment);
        }
        let frag_len = iplen - l3_len;
        if frag_start
            .checked_add(frag_len)
            .is_none_or(|end| end > buf.len())
        {
            return Err(PacketError::InvalidFragment);
        }
        if off != 0
        {
            buf.copy_within(frag_start..frag_start + frag_len, l3_len);
        }
        buf.truncate(iplen);
    }
    else
    {
        let total_len = u16::try_from(buf.len()).map_err(|_| PacketError::PayloadTooLarge(buf.len()))?;
        buf[2..4].copy_from_slice(&total_len.to_be_bytes());
    }
    fix_ipv4_checksum(&mut buf[..l3_len])
}

/// Finalizes IPv6 fragmentation slicing and updates `ip6_plen`.
pub(crate) fn finalize_ipv6_packet(buf: &mut Vec<u8>) -> PEResult<()>
{
    if let Some(frag_pos) = find_ipv6_exthdr(buf, IPPROTO_FRAGMENT)
        && frag_pos + 8 <= buf.len()
    {
        let offlg = u16::from_be_bytes([buf[frag_pos + 2], buf[frag_pos + 3]]);
        if (offlg & (IP6F_OFF_MASK | IP6F_MORE_FRAG)) != 0
        {
            let plen = u16::from_be_bytes([buf[4], buf[5]]) as usize;
            let off = (offlg & IP6F_OFF_MASK) as usize;
            let endfrag = frag_pos + 8;
            let size_unfragmentable = endfrag - IP6_BASE_LEN;
            if size_unfragmentable > plen
            {
                return Err(PacketError::InvalidFragment);
            }
            let size_fragmentable = plen - size_unfragmentable;
            if endfrag
                .checked_add(off)
                .and_then(|start| start.checked_add(size_fragmentable))
                .is_none_or(|end| end > buf.len())
            {
                return Err(PacketError::InvalidFragment);
            }
            if off != 0
            {
                buf.copy_within(endfrag + off..endfrag + off + size_fragmentable, endfrag);
            }
            buf.truncate(IP6_BASE_LEN + plen);
            return Ok(());
        }
    }

    let plen =
        u16::try_from(buf.len() - IP6_BASE_LEN).map_err(|_| PacketError::PayloadTooLarge(buf.len()))?;
    buf[4..6].copy_from_slice(&plen.to_be_bytes());
    Ok(())
}
