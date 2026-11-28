//! IPv6 extension-header chain traversal, base header dissection, and header offset lookup.

/// IPv6 extension header protocol identifiers, base length, and fragment header masks.
use crate::packet::constants::{
    IP6_BASE_LEN, IP6F_MORE_FRAG, IP6F_OFF_MASK, IPPROTO_AH, IPPROTO_DSTOPTS, IPPROTO_FRAGMENT, IPPROTO_HIP,
    IPPROTO_HOPOPTS, IPPROTO_MH, IPPROTO_NONE, IPPROTO_ROUTING, IPPROTO_SHIM6,
};
/// Parsed IPv6 base header and extension-header structs.
use crate::packet::types::{Ipv6ExtHeader, Ipv6Header};

/// Result produced by walking an IPv6 extension-header chain from byte 40 onward.
pub(crate) struct Ipv6ExtWalk
{
    /// Decoded extension headers collected along the chain.
    pub(crate) exthdrs: Vec<Ipv6ExtHeader>,
    /// Start byte offset (relative to the start of the IPv6 packet) of each extension header.
    pub(crate) offsets: Vec<usize>,
    /// Total byte length of L3 (40-byte base header plus walked extension headers).
    pub(crate) l3_len: usize,
    /// Protocol identifier following the walked extension-header chain.
    pub(crate) l4_proto: u8,
    /// True if an IPv6 Fragment header with non-zero offset or More-Fragments flag was seen.
    pub(crate) frag: bool,
    /// Byte fragment offset extracted from the IPv6 Fragment header (`0` if unfragmented or first).
    pub(crate) frag_off: u16,
    /// True when the extension-header chain terminated cleanly according to `proto_skip_ipv6`.
    pub(crate) chain_valid: bool,
}

/// Returns true if `proto` is a known IPv6 extension header traversed by `proto_skip_ipv6`.
fn is_ipv6_exthdr_proto(proto: u8) -> bool
{
    matches!(
        proto,
        IPPROTO_HOPOPTS
            | IPPROTO_ROUTING
            | IPPROTO_DSTOPTS
            | IPPROTO_MH
            | IPPROTO_HIP
            | IPPROTO_SHIM6
            | IPPROTO_FRAGMENT
            | IPPROTO_AH
    )
}

/// Walks the IPv6 extension-header chain starting at byte 40, bounded by `min(raw.len() - 40, ip6_plen)`.
pub(crate) fn walk_ipv6_exthdrs(raw: &[u8]) -> Ipv6ExtWalk
{
    let plen = u16::from_be_bytes([raw[4], raw[5]]) as usize;
    let mut cur_proto = raw[6];
    let mut offset = IP6_BASE_LEN;
    let mut rem = (raw.len() - IP6_BASE_LEN).min(plen);
    let mut exthdrs = Vec::new();
    let mut offsets = Vec::new();
    let mut frag = false;
    let mut frag_off = 0u16;
    let mut chain_valid = !is_ipv6_exthdr_proto(cur_proto);

    while rem > 0
    {
        let slice = &raw[offset..offset + rem];
        let hdrlen = match cur_proto
        {
            IPPROTO_HOPOPTS | IPPROTO_ROUTING | IPPROTO_DSTOPTS | IPPROTO_MH | IPPROTO_HIP
            | IPPROTO_SHIM6 =>
            {
                if rem < 2
                {
                    chain_valid = false;
                    break;
                }
                8 + ((slice[1] as usize) << 3)
            }
            IPPROTO_FRAGMENT =>
            {
                if rem < 8
                {
                    chain_valid = false;
                    break;
                }
                let offlg = u16::from_be_bytes([slice[2], slice[3]]);
                frag_off = offlg & IP6F_OFF_MASK;
                frag = (offlg & (IP6F_OFF_MASK | IP6F_MORE_FRAG)) != 0;
                8
            }
            IPPROTO_AH =>
            {
                if rem < 2
                {
                    chain_valid = false;
                    break;
                }
                8 + ((slice[1] as usize) << 2)
            }
            _ =>
            {
                chain_valid = true;
                break;
            }
        };

        if rem < hdrlen
        {
            chain_valid = false;
            break;
        }

        let next_header = slice[0];
        offsets.push(offset);
        exthdrs.push(Ipv6ExtHeader { header_type: cur_proto, next_header, data: slice[2..hdrlen].to_vec() });

        cur_proto = next_header;
        offset += hdrlen;
        rem -= hdrlen;

        if frag && frag_off != 0
        {
            chain_valid = true;
            break;
        }
        if rem == 0
        {
            chain_valid = cur_proto == IPPROTO_NONE;
            break;
        }
    }

    Ipv6ExtWalk { exthdrs, offsets, l3_len: offset, l4_proto: cur_proto, frag, frag_off, chain_valid }
}

/// Reads the fixed 40-byte IPv6 base header fields and attaches parsed extension headers.
pub(crate) fn dissect_ipv6_base(raw: &[u8], exthdr: Vec<Ipv6ExtHeader>) -> Ipv6Header
{
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&raw[8..24]);
    dst.copy_from_slice(&raw[24..40]);

    Ipv6Header {
        flow: u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]),
        payload_len: Some(u16::from_be_bytes([raw[4], raw[5]])),
        next_header: raw[6],
        hop_limit: raw[7],
        src,
        dst,
        exthdr,
    }
}

/// Parses a standalone IPv6 header and its extension-header chain from `raw` (`lua_push_ip6hdr`).
pub fn dissect_ipv6_header(raw: &[u8]) -> Option<Ipv6Header>
{
    if raw.len() < IP6_BASE_LEN
    {
        return None;
    }
    let walk = walk_ipv6_exthdrs(raw);
    Some(dissect_ipv6_base(raw, walk.exthdrs))
}

/// Returns the byte offset of the first IPv6 extension header matching `target_proto`, if present.
pub fn find_ipv6_exthdr(raw: &[u8], target_proto: u8) -> Option<usize>
{
    if raw.len() < IP6_BASE_LEN
    {
        return None;
    }
    let walk = walk_ipv6_exthdrs(raw);
    walk.exthdrs
        .iter()
        .zip(walk.offsets.iter())
        .find(|(ext, _)| ext.header_type == target_proto)
        .map(|(_, &offset)| offset)
}
