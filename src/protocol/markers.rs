//! Protocol-relative payload split markers and position resolver matching `protocol.c`.

/// L7 payload discriminator used when dispatching marker resolution.
use crate::protocol::l7::L7Payload;
/// Second-level domain finder and HTTP marker position resolver.
use crate::protocol::http::{find_nld, http_pos};
/// TLS handshake/SNI marker position resolver.
use crate::protocol::tls::tls_pos;

/// Maximum marker token length accepted by `posmarker_parse` (`sizeof(sm)` in `protocol.c`).
const MAX_MARKER_TOKEN_LEN: usize = 32;

/// Semantic anchor kind supported by `resolve_pos`, `resolve_multi_pos`, and `resolve_range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PosMarker {
    /// Absolute positive or negative offset within the payload (`abs` or bare integer).
    Abs,
    /// First byte of the extracted hostname (`host`).
    Host,
    /// Byte immediately following the hostname (`endhost`).
    HostEnd,
    /// First byte of the second-level domain label (`sld`).
    HostSld,
    /// Middle byte of the second-level domain label (`midsld`).
    HostMidSld,
    /// Byte immediately following the second-level domain label (`endsld`).
    HostEndSld,
    /// First byte of the HTTP request method (`method`).
    HttpMethod,
    /// Offset of the TLS ExtensionsLength 16-bit field (`extlen`).
    ExtLen,
    /// Start of the TLS SNI extension body (`sniext`).
    SniExt,
}

/// Parsed protocol split marker paired with its signed byte displacement (`struct proto_pos`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtoPos {
    /// Signed displacement added to the resolved marker offset (`int16_t` in C).
    pub pos: i16,
    /// Semantic anchor kind within the payload.
    pub marker: PosMarker,
}

/// Returns the canonical `zapret2` marker name string (`posmarker_name`).
pub const fn posmarker_name(marker: PosMarker) -> &'static str {
    match marker {
        PosMarker::Abs => "abs",
        PosMarker::Host => "host",
        PosMarker::HostEnd => "endhost",
        PosMarker::HostSld => "sld",
        PosMarker::HostMidSld => "midsld",
        PosMarker::HostEndSld => "endsld",
        PosMarker::HttpMethod => "method",
        PosMarker::ExtLen => "extlen",
        PosMarker::SniExt => "sniext",
    }
}

/// Parses a `zapret2` marker name into a [`PosMarker`] (`posmarker_from_name`).
pub fn posmarker_from_name(name: &str) -> Option<PosMarker> {
    match name {
        "abs" => Some(PosMarker::Abs),
        "host" => Some(PosMarker::Host),
        "endhost" => Some(PosMarker::HostEnd),
        "sld" => Some(PosMarker::HostSld),
        "midsld" => Some(PosMarker::HostMidSld),
        "endsld" => Some(PosMarker::HostEndSld),
        "method" => Some(PosMarker::HttpMethod),
        "extlen" => Some(PosMarker::ExtLen),
        "sniext" => Some(PosMarker::SniExt),
        _ => None,
    }
}

/// Parses a single marker specification such as `"midsld-1"`, `"host+2"`, or `"-5"` (`posmarker_parse`).
pub fn posmarker_parse(s: &str) -> Option<ProtoPos> {
    if let Ok(pos) = s.parse::<i16>() {
        return Some(ProtoPos {
            pos,
            marker: PosMarker::Abs,
        });
    }

    let split_idx = s.find(['+', '-']).unwrap_or(s.len());
    if split_idx >= MAX_MARKER_TOKEN_LEN {
        return None;
    }
    let marker = posmarker_from_name(&s[..split_idx])?;
    let rest = &s[split_idx..];
    let pos = if rest.is_empty() {
        0
    } else {
        rest.parse::<i16>().ok()?
    };
    Some(ProtoPos { pos, marker })
}

/// Parses a comma-separated list of up to `max_count` markers (`posmarker_list_parse`).
pub fn posmarker_list_parse(s: &str, max_count: usize) -> Option<Vec<ProtoPos>> {
    if s.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for token in s.split(',') {
        if out.len() >= max_count || token.len() >= MAX_MARKER_TOKEN_LEN {
            return None;
        }
        out.push(posmarker_parse(token)?);
    }
    Some(out)
}

/// Bounds-checks `offset` against `[0, sz)` matching `CheckPos` in `protocol.c:182`.
pub fn check_pos(sz: usize, offset: isize) -> Option<usize> {
    usize::try_from(offset).ok().filter(|&off| off < sz)
}

/// Resolves protocol-independent markers (`PM_ABS` with positive or from-end offsets).
pub fn any_proto_pos(marker: PosMarker, pos: i16, sz: usize) -> Option<usize> {
    match marker {
        PosMarker::Abs => {
            let sz_isize = isize::try_from(sz).ok()?;
            let pos_isize = isize::from(pos);
            let offset = if pos < 0 {
                sz_isize.checked_add(pos_isize)?
            } else {
                pos_isize
            };
            check_pos(sz, offset)
        }
        _ => None,
    }
}

/// Resolves host-relative markers (`host`, `endhost`, `sld`, `midsld`, `endsld`) inside `data`.
pub fn host_pos(
    marker: PosMarker,
    pos: i16,
    data: &[u8],
    offset_host: usize,
    len_host: usize,
) -> Option<usize> {
    let base = match marker {
        PosMarker::Host => offset_host,
        PosMarker::HostEnd => offset_host.checked_add(len_host)?,
        PosMarker::HostSld | PosMarker::HostMidSld | PosMarker::HostEndSld => {
            let end_host = offset_host.checked_add(len_host)?;
            let host_slice = data.get(offset_host..end_host)?;
            let (sld_rel, slen) = find_nld(host_slice, 2)?;
            let sld_abs = offset_host.checked_add(sld_rel)?;
            match marker {
                PosMarker::HostSld => sld_abs,
                PosMarker::HostEndSld => sld_abs.checked_add(slen)?,
                PosMarker::HostMidSld => {
                    // Preserve C quirk: 1-char SLDs point one past the SLD byte (`p + 1 - data`).
                    let step = if slen == 1 { 1 } else { slen / 2 };
                    sld_abs.checked_add(step)?
                }
                _ => return None,
            }
        }
        _ => return None,
    };

    let offset = isize::try_from(base).ok()?.checked_add(isize::from(pos))?;
    check_pos(data.len(), offset)
}

/// Resolves a single [`ProtoPos`] within `data` according to `l7payload` (`ResolvePos`).
pub fn resolve_pos(data: &[u8], l7payload: L7Payload, sp: ProtoPos) -> Option<usize> {
    match l7payload {
        L7Payload::HttpReq => http_pos(sp.marker, sp.pos, data),
        L7Payload::TlsClientHello => tls_pos(sp.marker, sp.pos, data),
        _ => any_proto_pos(sp.marker, sp.pos, data.len()),
    }
}

/// Resolves, sorts ascending, and deduplicates multiple [`ProtoPos`] markers (`ResolveMultiPos`).
pub fn resolve_multi_pos(data: &[u8], l7payload: L7Payload, markers: &[ProtoPos]) -> Vec<usize> {
    let mut positions: Vec<usize> = markers
        .iter()
        .filter_map(|&marker| resolve_pos(data, l7payload, marker))
        .collect();
    positions.sort_unstable();
    positions.dedup();
    positions
}
