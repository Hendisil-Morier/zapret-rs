//! TLS record/handshake detectors, extension parsers, SNI host extractor, and TLS markers.

/// Marker position helpers shared between HTTP and TLS resolvers.
use crate::protocol::markers::{PosMarker, any_proto_pos, check_pos, host_pos};

/// Maximum SNI hostname string length matching `char host[256]` buffers in `protocol.c`.
const MAX_TLS_HOST_LEN: usize = 255;

/// TLS content type for Handshake records (`0x16`).
const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
/// TLS handshake message type for `ClientHello` (`0x01`).
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// TLS handshake message type for `ServerHello` (`0x02`).
const TLS_HANDSHAKE_SERVER_HELLO: u8 = 0x02;
/// TLS Server Name Indication extension identifier (`0x0000`).
pub const TLS_EXT_SERVER_NAME: u16 = 0x0000;
/// TLS Padding extension identifier (`0x0015` = 21).
pub const TLS_EXT_PADDING: u16 = 21;

/// Returns the human-readable TLS/SSL version name or `"GREASE"`/`"UNKNOWN"` (`TLSVersionStr`).
pub const fn tls_version_str(tlsver: u16) -> &'static str {
    match tlsver {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => {
            if (tlsver & 0x0F0F) == 0x0A0A && (tlsver >> 12) == ((tlsver >> 4) & 0xF) {
                "GREASE"
            } else {
                "UNKNOWN"
            }
        }
    }
}

/// Reads the 24-bit body length from a TLS Handshake header (`TLSHandshakeDataLen`).
pub fn tls_handshake_data_len(data: &[u8]) -> Option<usize> {
    if data.len() < 4 {
        return None;
    }
    let val = u32::from_be_bytes([0, data[1], data[2], data[3]]);
    Some(val as usize)
}

/// Returns total TLS Handshake message byte length (`TLSHandshakeDataLen + 4`).
pub fn tls_handshake_len(data: &[u8]) -> Option<usize> {
    tls_handshake_data_len(data)?.checked_add(4)
}

/// Returns `true` when `data` contains the complete TLS Handshake message (`IsTLSHandshakeFull`).
pub fn is_tls_handshake_full(data: &[u8]) -> bool {
    tls_handshake_len(data).is_some_and(|full_len| full_len <= data.len())
}

/// Reads the 16-bit payload length field from a 5-byte TLS record header (`TLSRecordDataLen`).
pub fn tls_record_data_len(data: &[u8]) -> Option<u16> {
    if data.len() < 5 {
        return None;
    }
    Some(u16::from_be_bytes([data[3], data[4]]))
}

/// Returns total TLS record byte length (`TLSRecordDataLen + 5`).
pub fn tls_record_len(data: &[u8]) -> Option<usize> {
    Some(usize::from(tls_record_data_len(data)?) + 5)
}

/// Returns `true` when `data` contains the entire first TLS record (`IsTLSRecordFull`).
pub fn is_tls_record_full(data: &[u8]) -> bool {
    tls_record_len(data).is_some_and(|full_len| full_len <= data.len())
}

/// Checks whether a TLS Handshake body matches `hello_type` (`1`=Client, `2`=Server, `0`=either).
pub fn is_tls_handshake_hello(data: &[u8], hello_type: u8, partial_ok: bool) -> bool {
    data.len() >= 6
        && ((hello_type != 0 && data[0] == hello_type)
            || (hello_type == 0 && matches!(data[0], 0x01 | 0x02)))
        && data[4] == 0x03
        && data[5] <= 0x03
        && (partial_ok || is_tls_handshake_full(data))
}

/// Returns `true` for a TLS Handshake `ClientHello` message without the 5-byte record header.
pub fn is_tls_handshake_client_hello(data: &[u8], partial_ok: bool) -> bool {
    is_tls_handshake_hello(data, TLS_HANDSHAKE_CLIENT_HELLO, partial_ok)
}

/// Returns `true` for a TLS Handshake `ServerHello` message without the 5-byte record header.
pub fn is_tls_handshake_server_hello(data: &[u8], partial_ok: bool) -> bool {
    is_tls_handshake_hello(data, TLS_HANDSHAKE_SERVER_HELLO, partial_ok)
}

/// Checks whether a TLS record carries a `ClientHello`/`ServerHello` (`hello_type` `0` = either).
pub fn is_tls_hello(data: &[u8], hello_type: u8, partial_ok: bool) -> bool {
    data.len() >= 6
        && data[0] == TLS_CONTENT_HANDSHAKE
        && data[1] == 0x03
        && data[2] <= 0x03
        && (partial_ok || is_tls_record_full(data))
        && is_tls_handshake_hello(&data[5..], hello_type, partial_ok)
}

/// Returns `true` when `data` starts with a TLS `ClientHello` record (`IsTLSClientHello`).
pub fn is_tls_client_hello(data: &[u8], partial_ok: bool) -> bool {
    is_tls_hello(data, TLS_HANDSHAKE_CLIENT_HELLO, partial_ok)
}

/// Returns `true` when `data` starts with a TLS `ServerHello` record (`IsTLSServerHello`).
pub fn is_tls_server_hello(data: &[u8], partial_ok: bool) -> bool {
    is_tls_hello(data, TLS_HANDSHAKE_SERVER_HELLO, partial_ok)
}

/// Convenience wrapper checking for a complete or partial TLS `ClientHello` record.
pub fn is_tls_client_hello_partial(data: &[u8]) -> bool {
    is_tls_client_hello(data, true)
}

/// Convenience wrapper checking for a complete or partial TLS `ServerHello` record.
pub fn is_tls_server_hello_partial(data: &[u8]) -> bool {
    is_tls_server_hello(data, true)
}

/// Finds the offset of the 16-bit `ExtensionsLength` field inside a TLS Hello handshake body.
pub fn tls_find_ext_len_in_handshake(data: &[u8]) -> Option<usize> {
    let mut off = 1 + 3 + 2 + 32; // type(1) + len(3) + version(2) + random(32)
    if data.len() < off + 1 {
        return None;
    }
    off += usize::from(data[off]) + 1; // SessionID

    if data.len() < off + 2 {
        return None;
    }
    if data[0] == TLS_HANDSHAKE_CLIENT_HELLO {
        off += usize::from(u16::from_be_bytes([data[off], data[off + 1]]));
    }
    off += 2; // CipherSuites / CipherSuite

    if data.len() < off + 1 {
        return None;
    }
    if data[0] == TLS_HANDSHAKE_CLIENT_HELLO {
        off += usize::from(data[off]);
    }
    off += 1; // CompressionMethods / CompressionMethod

    if data.len() < off + 2 {
        return None;
    }
    Some(off)
}

/// Finds the offset of the 16-bit `ExtensionsLength` field in a full TLS record (`TLSFindExtLen`).
pub fn tls_find_ext_len(data: &[u8]) -> Option<usize> {
    if data.len() < 5 {
        return None;
    }
    tls_find_ext_len_in_handshake(&data[5..]).map(|rel| rel + 5)
}

/// Locates TLS extension `ext_type` inside a handshake body, returning `(data_offset, data_len)`.
pub fn tls_find_ext_in_handshake(
    data: &[u8],
    ext_type: u16,
    partial_ok: bool,
) -> Option<(usize, usize)> {
    if !partial_ok && !is_tls_handshake_full(data) {
        return None;
    }
    let ext_len_off = tls_find_ext_len_in_handshake(data)?;
    let declared_len = usize::from(u16::from_be_bytes([
        data[ext_len_off],
        data[ext_len_off + 1],
    ]));
    let mut cursor = ext_len_off + 2;
    let avail = data.len() - cursor;
    let mut rem = if partial_ok {
        declared_len.min(avail)
    } else if avail < declared_len {
        return None;
    } else {
        declared_len
    };

    while rem >= 4 {
        let etype = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
        let elen = usize::from(u16::from_be_bytes([data[cursor + 2], data[cursor + 3]]));
        cursor += 4;
        rem -= 4;
        if rem < elen {
            break;
        }
        if etype == ext_type {
            return Some((cursor, elen));
        }
        cursor += elen;
        rem -= elen;
    }

    None
}

/// Locates TLS extension `ext_type` inside a TLS Hello record, returning `(data_offset, data_len)`.
pub fn tls_find_ext(data: &[u8], ext_type: u16, partial_ok: bool) -> Option<(usize, usize)> {
    if !is_tls_hello(data, 0, partial_ok) {
        return None;
    }
    let rec_len = tls_record_len(data)?;
    let bounded = &data[..data.len().min(rec_len)];
    let (rel_off, ext_len) = tls_find_ext_in_handshake(&bounded[5..], ext_type, partial_ok)?;
    Some((5 + rel_off, ext_len))
}

/// Validates an SNI extension payload and returns `(hostname_offset, hostname_len)` inside `ext`.
pub fn tls_advance_to_host_in_sni(ext: &[u8]) -> Option<(usize, usize)> {
    if ext.len() < 5 || ext[2] != 0 {
        return None;
    }
    let name_list_len = usize::from(u16::from_be_bytes([ext[0], ext[1]]));
    let server_name_len = usize::from(u16::from_be_bytes([ext[3], ext[4]]));
    if name_list_len < server_name_len + 3 || name_list_len > ext.len() - 2 {
        return None;
    }
    Some((5, server_name_len))
}

/// Decodes an SNI hostname slice into a lowercased `String` capped at 255 bytes.
fn extract_host_from_ext(ext: &[u8]) -> Option<String> {
    let (host_off, host_len) = tls_advance_to_host_in_sni(ext)?;
    let capped_len = host_len.min(MAX_TLS_HOST_LEN);
    let raw = String::from_utf8_lossy(&ext[host_off..host_off + capped_len]);
    crate::protocol::sanitize_wire_hostname(&raw)
}

/// Extracts and lowercases the SNI hostname from a TLS Hello record (`TLSHelloExtractHost`).
pub fn tls_hello_extract_host(data: &[u8], partial_ok: bool) -> Option<String> {
    let (ext_off, ext_len) = tls_find_ext(data, TLS_EXT_SERVER_NAME, partial_ok)?;
    extract_host_from_ext(&data[ext_off..ext_off + ext_len])
}

/// Extracts and lowercases the SNI hostname from a TLS Handshake body (`TLSHelloExtractHostFromHandshake`).
pub fn tls_hello_extract_host_from_handshake(data: &[u8], partial_ok: bool) -> Option<String> {
    let (ext_off, ext_len) = tls_find_ext_in_handshake(data, TLS_EXT_SERVER_NAME, partial_ok)?;
    extract_host_from_ext(&data[ext_off..ext_off + ext_len])
}

/// Resolves TLS-specific or generic payload split markers (`TLSPos` in `protocol.c:707-741`).
pub fn tls_pos(marker: PosMarker, pos: i16, data: &[u8]) -> Option<usize> {
    match marker {
        PosMarker::Host
        | PosMarker::HostEnd
        | PosMarker::HostSld
        | PosMarker::HostMidSld
        | PosMarker::HostEndSld
        | PosMarker::SniExt => {
            let (ext_off, ext_len) = tls_find_ext(data, TLS_EXT_SERVER_NAME, true)?;
            if marker == PosMarker::SniExt {
                let offset = isize::try_from(ext_off)
                    .ok()?
                    .checked_add(isize::from(pos))?;
                check_pos(data.len(), offset)
            } else {
                let ext = data.get(ext_off..ext_off + ext_len)?;
                let (rel_host, host_len) = tls_advance_to_host_in_sni(ext)?;
                let offset_host = ext_off.checked_add(rel_host)?;
                host_pos(marker, pos, data, offset_host, host_len)
            }
        }
        PosMarker::ExtLen => {
            let ext_len_off = tls_find_ext_len(data)?;
            let offset = isize::try_from(ext_len_off)
                .ok()?
                .checked_add(isize::from(pos))?;
            check_pos(data.len(), offset)
        }
        _ => any_proto_pos(marker, pos, data.len()),
    }
}
