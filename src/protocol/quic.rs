//! QUIC Long Header parsers, varints, Initial packet classifier, and CRYPTO defragmenter.

/// TLS ClientHello handshake detector used inside `is_quic_crypto_hello`.
use crate::protocol::tls::is_tls_handshake_client_hello;

/// Maximum QUIC connection ID byte length permitted by RFC 9000 (`QUIC_MAX_CID_LENGTH`).
pub const QUIC_MAX_CID_LENGTH: usize = 20;

/// Maximum CRYPTO frame fragments tracked during defragmentation (`MAX_DEFRAG_PIECES`).
const MAX_DEFRAG_PIECES: usize = 128;

/// Extracted QUIC Connection ID buffer (`quic_cid_t` in `protocol.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuicCid
{
    /// Raw Connection ID bytes (valid over `0..usize::from(self.len)`).
    pub bytes: [u8; QUIC_MAX_CID_LENGTH],
    /// Actual byte length (`1..=20` when valid).
    pub len: u8,
}

impl QuicCid
{
    /// Borrows the active Connection ID byte slice.
    pub fn as_slice(&self) -> &[u8]
    {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Returns the encoded byte width (`1`, `2`, `4`, or `8`) of a QUIC variable-length integer.
pub const fn tvb_get_size(first_byte: u8) -> usize
{
    1usize << (first_byte >> 6)
}

/// Decodes a QUIC variable-length integer from `buf`, returning `(value, encoded_byte_len)`.
pub fn tvb_get_varint(buf: &[u8]) -> Option<(u64, usize)>
{
    let first = *buf.first()?;
    let width = tvb_get_size(first);
    let slice = buf.get(..width)?;
    let value = match width
    {
        1 => u64::from(slice[0] & 0x3F),
        2 => u64::from(u16::from_be_bytes([slice[0], slice[1]]) & 0x3FFF),
        4 => u64::from(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]) & 0x3FFF_FFFF),
        8 =>
        {
            let raw = u64::from_be_bytes([
                slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
            ]);
            raw & 0x3FFF_FFFF_FFFF_FFFF
        }
        _ => return None,
    };
    Some((value, width))
}

/// Returns `true` if `version` identifies QUIC v2 or its draft (`0x709a50c4` / `0x6b3343cf`).
pub const fn is_quic_v2(version: u32) -> bool
{
    version == 0x709A_50C4 || version == 0x6b33_43cf
}

/// Maps a QUIC wire `version` field to its draft generation (`QUICDraftVersion`), or `0` if unknown.
pub const fn quic_draft_version(version: u32) -> u8
{
    if (version >> 8) == 0x00ff_0000
    {
        return version as u8;
    }
    if version == 0xface_b001
    {
        return 22;
    }
    if version == 0xface_b002 || version == 0xface_b00e
    {
        return 27;
    }
    if version == 0x5130_3530 || version == 0x5430_3530 || version == 0x5430_3531
    {
        return 27;
    }
    if (version & 0x0F0F_0F0F) == 0x0a0a_0a0a
    {
        return 29;
    }
    if version == 0x0000_0001
    {
        return 34;
    }
    if is_quic_v2(version)
    {
        return 100;
    }
    0
}

/// Returns `true` when `data` begins with a QUIC Long Header (`QUICIsLongHeader`).
pub fn quic_is_long_header(data: &[u8]) -> bool
{
    data.len() >= 9 && (data[0] & 0x80) != 0
}

/// Reads the 32-bit version field from a QUIC Long Header packet (`QUICExtractVersion`).
pub fn quic_extract_version(data: &[u8]) -> u32
{
    if quic_is_long_header(data) { u32::from_be_bytes([data[1], data[2], data[3], data[4]]) } else { 0 }
}

/// Extracts a non-empty Destination Connection ID (`1..=20` bytes) from a QUIC Long Header.
pub fn quic_extract_dcid(data: &[u8]) -> Option<QuicCid>
{
    if !quic_is_long_header(data)
    {
        return None;
    }
    let len = usize::from(data[5]);
    if len == 0 || len > QUIC_MAX_CID_LENGTH || 6 + len > data.len()
    {
        return None;
    }
    let mut cid = QuicCid { bytes: [0u8; QUIC_MAX_CID_LENGTH], len: len as u8 };
    cid.bytes[..len].copy_from_slice(&data[6..6 + len]);
    Some(cid)
}

/// Walks past SCID, Token, and Initial Payload Length varints, returning `(pn_offset, payload_len)`.
pub(crate) fn parse_initial_scid_token_payload(
    data: &[u8],
    scid_offset: usize,
    max_scid_len: Option<usize>,
) -> Option<(usize, usize)>
{
    let scid_len = usize::from(*data.get(scid_offset)?);
    if max_scid_len.is_some_and(|max| scid_len > max)
    {
        return None;
    }
    let token_offset = scid_offset
        .checked_add(1)?
        .checked_add(scid_len)?;
    if token_offset >= data.len()
    {
        return None;
    }

    let (token_len, token_sz) = tvb_get_varint(&data[token_offset..])?;
    let token_len_us = usize::try_from(token_len).ok()?;
    let pay_len_offset = token_offset
        .checked_add(token_sz)?
        .checked_add(token_len_us)?;
    if pay_len_offset >= data.len()
    {
        return None;
    }

    let (pay_len, pay_sz) = tvb_get_varint(&data[pay_len_offset..])?;
    let pay_len_us = usize::try_from(pay_len).ok()?;
    let pn_offset = pay_len_offset.checked_add(pay_sz)?;
    if pn_offset.checked_add(pay_len_us)? > data.len()
    {
        return None;
    }
    Some((pn_offset, pay_len_us))
}

/// Returns `true` when `data` is a syntactically plausible QUIC Initial packet (`IsQUICInitial`).
pub fn is_quic_initial(data: &[u8]) -> bool
{
    if data.len() < 128
    {
        return false;
    }
    let ver = quic_extract_version(data);
    if quic_draft_version(ver) < 11
    {
        return false;
    }
    let expected_type = if is_quic_v2(ver) { 0xD0 } else { 0xC0 };
    if (data[0] & 0xF0) != expected_type
    {
        return false;
    }

    let dcid_len = usize::from(data[5]);
    if dcid_len > QUIC_MAX_CID_LENGTH
    {
        return false;
    }
    let scid_offset = 6 + dcid_len;
    if scid_offset >= data.len()
    {
        return false;
    }

    parse_initial_scid_token_payload(data, scid_offset, Some(QUIC_MAX_CID_LENGTH)).is_some()
}

/// Defragments QUIC `CRYPTO` frames into one contiguous synthetic `CRYPTO` frame + coverage flag.
///
/// Matches `QUICDefragCrypto` in `zapret2/nfq2/protocol.c:1270-1365`.
pub fn quic_defrag_crypto(clean: &[u8], max_defrag_len: usize) -> Option<(Vec<u8>, bool)>
{
    let max_payload = max_defrag_len.checked_sub(10)?;
    let mut defrag_payload = Vec::new();
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut szmax = 0u64;
    let mut pos = 0usize;
    let mut found = false;

    while pos < clean.len()
    {
        let ft = clean[pos];
        pos += 1;
        if ft <= 1
        {
            continue;
        }
        if ft != 6 || pos >= clean.len() || ranges.len() >= MAX_DEFRAG_PIECES
        {
            return None;
        }

        let (offset, off_sz) = tvb_get_varint(&clean[pos..])?;
        pos += off_sz;
        if pos >= clean.len()
        {
            return None;
        }

        let (sz, sz_len) = tvb_get_varint(&clean[pos..])?;
        pos += sz_len;
        let sz_us = usize::try_from(sz).ok()?;
        let off_us = usize::try_from(offset).ok()?;
        let frame_end = off_us.checked_add(sz_us)?;
        if pos.checked_add(sz_us)? > clean.len() || frame_end > max_payload
        {
            return None;
        }

        if !ranges
            .iter()
            .any(|&(r_off, r_len)| r_off == offset && r_len == sz)
        {
            if frame_end > defrag_payload.len()
            {
                defrag_payload.resize(frame_end, 0);
            }
            defrag_payload[off_us..frame_end].copy_from_slice(&clean[pos..pos + sz_us]);
            found = true;
            szmax = szmax.max(frame_end as u64);
            ranges.push((offset, sz));
        }

        pos += sz_us;
    }

    if !found
    {
        return None;
    }

    ranges.sort_unstable_by_key(|&(off, _)| off);
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (next_start, next_len) in ranges
    {
        if let Some(last) = merged.last_mut()
        {
            let cur_end = last.0 + last.1;
            if next_start <= cur_end
            {
                let next_end = next_start + next_len;
                last.1 = cur_end.max(next_end) - last.0;
                continue;
            }
        }
        merged.push((next_start, next_len));
    }

    let is_full = merged.len() == 1 && merged[0].0 == 0;
    let mut out = Vec::with_capacity(10 + defrag_payload.len());
    out.push(6);
    out.push(0);
    let mut encoded_len = szmax.to_be_bytes();
    encoded_len[0] |= 0xC0;
    out.extend_from_slice(&encoded_len);
    out.extend_from_slice(&defrag_payload);

    Some((out, is_full))
}

/// Validates a full QUIC `CRYPTO` frame containing a TLS `ClientHello` at offset 0.
///
/// Returns `(hello_offset, hello_len)` within `data` (`IsQUICCryptoHello` in `protocol.c:1005`).
pub fn is_quic_crypto_hello(data: &[u8]) -> Option<(usize, usize)>
{
    if data.len() < 3 || data[0] != 6
    {
        return None;
    }
    let (coff, coff_sz) = tvb_get_varint(data.get(1..)?)?;
    let offset = 1 + coff_sz;
    if coff != 0 || offset >= data.len()
    {
        return None;
    }
    let (clen, clen_sz) = tvb_get_varint(&data[offset..])?;
    let hello_offset = offset + clen_sz;
    let hello_len = usize::try_from(clen).ok()?;
    let hello_end = hello_offset.checked_add(hello_len)?;
    let slice = data.get(hello_offset..hello_end)?;
    if !is_tls_handshake_client_hello(slice, true)
    {
        return None;
    }
    Some((hello_offset, hello_len))
}
