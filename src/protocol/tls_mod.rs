//! TLS ClientHello mutator (`tls_mod`) matching `TLSMod_parse_list` and `TLSMod` in `protocol.c`.

/// Random generator traits (`Rng`, `RngExt`) used for `rnd` and `rndsni` mutations (`rand 0.10`).
use rand::{Rng, RngExt};

/// TLS extension scanners and SNI offset helpers reused by `tls_mod`.
use crate::protocol::tls::{
    TLS_EXT_PADDING, TLS_EXT_SERVER_NAME, is_tls_client_hello, is_tls_client_hello_partial,
    tls_advance_to_host_in_sni, tls_find_ext, tls_find_ext_len,
};

/// Randomizes ClientHello `random` (32B) and `session_id` fields (`FAKE_TLS_MOD_RND`).
pub const FAKE_TLS_MOD_RND: u32 = 0x01;
/// Randomizes the SNI hostname while preserving its byte length (`FAKE_TLS_MOD_RND_SNI`).
pub const FAKE_TLS_MOD_RND_SNI: u32 = 0x02;
/// Replaces the SNI hostname and adjusts all six enveloping TLS lengths (`FAKE_TLS_MOD_SNI`).
pub const FAKE_TLS_MOD_SNI: u32 = 0x04;
/// Copies `session_id` from the triggering original ClientHello payload (`FAKE_TLS_MOD_DUP_SID`).
pub const FAKE_TLS_MOD_DUP_SID: u32 = 0x08;
/// Expands TLS Padding (ext 21) lengths by payload size to encapsulate data (`FAKE_TLS_MOD_PADENCAP`).
pub const FAKE_TLS_MOD_PADENCAP: u32 = 0x10;

/// Maximum `sni=` byte length matching `sizeof(struct fake_tls_mod::sni) - 1` (`255`).
const MAX_MOD_SNI_LEN: usize = 255;

/// Common 3-letter TLDs used when generating synthetic SNI hostnames (`params.c:89`).
const RANDOM_TLDS: [&[u8; 3]; 6] = [b"com", b"org", b"net", b"edu", b"gov", b"biz"];

/// Parsed `tls_mod` modifier bitmask and optional replacement SNI string (`struct fake_tls_mod`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FakeTlsMod {
    /// Replacement SNI hostname when [`FAKE_TLS_MOD_SNI`] is set.
    pub sni: String,
    /// Bitwise OR of `FAKE_TLS_MOD_*` flags.
    pub mod_flags: u32,
}

impl FakeTlsMod {
    /// Parses a comma-separated `tls_mod` modifier list (`TLSMod_parse_list` in `protocol.c:745`).
    pub fn parse_list(modlist: &str) -> Option<Self> {
        let mut parsed = Self::default();
        let mut cursor = modlist;

        while !cursor.is_empty() {
            let (token, rest) = match cursor.find(',') {
                Some(comma) => (&cursor[..comma], &cursor[comma + 1..]),
                None => (cursor, ""),
            };
            let (name, val) = match token.find('=') {
                Some(eq) => (&token[..eq], Some(&token[eq + 1..])),
                None => (token, None),
            };

            match name {
                "rnd" => parsed.mod_flags |= FAKE_TLS_MOD_RND,
                "rndsni" => parsed.mod_flags |= FAKE_TLS_MOD_RND_SNI,
                "dupsid" => parsed.mod_flags |= FAKE_TLS_MOD_DUP_SID,
                "padencap" => parsed.mod_flags |= FAKE_TLS_MOD_PADENCAP,
                "sni" => {
                    let sni_val = val.filter(|s| !s.is_empty())?;
                    parsed.mod_flags |= FAKE_TLS_MOD_SNI;
                    parsed.sni = truncate_sni_utf8(sni_val, MAX_MOD_SNI_LEN).to_owned();
                }
                "none" => {}
                _ => return None,
            }

            cursor = rest;
        }

        Some(parsed)
    }
}

/// Truncates `s` on a valid UTF-8 boundary to at most `max_bytes` bytes.
fn truncate_sni_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Reads an unsigned big-endian 16-bit integer at `off`, returning `None` if out of bounds.
fn read_be16(buf: &[u8], off: usize) -> Option<u16> {
    let bytes: [u8; 2] = buf.get(off..off + 2)?.try_into().ok()?;
    Some(u16::from_be_bytes(bytes))
}

/// Writes `val` as a big-endian 16-bit integer at `off`.
fn write_be16(buf: &mut [u8], off: usize, val: u16) -> Option<()> {
    buf.get_mut(off..off + 2)?
        .copy_from_slice(&val.to_be_bytes());
    Some(())
}

/// Reads an unsigned big-endian 24-bit integer at `off`.
fn read_be24(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off + 3)?;
    Some(u32::from_be_bytes([0, slice[0], slice[1], slice[2]]))
}

/// Writes the lower 24 bits of `val` (`<= 0xFFFFFF`) at `off` in big-endian order.
fn write_be24(buf: &mut [u8], off: usize, val: u32) -> Option<()> {
    if val > 0x00FF_FFFF {
        return None;
    }
    let be = val.to_be_bytes();
    buf.get_mut(off..off + 3)?.copy_from_slice(&be[1..4]);
    Some(())
}

/// Adds a signed delta to the big-endian `u16` length field at `off` with range validation.
fn add_be16(buf: &mut [u8], off: usize, delta: isize) -> Option<()> {
    let cur = isize::try_from(usize::from(read_be16(buf, off)?)).ok()?;
    let next = u16::try_from(cur.checked_add(delta)?).ok()?;
    write_be16(buf, off, next)
}

/// Adds a signed delta to the big-endian `u24` length field at `off` with range validation.
fn add_be24(buf: &mut [u8], off: usize, delta: isize) -> Option<()> {
    let cur = isize::try_from(read_be24(buf, off)?).ok()?;
    let next = cur.checked_add(delta)?;
    if !(0..=0x00FF_FFFF).contains(&next) {
        return None;
    }
    write_be24(buf, off, next as u32)
}

/// Generates a random lowercase ASCII alphanumeric byte (`0-9` or `a-z`).
fn random_az09(rng: &mut impl RngExt) -> u8 {
    let r = rng.random_range(0u8..36);
    if r < 10 { b'0' + r } else { b'a' + (r - 10) }
}

/// Applies `sni=<host>` and/or `rndsni` mutations to the SNI extension inside `buf`.
fn apply_sni_mods(
    buf: &mut Vec<u8>,
    maxlen: usize,
    extlen_offset: usize,
    spec: &FakeTlsMod,
) -> Option<()> {
    let (sniext, extlen) = tls_find_ext(buf, TLS_EXT_SERVER_NAME, false)?;
    let (rel_host, mut slen) = tls_advance_to_host_in_sni(buf.get(sniext..sniext + extlen)?)?;
    let sni_off = sniext + rel_host;

    if (spec.mod_flags & FAKE_TLS_MOD_SNI) != 0 {
        let new_sni = spec.sni.as_bytes();
        let slen_new = new_sni.len();
        let slen_delta =
            isize::try_from(slen_new).ok()?.checked_sub(isize::try_from(slen).ok()?)?;

        if slen_delta != 0 {
            let next_len = usize::try_from(
                isize::try_from(buf.len()).ok()?.checked_add(slen_delta)?,
            )
            .ok()?;
            if next_len > maxlen {
                return None;
            }
            buf.splice(sni_off..sni_off + slen, new_sni.iter().copied());
            add_be16(buf, 3, slen_delta)?;
            add_be24(buf, 6, slen_delta)?;
            add_be16(buf, extlen_offset, slen_delta)?;
            add_be16(buf, sniext.checked_sub(2)?, slen_delta)?;
            add_be16(buf, sniext, slen_delta)?;
            add_be16(buf, sni_off.checked_sub(2)?, slen_delta)?;
            slen = slen_new;
        } else {
            buf.get_mut(sni_off..sni_off + slen_new)?
                .copy_from_slice(new_sni);
        }
    }

    if (spec.mod_flags & FAKE_TLS_MOD_RND_SNI) != 0 {
        if slen == 0 {
            return None;
        }
        let mut rng = rand::rng();
        let sni_slice = buf.get_mut(sni_off..sni_off + slen)?;
        sni_slice[0] = rng.random_range(b'a'..=b'z');
        if slen >= 7 {
            for b in &mut sni_slice[1..slen - 4] {
                *b = random_az09(&mut rng);
            }
            sni_slice[slen - 4] = b'.';
            let tld = RANDOM_TLDS[rng.random_range(0..RANDOM_TLDS.len())];
            sni_slice[slen - 3..slen].copy_from_slice(tld);
        } else {
            for b in &mut sni_slice[1..slen] {
                *b = random_az09(&mut rng);
            }
        }
    }

    Some(())
}

/// Applies `padencap` by locating or appending TLS extension `21` and adding `payload_len` to lengths.
fn apply_padencap(
    buf: &mut Vec<u8>,
    maxlen: usize,
    extlen_offset: usize,
    payload_len: usize,
) -> Option<()> {
    let padlen_offset = match tls_find_ext(buf, TLS_EXT_PADDING, false) {
        Some((ext_off, ext_len)) => {
            if ext_off.checked_add(ext_len)? != buf.len() {
                return None;
            }
            ext_off.checked_sub(2)?
        }
        None => {
            if buf.len().checked_add(4)? > maxlen {
                return None;
            }
            buf.extend_from_slice(&[0x00, 0x15, 0x00, 0x00]);
            let pad_off = buf.len() - 2;
            add_be16(buf, extlen_offset, 4)?;
            add_be16(buf, 3, 4)?;
            add_be24(buf, 6, 4)?;
            pad_off
        }
    };

    // Length overflow on payload encapsulation is non-fatal in `protocol.c:956-959`.
    if let (Some(sz_rec), Some(sz_hs), Some(sz_ext), Some(sz_pad)) = (
        usize::from(read_be16(buf, 3)?).checked_add(payload_len),
        usize::try_from(read_be24(buf, 6)?).ok().and_then(|v| v.checked_add(payload_len)),
        usize::from(read_be16(buf, extlen_offset)?).checked_add(payload_len),
        usize::from(read_be16(buf, padlen_offset)?).checked_add(payload_len),
    ) && sz_rec <= 0xFFFF
        && sz_hs <= 0x00FF_FFFF
        && sz_ext <= 0xFFFF
        && sz_pad <= 0xFFFF
    {
        write_be16(buf, 3, sz_rec as u16)?;
        write_be24(buf, 6, sz_hs as u32)?;
        write_be16(buf, extlen_offset, sz_ext as u16)?;
        write_be16(buf, padlen_offset, sz_pad as u16)?;
    }

    Some(())
}

/// Applies parsed [`FakeTlsMod`] mutations to `fake_tls` (`TLSMod` in `protocol.c:793-972`).
///
/// When `spec.mod_flags == 0`, returns `fake_tls` verbatim without validating TLS structure
/// (matching `luacall_tls_mod` when only `"none"` is requested). Returns `None` on fatal errors.
pub fn tls_mod(spec: &FakeTlsMod, payload: Option<&[u8]>, fake_tls: &[u8]) -> Option<Vec<u8>> {
    if spec.mod_flags == 0 {
        return Some(fake_tls.to_vec());
    }

    if !is_tls_client_hello(fake_tls, false) || fake_tls.len() < 44 + usize::from(fake_tls[43]) {
        return None;
    }

    let maxlen = fake_tls.len() + MAX_MOD_SNI_LEN + 1 + 4;
    let mut buf = fake_tls.to_vec();

    let extlen_offset =
        if (spec.mod_flags & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI | FAKE_TLS_MOD_PADENCAP)) != 0
        {
            tls_find_ext_len(&buf)?
        } else {
            0
        };

    if (spec.mod_flags & (FAKE_TLS_MOD_RND_SNI | FAKE_TLS_MOD_SNI)) != 0 {
        apply_sni_mods(&mut buf, maxlen, extlen_offset, spec)?;
    }

    if (spec.mod_flags & FAKE_TLS_MOD_RND) != 0 {
        let mut rng = rand::rng();
        rng.fill_bytes(buf.get_mut(11..43)?);
        let sid_len = usize::from(*buf.get(43)?);
        rng.fill_bytes(buf.get_mut(44..44 + sid_len)?);
    }

    if let Some(pl) = payload {
        if (spec.mod_flags & FAKE_TLS_MOD_DUP_SID) != 0
            && is_tls_client_hello_partial(pl)
            && pl.len() >= 44
            && buf[43] == pl[43]
        {
            let sid_len = usize::from(buf[43]);
            if pl.len() >= 44 + sid_len {
                buf.get_mut(44..44 + sid_len)?
                    .copy_from_slice(&pl[44..44 + sid_len]);
            }
        }
        if (spec.mod_flags & FAKE_TLS_MOD_PADENCAP) != 0 {
            apply_padencap(&mut buf, maxlen, extlen_offset, pl.len())?;
        }
    }

    Some(buf)
}
