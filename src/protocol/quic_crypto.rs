//! Pure-Rust QUIC Initial key derivation (HKDF-SHA256) and AEAD/header-protection decryption.

/// Pure-Rust AES block cipher, AES-GCM, and HKDF primitives replacing external `ring` runtime deps.
use crate::crypto::{AesKey, HashAlg, aes_gcm_crypt, hkdf_sha2_expand, hkdf_sha2_extract};
/// QUIC header parsers and draft/v1/v2 version classifiers.
use crate::protocol::quic::{
    is_quic_v2, parse_initial_scid_token_payload, quic_draft_version, quic_extract_dcid, quic_extract_version,
};

/// Maximum QUIC Initial unmasked header size supported during AEAD AAD assembly.
const MAX_QUIC_AAD_HEADER_LEN: usize = 2048;

/// RFC 9001 Section 5.2 Initial salt for QUIC v1 (`0x00000001`).
const HANDSHAKE_SALT_V1: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc,
    0xbb, 0x7f, 0x0a,
];
/// RFC 9369 Initial salt for QUIC v2 (`0x6b3343cf` / `0x709a50c4`).
const HANDSHAKE_SALT_V2: [u8; 20] = [
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9,
    0xbd, 0x2e, 0xd9,
];
/// IETF draft-22 Initial salt.
const HANDSHAKE_SALT_DRAFT_22: [u8; 20] = [
    0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a, 0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a,
    0x02, 0x64, 0x4a,
];
/// IETF draft-23..=28 Initial salt.
const HANDSHAKE_SALT_DRAFT_23: [u8; 20] = [
    0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7, 0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe,
    0xf9, 0xf5, 0x02,
];
/// IETF draft-29..=32 Initial salt.
const HANDSHAKE_SALT_DRAFT_29: [u8; 20] = [
    0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97, 0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43,
    0x90, 0xa8, 0x99,
];
/// Google QUIC Q050 Initial salt.
const HANDSHAKE_SALT_Q050: [u8; 20] = [
    0x50, 0x45, 0x74, 0xef, 0xd0, 0x66, 0xfe, 0x2f, 0x9d, 0x94, 0x5c, 0xfc, 0xdb, 0xd3, 0xa7, 0xf0, 0xd3,
    0xb5, 0x6b, 0x45,
];
/// Google QUIC T050 Initial salt.
const HANDSHAKE_SALT_T050: [u8; 20] = [
    0x7f, 0xf5, 0x79, 0xe5, 0xac, 0xd0, 0x72, 0x91, 0x55, 0x80, 0x30, 0x4c, 0x43, 0xa2, 0x36, 0x7c, 0x60,
    0x48, 0x83, 0x10,
];
/// Google QUIC T051 Initial salt.
const HANDSHAKE_SALT_T051: [u8; 20] = [
    0x7a, 0x4e, 0xde, 0xf4, 0xe7, 0xcc, 0xee, 0x5f, 0xa4, 0x50, 0x6c, 0x19, 0x12, 0x4f, 0xc8, 0xcc, 0xda,
    0x6e, 0x03, 0x3d,
];

/// Selects the RFC/draft Initial salt slice corresponding to QUIC wire `version`.
fn select_initial_salt(version: u32) -> &'static [u8; 20]
{
    let draft = quic_draft_version(version);
    if version == 0x5130_3530
    {
        &HANDSHAKE_SALT_Q050
    }
    else if version == 0x5430_3530
    {
        &HANDSHAKE_SALT_T050
    }
    else if version == 0x5430_3531
    {
        &HANDSHAKE_SALT_T051
    }
    else if draft != 0 && draft <= 22
    {
        &HANDSHAKE_SALT_DRAFT_22
    }
    else if draft != 0 && draft <= 28
    {
        &HANDSHAKE_SALT_DRAFT_23
    }
    else if draft != 0 && draft <= 32
    {
        &HANDSHAKE_SALT_DRAFT_29
    }
    else if draft != 0 && draft <= 34
    {
        &HANDSHAKE_SALT_V1
    }
    else
    {
        &HANDSHAKE_SALT_V2
    }
}

/// Runs TLS 1.3 `HKDF-Expand-Label` with an empty transcript context (`quic_hkdf_expand_label`).
fn hkdf_expand_label(prk: &[u8], label: &[u8], out: &mut [u8]) -> Option<()>
{
    let mut info_buf = [0u8; 64];
    let out_len_u16 = u16::try_from(out.len()).ok()?;
    let label_len_u8 = u8::try_from(label.len()).ok()?;
    let total_len = 2 + 1 + label.len() + 1;
    if total_len > info_buf.len()
    {
        return None;
    }

    info_buf[..2].copy_from_slice(&out_len_u16.to_be_bytes());
    info_buf[2] = label_len_u8;
    info_buf[3..3 + label.len()].copy_from_slice(label);
    info_buf[3 + label.len()] = 0;

    let okm = hkdf_sha2_expand(HashAlg::Sha256, prk, &info_buf[..total_len], out.len()).ok()?;
    out.copy_from_slice(&okm);
    Some(())
}

/// Constant-time 16-byte AEAD authentication tag comparison.
fn ct_eq_16(computed: &[u8; 16], received: &[u8]) -> bool
{
    if received.len() != 16
    {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..16
    {
        diff |= computed[i] ^ received[i];
    }
    std::hint::black_box(diff) == 0
}

/// Decrypts a QUIC client Initial packet payload using DCID-derived secrets (`QUICDecryptInitial`).
pub fn quic_decrypt_initial(data: &[u8]) -> Option<Vec<u8>>
{
    let ver = quic_extract_version(data);
    if ver == 0
    {
        return None;
    }
    let dcid = quic_extract_dcid(data)?;

    let salt = select_initial_salt(ver);
    let initial_prk = hkdf_sha2_extract(HashAlg::Sha256, Some(salt), dcid.as_slice());
    let mut client_initial_secret = [0u8; 32];
    hkdf_expand_label(&initial_prk, b"tls13 client in", &mut client_initial_secret)?;

    let v1_label = !is_quic_v2(ver);
    let mut aeskey = [0u8; 16];
    let mut aesiv = [0u8; 12];
    let mut aeshp = [0u8; 16];
    hkdf_expand_label(
        &client_initial_secret,
        if v1_label { b"tls13 quic key" } else { b"tls13 quicv2 key" },
        &mut aeskey,
    )?;
    hkdf_expand_label(
        &client_initial_secret,
        if v1_label { b"tls13 quic iv" } else { b"tls13 quicv2 iv" },
        &mut aesiv,
    )?;
    hkdf_expand_label(
        &client_initial_secret,
        if v1_label { b"tls13 quic hp" } else { b"tls13 quicv2 hp" },
        &mut aeshp,
    )?;

    let scid_offset = 6 + usize::from(dcid.len);
    let (pn_offset, payload_len_us) = parse_initial_scid_token_payload(data, scid_offset, None)?;
    if payload_len_us < 20
    {
        return None;
    }

    let sample: [u8; 16] = data.get(pn_offset + 4..pn_offset + 20)?.try_into().ok()?;
    let hp_key = AesKey::new(&aeshp).ok()?;
    let mask = hp_key.encrypt_block(&sample);

    let packet0 = data[0] ^ (mask[0] & 0x0f);
    let pkn_len = usize::from((packet0 & 0x03) + 1);
    let header_len = pn_offset.checked_add(pkn_len)?;
    if header_len > MAX_QUIC_AAD_HEADER_LEN
    {
        return None;
    }

    let mut header = data.get(..header_len)?.to_vec();
    header[0] = packet0;
    let mut pkn = 0u32;
    for i in 0..pkn_len
    {
        let decoded = data[pn_offset + i] ^ mask[1 + i];
        header[pn_offset + i] = decoded;
        pkn |= u32::from(decoded) << (8 * (pkn_len - 1 - i));
    }

    let iv_tail_bytes: [u8; 8] = aesiv[4..12].try_into().ok()?;
    let iv_tail = u64::from_be_bytes(iv_tail_bytes) ^ u64::from(pkn);
    aesiv[4..12].copy_from_slice(&iv_tail.to_be_bytes());

    let sealed_len = payload_len_us.checked_sub(pkn_len)?;
    let cipher_len = sealed_len.checked_sub(16)?;
    let sealed = data.get(header_len..header_len + sealed_len)?;
    let (ciphertext, received_tag) = sealed.split_at(cipher_len);
    let (plaintext, computed_tag) = aes_gcm_crypt(false, &aeskey, &aesiv, ciphertext, &header).ok()?;
    if !ct_eq_16(&computed_tag, received_tag)
    {
        return None;
    }
    Some(plaintext)
}
