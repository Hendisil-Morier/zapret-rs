//! Stateless L7 payload probes for XMPP, DNS, WireGuard, DHT, Discord, STUN, MTProto, DTLS, and BT.

/// AES-256 single-block cipher and counter increment used by the `IsMTProto` probe.
use crate::protocol::aes_block::{aes256_encrypt_block, ctr_add};

/// Checks a WireGuard 4-byte little-endian message header (`[kind, 0, 0, 0]`).
fn is_wg_header(data: &[u8], kind: u8) -> bool {
    data.len() >= 4 && data[..4] == [kind, 0, 0, 0]
}

/// Returns `true` for XMPP initial `<stream:stream ` headers (`IsXMPPStream`).
pub fn is_xmpp_stream(data: &[u8]) -> bool {
    const STREAM: &[u8] = b"<stream:stream ";
    (data.len() >= 16 && data.starts_with(STREAM))
        || (data.len() >= 36
            && data.starts_with(b"<?xml ")
            && data[21..].windows(STREAM.len()).any(|w| w == STREAM))
}

/// Returns `true` for XMPP `<starttls ` frames (`IsXMPPStartTLS`).
pub fn is_xmpp_starttls(data: &[u8]) -> bool {
    data.len() >= 10 && data.starts_with(b"<starttls ")
}

/// Returns `true` for XMPP `<proceed ` frames (`IsXMPPProceedTLS`).
pub fn is_xmpp_proceed_tls(data: &[u8]) -> bool {
    data.len() >= 9 && data.starts_with(b"<proceed ")
}

/// Returns `true` for XMPP `<stream:features` frames (`IsXMPPFeatures`).
pub fn is_xmpp_features(data: &[u8]) -> bool {
    data.len() >= 17 && data.starts_with(b"<stream:features")
}

/// Returns `true` for standard single-question DNS queries (`IsDNSQuery`).
pub fn is_dns_query(data: &[u8]) -> bool {
    data.len() >= 12
        && (data[2] & 0xFE) == 0
        && data[4..10] == [0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        && u16::from_be_bytes([data[10], data[11]]) <= 3
}

/// Returns `true` for standard DNS responses with bounded section counts (`IsDNSResponse`).
pub fn is_dns_response(data: &[u8]) -> bool {
    data.len() >= 12
        && (data[2] & 0xF8) == 0x80
        && u16::from_be_bytes([data[4], data[5]]) == 1
        && u16::from_be_bytes([data[6], data[7]]) <= 100
        && u16::from_be_bytes([data[8], data[9]]) <= 100
        && u16::from_be_bytes([data[10], data[11]]) <= 100
}

/// Returns `true` for 148-byte WireGuard Handshake Initiation packets (`IsWireguardHandshakeInitiation`).
pub fn is_wireguard_handshake_initiation(data: &[u8]) -> bool {
    data.len() == 148 && is_wg_header(data, 1)
}

/// Returns `true` for 92-byte WireGuard Handshake Response packets (`IsWireguardHandshakeResponse`).
pub fn is_wireguard_handshake_response(data: &[u8]) -> bool {
    data.len() == 92 && is_wg_header(data, 2)
}

/// Returns `true` for 64-byte WireGuard Cookie Reply packets (`IsWireguardHandshakeCookie`).
pub fn is_wireguard_handshake_cookie(data: &[u8]) -> bool {
    data.len() == 64 && is_wg_header(data, 3)
}

/// Returns `true` for WireGuard transport data packets (`len >= 52`, type 4) (`IsWireguardData`).
pub fn is_wireguard_data(data: &[u8]) -> bool {
    data.len() >= 52 && is_wg_header(data, 4)
}

/// Returns `true` for 32-byte WireGuard keepalive packets (`IsWireguardKeepalive`).
pub fn is_wireguard_keepalive(data: &[u8]) -> bool {
    data.len() == 32 && is_wg_header(data, 4)
}

/// Returns `true` for bencoded BitTorrent DHT messages (`d1:ad` / `d1:rd` / `d2:ip` / `d1:el`).
pub fn is_dht(data: &[u8]) -> bool {
    data.len() >= 5
        && data[0] == b'd'
        && data[data.len() - 1] == b'e'
        && matches!(&data[1..5], b"1:ad" | b"1:rd" | b"2:ip" | b"1:el")
}

/// Returns `true` for 74-byte Discord voice IP discovery requests (`IsDiscordIpDiscoveryRequest`).
pub fn is_discord_ip_discovery_request(data: &[u8]) -> bool {
    data.len() == 74
        && data[0..4] == [0x00, 0x01, 0x00, 70]
        && data[8..72].iter().all(|&b| b == 0)
}

/// Returns `true` for STUN messages carrying magic cookie `0x2112A442` (`IsStunMessage`).
pub fn is_stun_message(data: &[u8]) -> bool {
    data.len() >= 20
        && (data[0] & 0xC0) == 0
        && (data[3] & 3) == 0
        && data[4..8] == [0x21, 0x12, 0xA4, 0x42]
        && usize::from(u16::from_be_bytes([data[2], data[3]])) <= data.len() - 20
}

/// Returns `true` for obfuscated Telegram MTProto 64-byte initial packets (`IsMTProto`).
pub fn is_mtproto(data: &[u8]) -> bool {
    let (Ok(key), Ok(mut iv)) = (
        <[u8; 32]>::try_from(data.get(8..40).unwrap_or_default()),
        <[u8; 16]>::try_from(data.get(40..56).unwrap_or_default()),
    ) else {
        return false;
    };
    let Some(cipher_tag) = data.get(56..60) else {
        return false;
    };
    if data.len() < 64 {
        return false;
    }

    ctr_add(&mut iv, 3);
    let keystream = aes256_encrypt_block(&key, &iv);
    [
        keystream[8] ^ cipher_tag[0],
        keystream[9] ^ cipher_tag[1],
        keystream[10] ^ cipher_tag[2],
        keystream[11] ^ cipher_tag[3],
    ] == [0xEF, 0xEF, 0xEF, 0xEF]
}

/// Returns `true` when `data` contains a full DTLS 1.0/1.2/1.3 record header (`IsDTLS`).
pub fn is_dtls(data: &[u8]) -> bool {
    data.len() > 13
        && (0x14..=0x17).contains(&data[0])
        && matches!((data[1], data[2]), (0xfe, 0xff | 0xfd | 0xfc) | (0x01, 0x00))
        && usize::from(u16::from_be_bytes([data[11], data[12]])) + 13 <= data.len()
}

/// Returns `true` for DTLS Handshake `ClientHello` packets (`IsDTLSClientHello`).
pub fn is_dtls_client_hello(data: &[u8]) -> bool {
    is_dtls(data) && data[0] == 0x16 && data[13] == 1
}

/// Returns `true` for DTLS Handshake `ServerHello` packets (`IsDTLSServerHello`).
pub fn is_dtls_server_hello(data: &[u8]) -> bool {
    is_dtls(data) && data[0] == 0x16 && data[13] == 2
}

/// Returns `true` for TCP BitTorrent peer protocol handshakes (`IsBTHandshake`).
pub fn is_bt_handshake(data: &[u8]) -> bool {
    data.len() >= 68 && data.starts_with(b"\x13BitTorrent protocol")
}

/// Returns `true` for uTP-encapsulated BitTorrent peer handshakes (`IsUTP_BTHandshake`).
pub fn is_utp_bt_handshake(data: &[u8]) -> bool {
    data.len() >= 88 && data[0] == 0x01 && data[20..].starts_with(b"\x13BitTorrent protocol")
}
