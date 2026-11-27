//! L7 protocol detectors, QUIC Initial decryption, TLS mutation helpers, and split markers.

/// FIPS-197 AES-256 single-block cipher and 128-bit counter addition helper.
pub mod aes_block;
/// Stateless L7 probes for XMPP, DNS, WireGuard, DHT, Discord, STUN, MTProto, DTLS, and BT.
pub mod datagram;
/// HTTP protocol probes, header/host extractors, DPI redirect checker, and HTTP markers.
pub mod http;
/// Protocol-relative payload split markers and multi-position resolver.
pub mod markers;
/// QUIC Long Header parsers, varints, Initial classifier, and CRYPTO defragmenter.
pub mod quic;
/// QUIC Initial key derivation and pure-Rust AEAD/header-protection decryption.
pub mod quic_crypto;
/// TLS record/handshake detectors, extension scanners, and SNI extractors.
pub mod tls;
/// TLS ClientHello fake mutator (`tls_mod`).
pub mod tls_mod;

pub use aes_block::{aes256_encrypt_block, ctr_add};
pub use datagram::{
    dns_parse_in_ip_rr, dns_skip_name, is_bt_handshake, is_dht, is_discord_ip_discovery_request,
    is_dns_query, is_dns_response, is_dtls, is_dtls_client_hello, is_dtls_server_hello,
    is_mtproto, is_stun_message, is_utp_bt_handshake, is_wireguard_data,
    is_wireguard_handshake_cookie, is_wireguard_handshake_initiation,
    is_wireguard_handshake_response, is_wireguard_keepalive, is_xmpp_features,
    is_xmpp_proceed_tls, is_xmpp_starttls, is_xmpp_stream,
};
pub use http::{
    find_host_header_offset, find_nld, http_extract_header, http_extract_host, http_pos,
    http_reply_code, http_reply_looks_like_dpi_redirect, is_http, is_http_reply, strip_host_to_ip,
};
pub use markers::{
    PosMarker, ProtoPos, any_proto_pos, check_pos, host_pos, posmarker_from_name,
    posmarker_list_parse, posmarker_name, posmarker_parse, resolve_multi_pos, resolve_pos,
};
pub use quic::{
    QUIC_MAX_CID_LENGTH, QuicCid, is_quic_crypto_hello, is_quic_initial, is_quic_v2,
    quic_defrag_crypto, quic_draft_version, quic_extract_dcid, quic_extract_version,
    quic_is_long_header, tvb_get_size, tvb_get_varint,
};
pub use quic_crypto::quic_decrypt_initial;
pub use tls::{
    TLS_EXT_PADDING, TLS_EXT_SERVER_NAME, is_tls_client_hello, is_tls_client_hello_partial,
    is_tls_handshake_client_hello, is_tls_handshake_full, is_tls_handshake_hello,
    is_tls_handshake_server_hello, is_tls_hello, is_tls_record_full, is_tls_server_hello,
    is_tls_server_hello_partial, tls_advance_to_host_in_sni, tls_find_ext,
    tls_find_ext_in_handshake, tls_find_ext_len, tls_find_ext_len_in_handshake,
    tls_handshake_data_len, tls_handshake_len, tls_hello_extract_host,
    tls_hello_extract_host_from_handshake, tls_pos, tls_record_data_len, tls_record_len,
    tls_version_str,
};
pub use tls_mod::{
    FAKE_TLS_MOD_DUP_SID, FAKE_TLS_MOD_PADENCAP, FAKE_TLS_MOD_RND, FAKE_TLS_MOD_RND_SNI,
    FAKE_TLS_MOD_SNI, FakeTlsMod, tls_mod,
};
