//! Integration tests verifying L7 protocol detectors, AES-256 ECB, QUIC decryption, and defragmentation.

/// File path resolution for unmodified `zapret2/files/fake/` fixtures.
use std::path::Path;

/// Concrete `zapret2` protocol probes, QUIC Initial decryptor, and AES-256 block cipher under test.
use zapret_rs::protocol::{
    aes256_encrypt_block, ctr_add, http_extract_host, http_reply_code,
    http_reply_looks_like_dpi_redirect, is_bt_handshake, is_dht,
    is_discord_ip_discovery_request, is_dns_query, is_dns_response, is_dtls,
    is_dtls_client_hello, is_dtls_server_hello, is_http, is_http_reply, is_mtproto,
    is_quic_crypto_hello, is_quic_initial, is_quic_v2, is_stun_message, is_tls_client_hello,
    is_tls_server_hello, is_utp_bt_handshake, is_wireguard_data, is_wireguard_handshake_cookie,
    is_wireguard_handshake_initiation, is_wireguard_handshake_response, is_wireguard_keepalive,
    is_xmpp_features, is_xmpp_proceed_tls, is_xmpp_starttls, is_xmpp_stream, quic_decrypt_initial,
    quic_defrag_crypto, quic_draft_version, tls_hello_extract_host,
    tls_hello_extract_host_from_handshake, tls_version_str,
};

/// Reads a binary test fixture from `tests/fixtures/fake/`.
fn read_fake_fixture(name: &str) -> Vec<u8> {
    let path = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/fake")).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

/// Encodes an unsigned 6-bit integer as a 1-byte QUIC varint inside tests when `< 64`, or 2-byte varint.
fn push_quic_varint(out: &mut Vec<u8>, val: u16) {
    if val < 64 {
        out.push(val as u8);
    } else {
        out.extend_from_slice(&(val | 0x4000).to_be_bytes());
    }
}

/// Verifies FIPS-197 Appendix C.3 AES-256 ECB vector, `ctr_add` 64-bit carry, and `is_mtproto`.
#[test]
fn aes256_ctr_add_and_mtproto_probe_match_spec() {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    let pt: [u8; 16] = std::array::from_fn(|i| ((i * 0x11) & 0xFF) as u8);
    let expected: [u8; 16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60,
        0x89,
    ];
    assert_eq!(aes256_encrypt_block(&key, &pt), expected);

    let mut ctr: [u8; 16] = [0; 16];
    ctr[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    ctr_add(&mut ctr, 3);
    assert_eq!(ctr[7], 1);
    assert_eq!(ctr[15], 2);

    // Construct a valid obfuscated 64-byte MTProto packet: bytes [56..60] XOR keystream[8..12] == EF^4.
    let mut mt = vec![0xAAu8; 64];
    mt[8..40].copy_from_slice(&key);
    let iv_orig: [u8; 16] = [0x10; 16];
    mt[40..56].copy_from_slice(&iv_orig);
    let mut iv_blk3 = iv_orig;
    ctr_add(&mut iv_blk3, 3);
    let ks = aes256_encrypt_block(&key, &iv_blk3);
    for i in 0..4 {
        mt[56 + i] = ks[8 + i] ^ 0xEF;
    }
    assert!(is_mtproto(&mt));

    mt[59] ^= 0x01;
    assert!(!is_mtproto(&mt));
    assert!(!is_mtproto(&mt[..63]));
}

/// Verifies HTTP request/host extraction and HTTP 302/307 DPI redirect heuristics.
#[test]
fn http_probes_host_extraction_and_dpi_redirect_match_zapret2() {
    let http_req = read_fake_fixture("http_iana_org.bin");
    assert!(is_http(&http_req));
    assert_eq!(http_extract_host(&http_req).as_deref(), Some("www.iana.org"));
    assert!(!is_http(b"NOTHTTP / HTTP/1.1\r\n\r\n"));

    let redirect_off_sld =
        b"HTTP/1.1 302 Found\r\nLocation: https://block.censor.net/denied?r=1\r\n\r\n";
    assert!(is_http_reply(redirect_off_sld));
    assert_eq!(http_reply_code(redirect_off_sld), Some(302));
    assert!(http_reply_looks_like_dpi_redirect(
        redirect_off_sld,
        "www.blocked.org",
        false
    ));

    let same_sld_sub =
        b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://login.example.com/auth\r\n\r\n";
    assert!(!http_reply_looks_like_dpi_redirect(
        same_sld_sub,
        "www.example.com",
        false
    ));
    // Notice SLD matches (`example`) while TLD differs (`.com` vs `.org`) -> must still trigger redirect.
    assert!(http_reply_looks_like_dpi_redirect(
        same_sld_sub,
        "www.example.org",
        false
    ));

    let redirect_to_ip =
        b"HTTP/1.1 302 Moved\r\nLocation: http://[2001:db8::99]:8080/block\r\n\r\n";
    assert!(http_reply_looks_like_dpi_redirect(
        redirect_to_ip,
        "example.com",
        false
    ));
    assert!(!http_reply_looks_like_dpi_redirect(
        redirect_to_ip,
        "2001:db8::99",
        true
    ));
    assert!(http_reply_looks_like_dpi_redirect(
        redirect_to_ip,
        "2001:db8::1",
        true
    ));

    let non_dpi_status =
        b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://other.org/\r\n\r\n";
    assert!(!http_reply_looks_like_dpi_redirect(
        non_dpi_status,
        "example.com",
        false
    ));
}

/// Verifies TLS ClientHello/ServerHello detection, partial handling, SNI extraction, and GREASE tags.
#[test]
fn tls_probes_partial_handling_and_sni_extraction() {
    let ch_google = read_fake_fixture("tls_clienthello_www_google_com.bin");
    let ch_iana = read_fake_fixture("tls_clienthello_iana_org.bin");
    let sh_google = read_fake_fixture("tls_serverhello_google_com_tls13.bin");

    assert!(is_tls_client_hello(&ch_google, false));
    assert!(!is_tls_server_hello(&ch_google, true));
    assert_eq!(
        tls_hello_extract_host(&ch_google, false).as_deref(),
        Some("www.google.com")
    );
    assert_eq!(
        tls_hello_extract_host(&ch_iana, false).as_deref(),
        Some("iana.org")
    );

    assert!(is_tls_server_hello(&sh_google, false));
    assert!(!is_tls_client_hello(&sh_google, true));

    // Truncated record fails strict check while still allowing partial ClientHello SNI extraction.
    let truncated = &ch_google[..ch_google.len() - 10];
    assert!(!is_tls_client_hello(truncated, false));
    assert!(is_tls_client_hello(truncated, true));
    assert_eq!(
        tls_hello_extract_host(truncated, true).as_deref(),
        Some("www.google.com")
    );

    assert_eq!(tls_version_str(0x0303), "TLS 1.2");
    assert_eq!(tls_version_str(0x0a0a), "GREASE");
    assert_eq!(tls_version_str(0x1234), "UNKNOWN");
}

/// Verifies QUIC Initial detection, v1/v2/mvfst decryption, CRYPTO defrag, and SNI extraction.
#[test]
fn quic_initial_decrypt_defrag_and_sni_work_on_real_fixtures() {
    for (file, expected_sni, expected_v2, expected_draft) in [
        ("quic_initial_www_google_com.bin", "www.google.com", false, 34u8),
        ("quic2_example_com.bin", "example.com", true, 100u8),
        ("quic_initial_facebook_com.bin", "facebook.com", false, 29u8),
    ] {
        let pkt = read_fake_fixture(file);
        assert!(is_quic_initial(&pkt), "{file} must match is_quic_initial");
        let ver = u32::from_be_bytes([pkt[1], pkt[2], pkt[3], pkt[4]]);
        assert_eq!(is_quic_v2(ver), expected_v2, "{file} v2 check");
        assert!(
            quic_draft_version(ver) >= expected_draft.min(29),
            "{file} draft version was {}",
            quic_draft_version(ver)
        );

        let clean = quic_decrypt_initial(&pkt)
            .unwrap_or_else(|| panic!("{file} must decrypt via ring Initial AEAD"));
        let (defrag, full) = quic_defrag_crypto(&clean, 16384)
            .unwrap_or_else(|| panic!("{file} must defragment CRYPTO frames"));
        assert!(full, "{file} should have full CRYPTO coverage");
        let (hello_off, hello_len) = is_quic_crypto_hello(&defrag)
            .unwrap_or_else(|| panic!("{file} must contain TLS ClientHello"));
        assert_eq!(
            tls_hello_extract_host_from_handshake(&defrag[hello_off..hello_off + hello_len], true)
                .as_deref(),
            Some(expected_sni)
        );
    }

    let short_hdr = read_fake_fixture("quic_short_header.bin");
    assert!(!is_quic_initial(&short_hdr));
    assert!(quic_decrypt_initial(&short_hdr).is_none());

    // Synthetic out-of-order and gapped QUIC CRYPTO frame defragmentation.
    let tls_hs = &read_fake_fixture("tls_clienthello_iana_org.bin")[5..];
    let split = 20usize;
    let mut clean_ooo = vec![0x00, 0x01]; // PADDING + PING
    clean_ooo.push(6);
    push_quic_varint(&mut clean_ooo, split as u16);
    push_quic_varint(&mut clean_ooo, (tls_hs.len() - split) as u16);
    clean_ooo.extend_from_slice(&tls_hs[split..]);
    clean_ooo.push(6);
    push_quic_varint(&mut clean_ooo, 0);
    push_quic_varint(&mut clean_ooo, split as u16);
    clean_ooo.extend_from_slice(&tls_hs[..split]);

    let (defrag_ooo, full_ooo) = quic_defrag_crypto(&clean_ooo, 16384).expect("defrag succeeds");
    assert!(full_ooo);
    let (h_off, h_len) = is_quic_crypto_hello(&defrag_ooo).expect("complete ClientHello");
    assert_eq!(
        tls_hello_extract_host_from_handshake(&defrag_ooo[h_off..h_off + h_len], false).as_deref(),
        Some("iana.org")
    );

    let gapped = [6, 0, 4, b'a', b'b', b'c', b'd', 6, 10, 2, b'e', b'f'];
    let (defrag_gap, full_gap) = quic_defrag_crypto(&gapped, 16384).expect("partial defrag ok");
    assert!(!full_gap);
    assert_eq!(&defrag_gap[10..], b"abcd\0\0\0\0\0\0ef");
}

/// Verifies XMPP, DNS, WireGuard, DHT, Discord, STUN, DTLS, BitTorrent, and uTP-BT probes.
#[test]
fn datagram_and_other_stream_l7_probes_match_zapret2() {
    assert!(is_xmpp_stream(b"<stream:stream to='example.com'>"));
    assert!(is_xmpp_stream(
        b"<?xml version='1.0'?><stream:stream to='example.com'>"
    ));
    assert!(is_xmpp_starttls(b"<starttls xmlns='urn:ietf'/>"));
    assert!(is_xmpp_proceed_tls(b"<proceed xmlns='urn:ietf'/>"));
    assert!(is_xmpp_features(b"<stream:features></stream:features>"));

    let dns_q = read_fake_fixture("dns.bin");
    assert!(is_dns_query(&dns_q));
    assert!(!is_dns_response(&dns_q));
    let dns_resp = [0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
    assert!(is_dns_response(&dns_resp));

    let wg_init = read_fake_fixture("wireguard_initiation.bin");
    let wg_resp = read_fake_fixture("wireguard_response.bin");
    assert!(is_wireguard_handshake_initiation(&wg_init));
    assert!(is_wireguard_handshake_response(&wg_resp));
    let mut wg_cookie = vec![0u8; 64];
    wg_cookie[0] = 3;
    assert!(is_wireguard_handshake_cookie(&wg_cookie));
    let mut wg_keep = vec![0u8; 32];
    wg_keep[0] = 4;
    assert!(is_wireguard_keepalive(&wg_keep));
    assert!(!is_wireguard_data(&wg_keep));
    let mut wg_data = vec![0u8; 52];
    wg_data[0] = 4;
    assert!(is_wireguard_data(&wg_data));

    assert!(is_dht(&read_fake_fixture("dht_find_node.bin")));
    assert!(is_discord_ip_discovery_request(&read_fake_fixture(
        "discord-ip-discovery-without-port.bin"
    )));
    assert!(is_stun_message(&read_fake_fixture("stun.bin")));

    let dtls_ch = read_fake_fixture("dtls_clienthello_w3_org.bin");
    let dtls_sh = read_fake_fixture("dtls_serverhello.bin");
    assert!(is_dtls(&dtls_ch));
    assert!(is_dtls_client_hello(&dtls_ch));
    assert!(is_dtls_server_hello(&dtls_sh));

    let mut bt = b"\x13BitTorrent protocol".to_vec();
    bt.resize(68, 0);
    assert!(is_bt_handshake(&bt));

    let mut utp_bt = vec![0u8; 88];
    utp_bt[0] = 0x01;
    utp_bt[20..40].copy_from_slice(b"\x13BitTorrent protocol");
    assert!(is_utp_bt_handshake(&utp_bt));
}
