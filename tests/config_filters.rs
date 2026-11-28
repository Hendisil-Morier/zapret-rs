//! Integration tests for `zapret2` port, ICMP, IPP, mark, packet-range, L7 filters, and blobs.

/// Filesystem read/write helpers for temporary file blob offset tests.
use std::fs;
/// PathBuf helper for temporary test blob cleanup.
use std::path::PathBuf;

/// Filter primitives, L7 classification masks, timeout parsers, and default/custom blob helpers.
use zapret_rs::config::{
    ConfigError, FAKE_QUIC_DEFAULT_LEN, FilterMode, IcmpFilter, IppFilter, L7_PAYLOAD_NONE_MASK, L7Payload,
    L7Proto, MarkFilter, PacketPos, PacketPosMode, PacketRange, PortFilter, default_blobs,
    icmp_filters_match, ipp_filters_match, l7_payload_matches, l7_proto_matches, load_file_blob,
    parse_hex_blob, parse_l7_disable_mask, parse_l7_payload_mask, parse_l7_proto_mask, parse_timeouts,
    port_filters_match,
};

/// Returns a per-process unique temporary path under `std::env::temp_dir()`.
fn unique_temp_path(suffix: &str) -> PathBuf
{
    std::env::temp_dir().join(format!("zapret-rs-{}-{suffix}", std::process::id()))
}

/// Verifies `PortFilter` single ports, ranges, negation, wildcard, and deny-all (`0`) semantics.
#[test]
fn port_filter_parses_ranges_negations_and_rejects_invalid()
{
    let star = PortFilter::parse("*").expect("* should parse");
    assert!(star.matches(1) && star.matches(65535) && !star.matches(0));

    let single = PortFilter::parse("443").expect("443");
    assert!(single.matches(443) && !single.matches(80) && !single.matches(0));

    let range = PortFilter::parse("80-90").expect("80-90");
    assert!(range.matches(80) && range.matches(85) && range.matches(90) && !range.matches(79));

    let neg = PortFilter::parse("~22").expect("~22");
    assert!(!neg.matches(22) && neg.matches(80) && !neg.matches(0));

    // Port "0" or "~0" always acts as deny-all matching C `pf_parse`.
    let zero = PortFilter::parse("0").expect("0");
    let neg_zero = PortFilter::parse("~0").expect("~0");
    assert!(zero.neg && neg_zero.neg);
    assert!(!zero.matches(80) && !neg_zero.matches(443) && !PortFilter::deny_all().matches(80));

    assert!(port_filters_match(&[], 80));
    assert!(port_filters_match(&[single, range], 85));
    assert!(!port_filters_match(&[single, range], 25));

    assert!(matches!(PortFilter::parse("90-80"), Err(ConfigError::InvalidPortFilter(_))));
    assert!(matches!(PortFilter::parse("70000"), Err(ConfigError::InvalidPortFilter(_))));
    assert!(matches!(PortFilter::parse(""), Err(ConfigError::InvalidPortFilter(_))));
}

/// Verifies `IcmpFilter` and `IppFilter` parsing and matching.
#[test]
fn icmp_and_ipp_filters_match_and_reject_invalid()
{
    let any = IcmpFilter::parse("*").expect("*");
    let skip = IcmpFilter::parse("-").expect("-");
    let echo = IcmpFilter::parse("8").expect("8");
    let frag = IcmpFilter::parse("3:4").expect("3:4");

    assert_eq!(any.mode, FilterMode::Any);
    assert_eq!(skip.mode, FilterMode::Skip);
    assert!(echo.matches(8, 0) && echo.matches(8, 9));
    assert!(!frag.matches(3, 3) && frag.matches(3, 4) && !skip.matches(8, 0));

    assert!(icmp_filters_match(&[], 8, 0));
    assert!(icmp_filters_match(&[skip, frag], 3, 4));
    assert!(!icmp_filters_match(&[IcmpFilter::skip()], 8, 0));
    assert!(matches!(IcmpFilter::parse("256"), Err(ConfigError::InvalidIcmpFilter(_))));
    assert!(matches!(IcmpFilter::parse("3:256"), Err(ConfigError::InvalidIcmpFilter(_))));
    assert!(matches!(IcmpFilter::parse("3:4:5"), Err(ConfigError::InvalidIcmpFilter(_))));

    let ipp_any = IppFilter::parse("*").expect("*");
    let ipp_skip = IppFilter::skip();
    let gre = IppFilter::parse("47").expect("47");
    assert!(ipp_any.matches(6) && !ipp_skip.matches(47) && gre.matches(47) && !gre.matches(50));
    assert!(ipp_filters_match(&[ipp_skip, gre], 47));
    assert!(matches!(IppFilter::parse("256"), Err(ConfigError::InvalidIppFilter(_))));
    assert!(matches!(IppFilter::parse("abc"), Err(ConfigError::InvalidIppFilter(_))));
}

/// Verifies `MarkFilter` exact and masked fwmark matching.
#[test]
fn mark_filter_handles_hex_decimal_and_masks()
{
    let default = MarkFilter::default();
    assert!(default.matches(0));
    assert!(default.matches(u32::MAX));

    let exact = MarkFilter::parse("0x40000000").expect("exact hex");
    assert!(exact.matches(0x4000_0000));
    assert!(!exact.matches(0x4000_0001));

    let masked = MarkFilter::parse("0x10/0xff").expect("masked hex");
    let dec = MarkFilter::parse("16/255").expect("masked decimal");
    assert_eq!(masked, dec);
    assert!(masked.matches(0x1234_0010));
    assert!(!masked.matches(0x1234_0011));

    assert!(matches!(MarkFilter::parse("0xzz"), Err(ConfigError::InvalidMarkFilter(_))));
    assert!(matches!(MarkFilter::parse("1/2/3"), Err(ConfigError::InvalidMarkFilter(_))));
}

/// Verifies `PacketRange` syntax variants match `zapret2/nfq2/filter.c`.
#[test]
fn packet_range_parses_endpoints_and_rejects_malformed()
{
    assert_eq!(PacketRange::parse("x").expect("x"), PacketRange::NEVER);
    assert_eq!(PacketRange::parse("a").expect("a"), PacketRange::ALWAYS);

    let to_d1_inc = PacketRange::parse("-d1").expect("-d1");
    assert_eq!(to_d1_inc.from, PacketPos::ALWAYS);
    assert_eq!(to_d1_inc.to.mode, PacketPosMode::DataPacketNum);
    assert_eq!(to_d1_inc.to.pos, 1);
    assert!(!to_d1_inc.upper_cutoff);

    let to_d1_exc = PacketRange::parse("<d1").expect("<d1");
    assert!(to_d1_exc.upper_cutoff);
    assert_eq!(to_d1_exc.to.pos, 1);

    let from_s1 = PacketRange::parse("s1-").expect("s1-");
    assert_eq!(from_s1.from.mode, PacketPosMode::RelSeq);
    assert_eq!(from_s1.from.pos, 1);
    assert_eq!(from_s1.to, PacketPos::ALWAYS);
    assert!(!from_s1.upper_cutoff);

    let s1_lt_d1 = PacketRange::parse("s1<d1").expect("s1<d1");
    assert_eq!(s1_lt_d1.from.mode, PacketPosMode::RelSeq);
    assert_eq!(s1_lt_d1.to.mode, PacketPosMode::DataPacketNum);
    assert!(s1_lt_d1.upper_cutoff);

    let n1_n5 = PacketRange::parse("n1-n5").expect("n1-n5");
    assert_eq!((n1_n5.from.mode.as_char(), n1_n5.from.pos), ('n', 1));
    assert_eq!((n1_n5.to.mode.as_char(), n1_n5.to.pos), ('n', 5));

    assert!(matches!(PacketRange::parse("d1"), Err(ConfigError::InvalidPacketRange(_))));
    assert!(matches!(PacketRange::parse("z1-z2"), Err(ConfigError::InvalidPacketRange(_))));
    assert!(matches!(PacketRange::parse(""), Err(ConfigError::InvalidPacketRange(_))));
}

/// Verifies L7 protocol and payload bitmask parsing and `known`/`all` matching rules.
#[test]
fn l7_masks_handle_known_all_and_invalid_names()
{
    let tls_http = parse_l7_proto_mask(&["http,tls".to_owned()]).expect("http,tls");
    assert!(l7_proto_matches(L7Proto::Http, tls_http));
    assert!(l7_proto_matches(L7Proto::Tls, tls_http));
    assert!(!l7_proto_matches(L7Proto::Quic, tls_http));

    let known_mask = parse_l7_proto_mask(&["known".to_owned()]).expect("known");
    assert!(l7_proto_matches(L7Proto::Dns, known_mask));
    assert!(!l7_proto_matches(L7Proto::Unknown, known_mask));

    let all_mask = parse_l7_proto_mask(&["http".to_owned(), "all".to_owned()]).expect("all");
    assert_eq!(all_mask, 0);
    assert!(l7_proto_matches(L7Proto::Unknown, all_mask));

    let payload_known = parse_l7_payload_mask(&["known".to_owned()]).expect("known");
    assert!(l7_payload_matches(L7Payload::TlsClientHello, payload_known));
    assert!(!l7_payload_matches(L7Payload::Empty, payload_known));
    assert!(!l7_payload_matches(L7Payload::Unknown, payload_known));

    assert!(matches!(parse_l7_proto_mask(&["nope".to_owned()]), Err(ConfigError::InvalidL7Proto(_))));
    assert!(matches!(
        parse_l7_payload_mask(&["bad_payload".to_owned()]),
        Err(ConfigError::InvalidL7Payload(_))
    ));
}

/// Verifies built-in default blobs, inline hex decoding, and offset-based file loading.
#[test]
fn default_hex_and_file_blobs_load_accurately()
{
    let defaults = default_blobs();
    assert_eq!(defaults["fake_default_tls"].len(), 680);
    assert!(defaults["fake_default_http"].starts_with(b"GET / HTTP/1.1\r\n"));
    let quic = &defaults["fake_default_quic"];
    assert_eq!(quic.len(), FAKE_QUIC_DEFAULT_LEN);
    assert_eq!(quic[0], 0x40);
    assert!(quic[1..].iter().all(|&b| b == 0));

    let parsed = parse_hex_blob("custom", "0xdeAdBeEf").expect("valid hex blob");
    assert_eq!(parsed, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert!(matches!(parse_hex_blob("odd", "0x123"), Err(ConfigError::InvalidBlob { .. })));
    assert!(matches!(parse_hex_blob("bad", "zzzz"), Err(ConfigError::InvalidBlob { .. })));

    let path = unique_temp_path("blob.bin");
    fs::write(&path, b"header-abcdef").expect("write temp blob");
    let loaded = load_file_blob("custom_file", &path, 7).expect("read temp blob with offset");
    let _ = fs::remove_file(&path);
    assert_eq!(loaded, b"abcdef");
}

/// Verifies M3 `parse_l7_disable_mask` and `parse_timeouts` helpers match `zapret2` defaults.
#[test]
fn l7_disable_mask_and_ctrack_timeouts_parse_and_validate()
{
    let none = parse_l7_disable_mask(&[]).expect("empty means none disabled");
    assert_eq!(none, L7_PAYLOAD_NONE_MASK);
    assert!(!l7_payload_matches(L7Payload::HttpReq, none));

    let blank = parse_l7_disable_mask(&["  ".to_owned()]).expect("whitespace means none");
    assert_eq!(blank, L7_PAYLOAD_NONE_MASK);

    let all = parse_l7_disable_mask(&["http_req,all".to_owned()]).expect("all resets mask to 0");
    assert_eq!(all, 0);
    assert!(l7_payload_matches(L7Payload::TlsClientHello, all));

    let subset = parse_l7_disable_mask(&["http_req,quic_initial".to_owned()]).expect("subset");
    assert!(l7_payload_matches(L7Payload::HttpReq, subset));
    assert!(l7_payload_matches(L7Payload::QuicInitial, subset));
    assert!(!l7_payload_matches(L7Payload::TlsClientHello, subset));

    let three = parse_timeouts("10:20:30").expect("3-part S:E:F keeps default udp timeout");
    assert_eq!((three.syn, three.established, three.fin, three.udp), (10, 20, 30, 60));

    let four = parse_timeouts("5:15:25:35").expect("4-part S:E:F:U overrides udp timeout");
    assert_eq!((four.syn, four.established, four.fin, four.udp), (5, 15, 25, 35));

    assert!(matches!(parse_timeouts("10:20"), Err(ConfigError::Validation(_))));
    assert!(matches!(parse_timeouts("1:2:3:4:5"), Err(ConfigError::Validation(_))));
    assert!(matches!(parse_timeouts("1:bad:3"), Err(ConfigError::Validation(_))));
}
