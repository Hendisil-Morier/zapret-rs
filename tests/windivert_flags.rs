//! Regression tests for Windows WinDivert FFI flags, `WINDIVERT_ADDRESS` bits, and `ifout` parsing.

#![cfg(windows)]

/// WinDivert send-only flag constant and address builder under test.
use zapret_rs::intercepter::windivert_ffi::{WINDIVERT_FLAG_SEND_ONLY, WinDivertAddress};
/// Windows `ifout` index parser and `Impostor=1` min-TTL adjustment under test.
use zapret_rs::rawsend::windivert::{bump_impostor_min_ttl, parse_ifout_indices};

#[test]
fn windivert_send_only_flag_and_outbound_address_match_windivert_header() {
    // `windivert.h`: `WINDIVERT_FLAG_RECV_ONLY = 0x0004`, `WINDIVERT_FLAG_SEND_ONLY = 0x0008`.
    assert_eq!(WINDIVERT_FLAG_SEND_ONLY, 0x0008);
    assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

    let v4 = WinDivertAddress::outbound(14, 2, false);
    // Outbound (bit 17), Impostor (bit 19), IPChecksum (bit 21), TCPChecksum (bit 22), UDPChecksum (bit 23).
    assert_eq!(v4.layer_event_flags, (1 << 17) | (1 << 19) | (1 << 21) | (1 << 22) | (1 << 23));
    assert_eq!(v4.if_idx(), 14);
    assert_eq!(v4.sub_if_idx(), 2);
    assert_eq!(&v4.union_bytes[4..8], &2u32.to_ne_bytes());

    let v6 = WinDivertAddress::outbound(7, 0, true);
    assert_ne!(v6.layer_event_flags & (1 << 20), 0);
}

#[test]
fn parse_ifout_indices_accepts_single_and_dotted_windows_indices() {
    assert_eq!(parse_ifout_indices(Some("14")), Some((14, 0)));
    assert_eq!(parse_ifout_indices(Some("14.3")), Some((14, 3)));
    assert_eq!(parse_ifout_indices(Some("0")), None);
    assert_eq!(parse_ifout_indices(Some("")), None);
    assert_eq!(parse_ifout_indices(None), None);
}

#[test]
fn bump_impostor_min_ttl_raises_ttl1_and_updates_ipv4_checksum_without_allocating_for_higher_ttl() {
    use std::borrow::Cow;

    // Minimal valid IPv4 header with TTL=1, proto=6 (TCP), length=20.
    let mut pkt = [
        0x45, 0x00, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00,
        0x01, 0x06, 0x00, 0x00, 10, 0, 0, 1,
        10, 0, 0, 2,
    ];
    let csum = |hdr: &[u8]| -> u16 {
        let mut sum: u32 = 0;
        for chunk in hdr.chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    };
    let hc = csum(&pkt);
    pkt[10..12].copy_from_slice(&hc.to_be_bytes());
    assert_eq!(csum(&pkt), 0);

    let bumped = bump_impostor_min_ttl(&pkt);
    assert!(matches!(bumped, Cow::Owned(_)));
    assert_eq!(bumped[8], 2);
    assert_eq!(csum(&bumped), 0, "updated IPv4 header checksum must stay valid");

    // Higher TTL leaves packet borrowed untouched.
    assert!(matches!(bump_impostor_min_ttl(&bumped), Cow::Borrowed(_)));
}
