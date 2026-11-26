//! Regression tests for Windows WinDivert FFI flags, `WINDIVERT_ADDRESS` bits, and `ifout` parsing.

#![cfg(windows)]

/// WinDivert send-only flag constant and address builder under test.
use zapret_rs::intercepter::windivert_ffi::{WINDIVERT_FLAG_SEND_ONLY, WinDivertAddress};
/// Windows `ifout` index parser accepting `"IfIdx"` and `"IfIdx.SubIfIdx"`.
use zapret_rs::rawsend::windivert::parse_ifout_indices;

#[test]
fn windivert_send_only_flag_and_outbound_address_match_windivert_header() {
    // `windivert.h`: `WINDIVERT_FLAG_RECV_ONLY = 0x0004`, `WINDIVERT_FLAG_SEND_ONLY = 0x0008`.
    assert_eq!(WINDIVERT_FLAG_SEND_ONLY, 0x0008);
    assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);

    let v4 = WinDivertAddress::outbound(14, 2, false);
    // Outbound (bit 17), Impostor (bit 19), IPChecksum (bit 21), TCPChecksum (bit 22), UDPChecksum (bit 23).
    assert_eq!(v4.layer_event_flags, (1 << 17) | (1 << 19) | (1 << 21) | (1 << 22) | (1 << 23));
    assert_eq!(v4.if_idx(), 14);
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
