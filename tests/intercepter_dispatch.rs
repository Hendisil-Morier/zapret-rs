//! Integration tests for NFQUEUE configuration defaults, fwmark suppression, `SIOCGIFNAME` lookup, and `poll` timeouts.
#![cfg(target_os = "linux")]

/// Duration helpers for testing `poll_timeout_ms`.
use std::time::Duration;

/// NFQUEUE constants, configuration, packet view, dispatch helpers, and `SIOCGIFNAME` resolver.
use zapret_rs::intercepter::{
    DEFAULT_DESYNC_FWMARK, DEFAULT_QUEUE_MAXLEN, DEFAULT_QUEUE_NUM, DEFAULT_QUEUE_RCVBUF, Decision,
    IfNameResolver, QueueConfig, QueuedPacket, dispatch_packet, poll_timeout_ms,
};

/// Verifies `QueueConfig::default()` and `QueueConfig::with_queue_num` match `zapret2` defaults.
#[test]
fn queue_config_defaults_match_zapret2_constants()
{
    let def = QueueConfig::default();
    assert_eq!(def.queue_num, DEFAULT_QUEUE_NUM);
    assert_eq!(def.queue_num, 200);
    assert_eq!(def.queue_maxlen, DEFAULT_QUEUE_MAXLEN);
    assert_eq!(def.queue_maxlen, 4096);
    assert_eq!(def.rcvbuf_bytes, DEFAULT_QUEUE_RCVBUF);
    assert_eq!(def.rcvbuf_bytes, 1024 * 1024);
    assert_eq!(def.desync_fwmark, DEFAULT_DESYNC_FWMARK);
    assert_eq!(def.desync_fwmark, 0x4000_0000);
    assert!(def.fail_open);

    let custom = QueueConfig::with_queue_num(350);
    assert_eq!(custom.queue_num, 350);
    assert_eq!(custom.desync_fwmark, DEFAULT_DESYNC_FWMARK);
}

/// Verifies `dispatch_packet` short-circuits packets matching `desync_fwmark` and forwards others.
#[test]
fn dispatch_packet_skips_handler_when_fwmark_matches_desync_mask()
{
    let mut calls = 0usize;
    let payload = [0x45u8, 0x00, 0x00, 0x14];

    // Exact match with `desync_fwmark`.
    let marked = QueuedPacket {
        packet_id: 1,
        mark: DEFAULT_DESYNC_FWMARK,
        ifin: None,
        ifout: Some("eth0"),
        payload: &payload,
    };
    let mut exact_handler = |_: &QueuedPacket<'_>| {
        calls += 1;
        Decision::Drop
    };
    assert_eq!(dispatch_packet(&marked, DEFAULT_DESYNC_FWMARK, &mut exact_handler), Decision::Pass);
    assert_eq!(calls, 0);

    // Combined bitmask still matches `desync_fwmark`.
    let combined = QueuedPacket { mark: DEFAULT_DESYNC_FWMARK | 0x0000_0001, ..marked.clone() };
    let mut combined_handler = |_: &QueuedPacket<'_>| {
        calls += 1;
        Decision::Drop
    };
    assert_eq!(dispatch_packet(&combined, DEFAULT_DESYNC_FWMARK, &mut combined_handler), Decision::Pass);
    assert_eq!(calls, 0);

    // Non-matching mark invokes handler and propagates `Drop` and `Replace`.
    let unmarked = QueuedPacket { mark: 0x0000_0001, ..marked };
    let mut drop_handler = |pkt: &QueuedPacket<'_>| {
        calls += 1;
        assert_eq!(pkt.packet_id, 1);
        Decision::Drop
    };
    assert_eq!(dispatch_packet(&unmarked, DEFAULT_DESYNC_FWMARK, &mut drop_handler), Decision::Drop);
    assert_eq!(calls, 1);

    let replacement = vec![0x60, 0x00, 0x00, 0x00];
    let mut replace_handler = |_: &QueuedPacket<'_>| {
        calls += 1;
        Decision::Replace(replacement.clone())
    };
    assert_eq!(
        dispatch_packet(&unmarked, DEFAULT_DESYNC_FWMARK, &mut replace_handler),
        Decision::Replace(vec![0x60, 0x00, 0x00, 0x00])
    );
    assert_eq!(calls, 2);

    // Setting `desync_fwmark = 0` disables mark suppression.
    let mut zero_mark_handler = |_: &QueuedPacket<'_>| {
        calls += 1;
        Decision::Pass
    };
    assert_eq!(dispatch_packet(&combined, 0, &mut zero_mark_handler), Decision::Pass);
    assert_eq!(calls, 3);
}

/// Verifies `IfNameResolver` resolves the loopback index via `SIOCGIFNAME` and returns `None` for invalid indices.
#[test]
fn ifname_resolver_resolves_loopback_and_rejects_zero_or_missing_index()
{
    let resolver = IfNameResolver::new().expect("AF_INET SOCK_DGRAM socket should open");
    assert_eq!(resolver.resolve(0), None);
    assert_eq!(resolver.resolve(u32::MAX), None);
    assert_eq!(resolver.resolve(u32::MAX - 1), None);

    // SAFETY: `c"lo"` is a valid NUL-terminated static C string literal.
    let lo_idx = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(lo_idx, 0, "loopback interface `lo` must exist on Linux");
    assert_eq!(resolver.resolve(lo_idx).as_deref(), Some("lo"));
}

/// Verifies `poll_timeout_ms` converts infinite, zero, normal, and overflowing durations safely.
#[test]
fn poll_timeout_ms_handles_none_zero_normal_and_overflow()
{
    assert_eq!(poll_timeout_ms(None), -1);
    assert_eq!(poll_timeout_ms(Some(Duration::ZERO)), 0);
    assert_eq!(poll_timeout_ms(Some(Duration::from_millis(250))), 250);
    assert_eq!(poll_timeout_ms(Some(Duration::MAX)), libc::c_int::MAX);
}
