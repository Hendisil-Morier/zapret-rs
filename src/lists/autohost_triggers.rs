//! TCP/UDP connection failure and DPI-interception triggers for autohostlist discovery.

/// Conntrack flow, directional position, and retransmission-sentinel types.
use crate::conntrack::{ConnState, CtrackEntry, CtrackPosition, CtrackPositions, RETRANS_COUNTER_STOP};
/// Per-profile autohostlist thresholds evaluated against active connections.
use crate::lists::autohostlist::AutoHostlistSettings;
/// TCP protocol and header flag constants (`IPPROTO_TCP`, `TH_FIN`, `TH_RST`, `TH_SYN`).
use crate::packet::constants::{IPPROTO_TCP, TH_FIN, TH_RST, TH_SYN};
/// L7 tags, HTTP DPI-block detector, and TLS unencrypted fatal Alert detector.
use crate::protocol::{L7Payload, L7Proto, http_reply_looks_like_dpi_block, is_tls_fatal_alert};

/// Returns `true` when wrapping 32-bit sequence `s` lies in `[s1, s2]` (`seq_within` in `helpers.c`).
pub const fn seq_within(s: u32, s1: u32, s2: u32) -> bool {
    (s2 >= s1 && s >= s1 && s <= s2) || (s2 < s1 && (s <= s2 || s >= s1))
}

/// Returns `true` when the latest outgoing TCP segment overlaps previously sent data (`is_retransmission`).
pub const fn is_tcp_retransmission(pos: &CtrackPosition) -> bool {
    pos.is_retransmission()
}

/// Evaluates an outgoing payload segment for TCP retransmission failures (`auto_hostlist_retrans`).
pub fn check_tcp_retrans_trigger(entry: &mut CtrackEntry, settings: &AutoHostlistSettings) -> Option<bool> {
    if !entry.hostname_ah_check || entry.failure_detect_finalized || entry.req_retrans_counter == RETRANS_COUNTER_STOP {
        return None;
    }

    if entry.pos.ipproto == IPPROTO_TCP && entry.pos.state != ConnState::Syn {
        let client = &entry.pos.client;
        let max_seq = client.seq0.wrapping_add(settings.retrans_maxseq);
        if !seq_within(client.seq_last, client.seq0, max_seq) {
            entry.failure_detect_finalized = true;
            entry.req_retrans_counter = RETRANS_COUNTER_STOP;
            return Some(false);
        }
        if !is_tcp_retransmission(client) {
            return None;
        }
    }

    entry.req_retrans_counter = entry.req_retrans_counter.saturating_add(1);
    if entry.req_retrans_counter >= settings.retrans_threshold {
        entry.req_retrans_counter = RETRANS_COUNTER_STOP;
        entry.failure_detect_finalized = true;
        return Some(true);
    }
    None
}

/// Evaluates an incoming server TCP segment for RST, TLS fatal Alert, premature FIN, or HTTP DPI block pages.
pub fn check_tcp_incoming_trigger(
    entry: &mut CtrackEntry,
    tcp_flags: u8,
    payload: Option<&[u8]>,
    l7payload: L7Payload,
    settings: &AutoHostlistSettings,
) -> Option<bool> {
    if !entry.hostname_ah_check || entry.failure_detect_finalized || settings.incoming_maxseq == 0 {
        return None;
    }
    if (tcp_flags & TH_SYN) != 0 {
        return None;
    }

    let server = &entry.pos.server;
    let rseq = server.seq_last.wrapping_sub(server.seq0);
    let max_seq = server.seq0.wrapping_add(settings.incoming_maxseq);

    // Forged DPI RST packets sometimes carry `seq == server.seq0` (`rseq == 0`); inspect RST before the `rseq == 0` skip.
    if (tcp_flags & TH_RST) != 0 {
        entry.failure_detect_finalized = true;
        return Some(seq_within(server.seq_last, server.seq0, max_seq));
    }

    if rseq == 0 {
        return None;
    }
    if !seq_within(server.seq_last, server.seq0.wrapping_add(1), max_seq) {
        entry.failure_detect_finalized = true;
        return Some(false);
    }

    let is_tls_alert = payload.is_some_and(is_tls_fatal_alert);
    let is_http_block = l7payload == L7Payload::HttpReply
        && match (payload, entry.hostname.as_deref()) {
            (Some(data), Some(host)) if !data.is_empty() => {
                http_reply_looks_like_dpi_block(data, host, entry.hostname_is_ip)
            }
            _ => false,
        };
    let is_early_fin = (tcp_flags & TH_FIN) != 0
        && payload.is_none_or(<[u8]>::is_empty)
        && server.pdcounter == 0
        && entry.pos.client.pdcounter > 0
        && matches!(entry.l7proto, L7Proto::Tls | L7Proto::Http);

    if !(is_tls_alert || is_http_block || is_early_fin) {
        return None;
    }
    entry.failure_detect_finalized = true;
    Some(true)
}

/// Evaluates UDP packet counters for unidirectional client stalls vs server replies (`process_udp_fail`).
pub fn check_udp_trigger(
    entry: &mut CtrackEntry,
    tpos: &CtrackPositions,
    settings: &AutoHostlistSettings,
) -> Option<bool> {
    if entry.hostname.is_none() || !entry.hostname_ah_check || entry.failure_detect_finalized || settings.udp_out == 0 {
        return None;
    }
    if tpos.server.pcounter > settings.udp_in {
        entry.failure_detect_finalized = true;
        Some(false)
    } else if tpos.client.pcounter >= settings.udp_out {
        entry.failure_detect_finalized = true;
        Some(true)
    } else {
        None
    }
}
