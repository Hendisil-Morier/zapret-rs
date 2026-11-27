//! Stateful TCP DPI desync processor with L7 probes, TLS reassembly, replay, and RST handling.

/// L7 payload tags and payload disable bitmask checks.
use crate::config::{L7Payload, l7_payload_matches};
/// Client-side TCP payload buffer limit (`TCP_MAX_REASM`).
use crate::conntrack::TCP_MAX_REASM;
/// Autohostlist outgoing retransmission and incoming RST/redirect failure checks.
use crate::desync::autohost::{
    AutohostFailTarget, handle_tcp_incoming_fail, handle_tcp_retrans_fail,
};
/// Core desync engine executing Lua actions.
use crate::desync::engine::DesyncEngine;
/// Flow initialization and mutable per-packet state.
use crate::desync::play::{PlayState, ReplayContext, play_prolog};
/// Outgoing and incoming TCP L7 payload probes.
use crate::desync::probe::{probe_tcp_incoming, probe_tcp_outgoing};
/// Client-side stream reassembly, delayed queuing, and replay orchestration.
use crate::desync::reasm_replay::{
    clone_reasm_bytes, queue_delayed_packet, reasm_client_feed, reasm_client_start,
    reasm_client_stop, replay_and_finish,
};
/// Dynamic hostname/L7 profile rediscovery.
use crate::desync::rediscovery::dp_rediscovery;
/// Linux postnat drop workaround applied on initial outgoing segments.
use crate::desync::verdict::ct_new_postnat_fix;
/// Intercepted packet container and kernel NFQUEUE decision variants.
use crate::intercepter::{Decision, QueuedPacket};
/// TCP protocol identifier and SYN flag mask.
use crate::packet::constants::{IPPROTO_TCP, TH_SYN};
/// Dissected L3/L4 packet view.
use crate::packet::DissectedPacket;
/// HTTP Host and TLS SNI extractors and record-completeness predicate.
use crate::protocol::{
    http_extract_host, is_tls_record_full, tls_hello_extract_host, tls_record_len,
};
/// Monotonic boottime timestamp forwarded from the outer packet dispatch loop.
use crate::timer::MonotonicTime;

/// Evaluates live multi-segment TLS ClientHello reassembly, queueing, and delayed replay.
fn try_tcp_tls_reassembly(
    engine: &DesyncEngine,
    ps: &mut PlayState,
    pkt: &QueuedPacket<'_>,
    raw_payload: &[u8],
    rdata: &[u8],
) -> Option<Decision> {
    let is_full = is_tls_record_full(rdata);
    let ctrack_rc = ps.ctrack.as_ref()?;
    if l7_payload_matches(L7Payload::TlsClientHello, engine.reasm_disable) {
        return None;
    }

    let mut delayed_ready = None;
    let mut overflowed = false;
    {
        let mut entry = ctrack_rc.borrow_mut();
        if !is_full && entry.reasm_client.is_empty() && !entry.pos.client.is_retransmission() {
            let target_len = tls_record_len(raw_payload)?;
            if !reasm_client_start(
                &mut entry,
                IPPROTO_TCP,
                L7Payload::TlsClientHello,
                target_len,
                TCP_MAX_REASM,
                raw_payload,
            ) {
                return None;
            }
        }
        if entry.reasm_client.is_empty() {
            return None;
        }
        if !queue_delayed_packet(&mut entry, pkt.payload, pkt.mark, pkt.ifin, pkt.ifout) {
            overflowed = true;
        } else if entry.reasm_client.is_full() {
            delayed_ready = Some(entry.take_delayed());
        }
    }

    if overflowed {
        reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);
        ps.l7payload = L7Payload::Unknown;
        return None;
    }
    if let Some(delayed) = delayed_ready {
        replay_and_finish(engine, pkt.packet_id, ps.ctrack.as_ref(), delayed);
    }
    engine.record_outcome(crate::desync::play::PacketOutcome::Reasm);
    Some(Decision::Drop)
}

/// Processes a single TCP segment (live or replayed) through L7 probes, reassembly, and actions.
pub(crate) fn process_tcp_packet(
    engine: &DesyncEngine,
    replay: &ReplayContext<'_>,
    pkt: &QueuedPacket<'_>,
    dis: &DissectedPacket,
    now: MonotonicTime,
) -> Decision {
    let svc = engine.services();
    let Some(mut ps) = play_prolog(&svc, replay, dis, pkt.ifin, pkt.ifout, pkt.mark, now) else {
        return Decision::Pass;
    };
    let Some(tcp) = &dis.tcp else {
        return Decision::Pass;
    };
    let raw_payload = dis.payload.as_deref().unwrap_or(&[]);
    let is_syn = (tcp.flags & TH_SYN) != 0;
    let mut rdata_buf: Option<Vec<u8>> = None;

    if ps.b_reverse {
        if !is_syn && !raw_payload.is_empty() {
            probe_tcp_incoming(
                raw_payload,
                engine.payload_disable,
                ps.ctrack.as_ref(),
                &mut ps.l7proto,
                &mut ps.l7payload,
            );
        }
        let fail_tgt = ps.profile_idx.map(|i| AutohostFailTarget {
            profile: svc.profiles[i].as_ref(),
            runtime: &svc.profile_runtimes[i],
            server: engine.server,
            client_label: &ps.client_label,
            debug_log: engine.hostlist_auto_debug.as_deref(),
        });
        handle_tcp_incoming_fail(
            ps.ctrack.as_ref(),
            dis,
            ps.l7payload,
            fail_tgt.as_ref(),
        );
    } else if !is_syn && !raw_payload.is_empty() {
        if replay.is_replay() {
            rdata_buf = clone_reasm_bytes(ps.ctrack_replay.as_ref());
        } else if reasm_client_feed(
            ps.ctrack.as_ref(),
            IPPROTO_TCP,
            raw_payload,
            engine.desync_fwmark,
            &engine.sender,
        ) {
            rdata_buf = clone_reasm_bytes(ps.ctrack.as_ref());
        }

        let fail_tgt = ps.profile_idx.map(|i| AutohostFailTarget {
            profile: svc.profiles[i].as_ref(),
            runtime: &svc.profile_runtimes[i],
            server: engine.server,
            client_label: &ps.client_label,
            debug_log: engine.hostlist_auto_debug.as_deref(),
        });
        handle_tcp_retrans_fail(
            ps.ctrack.as_ref(),
            dis,
            fail_tgt.as_ref(),
            pkt.ifin,
            &engine.sender,
        );

        let rdata = rdata_buf.as_deref().unwrap_or(raw_payload);
        let reasm_empty = ps
            .ctrack_replay
            .as_ref()
            .is_none_or(|rc| rc.borrow().reasm_client.is_empty());
        if reasm_empty {
            let live_tpos = match (replay.tpos, &ps.ctrack_replay) {
                (Some(tp), _) => Some(*tp),
                (None, Some(rc)) => Some(rc.borrow().pos),
                (None, None) => None,
            };
            probe_tcp_outgoing(
                rdata,
                engine.payload_disable,
                ps.ctrack_replay.as_ref(),
                live_tpos.as_ref(),
                &mut ps.l7proto,
                &mut ps.l7payload,
            );
        }

        let is_tls_reasm = ps.l7payload == L7Payload::TlsClientHello
            || ps.ctrack_replay.as_ref().is_some_and(|rc| {
                let e = rc.borrow();
                e.reasm_client_payload == L7Payload::TlsClientHello && !e.reasm_client.is_empty()
            });

        if is_tls_reasm {
            ps.l7payload = L7Payload::TlsClientHello;
            if let Some(early_drop) =
                try_tcp_tls_reassembly(engine, &mut ps, pkt, raw_payload, rdata)
            {
                return early_drop;
            }
            let effective = if ps.l7payload == L7Payload::TlsClientHello {
                rdata
            } else {
                raw_payload
            };
            ps.host = tls_hello_extract_host(effective, true);
        } else {
            reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);
            if ps.l7payload == L7Payload::HttpReq {
                ps.host = http_extract_host(rdata);
            }
        }
    }

    if !dp_rediscovery(&svc, &mut ps, dis, replay.tpos, now.sec) {
        reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);
        return Decision::Pass;
    }

    let reasm_slice = if ps.l7payload == L7Payload::Unknown && rdata_buf.is_some() {
        Some(raw_payload)
    } else if rdata_buf.is_some() {
        rdata_buf.as_deref()
    } else {
        dis.payload.as_deref()
    };

    let decision = engine.dispatch_state(replay, pkt, dis, &ps, reasm_slice, None);
    if !ps.incoming && decision == Decision::Drop {
        return ct_new_postnat_fix(ps.ctrack.as_ref(), engine.server, dis, pkt.payload);
    }
    decision
}
