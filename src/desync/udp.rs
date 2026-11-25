//! Stateful UDP DPI desync processor with L7 probes, QUIC Initial decrypt/reassembly, and DNS learning.

/// L7 payload identifier and payload disable bitmask checks.
use crate::config::{L7Payload, l7_payload_matches};
/// UDP decrypted Initial reassembly capacity limit (`UDP_MAX_REASM`).
use crate::conntrack::UDP_MAX_REASM;
/// DNS IN A/AAAA response learner populating `--ipcache-hostname`.
use crate::desync::dns_cache::feed_dns_response;
/// Core desync engine executing Lua actions.
use crate::desync::engine::DesyncEngine;
/// Flow initialization and mutable per-packet state.
use crate::desync::play::{PlayState, ReplayContext, play_prolog};
/// Bidirectional UDP L7 classifier table.
use crate::desync::probe::probe_udp;
/// Stream reassembly initialization, feeding, stopping, queueing, and replay orchestration.
use crate::desync::reasm_replay::{
    clone_reasm_bytes, queue_delayed_packet, reasm_client_feed, reasm_client_start,
    reasm_client_stop, replay_and_finish,
};
/// Dynamic hostname/L7 profile rediscovery and UDP failure stall checks.
use crate::desync::rediscovery::dp_rediscovery;
/// Linux postnat drop workaround applied on initial outgoing datagrams.
use crate::desync::verdict::ct_new_postnat_fix;
/// Intercepted packet container and kernel NFQUEUE decision variants.
use crate::intercepter::{Decision, QueuedPacket};
/// UDP protocol number used when initializing UDP stream reassembly.
use crate::packet::constants::IPPROTO_UDP;
/// Dissected L3/L4 packet view.
use crate::packet::DissectedPacket;
/// QUIC Initial decryptor, CRYPTO defragmenter, and ClientHello SNI extractor.
use crate::protocol::{
    is_quic_crypto_hello, is_tls_handshake_full, quic_decrypt_initial, quic_defrag_crypto,
    tls_hello_extract_host_from_handshake,
};
/// Monotonic boottime timestamp forwarded from the outer packet dispatch loop.
use crate::timer::MonotonicTime;

/// Handles outgoing QUIC Initial decryption, client reassembly/replay, and handshake host extraction.
fn process_quic_initial_flow(
    engine: &DesyncEngine,
    ps: &mut PlayState,
    replay: &ReplayContext<'_>,
    pkt: &QueuedPacket<'_>,
    payload: &[u8],
) -> Result<Option<Vec<u8>>, Decision> {
    let mut clean = if replay.is_replay() {
        clone_reasm_bytes(ps.ctrack_replay.as_ref()).unwrap_or_default()
    } else {
        quic_decrypt_initial(payload).unwrap_or_default()
    };
    if clean.is_empty() {
        reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);
        return Ok(None);
    }

    let reasm_disable = l7_payload_matches(ps.l7payload, engine.reasm_disable);
    if let Some(ctrack_rc) = &ps.ctrack
        && !reasm_disable
    {
        let active_overflow = {
            let entry = ctrack_rc.borrow();
            !entry.reasm_client.is_empty() && !entry.reasm_client.has_space(clean.len())
        };
        if active_overflow {
            return Ok(None);
        }
        if reasm_client_feed(
            Some(ctrack_rc),
            IPPROTO_UDP,
            &clean,
            engine.desync_fwmark,
            &engine.sender,
        ) && let Some(full_clean) = clone_reasm_bytes(Some(ctrack_rc))
        {
            clean = full_clean;
        }
    }

    let Some((defrag, full_frag)) = quic_defrag_crypto(&clean, UDP_MAX_REASM) else {
        reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);
        return Ok(None);
    };

    if full_frag {
        let hello_span = is_quic_crypto_hello(&defrag);
        let req_full =
            hello_span.is_some_and(|(off, len)| is_tls_handshake_full(&defrag[off..off + len]));

        if let Some(ctrack_rc) = &ps.ctrack
            && !reasm_disable
        {
            if hello_span.is_none() {
                return Ok(None);
            }
            let mut delayed_ready = None;
            let mut started_ok = true;
            {
                let mut entry = ctrack_rc.borrow_mut();
                if !req_full && entry.reasm_client.is_empty() {
                    started_ok = reasm_client_start(
                        &mut entry,
                        IPPROTO_UDP,
                        L7Payload::QuicInitial,
                        UDP_MAX_REASM,
                        UDP_MAX_REASM,
                        &clean,
                    );
                }
                if started_ok && !entry.reasm_client.is_empty() {
                    if !queue_delayed_packet(&mut entry, pkt.payload, pkt.mark, pkt.ifin, pkt.ifout)
                    {
                        started_ok = false;
                    } else if req_full {
                        delayed_ready = Some(std::mem::take(&mut entry.delayed));
                    } else {
                        return Err(Decision::Drop);
                    }
                }
            }
            if !started_ok {
                return Ok(None);
            }
            if let Some(delayed) = delayed_ready {
                replay_and_finish(engine, pkt.packet_id, Some(ctrack_rc), delayed);
                return Err(Decision::Drop);
            }
        }

        if let Some((off, len)) = hello_span {
            let handshake = defrag[off..off + len].to_vec();
            ps.host = tls_hello_extract_host_from_handshake(&handshake, true);
            return Ok(Some(handshake));
        }
        return Ok(None);
    }

    if let Some(ctrack_rc) = &ps.ctrack
        && !reasm_disable
    {
        let queued = {
            let mut entry = ctrack_rc.borrow_mut();
            let started = !entry.reasm_client.is_empty()
                || reasm_client_start(
                    &mut entry,
                    IPPROTO_UDP,
                    L7Payload::QuicInitial,
                    UDP_MAX_REASM,
                    UDP_MAX_REASM,
                    &clean,
                );
            started && queue_delayed_packet(&mut entry, pkt.payload, pkt.mark, pkt.ifin, pkt.ifout)
        };
        if queued {
            return Err(Decision::Drop);
        }
    }
    Ok(None)
}

/// Processes a single UDP datagram through L7 probes, QUIC decryption, DNS caching, and actions.
pub(crate) fn process_udp_packet(
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
    let payload = dis.payload.as_deref().unwrap_or(&[]);
    let mut decrypt_buf: Option<Vec<u8>> = None;

    if !payload.is_empty() {
        probe_udp(
            payload,
            engine.payload_disable,
            ps.ctrack_replay.as_ref(),
            &mut ps.l7proto,
            &mut ps.l7payload,
        );
        if !ps.b_reverse && ps.l7payload == L7Payload::QuicInitial {
            match process_quic_initial_flow(engine, &mut ps, replay, pkt, payload) {
                Ok(dec) => decrypt_buf = dec,
                Err(Decision::Drop) => {
                    return ct_new_postnat_fix(ps.ctrack.as_ref(), engine.server, dis, pkt.payload);
                }
                Err(other) => return other,
            }
        }
        if ps.l7payload == L7Payload::DnsResponse {
            let _ = feed_dns_response(payload, &engine.ipcache, now.sec);
        }
    }

    reasm_client_stop(ps.ctrack.as_ref(), engine.desync_fwmark, &engine.sender);

    if !dp_rediscovery(&svc, &mut ps, dis, replay.tpos, now.sec) {
        return Decision::Pass;
    }

    let decision = engine.dispatch_state(replay, pkt, dis, &ps, None, decrypt_buf.as_deref());
    if !ps.incoming && decision == Decision::Drop {
        return ct_new_postnat_fix(ps.ctrack.as_ref(), engine.server, dis, pkt.payload);
    }
    decision
}
