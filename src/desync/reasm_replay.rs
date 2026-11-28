//! Client-side payload stream reassembly, delayed packet queuing, and replay orchestration.

/// Interior mutability for releasing `CtrackEntry` borrows prior to raw packet emission or replay.
use std::cell::RefCell;
/// FIFO storage for delayed segments queued while accumulating multi-packet handshakes.
use std::collections::VecDeque;
/// Single-thread reference counting for passing conntrack entries and [`PacketSender`].
use std::rc::Rc;

/// Classified payload identifier stored while accumulating client fragments.
use crate::config::L7Payload;
/// Conntrack flow record and frozen per-packet delayed snapshot types.
use crate::conntrack::{CtrackEntry, DelayedPacket};
/// Stateful desync engine re-entered for each delayed packet during replay.
use crate::desync::engine::DesyncEngine;
/// Replay batch metadata forwarded to `process_packet_play`.
use crate::desync::play::ReplayContext;
/// Target IP extractor and kernel NFQUEUE decision variants.
use crate::desync::verdict::extract_endpoint_ip;
/// Intercepted wire packet wrapper and kernel NFQUEUE verdict decision enum.
use crate::intercepter::{Decision, QueuedPacket};
/// IP protocol constant distinguishing TCP sequence tracking from UDP length offsets.
use crate::packet::constants::IPPROTO_TCP;
/// Wire packet parser used to determine destination IPs for flushed raw packets.
use crate::packet::dissect_packet;
/// Abstract raw socket transmitter used for both delayed flushes and modified replays.
use crate::rawsend::PacketSender;
/// Monotonic boottime clock stamped once per replayed packet batch.
use crate::timer::boottime_now;

/// Flushes a drained FIFO queue of delayed packets unmodified via `sender` (`send_delayed`).
pub(crate) fn send_delayed_queue(
    delayed: VecDeque<DelayedPacket>,
    desync_fwmark: u32,
    sender: &Rc<RefCell<dyn PacketSender>>,
)
{
    let mut tx = sender.borrow_mut();
    for pkt in delayed
    {
        let dis = dissect_packet(&pkt.raw, false);
        let Some(dst) = extract_endpoint_ip(&dis, false)
        else
        {
            continue;
        };
        let _ = tx.send(dst, pkt.fwmark | desync_fwmark, pkt.ifout.as_deref(), &pkt.raw);
    }
}

/// Initializes client-side stream reassembly on `entry` (`reasm_client_start` in `desync.c:567-582`).
pub(crate) fn reasm_client_start(
    entry: &mut CtrackEntry,
    proto: u8,
    payload_kind: L7Payload,
    target_size: usize,
    max_size: usize,
    data: &[u8],
) -> bool
{
    entry.clear_reasm();
    if target_size > max_size
    {
        return false;
    }
    if proto == IPPROTO_TCP
        && entry.pos.server.pcounter > 0
        && usize::try_from(entry.pos.server.winsize_calc).unwrap_or(usize::MAX) < target_size
    {
        return false;
    }

    let seq_start = if proto == IPPROTO_TCP { entry.pos.client.seq_last } else { 0 };
    entry.reasm_client_payload = payload_kind;
    if !entry.try_start_reasm(target_size, seq_start)
    {
        entry.reasm_client_payload = L7Payload::Unknown;
        return false;
    }
    if !entry.reasm_client.feed(seq_start, data)
    {
        entry.clear_reasm();
        entry.reasm_client_payload = L7Payload::Unknown;
        return false;
    }
    true
}

/// Feeds `data` into an active client reassembler, flushing queued packets if reassembly fails.
pub(crate) fn reasm_client_feed(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    proto: u8,
    data: &[u8],
    desync_fwmark: u32,
    sender: &Rc<RefCell<dyn PacketSender>>,
) -> bool
{
    let Some(entry_rc) = ctrack
    else
    {
        return false;
    };

    let (ok, failed_queue) = {
        let mut entry = entry_rc.borrow_mut();
        if entry.reasm_client.is_empty()
        {
            return false;
        }
        let seq = if proto == IPPROTO_TCP
        {
            entry.pos.client.seq_last
        }
        else
        {
            u32::try_from(entry.reasm_client.size_present()).unwrap_or(u32::MAX)
        };
        if entry.reasm_client.feed(seq, data)
        {
            (true, None)
        }
        else
        {
            entry.clear_reasm();
            entry.reasm_client_payload = L7Payload::Unknown;
            let drained = entry.take_delayed();
            (false, (!drained.is_empty()).then_some(drained))
        }
    };

    if let Some(delayed) = failed_queue
    {
        send_delayed_queue(delayed, desync_fwmark, sender);
    }
    ok
}

/// Clears any active `reasm_client` session and flushes remaining delayed packets unmodified.
pub(crate) fn reasm_client_stop(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    desync_fwmark: u32,
    sender: &Rc<RefCell<dyn PacketSender>>,
)
{
    let Some(entry_rc) = ctrack
    else
    {
        return;
    };
    let leftover = {
        let mut entry = entry_rc.borrow_mut();
        if !entry.reasm_client.is_empty()
        {
            entry.clear_reasm();
            entry.reasm_client_payload = L7Payload::Unknown;
        }
        let drained = entry.take_delayed();
        (!drained.is_empty()).then_some(drained)
    };
    if let Some(delayed) = leftover
    {
        send_delayed_queue(delayed, desync_fwmark, sender);
    }
}

/// Appends one intercepted packet and its current [`CtrackEntry::pos`] snapshot to `entry.delayed`.
pub(crate) fn queue_delayed_packet(
    entry: &mut CtrackEntry,
    raw_pkt: &[u8],
    fwmark: u32,
    ifin: Option<&str>,
    ifout: Option<&str>,
) -> bool
{
    let pkt = DelayedPacket {
        raw: raw_pkt.to_vec(),
        fwmark,
        ifin: ifin.map(str::to_owned),
        ifout: ifout.map(str::to_owned),
        tpos: entry.pos,
    };
    entry.push_delayed(pkt)
}

/// Replays every queued delayed packet through `play_one` (`replay_queue` in `desync.c:2267-2312`).
///
/// Caller must drain `delayed` and drop all `CtrackEntry` borrows before calling so re-entrant
/// `double_search` and Lua callbacks run safely.
pub(crate) fn replay_delayed_queue<F>(
    delayed: VecDeque<DelayedPacket>,
    desync_fwmark: u32,
    sender: &Rc<RefCell<dyn PacketSender>>,
    mut play_one: F,
) where
    F: FnMut(usize, usize, usize, &DelayedPacket) -> Decision,
{
    let count = delayed.len();
    let mut offset = 0usize;
    let mut seq0 = 0u32;

    for (idx, pkt) in delayed.into_iter().enumerate()
    {
        let is_tcp_seq = pkt.tpos.ipproto == IPPROTO_TCP;
        if is_tcp_seq
        {
            if idx == 0
            {
                seq0 = pkt.tpos.client.seq_last;
                offset = 0;
            }
            else
            {
                offset = usize::try_from(pkt.tpos.client.seq_last.wrapping_sub(seq0)).unwrap_or(0);
            }
        }

        let dis = dissect_packet(&pkt.raw, false);
        let decision = play_one(idx, count, offset, &pkt);
        if let Some(dst) = extract_endpoint_ip(&dis, false)
        {
            let mut tx = sender.borrow_mut();
            match decision
            {
                Decision::Replace(mod_bytes) =>
                {
                    let _ = tx.send(dst, pkt.fwmark | desync_fwmark, pkt.ifout.as_deref(), &mod_bytes);
                }
                Decision::Pass =>
                {
                    let _ = tx.send(dst, pkt.fwmark | desync_fwmark, pkt.ifout.as_deref(), &pkt.raw);
                }
                Decision::Drop =>
                {}
            }
        }

        if !is_tcp_seq
        {
            let payload_len = dis.payload.as_ref().map_or(0, Vec::len);
            offset = offset.saturating_add(payload_len);
        }
    }
}

/// Copies active `reasm_client` bytes into an owned vector without holding a `RefCell` borrow.
pub(crate) fn clone_reasm_bytes(entry: Option<&Rc<RefCell<CtrackEntry>>>) -> Option<Vec<u8>>
{
    let rc = entry?;
    let guard = rc.borrow();
    (!guard.reasm_client.is_empty()).then(|| guard.reasm_client.data().to_vec())
}

/// Replays `delayed` through `engine` and flushes/clears `reasm_client` (`replay_queue` + `reasm_client_fin`).
pub(crate) fn replay_and_finish(
    engine: &DesyncEngine,
    packet_id: u32,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    delayed: VecDeque<DelayedPacket>,
)
{
    let replay_now = boottime_now();
    replay_delayed_queue(delayed, engine.desync_fwmark, &engine.sender, |idx, count, off, dpkt| {
        let rctx = ReplayContext {
            replay_piece: idx,
            replay_piece_count: count,
            reasm_offset: off,
            tpos: Some(&dpkt.tpos),
        };
        let qpkt = QueuedPacket {
            packet_id,
            mark: dpkt.fwmark,
            ifin: dpkt.ifin.as_deref(),
            ifout: dpkt.ifout.as_deref(),
            payload: &dpkt.raw,
        };
        engine.process_packet_play(&rctx, &qpkt, replay_now)
    });
    reasm_client_stop(ctrack, engine.desync_fwmark, &engine.sender);
}
