//! Bidirectional TCP/UDP connection tracking table, state transitions, and timeout purging.

/// Single-threaded interior mutability for mutable per-flow state shared with `DesyncContextState`.
use std::cell::RefCell;
/// Hash map storing active connections keyed by client-to-server 5-tuple.
use std::collections::HashMap;
/// Single-thread reference counting for passing tracked flow handles across actions and Lua `ctx`.
use std::rc::Rc;

/// Embedded Lua state reference passed when initializing per-flow `lua_state` tables.
use mlua::Lua;

/// Per-flow tracking record and TCP handshake/option helper functions.
use crate::conntrack::entry::{
    CtrackEntry, extract_tcp_mss, extract_tcp_scale, is_tcp_syn, is_tcp_synack,
};
/// Shared global reassembly/delayed byte budget tracked across pool flows.
use crate::conntrack::reasm::{DEFAULT_GLOBAL_REASM_BUDGET_BYTES, GlobalBufferBudget};
/// Connection tuple key, handshake state, capacity cap, and configurable timeout thresholds.
use crate::conntrack::types::{
    ConnKey, ConnState, ConntrackTimeouts, DEFAULT_CTRACK_MAX_ENTRIES,
};
/// Protocol identifiers (`IPPROTO_TCP`/`UDP`) and FIN/RST control flag constants.
use crate::packet::constants::{IPPROTO_TCP, IPPROTO_UDP, TH_FIN, TH_RST};
/// Parsed packet and TCP header structs consumed on every tracked packet arrival.
use crate::packet::types::{DissectedPacket, TcpHeader};
/// Monotonic boottime `timespec` recorded on flow creation, packet update, and purge scans.
use crate::timer::MonotonicTime;

/// Highest signed positive 32-bit sequence delta bit (`2 GiB`) used for wraparound tracking.
const SEQ_MSB_MASK: u32 = 0x8000_0000;

/// Hash-indexed connection tracking pool with configurable state timeouts (`t_conntrack`).
pub struct ConntrackPool {
    /// Inactivity timeouts and minimum seconds between cleanup passes.
    timeouts: ConntrackTimeouts,
    /// Maximum tracked flows retained concurrently (`0` disables capacity clamping).
    max_entries: usize,
    /// Monotonic second timestamp of the previous eviction sweep (`t_last_purge`).
    last_purge_sec: i64,
    /// Shared memory budget bounding total reassembly and delayed packet bytes across flows.
    budget: GlobalBufferBudget,
    /// Active connections keyed by normalized client-to-server 5-tuple [`ConnKey`].
    entries: HashMap<ConnKey, Rc<RefCell<CtrackEntry>>>,
}

impl Default for ConntrackPool {
    /// Returns an empty conntrack pool with default timeouts and [`DEFAULT_CTRACK_MAX_ENTRIES`] cap.
    fn default() -> Self {
        Self::new(ConntrackTimeouts::default())
    }
}

impl ConntrackPool {
    /// Creates an empty conntrack pool governed by `timeouts` and [`DEFAULT_CTRACK_MAX_ENTRIES`].
    pub fn new(timeouts: ConntrackTimeouts) -> Self {
        Self {
            timeouts,
            max_entries: DEFAULT_CTRACK_MAX_ENTRIES,
            last_purge_sec: 0,
            budget: GlobalBufferBudget::new(DEFAULT_GLOBAL_REASM_BUDGET_BYTES),
            entries: HashMap::new(),
        }
    }

    /// Returns the total currently buffered bytes across active reassembly and delayed queues.
    pub fn queued_bytes(&self) -> usize {
        self.budget.used_bytes()
    }

    /// Returns the configured global byte cap across all concurrent flows (`0` = unbounded).
    pub fn max_buffer_bytes(&self) -> usize {
        self.budget.max_bytes()
    }

    /// Configures the global byte ceiling across active reassembly and delayed buffers.
    pub fn set_max_buffer_bytes(&mut self, max_bytes: usize) {
        self.budget.set_max_bytes(max_bytes);
    }

    /// Returns the configured maximum active flow capacity (`0` = unbounded).
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Configures the maximum concurrent tracked flow limit (`0` = unbounded).
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    /// Ensures room exists for a new flow, purging expired entries then evicting oldest idle flows.
    fn ensure_insert_capacity(&mut self, lua: Option<&Lua>, now_sec: i64) -> bool {
        if self.max_entries == 0 || self.entries.len() < self.max_entries {
            return true;
        }
        let before = self.entries.len();
        if self.last_purge_sec != now_sec {
            self.last_purge_sec = now_sec;
            self.purge_now(now_sec);
        }
        while self.entries.len() >= self.max_entries {
            let oldest = self
                .entries
                .iter()
                .filter_map(|(k, rc)| {
                    rc.try_borrow()
                        .ok()
                        .map(|e| (*k, (e.pos.t_last.sec, e.pos.t_last.nsec)))
                })
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k);
            let Some(evict_key) = oldest else {
                break;
            };
            self.entries.remove(&evict_key);
        }
        if self.entries.len() < before
            && let Some(l) = lua
        {
            l.expire_registry_values();
        }
        self.entries.len() < self.max_entries
    }

    /// Returns the number of currently tracked connections.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no connections are tracked.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all tracked connections immediately (releasing Lua registry keys cleanly before drop).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Clears cached unmatched-profile flags across live flows so updated lists (`SIGHUP`) re-evaluate.
    pub fn reset_unmatched_profiles(&mut self) {
        for entry_rc in self.entries.values() {
            let mut entry = entry_rc.borrow_mut();
            if entry.profile_index.is_none() {
                entry.profile_searched = false;
            }
        }
    }

    /// Returns the currently configured timeouts and purge cadence.
    pub const fn timeouts(&self) -> ConntrackTimeouts {
        self.timeouts
    }

    /// Updates timeout thresholds and purge cadence.
    pub const fn set_timeouts(&mut self, timeouts: ConntrackTimeouts) {
        self.timeouts = timeouts;
    }

    /// Looks up an existing flow in forward then reverse orientation without modifying state.
    pub fn double_search(&self, dis: &DissectedPacket) -> Option<(Rc<RefCell<CtrackEntry>>, bool)> {
        let key = ConnKey::extract(dis, false)?;
        if let Some(entry) = self.entries.get(&key) {
            return Some((Rc::clone(entry), false));
        }
        let rev = key.swapped();
        self.entries
            .get(&rev)
            .map(|entry| (Rc::clone(entry), true))
    }

    /// Drops the matching flow entry from either direction if present (`ConntrackPoolDrop`).
    pub fn drop_conn(&mut self, dis: &DissectedPacket) -> bool {
        let Some(key) = ConnKey::extract(dis, false) else {
            return false;
        };
        if self.entries.remove(&key).is_some() {
            return true;
        }
        self.entries.remove(&key.swapped()).is_some()
    }

    /// Scans all entries and removes any expired or `cutoff`-marked connections, returning count evicted.
    pub fn purge_now(&mut self, now_sec: i64) -> usize {
        let before = self.entries.len();
        let t = self.timeouts;
        self.entries.retain(|conn, entry_rc| {
            let Ok(entry) = entry_rc.try_borrow() else {
                return true;
            };
            if entry.cutoff {
                return false;
            }
            let idle = now_sec.saturating_sub(entry.pos.t_last.sec);
            let limit = match conn.l4proto {
                IPPROTO_TCP => match entry.pos.state {
                    ConnState::Syn => i64::from(t.syn),
                    ConnState::Established => i64::from(t.established),
                    ConnState::Fin => i64::from(t.fin),
                },
                IPPROTO_UDP => i64::from(t.udp),
                _ => return false,
            };
            idle < limit
        });
        before.saturating_sub(self.entries.len())
    }

    /// Purges expired entries at most once per [`ConntrackTimeouts::purge_interval`] seconds.
    pub fn purge_rate_limited(&mut self, now_sec: i64) -> usize {
        if now_sec.saturating_sub(self.last_purge_sec) < self.timeouts.purge_interval {
            return 0;
        }
        self.last_purge_sec = now_sec;
        self.purge_now(now_sec)
    }

    /// Feeds one packet into conntrack, creating new entries on TCP `SYN`, `SYN-ACK`, or UDP.
    ///
    /// Returns `Ok(None)` for non-TCP/UDP packets and mid-stream TCP packets lacking prior state.
    pub fn feed(
        &mut self,
        lua: Option<&Lua>,
        dis: &DissectedPacket,
        now: MonotonicTime,
    ) -> mlua::Result<Option<(Rc<RefCell<CtrackEntry>>, bool)>> {
        let Some(fwd_key) = ConnKey::extract(dis, false) else {
            return Ok(None);
        };

        let (entry_rc, b_reverse) = if let Some(hit) = self.entries.get(&fwd_key) {
            (Rc::clone(hit), false)
        } else {
            let rev_key = fwd_key.swapped();
            if let Some(hit) = self.entries.get(&rev_key) {
                (Rc::clone(hit), true)
            } else if let Some(tcp) = &dis.tcp {
                if (is_tcp_syn(tcp.flags) || is_tcp_synack(tcp.flags))
                    && self.ensure_insert_capacity(lua, now.sec)
                {
                    let is_synack = !is_tcp_syn(tcp.flags);
                    let key = if is_synack { rev_key } else { fwd_key };
                    let created =
                        Rc::new(RefCell::new(CtrackEntry::with_budget(lua, self.budget.clone())?));
                    self.entries.insert(key, Rc::clone(&created));
                    (created, is_synack)
                } else {
                    return Ok(None);
                }
            } else if dis.udp.is_some() && self.ensure_insert_capacity(lua, now.sec) {
                let created =
                    Rc::new(RefCell::new(CtrackEntry::with_budget(lua, self.budget.clone())?));
                self.entries.insert(fwd_key, Rc::clone(&created));
                (created, false)
            } else {
                return Ok(None);
            }
        };

        {
            let mut entry = entry_rc.borrow_mut();
            Self::feed_packet(&mut entry, lua, b_reverse, dis, now)?;
        }
        Ok(Some((entry_rc, b_reverse)))
    }

    /// Updates TCP state transitions, sequence tracking, and directional counters (`ConntrackFeedPacket`).
    fn feed_packet(
        entry: &mut CtrackEntry,
        lua: Option<&Lua>,
        b_reverse: bool,
        dis: &DissectedPacket,
        now: MonotonicTime,
    ) -> mlua::Result<()> {
        let payload_len = dis.payload.as_ref().map_or(0usize, Vec::len);
        let len_u16 = (payload_len.min(usize::from(u16::MAX))) as u16;

        if let Some(tcp) = &dis.tcp {
            if is_tcp_syn(tcp.flags) {
                if b_reverse {
                    // Reject unexpected reverse-direction SYN so it cannot reset an active flow.
                    return Ok(());
                }
                if entry.pos.state != ConnState::Syn {
                    entry.reinit(lua)?;
                }
                entry.pos.client.seq0 = tcp.seq;
            } else if is_tcp_synack(tcp.flags) {
                if !b_reverse {
                    return Ok(());
                }
                let derived_client_seq0 = tcp.ack.wrapping_sub(1);
                if entry.pos.state != ConnState::Syn
                    && entry.pos.client.seq0 != derived_client_seq0
                {
                    entry.reinit(lua)?;
                }
                if entry.pos.client.seq0 == 0 {
                    entry.pos.client.seq0 = derived_client_seq0;
                }
                entry.pos.server.seq0 = tcp.seq;
            } else if (tcp.flags & (TH_FIN | TH_RST)) != 0 {
                entry.pos.state = ConnState::Fin;
            } else if entry.pos.state == ConnState::Syn {
                entry.pos.state = ConnState::Established;
                if !b_reverse && entry.pos.server.seq0 == 0 {
                    entry.pos.server.seq0 = tcp.ack.wrapping_sub(1);
                }
            }
            Self::apply_tcp_pos(entry, b_reverse, dis, tcp, len_u16);
        }

        let direct = if b_reverse {
            &mut entry.pos.server
        } else {
            &mut entry.pos.client
        };
        direct.pcounter = direct.pcounter.saturating_add(1);
        if len_u16 > 0 {
            direct.pdcounter = direct.pdcounter.saturating_add(1);
            direct.pbcounter = direct.pbcounter.saturating_add(u64::from(len_u16));
        }

        entry.pos.ipproto = dis.l4proto;
        entry.pos.t_last = now;
        if entry.t_start.sec == 0 && entry.t_start.nsec == 0 {
            entry.t_start = now;
        }
        Ok(())
    }

    /// Updates TCP sequence numbers, window scaling, MSS, IPv6 flow label, and 2 GiB wrap latch.
    fn apply_tcp_pos(
        entry: &mut CtrackEntry,
        b_reverse: bool,
        dis: &DissectedPacket,
        tcp: &TcpHeader,
        len_u16: u16,
    ) {
        let state = entry.pos.state;
        let (direct, reverse) = if b_reverse {
            (&mut entry.pos.server, &mut entry.pos.client)
        } else {
            (&mut entry.pos.client, &mut entry.pos.server)
        };

        if let Some(ip6) = &dis.ip6 {
            direct.ip6flow = ip6.flow;
        }

        direct.winsize = tcp.window;
        direct.winsize_calc = u32::from(tcp.window);
        if state == ConnState::Syn {
            if let Some(scale) = extract_tcp_scale(&tcp.options) {
                direct.scale = scale;
            }
            direct.mss = extract_tcp_mss(&tcp.options);
        } else {
            direct.winsize_calc = direct.winsize_calc.wrapping_shl(u32::from(direct.scale));
        }

        direct.seq_last = tcp.seq;
        direct.pos = direct.seq_last.wrapping_add(u32::from(len_u16));
        reverse.seq_last = tcp.ack;
        reverse.pos = tcp.ack;

        if state == ConnState::Syn {
            direct.uppos_prev = direct.pos;
            direct.uppos = direct.pos;
        } else if len_u16 > 0 {
            direct.uppos_prev = direct.uppos;
            if (direct.pos.wrapping_sub(direct.uppos) & SEQ_MSB_MASK) == 0 {
                direct.uppos = direct.pos;
            }
        }

        if !direct.rseq_over_2g
            && (direct.seq_last.wrapping_sub(direct.seq0) & SEQ_MSB_MASK) != 0
        {
            direct.rseq_over_2g = true;
        }
        if !reverse.rseq_over_2g
            && (reverse.seq_last.wrapping_sub(reverse.seq0) & SEQ_MSB_MASK) != 0
        {
            reverse.rseq_over_2g = true;
        }
    }
}
