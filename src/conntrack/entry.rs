//! Per-flow connection tracking record (`CtrackEntry`) and TCP SYN option helpers.

/// Map and deque containers storing per-instance cutoffs and queued delayed packets.
use std::collections::{HashMap, VecDeque};

/// Embedded Lua registry handle preserving per-connection `lua_state` tables.
use mlua::{Lua, RegistryKey};

/// Discovered L7 protocol and reassembly payload classification tags stored on [`CtrackEntry`].
use crate::protocol::{L7Payload, L7Proto};
/// Continuous stream reassembly buffer and shared pool memory budget attached to flows.
use crate::conntrack::reasm::{GlobalBufferBudget, StreamReassembler};
/// Connection position snapshots, delayed packet storage, and queue bounds.
use crate::conntrack::types::{
    CtrackPositions, DelayedPacket, RAW_PACKET_QUEUE_DELAYED_MAX,
};
/// TCP option kind identifiers (`TCP_KIND_*`) and SYN/ACK flag masks.
use crate::packet::constants::{TCP_KIND_MSS, TCP_KIND_SCALE, TH_ACK, TH_SYN};
/// Parsed TCP option descriptor slice inspected on `SYN` and `SYN+ACK` packets.
use crate::packet::types::TcpOption;
/// Monotonic boottime timestamp recorded at flow creation and last packet arrival.
use crate::timer::MonotonicTime;

/// TCP flag mask isolating standard 6-bit control flags (`URG|ACK|PSH|RST|SYN|FIN`).
const TCP_CTRL_MASK: u8 = 0x3F;
/// RFC 7323 maximum legal TCP window scale shift value (`14`).
const TCP_MAX_WINDOW_SCALE: u8 = 14;

/// Returns `true` when TCP control flags match an initial `SYN` handshake segment (`darkmagic.c`).
pub const fn is_tcp_syn(flags: u8) -> bool {
    (flags & TCP_CTRL_MASK) == TH_SYN
}

/// Returns `true` when TCP control flags match a responder `SYN+ACK` segment (`darkmagic.c`).
pub const fn is_tcp_synack(flags: u8) -> bool {
    (flags & TCP_CTRL_MASK) == (TH_SYN | TH_ACK)
}

/// Extracts the RFC 7323 TCP window scale factor (`0..=14`) if option kind `3` is present.
pub(crate) fn extract_tcp_scale(opts: &[TcpOption]) -> Option<u8> {
    opts.iter().find_map(|opt| {
        if opt.kind == TCP_KIND_SCALE
            && let Some(data) = &opt.data
            && data.len() == 1
        {
            return Some(data[0].min(TCP_MAX_WINDOW_SCALE));
        }
        None
    })
}

/// Extracts the 16-bit TCP MSS option value if option kind `2` is present, otherwise `0`.
pub(crate) fn extract_tcp_mss(opts: &[TcpOption]) -> u16 {
    opts.iter()
        .find_map(|opt| {
            if opt.kind == TCP_KIND_MSS
                && let Some(data) = &opt.data
                && data.len() == 2
            {
                return Some(u16::from_be_bytes([data[0], data[1]]));
            }
            None
        })
        .unwrap_or(0)
}

/// Complete stateful tracking record for one active TCP or UDP connection (`t_ctrack` in `conntrack.h`).
pub struct CtrackEntry {
    /// Cached hostlist lookup completion flag (used in Milestone 3 list matching).
    pub check_done: bool,
    /// Cached positive hostlist match result.
    pub check_result: bool,
    /// Cached negative/exclude hostlist match result.
    pub check_excluded: bool,
    /// Monotonic boottime timestamp when this flow was created or re-initialized.
    pub t_start: MonotonicTime,
    /// Current state, timestamp, and bidirectional counters/sequences for client and server.
    pub pos: CtrackPositions,
    /// Matched 1-based `DesyncProfile` index cached on the flow.
    pub profile_index: Option<u32>,
    /// `true` once profile selection has run for the current flow/discovery state (`profile_index == None` cached miss).
    pub profile_searched: bool,
    /// Retransmission failure counter (`RETRANS_COUNTER_STOP` disables further increments).
    pub req_retrans_counter: u8,
    /// True once autohostlist failure detection has finalized for this connection.
    pub failure_detect_finalized: bool,
    /// First observed TTL / Hop Limit from incoming packets (`0` until observed).
    pub incoming_ttl: u8,
    /// Explicit purge flag marked by cutoff logic (`ConntrackPoolPurge` evicts when `true`).
    pub cutoff: bool,
    /// Global Lua cutoff flag suppressing incoming packet actions on this flow.
    pub lua_in_cutoff: bool,
    /// Global Lua cutoff flag suppressing outgoing packet actions on this flow.
    pub lua_out_cutoff: bool,
    /// Discovered L7 protocol tag persisted across packets of this connection.
    pub l7proto: L7Proto,
    /// True once [`Self::l7proto`] has been discovered to trigger profile rediscovery at most once.
    pub l7proto_discovered: bool,
    /// Discovered server hostname (from TLS SNI, QUIC Initial, HTTP `Host:`, or IPCache).
    pub hostname: Option<String>,
    /// True when [`Self::hostname`] is an IP address literal rather than a DNS name.
    pub hostname_is_ip: bool,
    /// True when autohostlist failure monitoring is active for this connection.
    pub hostname_ah_check: bool,
    /// Registry key holding the persistent per-connection `desync.track.lua_state` Lua table.
    pub lua_state: Option<RegistryKey>,
    /// Per-instance cutoff state keyed by `(func_instance, profile_n) -> (out_cutoff, in_cutoff)`.
    pub instance_cutoffs: HashMap<String, HashMap<u32, (bool, bool)>>,
    /// Client payload type currently buffered in [`Self::reasm_client`].
    pub reasm_client_payload: L7Payload,
    /// Client-side continuous stream reassembler for multi-segment handshakes.
    pub reasm_client: StreamReassembler,
    /// FIFO queue of delayed packets waiting for stream reassembly completion.
    pub delayed: VecDeque<DelayedPacket>,
    /// Shared pool-level byte budget governing aggregate reassembly and delayed memory.
    budget: GlobalBufferBudget,
    /// Bytes currently charged to [`Self::budget`] by `reasm_client`.
    reasm_reserved: usize,
    /// Bytes currently charged to [`Self::budget`] by `delayed`.
    delayed_reserved: usize,
}

impl CtrackEntry {
    /// Creates a fresh zeroed tracking entry, allocating an empty `lua_state` table if `lua` is present.
    pub fn new(lua: Option<&Lua>) -> mlua::Result<Self> {
        Self::with_budget(lua, GlobalBufferBudget::default())
    }

    /// Creates a fresh tracking entry bound to the owning pool's shared [`GlobalBufferBudget`].
    pub fn with_budget(lua: Option<&Lua>, budget: GlobalBufferBudget) -> mlua::Result<Self> {
        let lua_state = match lua {
            Some(l) => Some(l.create_registry_value(l.create_table()?)?),
            None => None,
        };
        Ok(Self {
            check_done: false,
            check_result: false,
            check_excluded: false,
            t_start: MonotonicTime::default(),
            pos: CtrackPositions::default(),
            profile_index: None,
            profile_searched: false,
            req_retrans_counter: 0,
            failure_detect_finalized: false,
            incoming_ttl: 0,
            cutoff: false,
            lua_in_cutoff: false,
            lua_out_cutoff: false,
            l7proto: L7Proto::Unknown,
            l7proto_discovered: false,
            hostname: None,
            hostname_is_ip: false,
            hostname_ah_check: false,
            lua_state,
            instance_cutoffs: HashMap::new(),
            reasm_client_payload: L7Payload::Unknown,
            reasm_client: StreamReassembler::default(),
            delayed: VecDeque::new(),
            budget,
            reasm_reserved: 0,
            delayed_reserved: 0,
        })
    }

    /// Re-initializes all state (used when a new `SYN` or mismatched `SYN-ACK` reuses a 5-tuple).
    pub fn reinit(&mut self, lua: Option<&Lua>) -> mlua::Result<()> {
        *self = Self::with_budget(lua, self.budget.clone())?;
        if let Some(l) = lua {
            l.expire_registry_values();
        }
        Ok(())
    }

    /// Clears any cached hostname metadata on this entry.
    pub fn clear_hostname(&mut self) {
        self.hostname = None;
        self.hostname_is_ip = false;
    }

    /// Returns `true` if `instance` on `profile_n` is cut off in the given direction (`incoming`).
    pub fn is_instance_cutoff(&self, instance: &str, profile_n: u32, incoming: bool) -> bool {
        self.instance_cutoffs
            .get(instance)
            .and_then(|by_prof| by_prof.get(&profile_n))
            .is_some_and(|&(out_cut, in_cut)| if incoming { in_cut } else { out_cut })
    }

    /// Records directional instance cutoff flags (`b_in` and/or `b_out`) for `(instance, profile_n)`.
    pub fn set_instance_cutoff(
        &mut self,
        instance: &str,
        profile_n: u32,
        b_in: bool,
        b_out: bool,
    ) {
        let entry = self
            .instance_cutoffs
            .entry(instance.to_owned())
            .or_default()
            .entry(profile_n)
            .or_insert((false, false));
        if b_out {
            entry.0 = true;
        }
        if b_in {
            entry.1 = true;
        }
    }

    /// Starts stream reassembly for `target_size` bytes if permitted by the shared pool byte budget.
    pub fn try_start_reasm(&mut self, target_size: usize, seq_start: u32) -> bool {
        self.clear_reasm();
        if !self.budget.try_reserve(target_size) {
            return false;
        }
        self.reasm_reserved = target_size;
        self.reasm_client.init(target_size, seq_start);
        true
    }

    /// Releases any buffered stream reassembly bytes back to [`Self::budget`] and resets the buffer.
    pub fn clear_reasm(&mut self) {
        if self.reasm_reserved > 0 {
            self.budget.release(self.reasm_reserved);
            self.reasm_reserved = 0;
        }
        self.reasm_client.clear();
    }

    /// Appends one delayed packet snapshot unless queue count or global byte budget is exhausted.
    pub fn push_delayed(&mut self, pkt: DelayedPacket) -> bool {
        if self.delayed.len() >= RAW_PACKET_QUEUE_DELAYED_MAX {
            return false;
        }
        let pkt_bytes = pkt.raw.len();
        if !self.budget.try_reserve(pkt_bytes) {
            return false;
        }
        self.delayed_reserved = self.delayed_reserved.saturating_add(pkt_bytes);
        self.delayed.push_back(pkt);
        true
    }

    /// Drains all delayed packets and releases their accounted byte reservation back to the budget.
    pub fn take_delayed(&mut self) -> VecDeque<DelayedPacket> {
        if self.delayed_reserved > 0 {
            self.budget.release(self.delayed_reserved);
            self.delayed_reserved = 0;
        }
        std::mem::take(&mut self.delayed)
    }
}

impl Drop for CtrackEntry {
    /// Releases all accounted reassembly and delayed queue bytes on flow removal or reinit.
    fn drop(&mut self) {
        self.clear_reasm();
        let _ = self.take_delayed();
    }
}
