//! Bidirectional TCP/UDP connection tracking pool and continuous stream reassembly.

/// Per-flow tracking record and TCP handshake/option helper functions.
pub mod entry;
/// Connection tracking table, state machine, and timeout-based eviction sweeps.
pub mod pool;
/// Continuous in-order stream reassembler for multi-segment client payloads.
pub mod reasm;
/// Normalized 5-tuple keys, flow positions, delayed packet snapshots, and timeout defaults.
pub mod types;

/// Re-exported per-flow tracking entry and TCP SYN classification helpers.
pub use entry::{CtrackEntry, is_tcp_syn, is_tcp_synack};
/// Re-exported connection tracking pool.
pub use pool::ConntrackPool;
/// Re-exported linear stream reassembler.
pub use reasm::StreamReassembler;
/// Re-exported conntrack constants, keys, position structs, and timeout defaults.
pub use types::{
    ConnKey, ConnState, ConntrackTimeouts, CtrackPosition, CtrackPositions,
    DEFAULT_CTRACK_PURGE_INTERVAL, DEFAULT_CTRACK_TIMEOUT_EST, DEFAULT_CTRACK_TIMEOUT_FIN,
    DEFAULT_CTRACK_TIMEOUT_SYN, DEFAULT_CTRACK_TIMEOUT_UDP, DelayedPacket,
    RAW_PACKET_QUEUE_DELAYED_MAX, RETRANS_COUNTER_STOP, TCP_MAX_REASM, UDP_MAX_REASM,
};
