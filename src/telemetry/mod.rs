//! Shared telemetry counters and decoded packet record model for `nfqws2` and the TUI.

/// Lock-free packet outcome counters shared across packet loop, control server, and TUI.
pub mod counters;
/// L3/L4/L7 packet verdict classification and serializable snapshot record builder.
pub mod record;

/// Re-exported lock-free packet counters.
pub use counters::PacketCounters;
/// Re-exported packet outcome classification, decoded record, and builder function.
pub use record::{PacketRecord, PacketVerdict, build_packet_record};
