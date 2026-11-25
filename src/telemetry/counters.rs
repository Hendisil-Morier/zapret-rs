//! Lock-free packet outcome counters updated by the live `nfqws2` packet loop.

/// Atomic 64-bit counters and relaxed ordering for low-overhead hot-path increments.
use std::sync::atomic::{AtomicU64, Ordering};

/// Lock-free packet outcome counters shared across the packet loop, IPC hub, and TUI.
#[derive(Debug, Default)]
pub struct PacketCounters {
    /// Total packets dispatched to [`crate::desync::DesyncEngine::process_packet_traced`].
    pub total: AtomicU64,
    /// Packets returned with [`crate::desync::PacketOutcome::Pass`].
    pub passed: AtomicU64,
    /// Multi-segment TLS/QUIC packets held or re-sent untouched via raw socket (`Reasm`).
    pub reassembled: AtomicU64,
    /// Packets modified in-place by a matched profile (`Modify`).
    pub modified: AtomicU64,
    /// Packets replaced/split via raw socket by a matched profile (`Desync`).
    pub desynced: AtomicU64,
}

impl PacketCounters {
    /// Returns a consistent snapshot `(total, passed, reassembled, modified, desynced)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.total.load(Ordering::Relaxed),
            self.passed.load(Ordering::Relaxed),
            self.reassembled.load(Ordering::Relaxed),
            self.modified.load(Ordering::Relaxed),
            self.desynced.load(Ordering::Relaxed),
        )
    }

    /// Resets all packet counters back to zero.
    pub fn reset(&self) {
        self.total.store(0, Ordering::Relaxed);
        self.passed.store(0, Ordering::Relaxed);
        self.reassembled.store(0, Ordering::Relaxed);
        self.modified.store(0, Ordering::Relaxed);
        self.desynced.store(0, Ordering::Relaxed);
    }
}
