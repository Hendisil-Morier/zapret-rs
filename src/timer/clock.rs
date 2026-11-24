//! Monotonic boottime clock reading used by timer scheduling and packet timestamps.

/// Standard C foreign function interface bindings and time structures.
use std::time::Duration;

/// Reads the system monotonic boottime clock in milliseconds.
///
/// Under Linux, this invokes `clock_gettime(CLOCK_BOOTTIME, ...)`, which continues
/// ticking during kernel system suspend, matching `zapret2`'s `boottime_ms()`.
/// If `CLOCK_BOOTTIME` is unavailable or fails, it falls back to `CLOCK_MONOTONIC`.
pub fn boottime_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid stack-allocated libc::timespec struct.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
    if rc == 0 {
        return (ts.tv_sec as u64)
            .saturating_mul(1_000)
            .saturating_add((ts.tv_nsec as u64) / 1_000_000);
    }

    // Fallback to CLOCK_MONOTONIC if CLOCK_BOOTTIME is unsupported.
    // SAFETY: `ts` is a valid stack-allocated libc::timespec struct.
    let rc_mono = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) };
    if rc_mono == 0 {
        (ts.tv_sec as u64)
            .saturating_mul(1_000)
            .saturating_add((ts.tv_nsec as u64) / 1_000_000)
    } else {
        0
    }
}

/// Converts a deadline in boottime milliseconds into an optional wait duration from `now_ms`.
///
/// Returns `Some(Duration::ZERO)` if `deadline_ms <= now_ms`, or `None` if `deadline_ms` is `0`.
pub fn duration_until(deadline_ms: Option<u64>, now_ms: u64) -> Option<Duration> {
    let deadline = deadline_ms?;
    if deadline <= now_ms {
        Some(Duration::ZERO)
    } else {
        Some(Duration::from_millis(deadline.saturating_sub(now_ms)))
    }
}
