//! Monotonic boottime clock reading used by timer scheduling, conntrack timestamps, and packets.

/// Standard duration representation for deadline math.
use std::time::Duration;
/// Portable monotonic epoch fallback used on non-Linux targets.
#[cfg(not(target_os = "linux"))]
use std::{sync::OnceLock, time::Instant};

/// Nanosecond-precision monotonic timestamp matching Linux `struct timespec`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MonotonicTime
{
    /// Whole seconds since monotonic clock epoch.
    pub sec: i64,
    /// Nanoseconds within the current second (`0..1_000_000_000`).
    pub nsec: i64,
}

impl MonotonicTime
{
    /// Converts this monotonic timestamp into floating-point seconds (`tv_sec + tv_nsec / 1e9`).
    pub fn as_secs_f64(self) -> f64
    {
        (self.sec as f64) + (self.nsec as f64) / 1_000_000_000.0
    }

    /// Computes elapsed seconds from `start` to `self` in floating-point seconds.
    pub fn elapsed_secs_f64(self, start: MonotonicTime) -> f64
    {
        ((self.sec - start.sec) as f64) + ((self.nsec - start.nsec) as f64) / 1_000_000_000.0
    }

    /// Converts this monotonic timestamp into whole milliseconds since the clock epoch.
    pub fn as_millis(self) -> u64
    {
        let secs = u64::try_from(self.sec).unwrap_or(0);
        let nsecs = u64::try_from(self.nsec).unwrap_or(0);
        secs.saturating_mul(1_000).saturating_add(nsecs / 1_000_000)
    }
}

/// Reads the system monotonic boottime `timespec`, falling back to `CLOCK_MONOTONIC` if needed.
///
/// Under Linux, `clock_gettime(CLOCK_BOOTTIME, ...)` continues advancing while suspended,
/// matching `zapret2`'s `CLOCK_BOOT_OR_UPTIME`.
#[cfg(target_os = "linux")]
pub fn boottime_now() -> MonotonicTime
{
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: `ts` is a valid stack-allocated libc::timespec struct.
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) } == 0
    {
        return MonotonicTime { sec: ts.tv_sec, nsec: ts.tv_nsec };
    }

    // Fallback to CLOCK_MONOTONIC if CLOCK_BOOTTIME is unsupported.
    // SAFETY: `ts` is a valid stack-allocated libc::timespec struct.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &raw mut ts) } == 0
    {
        MonotonicTime { sec: ts.tv_sec, nsec: ts.tv_nsec }
    }
    else
    {
        MonotonicTime::default()
    }
}

/// Reads elapsed monotonic time since first call using `std::time::Instant` on non-Linux targets.
#[cfg(not(target_os = "linux"))]
pub fn boottime_now() -> MonotonicTime
{
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    let elapsed = EPOCH.get_or_init(Instant::now).elapsed();
    MonotonicTime {
        sec: i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
        nsec: i64::from(elapsed.subsec_nanos()),
    }
}

/// Reads the current monotonic boottime in whole seconds (`boottime()` in `zapret2/nfq2/helpers.c`).
pub fn boottime_secs() -> i64
{
    boottime_now().sec
}

/// Reads the system monotonic boottime clock in milliseconds (`boottime_ms()` in `zapret2`).
pub fn boottime_ms() -> u64
{
    boottime_now().as_millis()
}

/// Converts a deadline in boottime milliseconds into an optional wait duration from `now_ms`.
///
/// Returns `Some(Duration::ZERO)` if `deadline_ms <= now_ms`, or `None` if `deadline_ms` is `0`.
pub fn duration_until(deadline_ms: Option<u64>, now_ms: u64) -> Option<Duration>
{
    let deadline = deadline_ms?;
    if deadline <= now_ms
    {
        Some(Duration::ZERO)
    }
    else
    {
        Some(Duration::from_millis(deadline.saturating_sub(now_ms)))
    }
}
