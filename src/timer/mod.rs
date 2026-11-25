//! Monotonic boottime clock, scheduled timer pool, and `--intercept=0` loop runner.

/// Monotonic boottime clock reading and deadline duration conversions.
pub mod clock;
/// Scheduled timer pool managing registration, re-entrant callbacks, and monotonic deadlines.
pub mod pool;
/// Standalone timer loop runner executing timers in the absence of NFQUEUE packet interception.
pub mod runner;

/// Re-exported monotonic boottime clock types and readers.
pub use clock::{MonotonicTime, boottime_ms, boottime_now, boottime_secs, duration_until};
/// Re-exported timer entry, info, and pool data structures.
pub use pool::{MIN_TIMER_PERIOD_MS, TimerEntry, TimerInfo, TimerPool};
/// Re-exported timer-only loop runners (`--intercept=0`).
pub use runner::{run_no_intercept, run_no_intercept_callbacks, run_no_intercept_with_tick};
