//! Callback-driven standalone timer execution loop implementing `--intercept=0` semantics.

/// Atomic boolean flag for cooperative shutdown signaling across threads or signal handlers.
use std::sync::atomic::{AtomicBool, Ordering};
/// Time duration and sleep primitives for waiting between timer deadlines.
use std::time::Duration;

/// Monotonic boottime clock reading helper.
use crate::timer::clock::boottime_ms;

/// Maximum duration in milliseconds to sleep in a single slice before re-checking `stop`.
const MAX_SLEEP_SLICE_MS: u64 = 50;

/// Callback-driven non-intercepting timer loop allowing callers to re-borrow their engine between ticks.
pub fn run_no_intercept_callbacks(
    stop: &AtomicBool,
    mut on_tick: impl FnMut(),
    mut is_empty: impl FnMut() -> bool,
    mut next_deadline: impl FnMut() -> Option<u64>,
    mut step_expired: impl FnMut() -> Option<u64>,
) {
    on_tick();
    if is_empty() {
        return;
    }

    let mut deadline_ms = next_deadline();

    while !stop.load(Ordering::Relaxed) && !is_empty() {
        on_tick();
        let now = boottime_ms();

        if let Some(deadline) = deadline_ms
            && deadline > now
        {
            let mut remaining_ms = deadline.saturating_sub(now);
            while remaining_ms > 0 && !stop.load(Ordering::Relaxed) {
                let slice = remaining_ms.min(MAX_SLEEP_SLICE_MS);
                std::thread::sleep(Duration::from_millis(slice));
                on_tick();
                remaining_ms = remaining_ms.saturating_sub(slice);
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }

        deadline_ms = step_expired();
    }
}
