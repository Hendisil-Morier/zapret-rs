//! Standalone timer execution loop implementing `--intercept=0` (`NoInterceptLoop`) semantics.

/// Single-threaded interior mutability for accessing the shared timer pool.
use std::cell::RefCell;
/// Reference counting for passing the shared timer pool handle.
use std::rc::Rc;
/// Atomic boolean flag for cooperative shutdown signaling across threads or signal handlers.
use std::sync::atomic::{AtomicBool, Ordering};
/// Time duration and sleep primitives for waiting between timer deadlines.
use std::time::Duration;

/// Monotonic boottime clock reading helper.
use crate::timer::clock::boottime_ms;
/// Core scheduled timer pool.
use crate::timer::pool::TimerPool;
/// Forward reference to the LuaRuntime orchestrator.
use crate::lua::LuaRuntime;

/// Maximum duration in milliseconds to sleep in a single slice before re-checking `stop`.
const MAX_SLEEP_SLICE_MS: u64 = 50;

/// Executes active timers in a non-intercepting loop until all timers complete or `stop` is set.
///
/// This provides exact parity with `zapret2`'s `NoInterceptLoop(void)` in `nfqws.c`. When
/// `stop` becomes `true` or the timer pool becomes empty, the loop exits gracefully.
pub fn run_no_intercept(
    pool_rc: &Rc<RefCell<TimerPool>>,
    runtime: &LuaRuntime,
    stop: &AtomicBool,
) {
    if pool_rc.borrow().is_empty() {
        return;
    }

    let mut next_deadline = pool_rc.borrow_mut().next_deadline_ms();

    while !stop.load(Ordering::Relaxed) && !pool_rc.borrow().is_empty() {
        let now = boottime_ms();

        if let Some(deadline) = next_deadline
            && deadline > now
        {
            let mut remaining_ms = deadline.saturating_sub(now);
            while remaining_ms > 0 && !stop.load(Ordering::Relaxed) {
                let slice = remaining_ms.min(MAX_SLEEP_SLICE_MS);
                std::thread::sleep(Duration::from_millis(slice));
                remaining_ms = remaining_ms.saturating_sub(slice);
            }
        }

        if stop.load(Ordering::Relaxed) {
            break;
        }

        let current_now = boottime_ms();
        runtime.do_gc(current_now);
        next_deadline = TimerPool::run_expired(pool_rc, runtime.lua(), current_now);
    }
}
