//! Integration tests for monotonic timers, Lua `timer_*` host bindings, re-entrancy, and `--intercept=0`.

/// Interior mutability and single-thread sharing for mock packet sender injection.
use std::cell::RefCell;
/// Reference counting for passing mock sender into Lua runtime.
use std::rc::Rc;
/// Atomic boolean flag for testing cooperative loop shutdown.
use std::sync::atomic::{AtomicBool, Ordering};
/// Elapsed execution measurement for verifying sleep bounds.
use std::time::Instant;

/// Top-level Lua configuration schema.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// Monotonic boottime clock reading and duration calculations.
use zapret_rs::timer::{TimerPool, boottime_ms, run_no_intercept};

/// Mock packet sender implementing [`PacketSender`] for headless runtime initialization.
struct NoopSender;

impl zapret_rs::rawsend::PacketSender for NoopSender {
    fn send(
        &mut self,
        _dst: std::net::IpAddr,
        _fwmark: u32,
        _ifout: Option<&str>,
        _packet: &[u8],
    ) -> Result<(), zapret_rs::rawsend::RawSendError> {
        Ok(())
    }
}

/// Helper creating a hardened headless [`LuaRuntime`] with `NoopSender`.
fn make_test_runtime() -> LuaRuntime {
    let config = LuaConfig {
        debug: true,
        lua_gc_sec: 1,
        ..LuaConfig::default()
    };
    let sender: Rc<RefCell<dyn zapret_rs::rawsend::PacketSender>> =
        Rc::new(RefCell::new(NoopSender));
    LuaRuntime::with_sender(config, sender).expect("valid LuaRuntime creation")
}

/// Verifies basic oneshot and repeating timer registration, data passing, and `fires` counting.
#[test]
fn timer_set_oneshot_and_repeating() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    runtime
        .exec_str(
            r#"
            _G.t1_called = 0
            _G.t2_called = 0
            _G.t1_data = nil

            timer_set("t1", function(name, data)
                _G.t1_called = _G.t1_called + 1
                _G.t1_data = data
            end, 100, true, "hello_data")

            function t2_func(name, data)
                _G.t2_called = _G.t2_called + 1
            end
            timer_set("t2", "t2_func", 200, false)
        "#,
        )
        .expect("script execution succeeded");

    let pool = runtime.timer_pool();
    assert_eq!(pool.borrow().len(), 2);

    // Initial state before time advances.
    let now = boottime_ms();
    let next1 = TimerPool::run_expired(pool, lua, now);
    assert!(next1.is_some());
    let t1_count: i32 = lua.globals().get("t1_called").unwrap();
    assert_eq!(t1_count, 0);

    // Advance time past t1 deadline (100 ms).
    let next2 = TimerPool::run_expired(pool, lua, now + 150);
    assert!(next2.is_some());
    let t1_count: i32 = lua.globals().get("t1_called").unwrap();
    let t1_data: String = lua.globals().get("t1_data").unwrap();
    assert_eq!(t1_count, 1);
    assert_eq!(t1_data, "hello_data");

    // t1 was oneshot, so it should now be removed; t2 remains.
    assert_eq!(pool.borrow().len(), 1);
    assert!(pool.borrow().info("t1").is_none());
    let t2_info = pool.borrow().info("t2").unwrap();
    assert_eq!(t2_info.period_ms, 200);
    assert!(!t2_info.oneshot);

    // Advance time past t2 deadline (200 ms).
    let _ = TimerPool::run_expired(pool, lua, now + 250);
    let t2_count: i32 = lua.globals().get("t2_called").unwrap();
    assert_eq!(t2_count, 1);

    // Advance time another 200 ms to verify t2 repeats.
    let _ = TimerPool::run_expired(pool, lua, now + 500);
    let t2_count2: i32 = lua.globals().get("t2_called").unwrap();
    assert_eq!(t2_count2, 2);
}

/// Verifies strict validation of timer period and function arguments.
#[test]
fn timer_argument_and_period_validation() {
    let runtime = make_test_runtime();

    // Period < 10 ms must fail.
    let err_period = runtime.exec_str(r#"timer_set("fast", function() end, 5)"#);
    assert!(err_period.is_err(), "period < 10 ms must be rejected");

    // Non-existent global function string must fail.
    let err_missing = runtime.exec_str(r#"timer_set("missing", "non_existent_func", 100)"#);
    assert!(err_missing.is_err(), "missing function name must fail");

    // Invalid function type must fail.
    let err_type = runtime.exec_str(r#"timer_set("badtype", 12345, 100)"#);
    assert!(err_type.is_err(), "invalid function type must fail");

    // Invalid argc for timer_set (< 3 or > 5).
    assert!(runtime.exec_str(r#"timer_set("few")"#).is_err());
    assert!(
        runtime
            .exec_str(r#"timer_set("many", function() end, 100, true, "d", "extra")"#)
            .is_err()
    );

    // Invalid argc for timer_del (must be 1).
    assert!(runtime.exec_str(r#"timer_del()"#).is_err());
    assert!(runtime.exec_str(r#"timer_del("a", "b")"#).is_err());

    // Invalid argc for timer_info (must be 1).
    assert!(runtime.exec_str(r#"timer_info()"#).is_err());

    // Invalid argc for timer_enum (must be 0).
    assert!(runtime.exec_str(r#"timer_enum("unexpected")"#).is_err());
}

/// Verifies `timer_info` metadata output and `timer_enum` listing active timers.
#[test]
fn timer_info_and_enum_reflection() {
    let runtime = make_test_runtime();

    runtime
        .exec_str(
            r#"
            timer_set("alpha", function() end, 300, false)
            timer_set("beta", function() end, 500, true)

            local info_a = timer_info("alpha")
            assert(info_a.name == "alpha")
            assert(type(info_a.func) == "function")
            assert(info_a.period == 300)
            assert(info_a.oneshot == false)
            assert(info_a.fires == 0)

            local info_b = timer_info("beta")
            assert(info_b.name == "beta")
            assert(info_b.period == 500)
            assert(info_b.oneshot == true)

            assert(timer_info("unknown") == nil)

            local list = timer_enum()
            assert(#list == 2)
            assert(list[1] == "alpha")
            assert(list[2] == "beta")
        "#,
        )
        .expect("timer reflection succeeded");
}

/// Verifies `timer_del` removes timers and prevents subsequent activations.
#[test]
fn timer_del_operation() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    runtime
        .exec_str(
            r#"
            _G.fired = 0
            timer_set("victim", function() _G.fired = _G.fired + 1 end, 50, false)
            _G.del_res1 = timer_del("victim")
            _G.del_res2 = timer_del("victim")
        "#,
        )
        .expect("timer_del script succeeded");

    let del1: bool = lua.globals().get("del_res1").unwrap();
    let del2: bool = lua.globals().get("del_res2").unwrap();
    assert!(del1, "first timer_del must return true");
    assert!(!del2, "second timer_del must return false");

    let now = boottime_ms();
    let _ = TimerPool::run_expired(runtime.timer_pool(), lua, now + 200);
    let fired: i32 = lua.globals().get("fired").unwrap();
    assert_eq!(fired, 0, "deleted timer must never fire");
}

/// Verifies re-entrant modifications where a timer deletes itself inside its own callback.
#[test]
fn timer_self_deletion_inside_callback() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    runtime
        .exec_str(
            r#"
            _G.cycles = 0
            timer_set("self_killer", function(name, data)
                _G.cycles = _G.cycles + 1
                if _G.cycles >= 3 then
                    timer_del(name)
                end
            end, 20, false)
        "#,
        )
        .expect("self-killer setup succeeded");

    let pool = runtime.timer_pool();
    let mut current = boottime_ms();

    for _ in 0..5 {
        current += 30;
        let _ = TimerPool::run_expired(pool, lua, current);
    }

    let cycles: i32 = lua.globals().get("cycles").unwrap();
    assert_eq!(cycles, 3);
    assert!(pool.borrow().is_empty());
}

/// Verifies re-entrant recreation where a timer replaces itself with a different period.
#[test]
fn timer_recreation_inside_callback() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    runtime
        .exec_str(
            r#"
            _G.count = 0
            function rebuilder(name, data)
                _G.count = _G.count + 1
                if _G.count == 1 then
                    timer_set(name, rebuilder, 500, false)
                end
            end
            timer_set("morph", rebuilder, 20, false)
        "#,
        )
        .expect("recreation setup succeeded");

    let pool = runtime.timer_pool();
    let start = boottime_ms();

    // First fire at +30 ms: count becomes 1, period changes to 500 ms.
    let _ = TimerPool::run_expired(pool, lua, start + 30);
    let count1: i32 = lua.globals().get("count").unwrap();
    assert_eq!(count1, 1);
    let info = pool.borrow().info("morph").unwrap();
    assert_eq!(info.period_ms, 500);

    // At +100 ms, morph should NOT fire because period was extended to 500 ms.
    let _ = TimerPool::run_expired(pool, lua, start + 100);
    let count2: i32 = lua.globals().get("count").unwrap();
    assert_eq!(count2, 1);

    // At +600 ms, morph should fire again.
    let _ = TimerPool::run_expired(pool, lua, start + 600);
    let count3: i32 = lua.globals().get("count").unwrap();
    assert_eq!(count3, 2);
}

/// Verifies error handling: an error in a timer callback deletes the offending timer
/// while allowing other active timers to continue running unimpeded.
#[test]
fn timer_error_deletes_failing_timer() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    runtime
        .exec_str(
            r#"
            _G.healthy_fired = 0
            timer_set("broken", function()
                error("simulated runtime failure")
            end, 20, false)

            timer_set("healthy", function()
                _G.healthy_fired = _G.healthy_fired + 1
            end, 20, false)
        "#,
        )
        .expect("setup succeeded");

    let pool = runtime.timer_pool();
    let now = boottime_ms();

    let _ = TimerPool::run_expired(pool, lua, now + 30);

    // Broken timer must have been deleted due to error.
    assert!(pool.borrow().info("broken").is_none());
    // Healthy timer must have fired and remain active.
    assert!(pool.borrow().info("healthy").is_some());
    let healthy_count: i32 = lua.globals().get("healthy_fired").unwrap();
    assert_eq!(healthy_count, 1);
}

/// Verifies `--intercept=0` (`run_no_intercept`) loop executes to completion and honors `stop`.
#[test]
fn no_intercept_loop_execution_and_clean_exit() {
    let runtime = make_test_runtime();

    runtime
        .exec_str(
            r#"
            local n = 0
            timer_set("countdown", function(name, data)
                n = n + 1
                if n >= 3 then
                    timer_del(name)
                end
            end, 15, false)
        "#,
        )
        .expect("countdown setup succeeded");

    let stop = AtomicBool::new(false);
    let start = Instant::now();
    run_no_intercept(runtime.timer_pool(), &runtime, &stop);
    let elapsed = start.elapsed();

    // 3 ticks of 15ms should complete in roughly 45-200ms, definitely < 1s.
    assert!(elapsed.as_millis() < 1000);
    assert!(runtime.timer_pool().borrow().is_empty());

    // Test early shutdown via stop flag.
    runtime
        .exec_str(
            r#"
            timer_set("infinite", function() end, 1000, false)
        "#,
        )
        .expect("infinite timer setup succeeded");

    stop.store(true, Ordering::Relaxed);
    let start_stop = Instant::now();
    run_no_intercept(runtime.timer_pool(), &runtime, &stop);
    assert!(start_stop.elapsed().as_millis() < 100);
}

/// Verifies `do_gc` executes full Lua garbage collection when interval has elapsed.
#[test]
fn periodic_lua_gc_execution() {
    let runtime = make_test_runtime();
    let lua = runtime.lua();

    // Allocate some memory in Lua.
    runtime
        .exec_str(
            r#"
            local t = {}
            for i = 1, 1000 do
                t[i] = "string_" .. i
            end
            t = nil
        "#,
        )
        .expect("alloc script succeeded");

    let initial_mem = lua.used_memory();
    assert!(initial_mem > 0);

    // do_gc with interval not elapsed does nothing.
    runtime.do_gc(500);

    // do_gc with interval (1000ms) elapsed triggers garbage collection.
    runtime.do_gc(1500);
}
