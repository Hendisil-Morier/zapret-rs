//! Integration tests verifying Lua `desync_ctx` bridge semantics, `rawsend_dissect`
//! re-entrancy, `zapret-lib.lua` orchestration, and graceful error fallback.

/// Shared synthetic packet builders and mock [`PacketSender`] fixtures.
mod common;

/// Interior mutability and single-thread sharing for recording mocked packets.
use std::cell::RefCell;
/// Standard IP address type for checking captured destination addresses.
use std::net::IpAddr;
/// Single-thread reference counting for passing mocked senders into [`DesyncEngine`].
use std::rc::Rc;

/// Configuration schema parser for TOML profiles and inline Lua scripts.
use zapret_rs::config::AppConfig;
/// Core desync engine orchestrating profile execution.
use zapret_rs::desync::DesyncEngine;
/// Intercepted packet view and kernel verdict decision enum.
use zapret_rs::intercepter::{Decision, QueuedPacket};
/// Lua error type for checking missing function validation at startup.
use zapret_rs::lua::LuaEngineError;
/// Packet dissector used to inspect injected fake packets.
use zapret_rs::packet::dissect_packet;
/// Raw packet sender trait object coerced from [`CapturingSender`].
use zapret_rs::rawsend::PacketSender;

/// Shared fixtures imported from `tests/common/mod.rs`.
use common::{CapturingSender, ZAPRET_LIB_LUA, build_ipv4_tcp};

/// Verifies `raw_packet(ctx)`, re-entrant `rawsend_dissect`, `VERDICT_DROP`, and post-call `ctx` invalidation.
#[test]
fn reentrant_rawsend_dissect_and_stashed_ctx_invalidation()
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let toml = r#"
        fwmark = 0x40000000
        lua_init = [
            { inline = """
                function send_fake_and_drop(ctx, desync)
                    local raw = raw_packet(ctx)
                    assert(raw == _G.expected_raw, "raw_packet(ctx) must return exact wire bytes")
                    desync.dis.ip.ip_ttl = 1
                    assert(rawsend_dissect(desync.dis, { fwmark = 0x10, ifout = desync.ifout }))
                    _G.leaked_ctx = ctx
                    return VERDICT_DROP
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["443"]
        actions = [{ func = "send_fake_and_drop" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let sender_trait: Rc<RefCell<dyn PacketSender>> = Rc::clone(&sender) as _;
    let engine = DesyncEngine::with_sender(&cfg, sender_trait).expect("engine with mock sender should init");

    let raw = build_ipv4_tcp(41234, 443, b"tls_hello");
    let lua_expected = engine.runtime().lua().create_string(&raw).expect("Lua byte string");
    engine.runtime().lua().globals().set("expected_raw", lua_expected).expect("set expected_raw");

    let pkt = QueuedPacket { packet_id: 30, mark: 0, ifin: None, ifout: Some("wlan0"), payload: &raw };
    assert_eq!(engine.process_packet(&pkt), Decision::Drop);

    let captured = &sender.borrow().packets;
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].dst, "93.184.216.34".parse::<IpAddr>().expect("valid IPv4 dst"));
    assert_eq!(captured[0].fwmark, 0x4000_0010);
    assert_eq!(captured[0].ifout.as_deref(), Some("wlan0"));
    let sent_dis = dissect_packet(&captured[0].data, false);
    assert_eq!(sent_dis.ip.as_ref().expect("ip").ttl, 1);

    // Calling raw_packet on the leaked ctx after return must error with "ctx is invalid".
    let leaked_err = engine
        .runtime()
        .exec_str("raw_packet(_G.leaked_ctx)")
        .expect_err("leaked ctx must be invalidated after action returns");
    assert!(leaked_err.to_string().contains("ctx is invalid"), "unexpected error: {leaked_err}");
}

/// Verifies `zapret2/lua/zapret-lib.lua`'s `desync_orchestrator_example` with `execution_plan` and cutoffs.
#[test]
fn zapret_lib_orchestrator_runs_execution_plan_once_and_allows_cutoffs()
{
    let toml = format!(
        r#"
        lua_init = [
            "{ZAPRET_LIB_LUA}",
            {{ inline = """
                function custom_step_1(ctx, desync)
                    _G.step1_calls = (_G.step1_calls or 0) + 1
                    assert(desync.arg.blob == fake_default_http)
                    instance_cutoff(ctx)
                    return VERDICT_PASS
                end
                function custom_step_2(ctx, desync)
                    _G.step2_calls = (_G.step2_calls or 0) + 1
                    desync.dis.payload = "ORCH_DONE"
                    return VERDICT_MODIFY
                end
                function test_cutoffs(ctx, desync)
                    instance_cutoff(ctx)
                    instance_cutoff(ctx, true)
                    lua_cutoff(ctx)
                    lua_cutoff(ctx, false)
                    local plan = execution_plan(ctx)
                    assert(#plan == 0)
                    return VERDICT_PASS
                end
            """ }}
        ]

        [[profiles]]
        name = "orch_profile"
        filter_tcp = ["80"]

        [[profiles.actions]]
        func = "desync_orchestrator_example"

        [[profiles.actions]]
        func = "custom_step_1"
        args = {{ blob = "%fake_default_http" }}

        [[profiles.actions]]
        func = "custom_step_2"

        [[profiles]]
        name = "cutoff_profile"
        filter_tcp = ["8080"]
        actions = [{{ func = "test_cutoffs" }}]
    "#
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("engine with zapret-lib.lua should initialize");

    // 1) Orchestrator cancels native calls to custom_step_1/2, replays each exactly once, and modifies packet.
    let raw_80 = build_ipv4_tcp(45000, 80, b"GET / HTTP/1.1\r\n\r\n");
    let pkt_80 = QueuedPacket { packet_id: 40, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_80 };
    let Decision::Replace(mod_80) = engine.process_packet(&pkt_80)
    else
    {
        panic!("expected Decision::Replace from orchestrated replay");
    };
    let dis_80 = dissect_packet(&mod_80, false);
    assert_eq!(dis_80.payload.as_deref(), Some(b"ORCH_DONE".as_slice()));

    engine
        .runtime()
        .exec_str(
            r#"
            assert(_G.step1_calls == 1, "custom_step_1 must execute once, not twice")
            assert(_G.step2_calls == 1, "custom_step_2 must execute once, not twice")
            "#,
        )
        .expect("call counts verified");

    // 2) Direct instance_cutoff / lua_cutoff calls work cleanly; lua_cutoff(nil) errors "missing ctx".
    let raw_8080 = build_ipv4_tcp(45001, 8080, b"hi");
    let pkt_8080 =
        QueuedPacket { packet_id: 41, mark: 0, ifin: None, ifout: Some("eth0"), payload: &raw_8080 };
    assert_eq!(engine.process_packet(&pkt_8080), Decision::Pass);

    let nil_err =
        engine.runtime().exec_str("lua_cutoff(nil)").expect_err("lua_cutoff(nil) must reject missing ctx");
    assert!(nil_err.to_string().contains("missing ctx"), "unexpected error: {nil_err}");
}

/// Verifies missing desync functions fail startup and runtime/verdict errors degrade to `Decision::Pass`.
#[test]
fn startup_missing_function_fails_and_runtime_errors_degrade_to_pass()
{
    let missing_cfg = AppConfig::from_toml_str(
        r#"
        [[profiles]]
        actions = [{ func = "does_not_exist" }]
        "#,
        None,
    )
    .expect("TOML parses cleanly");
    let Err(err) = DesyncEngine::new(&missing_cfg)
    else
    {
        panic!("expected MissingFunction error");
    };
    assert!(matches!(err, LuaEngineError::MissingFunction(ref name) if name == "does_not_exist"));

    let toml = r#"
        lua_init = [
            { inline = """
                function act_error(ctx, desync) error("boom") end
                function act_str(ctx, desync) return "bad" end
                function act_float(ctx, desync) return 1.5 end
                function act_range(ctx, desync) return 99 end
                function act_multi(ctx, desync) return VERDICT_PASS, VERDICT_DROP end
                function act_ok(ctx, desync) return VERDICT_PASS end
                function act_corrupt_dis(ctx, desync)
                    desync.dis = "not_a_table"
                    return VERDICT_MODIFY
                end
            """ }
        ]

        [[profiles]]
        filter_tcp = ["1001"]
        actions = [{ func = "act_error" }]

        [[profiles]]
        filter_tcp = ["1002"]
        actions = [{ func = "act_str" }]

        [[profiles]]
        filter_tcp = ["1003"]
        actions = [{ func = "act_float" }]

        [[profiles]]
        filter_tcp = ["1004"]
        actions = [{ func = "act_range" }]

        [[profiles]]
        filter_tcp = ["1005"]
        actions = [{ func = "act_multi" }]

        [[profiles]]
        filter_tcp = ["1006"]
        actions = [{ func = "act_ok", args = { bad = "%missing_blob" } }]

        [[profiles]]
        filter_tcp = ["1007"]
        actions = [{ func = "act_corrupt_dis" }]
    "#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("valid TOML");
    let engine = DesyncEngine::new(&cfg).expect("all functions defined");

    for port in 1001..=1007
    {
        let raw = build_ipv4_tcp(40000, port, b"payload");
        let pkt = QueuedPacket {
            packet_id: u32::from(port),
            mark: 0,
            ifin: None,
            ifout: Some("eth0"),
            payload: &raw,
        };
        assert_eq!(
            engine.process_packet(&pkt),
            Decision::Pass,
            "error case on port {port} must degrade safely to Decision::Pass"
        );
    }
}
