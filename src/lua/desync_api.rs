//! Desync execution context userdata and `zapret2` Rust host execution callbacks.

/// Interior mutability for sharing [`DesyncContextState`] across `DesyncEngine` and Lua closures.
use std::cell::RefCell;
/// Single-thread reference counting for sharing context state without leaks.
use std::rc::Rc;

/// Core `mlua` types for Lua registry keys, userdata, values, and variadic arguments.
use mlua::{Lua, RegistryKey, UserData, Value, Variadic};

/// Configuration profile type and payload filter string formatter.
use crate::config::{DesyncProfile, l7_payload_str_list};
/// Bidirectional connection tracking pool and flow entry types.
use crate::conntrack::{ConntrackPool, CtrackEntry};
/// Runtime configuration flags read by Lua desync host helpers.
use crate::lua::constants::LuaConfig;
/// Conntrack-to-Lua table serializer used by `conntrack_feed`.
use crate::lua::ctrack_encode::ctrack_to_lua;
/// Lua table serializers for `execution_plan` entries, arguments, ranges, and payload masks.
use crate::lua::desync_encode::{
    build_action_args_table, desync_instance_name, packet_range_to_lua, payload_mask_to_lua_table,
};
/// Shared Lua argument-count check helpers.
use crate::lua::helpers::{check_argc, check_argc_range};
/// Lua table dissectors and reconstruct option parsers used by `conntrack_feed`.
use crate::lua::packet_decode::{lua_to_dissect, parse_reconstruct_opts};
/// Wire packet dissector and reconstructor invoked by `conntrack_feed`.
use crate::packet::{dissect_packet, reconstruct_packet};
/// Monotonic boottime `timespec` helper for conntrack feeding and expiration sweeps.
use crate::timer::boottime_now;

/// Mutable per-packet state backing Lua's singleton `ctx` userdata during profile execution.
#[derive(Default)]
pub struct DesyncContextState {
    /// True only while Lua is executing inside a direct `DesyncEngine` callback.
    pub valid: bool,
    /// Set by `execution_plan_cancel(ctx)` to abort remaining native action calls.
    pub cancel: bool,
    /// Packet direction flag (`true` for inbound packets, `false` for outbound).
    pub incoming: bool,
    /// Active 1-based profile index (`dp.index`).
    pub profile_n: u32,
    /// Active 1-based action index within `profile.actions`.
    pub func_n: u32,
    /// Name of the currently executing Lua desync function.
    pub func: String,
    /// Unique instance tag (`<func>_<profile_n>_<func_n>`).
    pub instance: String,
    /// Reused buffer holding the raw L3 wire bytes for `raw_packet(ctx)`.
    pub raw_packet: Vec<u8>,
    /// Active profile snapshot backing `execution_plan(ctx)`.
    pub profile: Option<Rc<DesyncProfile>>,
    /// Active connection tracking entry associated with this packet or created by `conntrack_feed`.
    pub ctrack: Option<Rc<RefCell<CtrackEntry>>>,
}

/// Lua userdata wrapper referencing the shared [`DesyncContextState`].
struct DesyncCtxUserData(
    /// Shared handle to the engine's reusable context state.
    Rc<RefCell<DesyncContextState>>,
);

impl UserData for DesyncCtxUserData {}

/// Creates the singleton `desync_ctx` userdata in Lua and pins it in the registry.
pub fn create_desync_ctx_userdata(
    lua: &Lua,
    state: Rc<RefCell<DesyncContextState>>,
) -> mlua::Result<RegistryKey> {
    let ud = lua.create_userdata(DesyncCtxUserData(state))?;
    lua.create_registry_value(ud)
}

/// Unwraps `val` as a currently valid [`DesyncContextState`] handle, rejecting nil or stale handles.
fn extract_valid_ctx(val: &Value) -> mlua::Result<Rc<RefCell<DesyncContextState>>> {
    if val.is_nil() {
        return Err(mlua::Error::external("missing ctx"));
    }
    let Value::UserData(ud) = val else {
        return Err(mlua::Error::external("desync_ctx expected"));
    };
    let state_rc = {
        let guard = ud.borrow::<DesyncCtxUserData>()?;
        Rc::clone(&guard.0)
    };
    if !state_rc.borrow().valid {
        return Err(mlua::Error::external("ctx is invalid"));
    }
    Ok(state_rc)
}

/// Parses optional cutoff direction argument (`true` => out, `false` => in, `nil` => both).
fn parse_cutoff_direction(opt: Option<&Value>) -> mlua::Result<(bool, bool)> {
    match opt {
        None | Some(Value::Nil) => Ok((true, true)),
        Some(Value::Boolean(b_out)) => Ok((!*b_out, *b_out)),
        Some(other) => Err(mlua::Error::external(format!(
            "boolean expected, got {}",
            other.type_name()
        ))),
    }
}

/// Registers `raw_packet`, `execution_plan`, `execution_plan_cancel`, `instance_cutoff`,
/// `lua_cutoff`, and `conntrack_feed` into Lua `_G`.
pub fn register_desync_functions(
    lua: &Lua,
    config: &LuaConfig,
    ctx_state: Rc<RefCell<DesyncContextState>>,
    conntrack: Rc<RefCell<ConntrackPool>>,
) -> mlua::Result<()> {
    let globals = lua.globals();
    let debug = config.debug;
    let ctrack_disable = config.ctrack_disable;
    let server = config.server;

    globals.set(
        "raw_packet",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("raw_packet", &args, 1)?;
            let ctx = extract_valid_ctx(&args[0])?;
            let raw_str = {
                let state = ctx.borrow();
                lua.create_string(&state.raw_packet)?
            };
            Ok(Value::String(raw_str))
        })?,
    )?;

    globals.set(
        "execution_plan_cancel",
        lua.create_function(move |_, args: Variadic<Value>| {
            check_argc("execution_plan_cancel", &args, 1)?;
            let ctx = extract_valid_ctx(&args[0])?;
            let inst = {
                let mut state = ctx.borrow_mut();
                state.cancel = true;
                if debug {
                    Some(state.instance.clone())
                } else {
                    None
                }
            };
            if let Some(name) = inst {
                eprintln!("execution plan cancel from '{name}'");
            }
            Ok(())
        })?,
    )?;

    globals.set(
        "execution_plan",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("execution_plan", &args, 1)?;
            let ctx = extract_valid_ctx(&args[0])?;
            let (profile_opt, current_func_n, incoming) = {
                let state = ctx.borrow();
                (state.profile.clone(), state.func_n, state.incoming)
            };

            let plan_tbl = lua.create_table()?;
            let Some(profile) = profile_opt else {
                return Ok(Value::Table(plan_tbl));
            };
            for (idx, action) in profile.actions.iter().enumerate() {
                let n = (idx as u32) + 1;
                if n <= current_func_n {
                    continue;
                }
                let instance = desync_instance_name(&action.func, profile.index, n);
                let range = if incoming {
                    action.in_range
                } else {
                    action.out_range
                };
                let entry = lua.create_table_with_capacity(0, 7)?;
                let arg_tbl = build_action_args_table(lua, &action.args, None, false)?
                    .ok_or_else(|| {
                        mlua::Error::external("unexpected blob substitution failure")
                    })?;
                entry.raw_set("arg", arg_tbl)?;
                entry.raw_set("func", action.func.as_str())?;
                entry.raw_set("func_n", i64::from(n))?;
                entry.raw_set("func_instance", instance.as_str())?;
                entry.raw_set("range", packet_range_to_lua(lua, range)?)?;
                entry.raw_set("payload", payload_mask_to_lua_table(lua, action.payload_mask)?)?;
                entry.raw_set("payload_filter", l7_payload_str_list(action.payload_mask))?;

                plan_tbl.raw_set(i64::from(n - current_func_n), entry)?;
            }

            Ok(Value::Table(plan_tbl))
        })?,
    )?;

    globals.set(
        "instance_cutoff",
        lua.create_function(move |_, args: Variadic<Value>| {
            check_argc_range("instance_cutoff", &args, 1, 2)?;
            if args[0].is_nil() {
                if debug {
                    eprintln!("instance cutoff not possible because missing ctx");
                }
                return Ok(());
            }
            let ctx = extract_valid_ctx(&args[0])?;
            let (b_in, b_out) = parse_cutoff_direction(args.get(1))?;
            let (ctrack_opt, inst, profile_n) = {
                let state = ctx.borrow();
                (state.ctrack.clone(), state.instance.clone(), state.profile_n)
            };
            if let Some(ctrack_rc) = ctrack_opt {
                ctrack_rc
                    .borrow_mut()
                    .set_instance_cutoff(&inst, profile_n, b_in, b_out);
                if debug {
                    eprintln!(
                        "instance cutoff from '{inst}' in={} out={}",
                        u8::from(b_in),
                        u8::from(b_out)
                    );
                }
            } else if debug {
                eprintln!(
                    "instance cutoff requested for '{inst}' in={} out={} without active conntrack",
                    u8::from(b_in),
                    u8::from(b_out)
                );
            }
            Ok(())
        })?,
    )?;

    globals.set(
        "lua_cutoff",
        lua.create_function(move |_, args: Variadic<Value>| {
            check_argc_range("lua_cutoff", &args, 1, 2)?;
            let ctx = extract_valid_ctx(&args[0])?;
            let (b_in, b_out) = parse_cutoff_direction(args.get(1))?;
            let (ctrack_opt, inst) = {
                let state = ctx.borrow();
                (state.ctrack.clone(), state.instance.clone())
            };
            if let Some(ctrack_rc) = ctrack_opt {
                let mut ct = ctrack_rc.borrow_mut();
                if b_in {
                    ct.lua_in_cutoff = true;
                }
                if b_out {
                    ct.lua_out_cutoff = true;
                }
                if debug {
                    eprintln!(
                        "lua cutoff from '{inst}' in={} out={}",
                        u8::from(b_in),
                        u8::from(b_out)
                    );
                }
            } else if debug {
                eprintln!(
                    "lua cutoff requested from '{inst}' in={} out={} without active conntrack",
                    u8::from(b_in),
                    u8::from(b_out)
                );
            }
            Ok(())
        })?,
    )?;

    globals.set(
        "conntrack_feed",
        lua.create_function(move |lua, args: Variadic<Value>| {
            check_argc_range("conntrack_feed", &args, 1, 2)?;
            if ctrack_disable {
                return Ok((Value::Nil, Value::Nil));
            }
            let raw = match &args[0] {
                Value::Table(dis_tbl) => {
                    let dis = lua_to_dissect(lua, dis_tbl)
                        .map_err(|_| mlua::Error::external("invalid dissect data"))?;
                    let opts = parse_reconstruct_opts(lua, args.get(1))?;
                    reconstruct_packet(&dis, &opts)
                        .map_err(|_| mlua::Error::external("invalid dissect data"))?
                }
                Value::String(s) => s.as_bytes().to_vec(),
                _ => return Err(mlua::Error::external("invalid packet data type")),
            };

            let dis = dissect_packet(&raw, false);
            let now = boottime_now();
            let hit = {
                let mut pool = conntrack.borrow_mut();
                pool.purge_rate_limited(now.sec);
                pool.feed(Some(lua), &dis, now)?
            };

            let Some((entry_rc, b_reverse)) = hit else {
                return Ok((Value::Nil, Value::Nil));
            };

            let track_tbl = {
                let entry = entry_rc.borrow();
                ctrack_to_lua(lua, &entry, None, b_reverse ^ server)?
            };
            {
                let mut state = ctx_state.borrow_mut();
                if state.ctrack.is_none() {
                    state.ctrack = Some(Rc::clone(&entry_rc));
                    state.incoming = b_reverse;
                }
            }

            Ok((Value::Table(track_tbl), Value::Boolean(!b_reverse)))
        })?,
    )?;

    Ok(())
}
