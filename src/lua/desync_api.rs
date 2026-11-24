//! Desync execution context userdata and `zapret2` C-API callback bindings.

/// Interior mutability for sharing [`DesyncContextState`] across `DesyncEngine` and Lua closures.
use std::cell::RefCell;
/// Single-thread reference counting for sharing context state without leaks.
use std::rc::Rc;

/// Core `mlua` types for Lua registry keys, userdata, values, and variadic arguments.
use mlua::{Lua, RegistryKey, UserData, Value, Variadic};

/// Configuration profile type and payload filter string formatter.
use crate::config::{DesyncProfile, l7_payload_str_list};
/// Lua table serializers for `execution_plan` entries, arguments, ranges, and payload masks.
use crate::lua::desync_encode::{
    build_action_args_table, desync_instance_name, packet_range_to_lua, payload_mask_to_lua_table,
};
/// Shared Lua argument-count check helpers.
use crate::lua::helpers::{check_argc, check_argc_range};

/// Mutable per-packet state backing Lua's singleton `ctx` userdata during profile execution.
#[derive(Debug, Default)]
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

/// Registers `raw_packet`, `execution_plan`, `execution_plan_cancel`, `instance_cutoff`, and `lua_cutoff`.
pub fn register_desync_functions(lua: &Lua, debug: bool) -> mlua::Result<()> {
    let globals = lua.globals();

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
            if let Some(profile) = profile_opt {
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
            if debug {
                let inst = ctx.borrow().instance.clone();
                eprintln!(
                    "instance cutoff requested for '{inst}' in={} out={} but not possible without conntrack",
                    u8::from(b_in),
                    u8::from(b_out)
                );
            }
            // shortcut: no conntrack table in Milestone 2; per-instance cutoff storage arrives in Milestone 3
            Ok(())
        })?,
    )?;

    globals.set(
        "lua_cutoff",
        lua.create_function(move |_, args: Variadic<Value>| {
            check_argc_range("lua_cutoff", &args, 1, 2)?;
            let ctx = extract_valid_ctx(&args[0])?;
            let (b_in, b_out) = parse_cutoff_direction(args.get(1))?;
            if debug {
                let inst = ctx.borrow().instance.clone();
                eprintln!(
                    "lua cutoff requested from '{inst}' in={} out={} but not possible without conntrack",
                    u8::from(b_in),
                    u8::from(b_out)
                );
            }
            // shortcut: no conntrack table in Milestone 2; connection cutoff flags arrive in Milestone 3
            Ok(())
        })?,
    )?;

    Ok(())
}
