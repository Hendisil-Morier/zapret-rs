//! Desync execution context userdata, `zapret2` C-API callbacks, and `desync` / `arg` table builders.

/// Interior mutability for sharing [`DesyncContextState`] across `DesyncEngine` and Lua closures.
use std::cell::RefCell;
/// Ordered map storing per-action string parameters (`desync.arg`).
use std::collections::BTreeMap;
/// Single-thread reference counting for sharing context state without leaks.
use std::rc::Rc;

/// Core `mlua` types for Lua registry keys, userdata, tables, and values.
use mlua::{Lua, RegistryKey, Table, UserData, Value, Variadic};

/// Configuration filters, L7 payload helpers, and profile definitions.
use crate::config::{
    DesyncProfile, L7Payload, L7Proto, PacketPos, PacketRange, l7_payload_names,
    l7_payload_str_list,
};
/// Shared Lua argument-count check helpers.
use crate::lua::helpers::{check_argc, check_argc_range};
/// Packet dissection to Lua table serializer.
use crate::lua::packet_encode::dissect_to_lua;
/// Parsed wire packet representation passed into `desync.dis`.
use crate::packet::DissectedPacket;

/// Formats a unique instance identifier matching `desync_instance` in `zapret2/nfq2/lua.c`.
pub fn desync_instance_name(func: &str, profile_n: u32, func_n: u32) -> String {
    format!("{func}_{profile_n}_{func_n}")
}

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

/// Serializes one [`PacketPos`] into `{ mode = <char>, pos = <u32> }`.
fn packet_pos_to_lua(lua: &Lua, pos: PacketPos) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 2)?;
    let mut mode_buf = [0u8; 4];
    let mode_str: &str = pos.mode.as_char().encode_utf8(&mut mode_buf);
    tbl.raw_set("mode", mode_str)?;
    tbl.raw_set("pos", i64::from(pos.pos))?;
    Ok(tbl)
}

/// Serializes a [`PacketRange`] into `{ upper_cutoff, from, to }` matching `lua_pushf_range`.
pub fn packet_range_to_lua(lua: &Lua, range: PacketRange) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 3)?;
    tbl.raw_set("upper_cutoff", range.upper_cutoff)?;
    tbl.raw_set("from", packet_pos_to_lua(lua, range.from)?)?;
    tbl.raw_set("to", packet_pos_to_lua(lua, range.to)?)?;
    Ok(tbl)
}

/// Builds `{ [payload_name] = true }` matching `luacall_execution_plan`'s `payload` field.
pub fn payload_mask_to_lua_table(lua: &Lua, mask: u64) -> mlua::Result<Table> {
    let names = l7_payload_names(mask);
    let tbl = lua.create_table_with_capacity(0, names.len())?;
    for name in names {
        tbl.raw_set(name, true)?;
    }
    Ok(tbl)
}

/// Resolves `name` from `desync_tbl` first, falling back to Lua `_G`, matching `lua_push_blob`.
fn lookup_blob_value(lua: &Lua, desync_tbl: Option<&Table>, name: &str) -> mlua::Result<Value> {
    if let Some(desync) = desync_tbl {
        let val = desync.get::<Value>(name)?;
        if !val.is_nil() {
            return Ok(val);
        }
    }
    lua.globals().get::<Value>(name)
}

/// Computes raw byte length of a Lua value for `#blob` substitution (`lua_rawlen` semantics).
fn blob_byte_len(val: &Value) -> usize {
    match val {
        Value::String(s) => s.as_bytes().len(),
        Value::Integer(i) => i.to_string().len(),
        Value::Number(n) => n.to_string().len(),
        Value::Table(t) => t.raw_len(),
        _ => 0,
    }
}

/// Builds a Lua `arg` table with optional `%blob` and `#blob` substitution (`lua_pushf_args`).
///
/// Returns `Ok(None)` when a referenced `%blob` or `#blob` variable is missing from both
/// `desync_tbl` and Lua `_G`.
pub fn build_action_args_table(
    lua: &Lua,
    args: &BTreeMap<String, String>,
    desync_tbl: Option<&Table>,
    subst_prefix: bool,
) -> mlua::Result<Option<Table>> {
    let tbl = lua.create_table_with_capacity(0, args.len())?;

    for (key, val) in args {
        if !subst_prefix {
            tbl.raw_set(key.as_str(), val.as_str())?;
            continue;
        }

        if val.starts_with("\\%") || val.starts_with("\\#") {
            tbl.raw_set(key.as_str(), &val[1..])?;
        } else if let Some(blob_name) = val.strip_prefix('%') {
            let blob_val = lookup_blob_value(lua, desync_tbl, blob_name)?;
            if blob_val.is_nil() {
                eprintln!("blob '{blob_name}' unavailable");
                return Ok(None);
            }
            match blob_val {
                Value::Integer(i) => tbl.raw_set(key.as_str(), i.to_string())?,
                Value::Number(n) => tbl.raw_set(key.as_str(), n.to_string())?,
                other => tbl.raw_set(key.as_str(), other)?,
            }
        } else if let Some(blob_name) = val.strip_prefix('#') {
            let blob_val = lookup_blob_value(lua, desync_tbl, blob_name)?;
            if blob_val.is_nil() {
                eprintln!("blob '{blob_name}' unavailable");
                return Ok(None);
            }
            let len = blob_byte_len(&blob_val);
            tbl.raw_set(key.as_str(), len.to_string())?;
        } else {
            tbl.raw_set(key.as_str(), val.as_str())?;
        }
    }

    Ok(Some(tbl))
}

/// Input packet and profile metadata used to construct Lua's `desync` argument table.
pub struct DesyncTableInput<'a> {
    /// Dissected wire packet serialized into `desync.dis`.
    pub dis: &'a DissectedPacket,
    /// Matched desync profile supplying `profile_n`, `profile_name`, and `cookie`.
    pub profile: &'a DesyncProfile,
    /// `true` for inbound packets (`outgoing = false`), `false` for outbound packets.
    pub incoming: bool,
    /// Incoming network interface name, if known.
    pub ifin: Option<&'a str>,
    /// Outgoing network interface name, if known.
    pub ifout: Option<&'a str>,
    /// Firewall mark attached to the packet (`desync.fwmark`).
    pub fwmark: u32,
    /// Remote peer IPv4 address for `desync.target.ip`, when L3 is IPv4.
    pub target_ip4: Option<[u8; 4]>,
    /// Remote peer IPv6 address for `desync.target.ip6`, when L3 is IPv6.
    pub target_ip6: Option<[u8; 16]>,
    /// Remote peer transport port for `desync.target.port` (`0` omits field).
    pub target_port: u16,
    /// Baseline L7 payload classification name (`desync.l7payload`).
    pub l7payload: L7Payload,
    /// L7 protocol classification name (`desync.l7proto`).
    pub l7proto: L7Proto,
}

/// Builds the base `desync` Lua table shared across all action invocations for one packet.
pub fn build_desync_table(lua: &Lua, input: &DesyncTableInput<'_>) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 14)?;
    tbl.raw_set("dis", dissect_to_lua(lua, input.dis)?)?;
    // shortcut: conntrack table arrives in Milestone 3
    tbl.raw_set("track", Value::Nil)?;
    tbl.raw_set("profile_n", i64::from(input.profile.index))?;
    if let Some(name) = &input.profile.name {
        tbl.raw_set("profile_name", name.as_str())?;
    }
    if let Some(cookie) = &input.profile.cookie {
        tbl.raw_set("cookie", cookie.as_str())?;
    }
    tbl.raw_set("outgoing", !input.incoming)?;
    if let Some(ifin) = input.ifin.filter(|s| !s.is_empty()) {
        tbl.raw_set("ifin", ifin)?;
    }
    if let Some(ifout) = input.ifout.filter(|s| !s.is_empty()) {
        tbl.raw_set("ifout", ifout)?;
    }
    tbl.raw_set("fwmark", i64::from(input.fwmark))?;

    let target = lua.create_table_with_capacity(0, 3)?;
    if input.target_port != 0 {
        target.raw_set("port", i64::from(input.target_port))?;
    }
    if let Some(ip4) = input.target_ip4 {
        target.raw_set("ip", lua.create_string(ip4)?)?;
    }
    if let Some(ip6) = input.target_ip6 {
        target.raw_set("ip6", lua.create_string(ip6)?)?;
    }
    tbl.raw_set("target", target)?;

    tbl.raw_set("replay", false)?;
    tbl.raw_set("l7payload", input.l7payload.as_str())?;
    tbl.raw_set("l7proto", input.l7proto.as_str())?;
    tbl.raw_set("reasm_offset", 0i64)?;
    if input.dis.tcp.is_some() {
        let default_mss = lua.globals().get::<Value>("DEFAULT_MSS")?;
        tbl.raw_set("tcp_mss", default_mss)?;
    }

    Ok(tbl)
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
