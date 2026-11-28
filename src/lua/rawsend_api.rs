//! Lua packet-injection bindings (`rawsend` and `rawsend_dissect`).

/// Shared interior-mutability smart pointers for injecting the active [`PacketSender`].
use std::cell::RefCell;
/// Single-thread reference counting for the shared [`PacketSender`].
use std::rc::Rc;

/// Core `mlua` types for Lua table/value parsing and variadic function arguments.
use mlua::{Lua, Value, Variadic};

/// Shared Lua runtime configuration providing the base `desync_fwmark`.
use crate::lua::constants::LuaConfig;
/// Shared Lua argument validation and value coercion helpers.
use crate::lua::helpers::{check_argc_range, optional_i64, require_strict_bytes};
/// Lua dissect table decoding and reconstruction option parsing helpers.
use crate::lua::packet_decode::{lua_to_dissect, parse_reconstruct_opts};
/// Destination extraction and packet reconstruction for `rawsend` and `rawsend_dissect`.
use crate::packet::{extract_dst, reconstruct_packet};
/// Abstract packet sender trait used for raw kernel socket injection.
use crate::rawsend::PacketSender;

/// Extracts `{ repeats, fwmark, ifout }` options for `rawsend` and `rawsend_dissect`.
fn parse_rawsend_opts(
    lua: &Lua,
    val: Option<&Value>,
    base_fwmark: u32,
) -> mlua::Result<(usize, u32, Option<String>)>
{
    let Some(val) = val
    else
    {
        return Ok((1, base_fwmark, None));
    };
    if val.is_nil()
    {
        return Ok((1, base_fwmark, None));
    }
    let Value::Table(tbl) = val
    else
    {
        return Err(mlua::Error::external("rawsend options must be a table"));
    };

    let rep_val = tbl.raw_get::<Value>("repeats")?;
    let rep_i64 = optional_i64(lua, &rep_val);
    if rep_i64 < 0
    {
        return Err(mlua::Error::external("rawsend: negative repeats"));
    }
    let repeats = if rep_i64 == 0 { 1 } else { rep_i64 as usize };

    let mark_val = tbl.raw_get::<Value>("fwmark")?;
    let fwmark = (optional_i64(lua, &mark_val) as u32) | base_fwmark;

    let ifout = match tbl.raw_get::<Value>("ifout")?
    {
        Value::String(s) => Some(s.to_string_lossy()),
        _ => None,
    };

    Ok((repeats, fwmark, ifout))
}

/// Registers `rawsend` and `rawsend_dissect` globals into `lua` using `sender`.
pub fn register_rawsend_functions(
    lua: &Lua,
    config: &LuaConfig,
    sender: Rc<RefCell<dyn PacketSender>>,
) -> mlua::Result<()>
{
    let globals = lua.globals();
    let desync_fwmark = config.desync_fwmark;

    let raw_sender = Rc::clone(&sender);
    globals.set(
        "rawsend",
        lua.create_function(move |lua, args: Variadic<Value>| {
            check_argc_range("rawsend", &args, 1, 2)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            let (repeats, fwmark, ifout) = parse_rawsend_opts(lua, args.get(1), desync_fwmark)?;
            let dst = extract_dst(&raw).map_err(|_| mlua::Error::external("bad ip4/ip6 header"))?;
            let ok = raw_sender
                .borrow_mut()
                .send_repeat(repeats, dst, fwmark, ifout.as_deref(), &raw)
                .is_ok();
            Ok(ok)
        })?,
    )?;

    globals.set(
        "rawsend_dissect",
        lua.create_function(move |lua, args: Variadic<Value>| {
            check_argc_range("rawsend_dissect", &args, 1, 3)?;
            let Value::Table(dis_tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("bad argument #1 to 'rawsend_dissect' (table expected)"));
            };
            let (repeats, fwmark, ifout) = parse_rawsend_opts(lua, args.get(1), desync_fwmark)?;
            let rec_opts = parse_reconstruct_opts(lua, args.get(2))?;
            let dis = lua_to_dissect(lua, dis_tbl)?;
            let packet = reconstruct_packet(&dis, &rec_opts)
                .map_err(|_| mlua::Error::external("invalid dissect data"))?;
            let dst = extract_dst(&packet).map_err(|_| mlua::Error::external("bad ip4/ip6 header"))?;
            let ok = sender
                .borrow_mut()
                .send_repeat(repeats, dst, fwmark, ifout.as_deref(), &packet)
                .is_ok();
            Ok(ok)
        })?,
    )?;

    Ok(())
}
