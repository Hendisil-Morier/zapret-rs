//! Lua bindings for protocol position markers (`resolve_pos`, `resolve_multi_pos`, `resolve_range`) and `tls_mod`.

/// Core `mlua` Lua state, table, value, and variadic argument types.
use mlua::{Lua, Value, Variadic};

/// Shared Lua argument-count checks and strict string/byte/bool extractors.
use crate::lua::helpers::{check_argc_range, is_truthy, require_strict_bytes, require_strict_str};
/// L7 payload tag parser, split marker resolver, and TLS ClientHello mutator.
use crate::protocol::{
    FakeTlsMod, L7Payload, posmarker_list_parse, posmarker_parse, resolve_multi_pos, resolve_pos, tls_mod,
};

/// Maximum markers accepted by `resolve_multi_pos` (`sizeof(markers)/sizeof(*markers)` in `lua.c`).
const MAX_MULTI_POS_MARKERS: usize = 128;

/// Parses a `zapret2` L7 payload name or raises `bad payload type` matching `lua.c`.
fn parse_payload_type(name: &str) -> mlua::Result<L7Payload>
{
    L7Payload::from_name(name).ok_or_else(|| mlua::Error::external(format!("bad payload type : '{name}'")))
}

/// Converts a 0-based Rust payload index into Lua's 1-based or 0-based integer coordinate.
fn to_lua_pos(pos: usize, zero_based: bool) -> mlua::Result<i64>
{
    let adjusted = pos.saturating_add(usize::from(!zero_based));
    i64::try_from(adjusted).map_err(|_| mlua::Error::external("position overflow"))
}

/// Registers `resolve_pos`, `resolve_multi_pos`, `resolve_range`, and `tls_mod` into Lua `_G`.
pub fn register_protocol_functions(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();

    globals.set(
        "resolve_pos",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc_range("resolve_pos", &args, 3, 4)?;
            let data = require_strict_bytes(&args[0])?;
            let sl7payload = require_strict_str(&args[1])?;
            let smarker = require_strict_str(&args[2])?;
            let zero_based = args.get(3).is_some_and(is_truthy);

            let l7payload = parse_payload_type(&sl7payload)?;
            let marker = posmarker_parse(&smarker)
                .ok_or_else(|| mlua::Error::external(format!("bad marker : '{smarker}'")))?;

            match resolve_pos(&data.as_bytes(), l7payload, marker)
            {
                Some(pos) => Ok(Value::Integer(to_lua_pos(pos, zero_based)?)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set(
        "resolve_multi_pos",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("resolve_multi_pos", &args, 3, 4)?;
            let data = require_strict_bytes(&args[0])?;
            let sl7payload = require_strict_str(&args[1])?;
            let smarkers = require_strict_str(&args[2])?;
            let zero_based = args.get(3).is_some_and(is_truthy);

            let l7payload = parse_payload_type(&sl7payload)?;
            let markers = posmarker_list_parse(&smarkers, MAX_MULTI_POS_MARKERS)
                .ok_or_else(|| mlua::Error::external("bad marker list"))?;

            let positions = resolve_multi_pos(&data.as_bytes(), l7payload, &markers);
            let tbl = lua.create_table_with_capacity(positions.len(), 0)?;
            for (idx, pos) in positions.into_iter().enumerate()
            {
                tbl.raw_set(idx + 1, to_lua_pos(pos, zero_based)?)?;
            }
            Ok(Value::Table(tbl))
        })?,
    )?;

    globals.set(
        "resolve_range",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("resolve_range", &args, 3, 5)?;
            let data = require_strict_bytes(&args[0])?;
            let sl7payload = require_strict_str(&args[1])?;
            let smarkers = require_strict_str(&args[2])?;
            let strict = args.get(3).is_some_and(is_truthy);
            let zero_based = args.get(4).is_some_and(is_truthy);

            let l7payload = parse_payload_type(&sl7payload)?;
            let markers =
                posmarker_list_parse(&smarkers, 2).ok_or_else(|| mlua::Error::external("bad marker list"))?;
            if markers.len() != 2
            {
                return Err(mlua::Error::external("resolve_range require 2 markers"));
            }

            let bytes = data.as_bytes();
            let p0_opt = resolve_pos(&bytes, l7payload, markers[0]);
            let p1_opt = resolve_pos(&bytes, l7payload, markers[1]);
            if (p0_opt.is_none() && p1_opt.is_none()) || (strict && (p0_opt.is_none() || p1_opt.is_none()))
            {
                return Ok(Value::Nil);
            }

            let Some(last_idx) = bytes.len().checked_sub(1)
            else
            {
                return Ok(Value::Nil);
            };
            let p0 = p0_opt.unwrap_or(0);
            let p1 = p1_opt.unwrap_or(last_idx);
            if p0 > p1
            {
                return Ok(Value::Nil);
            }

            let tbl = lua.create_table_with_capacity(2, 0)?;
            tbl.raw_set(1, to_lua_pos(p0, zero_based)?)?;
            tbl.raw_set(2, to_lua_pos(p1, zero_based)?)?;
            Ok(Value::Table(tbl))
        })?,
    )?;

    globals.set(
        "tls_mod",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("tls_mod", &args, 2, 3)?;
            let fake_tls = require_strict_bytes(&args[0])?;
            let modlist = require_strict_str(&args[1])?;
            let payload = match args.get(2)
            {
                None | Some(Value::Nil) => None,
                Some(val) => Some(require_strict_bytes(val)?),
            };

            let spec = FakeTlsMod::parse_list(&modlist)
                .ok_or_else(|| mlua::Error::external(format!("invalid tls mod list : '{modlist}'")))?;
            let payload_borrowed = payload.as_ref().map(|s| s.as_bytes());
            let fake_bytes = fake_tls.as_bytes();

            match tls_mod(&spec, payload_borrowed.as_deref(), &fake_bytes)
            {
                Some(out) => Ok(Value::String(lua.create_string(&out)?)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    Ok(())
}
