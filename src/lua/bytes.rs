//! Random byte-blob generation, bytewise logical string ops, and hex-decoding Lua bindings.

/// Core `mlua` types for registering Lua functions and handling variadic arguments.
use mlua::{Lua, Value, Variadic};
/// Random generators (`rand::rng()`, `SysRng`) and fill/range traits (`rand 0.10`).
use rand::{Rng, RngExt, TryRng, rngs::SysRng};

/// Shared argument-count validators and numeric/byte extractors.
use crate::lua::helpers::{check_argc, coerce_i64, require_strict_bytes};

/// Registers a bytewise binary string operator (`bxor`, `bor`, `band`).
fn register_byte_op<F>(lua: &Lua, name: &'static str, op: F) -> mlua::Result<()>
where
    F: Fn(u8, u8) -> u8 + 'static,
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc(name, &args, 2)?;
        let b1 = require_strict_bytes(&args[0])?.as_bytes();
        let b2 = require_strict_bytes(&args[1])?.as_bytes();
        if b1.len() != b2.len() {
            return Err(mlua::Error::external("string lengths must be the same"));
        }
        let out: Vec<u8> = b1.iter().zip(b2.iter()).map(|(&x, &y)| op(x, y)).collect();
        lua.create_string(&out)
    })?;
    lua.globals().set(name, f)
}

/// Decodes one ASCII hex digit into `0..=15`, or `None` if invalid.
fn decode_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Registers `brandom*`, `bcryptorandom`, `bxor`, `bor`, `band`, and `parse_hex` globals into `lua`.
pub fn register_bytes_functions(lua: &Lua) -> mlua::Result<()> {
    let globals = lua.globals();

    globals.set(
        "brandom",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("brandom", &args, 1)?;
            let len = coerce_i64(lua, &args[0])?;
            if len < 0 {
                return Err(mlua::Error::external("brandom: invalid arg"));
            }
            let mut buf = vec![0u8; len as usize];
            rand::rng().fill_bytes(&mut buf);
            lua.create_string(&buf)
        })?,
    )?;

    globals.set(
        "brandom_az",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("brandom_az", &args, 1)?;
            let len = coerce_i64(lua, &args[0])?;
            if len < 0 {
                return Err(mlua::Error::external("brandom_az: invalid arg"));
            }
            let mut rng = rand::rng();
            let buf: Vec<u8> = (0..len as usize)
                .map(|_| rng.random_range(b'a'..=b'z'))
                .collect();
            lua.create_string(&buf)
        })?,
    )?;

    globals.set(
        "brandom_az09",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("brandom_az09", &args, 1)?;
            let len = coerce_i64(lua, &args[0])?;
            if len < 0 {
                return Err(mlua::Error::external("brandom_az09: invalid arg"));
            }
            let mut rng = rand::rng();
            let buf: Vec<u8> = (0..len as usize)
                .map(|_| {
                    let r = rng.random_range(0u8..36);
                    if r < 10 { b'0' + r } else { b'a' + (r - 10) }
                })
                .collect();
            lua.create_string(&buf)
        })?,
    )?;

    globals.set(
        "bcryptorandom",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("bcryptorandom", &args, 1)?;
            let len = coerce_i64(lua, &args[0])?;
            if len < 0 {
                return Err(mlua::Error::external("bcryptorandom: invalid arg"));
            }
            let mut buf = vec![0u8; len as usize];
            SysRng
                .try_fill_bytes(&mut buf)
                .map_err(|_| mlua::Error::external("could not get entropy bytes"))?;
            lua.create_string(&buf)
        })?,
    )?;

    register_byte_op(lua, "bxor", |a, b| a ^ b)?;
    register_byte_op(lua, "bor", |a, b| a | b)?;
    register_byte_op(lua, "band", |a, b| a & b)?;

    globals.set(
        "parse_hex",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("parse_hex", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            if !raw.len().is_multiple_of(2) {
                return Ok(Value::Nil);
            }
            let mut out = Vec::with_capacity(raw.len() / 2);
            for &[b_hi, b_lo] in raw.as_chunks::<2>().0 {
                let Some(hi) = decode_hex_nibble(b_hi) else {
                    return Ok(Value::Nil);
                };
                let Some(lo) = decode_hex_nibble(b_lo) else {
                    return Ok(Value::Nil);
                };
                out.push((hi << 4) | lo);
            }
            lua.create_string(&out).map(Value::String)
        })?,
    )?;

    Ok(())
}
