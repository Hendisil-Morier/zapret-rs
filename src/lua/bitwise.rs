//! 48-bit bitwise operators, big-endian integer unpack/pack, wrapping add, swap, and integer division Lua bindings.

/// Core `mlua` types for registering Lua functions and handling variadic arguments.
use mlua::{Lua, Value, Variadic};

/// Shared argument-count validators and numeric/byte extractors.
use crate::lua::helpers::{
    check_argc, check_argc_range, coerce_i64, require_i64_in_range, require_strict_bytes,
};

/// 48-bit unsigned mask matching LuaJIT's exact integer precision ceiling in `zapret2`.
const MASK_48: i64 = 0xFFFF_FFFF_FFFF;

/// Registers a unary `bitnot*` Lua function bound to a fixed bitmask width `max`.
fn register_bitnot(lua: &Lua, name: &'static str, max: i64) -> mlua::Result<()>
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc(name, &args, 1)?;
        let v = require_i64_in_range(lua, &args[0], max)?;
        Ok((!(v as u64) & (max as u64)) as i64)
    })?;
    lua.globals().set(name, f)
}

/// Registers an N-byte big-endian unsigned read helper (`u8`, `u16`, `u24`, `u32`, `u48`).
fn register_unpack_uint(lua: &Lua, name: &'static str, width: usize) -> mlua::Result<()>
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc_range(name, &args, 1, 2)?;
        let bytes = require_strict_bytes(&args[0])?.as_bytes();
        let offset = if args.len() >= 2 && !args[1].is_nil() { coerce_i64(lua, &args[1])? - 1 } else { 0 };
        if offset < 0 || (offset as usize).checked_add(width).is_none_or(|end| end > bytes.len())
        {
            return Err(mlua::Error::external("out of range"));
        }
        let start = offset as usize;
        let mut acc = 0u64;
        for &b in &bytes[start..start + width]
        {
            acc = (acc << 8) | u64::from(b);
        }
        Ok(acc as i64)
    })?;
    lua.globals().set(name, f)
}

/// Registers a wrapping unsigned addition helper (`u8add`..`u48add`) supporting 1..=100 signed args.
fn register_uxadd(lua: &Lua, name: &'static str, max: i64) -> mlua::Result<()>
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc_range(name, &args, 1, 100)?;
        let mut sum = 0u64;
        for arg in args.iter()
        {
            let v = require_i64_in_range(lua, arg, max)?;
            sum = sum.wrapping_add(v as u64);
        }
        Ok((sum & (max as u64)) as i64)
    })?;
    lua.globals().set(name, f)
}

/// Registers a big-endian byte-string packer (`bu8`..`bu48`).
fn register_pack_uint(lua: &Lua, name: &'static str, width: usize, max: i64) -> mlua::Result<()>
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc(name, &args, 1)?;
        let v = require_i64_in_range(lua, &args[0], max)?;
        let be = (v as u64).to_be_bytes();
        lua.create_string(&be[8 - width..])
    })?;
    lua.globals().set(name, f)
}

/// Registers bitwise shift, mask, and bitfield extract/insert Lua globals.
fn register_bitwise_ops(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "bitlshift",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("bitlshift", &args, 2)?;
            let v = require_i64_in_range(lua, &args[0], MASK_48)?;
            let shift = coerce_i64(lua, &args[1])?;
            if !(0..=48).contains(&shift)
            {
                return Err(mlua::Error::external("out of range"));
            }
            let u = (v as u64) & (MASK_48 as u64);
            let shifted = if shift == 48 { 0 } else { (u << (shift as u32)) & (MASK_48 as u64) };
            Ok(shifted as i64)
        })?,
    )?;

    globals.set(
        "bitrshift",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("bitrshift", &args, 2)?;
            let v = require_i64_in_range(lua, &args[0], MASK_48)?;
            let shift = coerce_i64(lua, &args[1])?;
            if !(0..=48).contains(&shift)
            {
                return Err(mlua::Error::external("out of range"));
            }
            let u = (v as u64) & (MASK_48 as u64);
            let shifted = if shift == 48 { 0 } else { u >> (shift as u32) };
            Ok(shifted as i64)
        })?,
    )?;

    globals.set(
        "bitand",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("bitand", &args, 2, 100)?;
            let mut sum = MASK_48 as u64;
            for arg in args.iter()
            {
                let v = require_i64_in_range(lua, arg, MASK_48)?;
                sum &= v as u64;
            }
            Ok(sum as i64)
        })?,
    )?;

    globals.set(
        "bitor",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("bitor", &args, 1, 100)?;
            let mut sum = 0u64;
            for arg in args.iter()
            {
                let v = require_i64_in_range(lua, arg, MASK_48)?;
                sum |= (v as u64) & (MASK_48 as u64);
            }
            Ok(sum as i64)
        })?,
    )?;

    globals.set(
        "bitxor",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("bitxor", &args, 1, 100)?;
            let mut sum = 0u64;
            for arg in args.iter()
            {
                let v = require_i64_in_range(lua, arg, MASK_48)?;
                sum ^= (v as u64) & (MASK_48 as u64);
            }
            Ok(sum as i64)
        })?,
    )?;

    register_bitfield_ops(lua, globals)
}

/// Registers `bitget` and `bitset` range extraction/replacement Lua globals.
fn register_bitfield_ops(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "bitget",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("bitget", &args, 3)?;
            let what = require_i64_in_range(lua, &args[0], MASK_48)? as u64;
            let from = coerce_i64(lua, &args[1])?;
            let to = coerce_i64(lua, &args[2])?;
            if from < 0 || to < 0 || from > to || from > 47 || to > 47
            {
                return Err(mlua::Error::external("bit range invalid"));
            }
            let width = (to - from + 1) as u32;
            let mask = (1u64 << width) - 1;
            Ok(((what >> (from as u32)) & mask) as i64)
        })?,
    )?;

    globals.set(
        "bitset",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("bitset", &args, 4)?;
            let what = require_i64_in_range(lua, &args[0], MASK_48)? as u64;
            let from = coerce_i64(lua, &args[1])?;
            let to = coerce_i64(lua, &args[2])?;
            let set = require_i64_in_range(lua, &args[3], MASK_48)? as u64;
            if from < 0 || to < 0 || from > to || from > 47 || to > 47
            {
                return Err(mlua::Error::external("bit range invalid"));
            }
            let width = (to - from + 1) as u32;
            let base_mask = (1u64 << width) - 1;
            let shifted_val = (set & base_mask) << (from as u32);
            let mask = base_mask << (from as u32);
            Ok(((what & !mask) | shifted_val) as i64)
        })?,
    )?;

    Ok(())
}

/// Registers byte-swap helpers and `divint` Lua globals.
fn register_swap_and_div(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "swap16",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("swap16", &args, 1)?;
            let v = require_i64_in_range(lua, &args[0], 0xFFFF)?;
            Ok(i64::from((v as u16).swap_bytes()))
        })?,
    )?;
    globals.set(
        "swap24",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("swap24", &args, 1)?;
            let u = require_i64_in_range(lua, &args[0], 0xFF_FFFF)? as u32;
            let swapped = ((u >> 16) & 0xFF) | (u & 0xFF00) | ((u & 0xFF) << 16);
            Ok(i64::from(swapped))
        })?,
    )?;
    globals.set(
        "swap32",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("swap32", &args, 1)?;
            let v = require_i64_in_range(lua, &args[0], 0xFFFF_FFFF)?;
            Ok(i64::from((v as u32).swap_bytes()))
        })?,
    )?;
    globals.set(
        "swap48",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("swap48", &args, 1)?;
            let u = require_i64_in_range(lua, &args[0], MASK_48)? as u64;
            Ok((u.swap_bytes() >> 16) as i64)
        })?,
    )?;

    globals.set(
        "divint",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("divint", &args, 2)?;
            let v1 = coerce_i64(lua, &args[0])?;
            let v2 = coerce_i64(lua, &args[1])?;
            if v2 == 0 { Ok(Value::Nil) } else { Ok(Value::Integer(v1.wrapping_div(v2))) }
        })?,
    )?;

    Ok(())
}

/// Registers all 48-bit bitwise, integer unpack/pack, byte-swap, and `divint` Lua globals.
pub fn register_bitwise_functions(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();
    register_bitwise_ops(lua, &globals)?;

    register_bitnot(lua, "bitnot", MASK_48)?;
    register_bitnot(lua, "bitnot8", 0xFF)?;
    register_bitnot(lua, "bitnot16", 0xFFFF)?;
    register_bitnot(lua, "bitnot24", 0xFF_FFFF)?;
    register_bitnot(lua, "bitnot32", 0xFFFF_FFFF)?;
    register_bitnot(lua, "bitnot48", MASK_48)?;

    register_unpack_uint(lua, "u8", 1)?;
    register_unpack_uint(lua, "u16", 2)?;
    register_unpack_uint(lua, "u24", 3)?;
    register_unpack_uint(lua, "u32", 4)?;
    register_unpack_uint(lua, "u48", 6)?;

    register_uxadd(lua, "u8add", 0xFF)?;
    register_uxadd(lua, "u16add", 0xFFFF)?;
    register_uxadd(lua, "u24add", 0xFF_FFFF)?;
    register_uxadd(lua, "u32add", 0xFFFF_FFFF)?;
    register_uxadd(lua, "u48add", MASK_48)?;

    register_pack_uint(lua, "bu8", 1, 0xFF)?;
    register_pack_uint(lua, "bu16", 2, 0xFFFF)?;
    register_pack_uint(lua, "bu24", 3, 0xFF_FFFF)?;
    register_pack_uint(lua, "bu32", 4, 0xFFFF_FFFF)?;
    register_pack_uint(lua, "bu48", 6, MASK_48)?;

    register_swap_and_div(lua, &globals)
}
