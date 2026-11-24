//! Shared argument-count checks and strict/coercing Lua value extractors matching `zapret2`'s `lua.c`.

/// Core `mlua` types for Lua state inspection, strings, and variadic arguments.
use mlua::{Lua, LuaString, Value, Variadic};

/// Verifies that a Lua function received exactly `expected` arguments (`lua_check_argc`).
pub fn check_argc(name: &str, args: &Variadic<Value>, expected: usize) -> mlua::Result<()> {
    if args.len() != expected {
        return Err(mlua::Error::external(format!(
            "{name} expect exactly {expected} arguments, got {}",
            args.len()
        )));
    }
    Ok(())
}

/// Verifies that a Lua function received between `min` and `max` arguments inclusive (`lua_check_argc_range`).
pub fn check_argc_range(
    name: &str,
    args: &Variadic<Value>,
    min: usize,
    max: usize,
) -> mlua::Result<()> {
    if args.len() < min || args.len() > max {
        return Err(mlua::Error::external(format!(
            "{name} expect from {min} to {max} arguments, got {}",
            args.len()
        )));
    }
    Ok(())
}

/// Converts a finite `f64` to `i64` by truncation toward zero, rejecting NaN, infinity, and `i64` overflow.
fn finite_f64_to_i64(n: f64) -> mlua::Result<i64> {
    // `i64::MIN as f64` is exact (-2^63); 2^63 is the exclusive upper bound for valid `i64` values.
    if !n.is_finite() || n < (i64::MIN as f64) || n >= 9223372036854775808.0 {
        return Err(mlua::Error::external("number out of range"));
    }
    Ok(n.trunc() as i64)
}

/// Coerces an integer, float, or numeric string into `i64`, mirroring `luaL_checkinteger`/`luaL_checklint`.
pub fn coerce_i64(lua: &Lua, val: &Value) -> mlua::Result<i64> {
    match val {
        Value::Integer(i) => Ok(*i),
        Value::Number(n) => finite_f64_to_i64(*n),
        Value::String(_) => {
            if let Some(i) = lua.coerce_integer(val.clone())? {
                Ok(i)
            } else if let Some(n) = lua.coerce_number(val.clone())? {
                finite_f64_to_i64(n)
            } else {
                Err(mlua::Error::external("number expected"))
            }
        }
        other => Err(mlua::Error::external(format!(
            "number expected, got {}",
            other.type_name()
        ))),
    }
}

/// Coerces `val` to `i64` and validates that it lies within `[-max, max]` (`out of range` on failure).
pub fn require_i64_in_range(lua: &Lua, val: &Value, max: i64) -> mlua::Result<i64> {
    let v = coerce_i64(lua, val)?;
    if v > max || v < -max {
        return Err(mlua::Error::external("out of range"));
    }
    Ok(v)
}

/// Extracts a raw Lua byte string without numeric coercion, matching `lua_reqlstring`.
pub fn require_strict_bytes(val: &Value) -> mlua::Result<&LuaString> {
    match val {
        Value::String(s) => Ok(s),
        other => Err(mlua::Error::external(format!(
            "string expected, got {}",
            other.type_name()
        ))),
    }
}

/// Extracts a strict UTF-8 Lua string without numeric coercion, matching `lua_reqstring`.
pub fn require_strict_str(val: &Value) -> mlua::Result<String> {
    let s = require_strict_bytes(val)?;
    s.to_str()
        .map(|borrowed| borrowed.to_owned())
        .map_err(|_| mlua::Error::external("invalid UTF-8 string"))
}

/// Extracts an integer strictly from `LUA_TNUMBER` (`Value::Integer` or `Value::Number`), rejecting strings.
pub fn require_number_i64(val: &Value) -> mlua::Result<i64> {
    match val {
        Value::Integer(i) => Ok(*i),
        Value::Number(n) => finite_f64_to_i64(*n),
        other => Err(mlua::Error::external(format!(
            "number expected, got {}",
            other.type_name()
        ))),
    }
}

/// Coerces optional/possibly-nil Lua fields into `i64`, returning `0` on `nil` or non-numeric values like `lua_tointeger`.
pub fn optional_i64(lua: &Lua, val: &Value) -> i64 {
    if val.is_nil() {
        return 0;
    }
    coerce_i64(lua, val).unwrap_or(0)
}

/// Evaluates Lua truthiness (`false` and `nil` are falsy; all other values including `0` and tables are truthy).
pub fn is_truthy(val: &Value) -> bool {
    !matches!(val, Value::Nil | Value::Boolean(false))
}

/// Evaluates `zapret2`'s option-flag semantics (`nil` => false, `boolean(b)` => b, any other non-nil value => true).
pub fn parse_flag_value(val: &Value) -> bool {
    match val {
        Value::Nil => false,
        Value::Boolean(b) => *b,
        _ => true,
    }
}
