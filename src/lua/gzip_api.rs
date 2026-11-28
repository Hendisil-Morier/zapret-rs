//! LuaJIT streaming gzip/gunzip bindings matching `zapret2/nfq2/lua.c`.

/// Interior mutability for stateful gzip/gunzip `UserData` streams.
use std::cell::RefCell;

/// Embedded LuaJIT interpreter, userdata handle, and dynamic Lua value types.
use mlua::{Lua, UserData, UserDataRef, Value, Variadic};

/// Streaming deflate compression engine and window/level validation helpers.
use crate::lua::gzip_deflate::{DeflateMode, DeflateStream, parse_deflate_level};
/// Streaming inflate decompression engine and window mode parser.
use crate::lua::gzip_inflate::{InflateMode, InflateStream};
/// Shared argument count checks and byte/integer coercion helpers.
use crate::lua::helpers::{check_argc, check_argc_range, coerce_bytes, coerce_i64};

/// Default zlib `windowBits` (`47`) enabling automatic gzip/zlib detection on `gunzip_init`.
const DEFAULT_INFLATE_WINDOW_BITS: i64 = 47;
/// Default zlib `windowBits` (`31`) selecting gzip framing on `gzip_init`.
const DEFAULT_DEFLATE_WINDOW_BITS: i64 = 31;
/// Default compression level (`9`) matching `zapret2`'s `gzip_init`.
const DEFAULT_DEFLATE_LEVEL: i64 = 9;
/// Default zlib memory level (`8`) matching `zapret2`'s `gzip_init`.
const DEFAULT_DEFLATE_MEMLEVEL: i64 = 8;
/// Maximum preallocation capacity hint honored from Lua caller estimates (`1 MiB`).
const MAX_CAPACITY_HINT: usize = 1_048_576;

/// Active compression or decompression state held inside a Lua `zstream` userdata.
enum ZStreamKind
{
    /// Decompression stream created by `gunzip_init`.
    Inflate(InflateStream),
    /// Compression stream created by `gzip_init`.
    Deflate(DeflateStream),
}

/// Lua userdata representing an open or finalized `gunzip` / `gzip` stream.
struct ZStreamUserData
{
    /// Inner stream state (`None` after `gunzip_end` or `gzip_end`).
    state: RefCell<Option<ZStreamKind>>,
    /// Immutable role tag distinguishing `gunzip` (`true`) from `gzip` (`false`).
    is_inflate: bool,
}

impl UserData for ZStreamUserData {}

/// Extracts and validates a `ZStreamUserData` handle matching `zapret2`'s `lua_uzs`.
fn extract_zstream(val: &Value, expect_inflate: bool) -> mlua::Result<UserDataRef<ZStreamUserData>>
{
    let ud = match val
    {
        Value::UserData(ud) => ud
            .borrow::<ZStreamUserData>()
            .map_err(|_| mlua::Error::external("bad argument #1 (userdata_zstream expected)"))?,
        other =>
        {
            return Err(mlua::Error::external(format!(
                "bad argument #1 (userdata_zstream expected, got {})",
                other.type_name()
            )));
        }
    };
    if ud
        .state
        .borrow()
        .is_none()
    {
        return Err(mlua::Error::external("gzip stream is not valid"));
    }
    if ud.is_inflate != expect_inflate
    {
        return Err(mlua::Error::external("gzip stream role mismatch"));
    }
    Ok(ud)
}

/// Coerces an optional integer parameter when present and non-nil, falling back to `default`.
fn optional_i64_arg(lua: &Lua, args: &Variadic<Value>, idx: usize, default: i64) -> mlua::Result<i64>
{
    match args.get(idx)
    {
        Some(v) if !v.is_nil() => coerce_i64(lua, v),
        _ => Ok(default),
    }
}

/// Clamps caller's expected output buffer size hint into `[0, MAX_CAPACITY_HINT]`.
fn clamp_capacity_hint(lua: &Lua, args: &Variadic<Value>, idx: usize, default: usize) -> mlua::Result<usize>
{
    if let Some(arg) = args.get(idx)
    {
        let requested = coerce_i64(lua, arg)?;
        if requested <= 0
        {
            return Ok(0);
        }
        return Ok(usize::try_from(requested)
            .unwrap_or(MAX_CAPACITY_HINT)
            .min(MAX_CAPACITY_HINT));
    }
    Ok(default.min(MAX_CAPACITY_HINT))
}

/// Registers `gunzip_init`, `gunzip_end`, and `gunzip_inflate` in Lua `_G`.
fn register_gunzip_functions(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "gunzip_init",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("gunzip_init", &args, 0, 1)?;
            let wb = optional_i64_arg(lua, &args, 0, DEFAULT_INFLATE_WINDOW_BITS)?;
            let Some(mode) = InflateMode::from_window_bits(wb)
            else
            {
                return Ok(Value::Nil);
            };
            let ud = lua.create_userdata(ZStreamUserData {
                state: RefCell::new(Some(ZStreamKind::Inflate(InflateStream::new(mode)))),
                is_inflate: true,
            })?;
            Ok(Value::UserData(ud))
        })?,
    )?;

    globals.set(
        "gunzip_end",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("gunzip_end", &args, 1)?;
            let zs = extract_zstream(&args[0], true)?;
            *zs.state
                .borrow_mut() = None;
            Ok(())
        })?,
    )?;

    globals.set(
        "gunzip_inflate",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("gunzip_inflate", &args, 2, 3)?;
            let zs = extract_zstream(&args[0], true)?;
            let input = coerce_bytes(lua, &args[1])?;
            let hint = clamp_capacity_hint(
                lua,
                &args,
                2,
                input
                    .len()
                    .saturating_mul(4),
            )?;
            let mut state_ref = zs
                .state
                .borrow_mut();
            let Some(ZStreamKind::Inflate(stream)) = state_ref.as_mut()
            else
            {
                return Ok((Value::Nil, Value::Nil));
            };
            match stream.inflate(&input, hint)
            {
                Some((bytes, eof)) => Ok((Value::String(lua.create_string(&bytes)?), Value::Boolean(eof))),
                None => Ok((Value::Nil, Value::Nil)),
            }
        })?,
    )?;

    Ok(())
}

/// Registers `gzip_init`, `gzip_end`, and `gzip_deflate` in Lua `_G`.
fn register_gzip_deflate_functions(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "gzip_init",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("gzip_init", &args, 0, 3)?;
            let wb = optional_i64_arg(lua, &args, 0, DEFAULT_DEFLATE_WINDOW_BITS)?;
            let level = optional_i64_arg(lua, &args, 1, DEFAULT_DEFLATE_LEVEL)?;
            let memlevel = optional_i64_arg(lua, &args, 2, DEFAULT_DEFLATE_MEMLEVEL)?;
            let Some(mode) = DeflateMode::from_window_bits(wb)
            else
            {
                return Ok(Value::Nil);
            };
            let Some(compression) = parse_deflate_level(level, memlevel)
            else
            {
                return Ok(Value::Nil);
            };
            let ud = lua.create_userdata(ZStreamUserData {
                state: RefCell::new(Some(ZStreamKind::Deflate(DeflateStream::new(mode, compression)))),
                is_inflate: false,
            })?;
            Ok(Value::UserData(ud))
        })?,
    )?;

    globals.set(
        "gzip_end",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("gzip_end", &args, 1)?;
            let zs = extract_zstream(&args[0], false)?;
            *zs.state
                .borrow_mut() = None;
            Ok(())
        })?,
    )?;

    globals.set(
        "gzip_deflate",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("gzip_deflate", &args, 1, 3)?;
            let zs = extract_zstream(&args[0], false)?;
            let input = match args.get(1)
            {
                Some(v) if !v.is_nil() => coerce_bytes(lua, v)?,
                _ => Vec::new(),
            };
            let hint = clamp_capacity_hint(lua, &args, 2, input.len() / 2)?;
            let mut state_ref = zs
                .state
                .borrow_mut();
            let Some(ZStreamKind::Deflate(stream)) = state_ref.as_mut()
            else
            {
                return Ok((Value::Nil, Value::Nil));
            };
            match stream.deflate(&input, hint)
            {
                Some((bytes, eof)) => Ok((Value::String(lua.create_string(&bytes)?), Value::Boolean(eof))),
                None => Ok((Value::Nil, Value::Nil)),
            }
        })?,
    )?;

    Ok(())
}

/// Registers `gunzip_init`, `gunzip_end`, `gunzip_inflate`, `gzip_init`, `gzip_end`, and `gzip_deflate`.
pub fn register_gzip_functions(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();
    register_gunzip_functions(lua, &globals)?;
    register_gzip_deflate_functions(lua, &globals)
}
