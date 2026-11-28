//! Cryptographic Lua bindings (`hash`, `aes`, `aes_gcm`, `aes_ctr`, `hkdf`) matching `zapret2/nfq2/lua.c`.

/// Embedded LuaJIT state, dynamic value, and variadic argument handles.
use mlua::{Lua, Value, Variadic};

/// Pure-Rust SHA-2, HKDF, AES-ECB, AES-CTR, and AES-GCM primitives.
use crate::crypto::{AesKey, HashAlg, aes_ctr_crypt, aes_gcm_crypt, hkdf_sha2, sha2_hash};
/// Shared argument count checks, truthiness, strict byte extractors, and Lua string/integer coercion helpers.
use crate::lua::helpers::{
    check_argc, check_argc_range, coerce_bytes, coerce_i64, coerce_str, is_truthy, require_strict_bytes,
};

/// Parses a `zapret2` hash identifier or raises `"unsupported hash type ..."`.
fn parse_lua_hash_type(name: &str) -> mlua::Result<HashAlg>
{
    HashAlg::from_name(name).map_err(mlua::Error::external)
}

/// Validates a 16-, 24-, or 32-byte AES key length with `zapret2`'s error format.
fn require_aes_key(func: &str, val: &Value) -> mlua::Result<Vec<u8>>
{
    let bytes = require_strict_bytes(val)?.as_bytes();
    let len = bytes.len();
    if !matches!(len, 16 | 24 | 32)
    {
        return Err(mlua::Error::external(format!("{func}: wrong key length {len}. should be 16,24,32.")));
    }
    Ok(bytes.to_vec())
}

/// Extracts a fixed-size 16-byte array from a slice, reporting `label` length mismatch errors.
fn to_block16(func: &str, label: &str, bytes: &[u8]) -> mlua::Result<[u8; 16]>
{
    <[u8; 16]>::try_from(bytes).map_err(|_| {
        mlua::Error::external(format!("{func}: wrong {label} length {}. should be 16.", bytes.len()))
    })
}

/// Extracts an optional Lua byte buffer where `nil` yields `None`.
fn optional_coerced_bytes(lua: &Lua, val: &Value) -> mlua::Result<Option<Vec<u8>>>
{
    if val.is_nil()
    {
        return Ok(None);
    }
    Ok(Some(coerce_bytes(lua, val)?))
}

/// Registers `hash`, `aes`, `aes_gcm`, `aes_ctr`, and `hkdf` on `_G` matching `zapret2/nfq2/lua.c`.
pub fn register_crypto_functions(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();

    globals.set(
        "hash",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("hash", &args, 2)?;
            let hash_type = coerce_str(lua, &args[0])?;
            let alg = parse_lua_hash_type(&hash_type)?;
            let data = require_strict_bytes(&args[1])?.as_bytes();
            let digest = sha2_hash(alg, &data);
            lua.create_string(&digest)
        })?,
    )?;

    globals.set(
        "aes",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("aes", &args, 3)?;
            let encrypt = is_truthy(&args[0]);
            let key = require_aes_key("aes", &args[1])?;
            let input = require_strict_bytes(&args[2])?.as_bytes();
            let block = to_block16("aes", "data", &input)?;
            let cipher = AesKey::new(&key).map_err(mlua::Error::external)?;
            let out = if encrypt { cipher.encrypt_block(&block) } else { cipher.decrypt_block(&block) };
            lua.create_string(out)
        })?,
    )?;

    globals.set(
        "aes_gcm",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("aes_gcm", &args, 4, 5)?;
            let encrypt = is_truthy(&args[0]);
            let key = require_aes_key("aes_gcm", &args[1])?;
            let iv = require_strict_bytes(&args[2])?.as_bytes();
            if iv.is_empty()
            {
                return Err(mlua::Error::external("aes_gcm: zero iv length"));
            }
            let input = require_strict_bytes(&args[3])?.as_bytes();
            let aad = match args.get(4)
            {
                Some(v) if !v.is_nil() => require_strict_bytes(v)?
                    .as_bytes()
                    .to_vec(),
                _ => Vec::new(),
            };
            let (out, tag) =
                aes_gcm_crypt(encrypt, &key, &iv, &input, &aad).map_err(mlua::Error::external)?;
            Ok((Value::String(lua.create_string(&out)?), Value::String(lua.create_string(tag)?)))
        })?,
    )?;

    globals.set(
        "aes_ctr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("aes_ctr", &args, 3)?;
            let key = require_aes_key("aes_ctr", &args[0])?;
            let iv = require_strict_bytes(&args[1])?.as_bytes();
            let iv_block = to_block16("aes_ctr", "iv", &iv)?;
            let input = coerce_bytes(lua, &args[2])?;
            let out = aes_ctr_crypt(&key, &iv_block, &input).map_err(mlua::Error::external)?;
            lua.create_string(&out)
        })?,
    )?;

    globals.set(
        "hkdf",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("hkdf", &args, 5)?;
            let hash_type = coerce_str(lua, &args[0])?;
            let alg = parse_lua_hash_type(&hash_type)?;
            let salt = optional_coerced_bytes(lua, &args[1])?;
            let ikm = optional_coerced_bytes(lua, &args[2])?;
            let info = optional_coerced_bytes(lua, &args[3])?;
            let okm_len = coerce_i64(lua, &args[4])?;
            if okm_len < 0
            {
                return Err(mlua::Error::external("hkdf: invalid arg"));
            }
            let Ok(okm_usize) = usize::try_from(okm_len)
            else
            {
                return Ok(Value::Nil);
            };
            match hkdf_sha2(
                alg,
                salt.as_deref(),
                ikm.as_deref()
                    .unwrap_or(&[]),
                info.as_deref()
                    .unwrap_or(&[]),
                okm_usize,
            )
            {
                Ok(okm) => Ok(Value::String(lua.create_string(&okm)?)),
                Err(_) => Ok(Value::Nil),
            }
        })?,
    )?;

    Ok(())
}
