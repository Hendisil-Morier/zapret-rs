//! Logging, OS metadata, clock, and kernel route/interface inspection Lua bindings.

/// C string parsing for `libc::uname` fields.
#[cfg(unix)]
use std::ffi::CStr;
/// IP address types for `get_source_ip` argument decoding.
#[cfg(target_os = "linux")]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Wall-clock time source for `clock_gettime` and `clock_getfloattime`.
use std::time::{SystemTime, UNIX_EPOCH};

/// Core `mlua` types for multi-return values, Lua tables, and variadic arguments.
use mlua::{Lua, MultiValue, Value, Variadic};

/// Shared Lua runtime configuration (`debug`).
use crate::lua::constants::LuaConfig;
/// Shared Lua argument validation helper.
use crate::lua::helpers::check_argc;
/// Strict byte extraction helper for `get_source_ip`.
#[cfg(target_os = "linux")]
use crate::lua::helpers::require_strict_bytes;
/// Wire IP byte-slice serialization helper for `get_ifaddrs` formatting.
#[cfg(target_os = "linux")]
use crate::lua::packet_encode::ip_to_wire_bytes;
/// Kernel topology queries (`get_ifaddrs`, `get_source_ip`).
#[cfg(target_os = "linux")]
use crate::rawsend::{get_ifaddrs, get_source_ip};

/// Converts a Lua log argument (`string` or `number`) to a Rust `String`, matching `luaL_checkstring`.
fn check_log_string(val: &Value) -> mlua::Result<String>
{
    match val
    {
        Value::String(s) => Ok(s.to_string_lossy()),
        Value::Integer(i) => Ok(i.to_string()),
        Value::Number(n) => Ok(n.to_string()),
        other => Err(mlua::Error::external(format!("string expected, got {}", other.type_name()))),
    }
}

/// Converts a fixed `c_char` buffer from `libc::utsname` into an owned UTF-8 lossy string.
#[cfg(unix)]
fn c_buf_to_string(buf: &[libc::c_char]) -> String
{
    // SAFETY: `libc::uname` NUL-terminates every string field inside its fixed-size array.
    let cstr = unsafe { CStr::from_ptr(buf.as_ptr()) };
    cstr.to_string_lossy()
        .into_owned()
}

/// Reads wall-clock `(seconds, nanoseconds)` since `UNIX_EPOCH` using `CLOCK_REALTIME` semantics.
fn realtime_secs_nanos() -> Option<(i64, i64)>
{
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()?;
    Some((dur.as_secs() as i64, i64::from(dur.subsec_nanos())))
}

/// Registers logging, OS, clock, and network inspection globals into `lua`.
pub fn register_system_functions(lua: &Lua, config: &LuaConfig) -> mlua::Result<()>
{
    let globals = lua.globals();
    let debug = config.debug;

    globals.set(
        "DLOG",
        lua.create_function(move |_, args: Variadic<Value>| {
            check_argc("DLOG", &args, 1)?;
            let msg = check_log_string(&args[0])?;
            if debug
            {
                eprintln!("LUA: {msg}");
            }
            Ok(())
        })?,
    )?;

    globals.set(
        "DLOG_ERR",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("DLOG_ERR", &args, 1)?;
            let msg = check_log_string(&args[0])?;
            eprintln!("LUA: {msg}");
            Ok(())
        })?,
    )?;

    globals.set(
        "DLOG_CONDUP",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("DLOG_CONDUP", &args, 1)?;
            let msg = check_log_string(&args[0])?;
            println!("LUA: {msg}");
            Ok(())
        })?,
    )?;

    globals.set(
        "getpid",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("getpid", &args, 0)?;
            Ok(i64::from(std::process::id()))
        })?,
    )?;

    globals.set("gettid", lua.create_function(lua_gettid)?)?;

    globals.set("uname", lua.create_function(lua_uname)?)?;

    globals.set(
        "clock_gettime",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("clock_gettime", &args, 0)?;
            match realtime_secs_nanos()
            {
                Some((sec, nsec)) =>
                {
                    Ok(MultiValue::from_vec(vec![Value::Integer(sec), Value::Integer(nsec)]))
                }
                None => Ok(MultiValue::from_vec(vec![Value::Nil, Value::Nil])),
            }
        })?,
    )?;

    globals.set(
        "clock_getfloattime",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("clock_getfloattime", &args, 0)?;
            match realtime_secs_nanos()
            {
                Some((sec, nsec)) => Ok(Value::Number(sec as f64 + (nsec as f64) / 1_000_000_000.0)),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set("get_source_ip", lua.create_function(lua_get_source_ip)?)?;

    globals.set("get_ifaddrs", lua.create_function(lua_get_ifaddrs)?)?;

    Ok(())
}

/// Resolves the kernel routing source IP for a wire-encoded target address on Linux.
#[cfg(target_os = "linux")]
fn lua_get_source_ip(lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("get_source_ip", &args, 1)?;
    let bytes = require_strict_bytes(&args[0])?.as_bytes();
    let target = if let Ok(octets) = <[u8; 4]>::try_from(bytes.as_ref())
    {
        IpAddr::V4(Ipv4Addr::from(octets))
    }
    else if let Ok(octets) = <[u8; 16]>::try_from(bytes.as_ref())
    {
        IpAddr::V6(Ipv6Addr::from(octets))
    }
    else
    {
        return Err(mlua::Error::external(format!("invalid IP length {}", bytes.len())));
    };
    match get_source_ip(target)
    {
        Some(src) => lua
            .create_string(ip_to_wire_bytes(src))
            .map(Value::String),
        None => Ok(Value::Nil),
    }
}

/// Non-Linux stub returning `nil` for `get_source_ip` until target routing lookup is implemented.
#[cfg(not(target_os = "linux"))]
fn lua_get_source_ip(_lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("get_source_ip", &args, 1)?;
    Ok(Value::Nil)
}

/// Enumerates kernel network interfaces and addresses into a Lua table on Linux.
#[cfg(target_os = "linux")]
fn lua_get_ifaddrs(lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("get_ifaddrs", &args, 0)?;
    let Ok(ifaces) = get_ifaddrs()
    else
    {
        return Ok(Value::Nil);
    };
    let tbl = lua.create_table_with_capacity(0, ifaces.len())?;
    for iface in ifaces
    {
        let info_tbl = lua.create_table_with_capacity(0, 4)?;
        if let Some(index) = iface.index
        {
            info_tbl.raw_set("index", index)?;
        }
        info_tbl.raw_set("flags", iface.flags)?;
        if let Some(mtu) = iface.mtu
        {
            info_tbl.raw_set("mtu", mtu)?;
        }
        let addr_arr = lua.create_table_with_capacity(
            iface
                .addrs
                .len(),
            0,
        )?;
        for (idx, item) in iface
            .addrs
            .iter()
            .enumerate()
        {
            let entry = lua.create_table_with_capacity(0, 3)?;
            entry.raw_set("addr", lua.create_string(ip_to_wire_bytes(item.addr))?)?;
            if let Some(mask) = item.netmask
            {
                entry.raw_set("netmask", lua.create_string(ip_to_wire_bytes(mask))?)?;
            }
            if let Some(bcast) = item.broadcast
            {
                entry.raw_set("broadcast", lua.create_string(ip_to_wire_bytes(bcast))?)?;
            }
            if let Some(dst) = item.dst
            {
                entry.raw_set("dst", lua.create_string(ip_to_wire_bytes(dst))?)?;
            }
            addr_arr.raw_set(idx + 1, entry)?;
        }
        info_tbl.raw_set("addr", addr_arr)?;
        tbl.raw_set(
            iface
                .name
                .as_str(),
            info_tbl,
        )?;
    }
    Ok(Value::Table(tbl))
}

/// Non-Linux stub returning `nil` for `get_ifaddrs` until target interface enumeration is implemented.
#[cfg(not(target_os = "linux"))]
fn lua_get_ifaddrs(_lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("get_ifaddrs", &args, 0)?;
    Ok(Value::Nil)
}

/// Returns the calling kernel thread ID on Linux via `SYS_gettid`.
#[cfg(target_os = "linux")]
fn lua_gettid(_lua: &Lua, args: Variadic<Value>) -> mlua::Result<i64>
{
    check_argc("gettid", &args, 0)?;
    // SAFETY: `SYS_gettid` takes no arguments and always returns the calling thread ID on Linux.
    let tid = unsafe { libc::syscall(libc::SYS_gettid) };
    Ok(tid as i64)
}

/// Non-Linux fallback for `gettid` returning `0`.
#[cfg(not(target_os = "linux"))]
fn lua_gettid(_lua: &Lua, args: Variadic<Value>) -> mlua::Result<i64>
{
    check_argc("gettid", &args, 0)?;
    Ok(0)
}

/// Returns `utsname` metadata via `libc::uname` on Unix targets.
#[cfg(unix)]
fn lua_uname(lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("uname", &args, 0)?;
    // SAFETY: `libc::utsname` is a plain C struct populated completely on `uname(...) == 0`.
    let mut uts: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: `uts` points to writable stack storage of type `libc::utsname`.
    if unsafe { libc::uname(&raw mut uts) } != 0
    {
        return Ok(Value::Nil);
    }
    let tbl = lua.create_table_with_capacity(0, 5)?;
    tbl.raw_set("sysname", c_buf_to_string(&uts.sysname))?;
    tbl.raw_set("nodename", c_buf_to_string(&uts.nodename))?;
    tbl.raw_set("release", c_buf_to_string(&uts.release))?;
    tbl.raw_set("version", c_buf_to_string(&uts.version))?;
    tbl.raw_set("machine", c_buf_to_string(&uts.machine))?;
    Ok(Value::Table(tbl))
}

/// Non-Unix fallback for `uname` using Rust compile-time target constants.
#[cfg(not(unix))]
fn lua_uname(lua: &Lua, args: Variadic<Value>) -> mlua::Result<Value>
{
    check_argc("uname", &args, 0)?;
    let tbl = lua.create_table_with_capacity(0, 5)?;
    tbl.raw_set("sysname", std::env::consts::OS)?;
    tbl.raw_set("nodename", "")?;
    tbl.raw_set("release", "")?;
    tbl.raw_set("version", "")?;
    tbl.raw_set("machine", std::env::consts::ARCH)?;
    Ok(Value::Table(tbl))
}
