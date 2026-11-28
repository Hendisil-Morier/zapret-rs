//! Lua global registration for `dissect*`, `reconstruct*`, `csum_*_fix`, `ntop`, and `pton`.

/// Standard IPv4 and IPv6 string conversion types (`ntop`, `pton`).
use std::net::{Ipv4Addr, Ipv6Addr};

/// Core `mlua` Lua state, value, and variadic types.
use mlua::{Lua, Value, Variadic};

/// Shared argument-count and byte-string validators.
use crate::lua::helpers::{check_argc, check_argc_range, require_strict_bytes};
/// Lua table -> Rust header/dissect decoders.
use crate::lua::packet_decode::{
    lua_to_dissect, lua_to_icmp, lua_to_ipv4, lua_to_ipv6, lua_to_tcp, lua_to_udp, parse_reconstruct_opts,
};
/// Rust header/dissect -> Lua table encoders.
use crate::lua::packet_encode::{
    dissect_to_lua, icmp_to_lua, ipv4_to_lua, ipv6_to_lua, tcp_to_lua, udp_to_lua,
};
/// Shared packet result type and checksum fixup helpers.
use crate::packet::byte_reader::PEResult;
/// Header checksum fixup routines.
use crate::packet::checksum::{fix_icmp_checksum, fix_ipv4_checksum, fix_tcp_checksum, fix_udp_checksum};
/// Default trailing protocol constant for standalone `reconstruct_ip6hdr`.
use crate::packet::constants::IPPROTO_NONE;
/// Dissectors, standalone header parsers, and header bounds validators.
use crate::packet::{
    check_icmp_header, check_ipv4_header, check_ipv6_header, check_tcp_header, check_udp_header,
    dissect_icmp_header, dissect_ipv4_header, dissect_ipv6_header, dissect_packet, dissect_tcp_header,
    dissect_udp_header, reconstruct_icmp_header, reconstruct_ipv4_header, reconstruct_ipv6_header,
    reconstruct_packet, reconstruct_tcp_header, reconstruct_udp_header,
};

/// Shared Lua wrapper for `csum_tcp_fix`, `csum_udp_fix`, and `csum_icmp_fix`.
fn register_l4_csum_fix<V, F>(
    lua: &Lua,
    name: &'static str,
    l4_err: &'static str,
    validate_l4: V,
    fix_l4: F,
) -> mlua::Result<()>
where
    V: Fn(&[u8]) -> bool + 'static,
    F: Fn(&[u8], &mut [u8], &[u8]) -> PEResult<()> + 'static,
{
    let f = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc(name, &args, 3)?;
        let ip_bytes = require_strict_bytes(&args[0])?.as_bytes();
        if !check_ipv4_header(&ip_bytes) && !check_ipv6_header(&ip_bytes)
        {
            return Err(mlua::Error::external("invalid ip header"));
        }
        let l4_bytes = require_strict_bytes(&args[1])?.as_bytes();
        if !validate_l4(&l4_bytes)
        {
            return Err(mlua::Error::external(l4_err));
        }
        let pl_bytes = require_strict_bytes(&args[2])?.as_bytes();
        if pl_bytes.len() > 0xFFFF
        {
            return Err(mlua::Error::external("invalid payload length"));
        }
        let mut l4_mut = l4_bytes.to_vec();
        fix_l4(&ip_bytes, &mut l4_mut, &pl_bytes).map_err(mlua::Error::external)?;
        lua.create_string(&l4_mut)
    })?;
    lua.globals().set(name, f)
}

/// Registers packet and individual header dissection Lua globals (`dissect*`).
fn register_dissect_functions(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "dissect",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("dissect", &args, 1, 2)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            let no_payload_check =
                args.get(1).is_some_and(|v| !matches!(v, Value::Nil | Value::Boolean(false)));
            let dis = dissect_packet(&raw, no_payload_check);
            dissect_to_lua(lua, &dis)
        })?,
    )?;

    globals.set(
        "dissect_iphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("dissect_iphdr", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            match dissect_ipv4_header(&raw)
            {
                Some(ip) => ipv4_to_lua(lua, &ip).map(Value::Table),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set(
        "dissect_ip6hdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("dissect_ip6hdr", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            match dissect_ipv6_header(&raw)
            {
                Some(ip6) => ipv6_to_lua(lua, &ip6).map(Value::Table),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set(
        "dissect_tcphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("dissect_tcphdr", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            match dissect_tcp_header(&raw)
            {
                Some(tcp) => tcp_to_lua(lua, &tcp).map(Value::Table),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set(
        "dissect_udphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("dissect_udphdr", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            match dissect_udp_header(&raw)
            {
                Some(udp) => udp_to_lua(lua, &udp).map(Value::Table),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    globals.set(
        "dissect_icmphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("dissect_icmphdr", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            match dissect_icmp_header(&raw)
            {
                Some(icmp) => icmp_to_lua(lua, &icmp).map(Value::Table),
                None => Ok(Value::Nil),
            }
        })?,
    )?;

    Ok(())
}

/// Registers packet and individual header reconstruction Lua globals (`reconstruct_*`).
fn register_reconstruct_functions(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "reconstruct_dissect",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("reconstruct_dissect", &args, 1, 2)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid dissect data"));
            };
            let dis = lua_to_dissect(lua, tbl)?;
            let opts = parse_reconstruct_opts(lua, args.get(1))?;
            let bytes = reconstruct_packet(&dis, &opts).map_err(mlua::Error::external)?;
            lua.create_string(&bytes)
        })?,
    )?;

    globals.set(
        "reconstruct_iphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("reconstruct_iphdr", &args, 1)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid data for iphdr"));
            };
            let ip = lua_to_ipv4(lua, tbl)?;
            let bytes = reconstruct_ipv4_header(&ip).map_err(mlua::Error::external)?;
            lua.create_string(&bytes)
        })?,
    )?;

    globals.set(
        "reconstruct_ip6hdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc_range("reconstruct_ip6hdr", &args, 1, 2)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid data for ip6hdr"));
            };
            let ip6 = lua_to_ipv6(lua, tbl)?;
            let opts = parse_reconstruct_opts(lua, args.get(1))?;
            let last_proto = opts.ip6_last_proto.unwrap_or(IPPROTO_NONE);
            let bytes = reconstruct_ipv6_header(&ip6, last_proto, opts.ip6_preserve_next)
                .map_err(mlua::Error::external)?;
            lua.create_string(&bytes)
        })?,
    )?;

    globals.set(
        "reconstruct_tcphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("reconstruct_tcphdr", &args, 1)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid data for tcphdr"));
            };
            let tcp = lua_to_tcp(lua, tbl)?;
            let bytes = reconstruct_tcp_header(&tcp).map_err(mlua::Error::external)?;
            lua.create_string(&bytes)
        })?,
    )?;

    globals.set(
        "reconstruct_udphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("reconstruct_udphdr", &args, 1)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid data for udphdr"));
            };
            let udp = lua_to_udp(lua, tbl)?;
            let bytes = reconstruct_udp_header(&udp);
            lua.create_string(bytes)
        })?,
    )?;

    globals.set(
        "reconstruct_icmphdr",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("reconstruct_icmphdr", &args, 1)?;
            let Value::Table(tbl) = &args[0]
            else
            {
                return Err(mlua::Error::external("invalid data for icmphdr"));
            };
            let icmp = lua_to_icmp(lua, tbl)?;
            let bytes = reconstruct_icmp_header(&icmp);
            lua.create_string(bytes)
        })?,
    )?;

    Ok(())
}

/// Registers checksum fixup (`csum_*`) and IP formatting/parsing (`ntop`, `pton`) Lua globals.
fn register_checksum_and_ip_functions(lua: &Lua, globals: &mlua::Table) -> mlua::Result<()>
{
    globals.set(
        "csum_ip4_fix",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("csum_ip4_fix", &args, 1)?;
            let raw = require_strict_bytes(&args[0])?.as_bytes();
            if raw.len() > 60 || !check_ipv4_header(&raw)
            {
                return Err(mlua::Error::external("invalid ip header"));
            }
            let mut copy = raw.to_vec();
            fix_ipv4_checksum(&mut copy).map_err(mlua::Error::external)?;
            lua.create_string(&copy)
        })?,
    )?;

    register_l4_csum_fix(lua, "csum_tcp_fix", "invalid tcp header", check_tcp_header, fix_tcp_checksum)?;
    register_l4_csum_fix(lua, "csum_udp_fix", "invalid udp header", check_udp_header, fix_udp_checksum)?;
    register_l4_csum_fix(lua, "csum_icmp_fix", "invalid icmp header", check_icmp_header, fix_icmp_checksum)?;

    globals.set(
        "ntop",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("ntop", &args, 1)?;
            let bytes = require_strict_bytes(&args[0])?.as_bytes();
            if let Ok(octets) = <[u8; 4]>::try_from(bytes.as_ref())
            {
                lua.create_string(Ipv4Addr::from(octets).to_string()).map(Value::String)
            }
            else if let Ok(octets) = <[u8; 16]>::try_from(bytes.as_ref())
            {
                lua.create_string(Ipv6Addr::from(octets).to_string()).map(Value::String)
            }
            else
            {
                Ok(Value::Nil)
            }
        })?,
    )?;

    globals.set(
        "pton",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("pton", &args, 1)?;
            let bytes = require_strict_bytes(&args[0])?.as_bytes();
            let Ok(s) = std::str::from_utf8(&bytes)
            else
            {
                return Ok(Value::Nil);
            };
            if let Ok(v4) = s.parse::<Ipv4Addr>()
            {
                lua.create_string(v4.octets()).map(Value::String)
            }
            else if let Ok(v6) = s.parse::<Ipv6Addr>()
            {
                lua.create_string(v6.octets()).map(Value::String)
            }
            else
            {
                Ok(Value::Nil)
            }
        })?,
    )?;

    Ok(())
}

/// Registers all packet dissect, reconstruct, checksum, and IP formatting globals into `lua`.
pub fn register_packet_functions(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();
    register_dissect_functions(lua, &globals)?;
    register_reconstruct_functions(lua, &globals)?;
    register_checksum_and_ip_functions(lua, &globals)
}
