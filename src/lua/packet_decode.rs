//! Lua table to Rust packet header / dissect struct deserializers (`lua_to_*`).

/// Core `mlua` Lua state, table, and value types.
use mlua::{Lua, Table, Value};

/// Shared Lua value extractors matching `zapret2`'s strict/coercing conventions.
use crate::lua::helpers::{
    coerce_i64, optional_i64, parse_flag_value, require_number_i64, require_strict_bytes,
};
/// Protocol constants used when decoding optional fields.
use crate::packet::constants::{
    IPPROTO_NONE, IPV6_DEFAULT_FLOW, MAX_IP4_OPTIONS_LEN, TCP_KIND_END, TCP_KIND_NOOP,
};
/// Reconstruction options struct populated from Lua reconstruct opts tables.
use crate::packet::reconstruct::ReconstructOptions;
/// Parsed L3/L4 header and packet structs constructed from Lua tables.
use crate::packet::types::{
    DissectedPacket, IcmpHeader, Ipv4Header, Ipv6ExtHeader, Ipv6Header, TcpHeader, TcpOption, UdpHeader,
};

/// Parses a Lua `ip` table into an [`Ipv4Header`], mirroring `lua_reconstruct_iphdr`.
pub fn lua_to_ipv4(lua: &Lua, tbl: &Table) -> mlua::Result<Ipv4Header>
{
    let tos = optional_i64(lua, &tbl.raw_get::<Value>("ip_tos")?) as u8;
    let total_len = optional_i64(lua, &tbl.raw_get::<Value>("ip_len")?) as u16;
    let id = optional_i64(lua, &tbl.raw_get::<Value>("ip_id")?) as u16;
    let frag_off = optional_i64(lua, &tbl.raw_get::<Value>("ip_off")?) as u16;
    let ttl = require_number_i64(&tbl.raw_get::<Value>("ip_ttl")?)? as u8;
    let protocol = require_number_i64(&tbl.raw_get::<Value>("ip_p")?)? as u8;

    let src_val = tbl.raw_get::<Value>("ip_src")?;
    let src_bytes = require_strict_bytes(&src_val)?.as_bytes();
    let src: [u8; 4] = src_bytes
        .as_ref()
        .try_into()
        .map_err(|_| mlua::Error::external("ip_src must be 4 bytes"))?;

    let dst_val = tbl.raw_get::<Value>("ip_dst")?;
    let dst_bytes = require_strict_bytes(&dst_val)?.as_bytes();
    let dst: [u8; 4] = dst_bytes
        .as_ref()
        .try_into()
        .map_err(|_| mlua::Error::external("ip_dst must be 4 bytes"))?;

    let options = match tbl.raw_get::<Value>("options")?
    {
        Value::String(s) =>
        {
            let b = s.as_bytes();
            if b.len() > MAX_IP4_OPTIONS_LEN
            {
                return Err(mlua::Error::external("IPv4 options exceed 40 bytes"));
            }
            b.to_vec()
        }
        _ => Vec::new(),
    };

    let padded_opt_len = (options.len() + 3) & !3;
    let header_len = ((20 + padded_opt_len) / 4) as u8;

    Ok(Ipv4Header {
        version: 4,
        header_len,
        tos,
        total_len,
        id,
        frag_off,
        ttl,
        protocol,
        checksum: 0,
        src,
        dst,
        options,
    })
}

/// Parses a Lua `ip6` table into an [`Ipv6Header`], mirroring `lua_reconstruct_ip6hdr`.
pub fn lua_to_ipv6(lua: &Lua, tbl: &Table) -> mlua::Result<Ipv6Header>
{
    let flow_val = tbl.raw_get::<Value>("ip6_flow")?;
    let flow = match &flow_val
    {
        Value::Integer(_) | Value::Number(_) => require_number_i64(&flow_val)? as u32,
        _ => IPV6_DEFAULT_FLOW,
    };

    let next_header = optional_i64(lua, &tbl.raw_get::<Value>("ip6_nxt")?) as u8;
    let hop_limit = optional_i64(lua, &tbl.raw_get::<Value>("ip6_hlim")?) as u8;

    let src_val = tbl.raw_get::<Value>("ip6_src")?;
    let src_bytes = require_strict_bytes(&src_val)?.as_bytes();
    let src: [u8; 16] = src_bytes
        .as_ref()
        .try_into()
        .map_err(|_| mlua::Error::external("ip6_src must be 16 bytes"))?;

    let dst_val = tbl.raw_get::<Value>("ip6_dst")?;
    let dst_bytes = require_strict_bytes(&dst_val)?.as_bytes();
    let dst: [u8; 16] = dst_bytes
        .as_ref()
        .try_into()
        .map_err(|_| mlua::Error::external("ip6_dst must be 16 bytes"))?;

    let plen_val = tbl.raw_get::<Value>("ip6_plen")?;
    let payload_len = match &plen_val
    {
        Value::Nil => None,
        Value::Integer(_) | Value::Number(_) => Some(coerce_i64(lua, &plen_val)? as u16),
        _ =>
        {
            return Err(mlua::Error::external("reconstruct_ip6hdr: ip6_plen wrong type"));
        }
    };

    let mut exthdr = Vec::new();
    if let Value::Table(arr) = tbl.raw_get::<Value>("exthdr")?
    {
        let mut idx = 1i64;
        loop
        {
            let entry = arr.raw_get::<Value>(idx)?;
            if entry.is_nil()
            {
                break;
            }
            let Value::Table(ext_tbl) = entry
            else
            {
                return Err(mlua::Error::external("ip6.exthdr entry must be a table"));
            };
            let header_type = require_number_i64(&ext_tbl.raw_get::<Value>("type")?)? as u8;
            let next_val = ext_tbl.raw_get::<Value>("next")?;
            let ext_next = match &next_val
            {
                Value::Integer(_) | Value::Number(_) => require_number_i64(&next_val)? as u8,
                _ => IPPROTO_NONE,
            };
            let data_val = ext_tbl.raw_get::<Value>("data")?;
            let data = require_strict_bytes(&data_val)?
                .as_bytes()
                .to_vec();
            exthdr.push(Ipv6ExtHeader { header_type, next_header: ext_next, data });
            idx += 1;
        }
    }

    Ok(Ipv6Header { flow, payload_len, next_header, hop_limit, src, dst, exthdr })
}

/// Parses a Lua `tcp` table into a [`TcpHeader`], mirroring `lua_reconstruct_tcphdr`.
pub fn lua_to_tcp(lua: &Lua, tbl: &Table) -> mlua::Result<TcpHeader>
{
    let s_port = require_number_i64(&tbl.raw_get::<Value>("th_sport")?)? as u16;
    let d_port = require_number_i64(&tbl.raw_get::<Value>("th_dport")?)? as u16;
    let seq = require_number_i64(&tbl.raw_get::<Value>("th_seq")?)? as u32;
    let ack = require_number_i64(&tbl.raw_get::<Value>("th_ack")?)? as u32;
    let reserved = optional_i64(lua, &tbl.raw_get::<Value>("th_x2")?) as u8;
    let flags = require_number_i64(&tbl.raw_get::<Value>("th_flags")?)? as u8;
    let window = require_number_i64(&tbl.raw_get::<Value>("th_win")?)? as u16;
    let checksum = optional_i64(lua, &tbl.raw_get::<Value>("th_sum")?) as u16;
    let urgent_ptr = optional_i64(lua, &tbl.raw_get::<Value>("th_urp")?) as u16;

    let mut options = Vec::new();
    if let Value::Table(arr) = tbl.raw_get::<Value>("options")?
    {
        let mut idx = 1i64;
        loop
        {
            let entry = arr.raw_get::<Value>(idx)?;
            if entry.is_nil()
            {
                break;
            }
            let Value::Table(opt_tbl) = entry
            else
            {
                return Err(mlua::Error::external("tcp.options entry must be a table"));
            };
            let kind = require_number_i64(&opt_tbl.raw_get::<Value>("kind")?)? as u8;
            if kind == TCP_KIND_END || kind == TCP_KIND_NOOP
            {
                options.push(TcpOption { kind, data: None });
            }
            else
            {
                let data = match opt_tbl.raw_get::<Value>("data")?
                {
                    Value::String(s) => Some(
                        s.as_bytes()
                            .to_vec(),
                    ),
                    _ => None,
                };
                options.push(TcpOption { kind, data });
            }
            idx += 1;
        }
    }

    Ok(TcpHeader {
        s_port,
        d_port,
        seq,
        ack,
        reserved,
        data_offset: 5,
        flags,
        window,
        checksum,
        urgent_ptr,
        options,
    })
}

/// Parses a Lua `udp` table into a [`UdpHeader`], mirroring `lua_reconstruct_udphdr`.
pub fn lua_to_udp(lua: &Lua, tbl: &Table) -> mlua::Result<UdpHeader>
{
    let s_port = require_number_i64(&tbl.raw_get::<Value>("uh_sport")?)? as u16;
    let d_port = require_number_i64(&tbl.raw_get::<Value>("uh_dport")?)? as u16;
    let len = optional_i64(lua, &tbl.raw_get::<Value>("uh_ulen")?) as u16;
    let checksum = optional_i64(lua, &tbl.raw_get::<Value>("uh_sum")?) as u16;
    Ok(UdpHeader { s_port, d_port, len, checksum })
}

/// Parses a Lua `icmp` table into an [`IcmpHeader`], mirroring `lua_reconstruct_icmphdr`.
pub fn lua_to_icmp(lua: &Lua, tbl: &Table) -> mlua::Result<IcmpHeader>
{
    let icmp_type = require_number_i64(&tbl.raw_get::<Value>("icmp_type")?)? as u8;
    let icmp_code = require_number_i64(&tbl.raw_get::<Value>("icmp_code")?)? as u8;
    let data = require_number_i64(&tbl.raw_get::<Value>("icmp_data")?)? as u32;
    let checksum = optional_i64(lua, &tbl.raw_get::<Value>("icmp_cksum")?) as u16;
    Ok(IcmpHeader { icmp_type, icmp_code, checksum, data })
}

/// Parses a Lua `dis` table into a [`DissectedPacket`], mirroring `lua_reconstruct_dissect`.
pub fn lua_to_dissect(lua: &Lua, tbl: &Table) -> mlua::Result<DissectedPacket>
{
    let frag_val = tbl.raw_get::<Value>("frag_off")?;
    let frag_off = if frag_val.is_nil() { None } else { Some(coerce_i64(lua, &frag_val)? as u16) };

    let (ip, ip6) = match tbl.raw_get::<Value>("ip")?
    {
        Value::Table(ip_tbl) => (Some(lua_to_ipv4(lua, &ip_tbl)?), None),
        _ => match tbl.raw_get::<Value>("ip6")?
        {
            Value::Table(ip6_tbl) => (None, Some(lua_to_ipv6(lua, &ip6_tbl)?)),
            _ =>
            {
                return Err(mlua::Error::external("invalid dissect data: missing ip or ip6"));
            }
        },
    };

    let mut tcp = None;
    let mut udp = None;
    let mut icmp = None;
    if frag_off.is_none()
    {
        if let Value::Table(tcp_tbl) = tbl.raw_get::<Value>("tcp")?
        {
            tcp = Some(lua_to_tcp(lua, &tcp_tbl)?);
        }
        else if let Value::Table(udp_tbl) = tbl.raw_get::<Value>("udp")?
        {
            udp = Some(lua_to_udp(lua, &udp_tbl)?);
        }
        else if let Value::Table(icmp_tbl) = tbl.raw_get::<Value>("icmp")?
        {
            icmp = Some(lua_to_icmp(lua, &icmp_tbl)?);
        }
    }

    let payload = match tbl.raw_get::<Value>("payload")?
    {
        Value::String(s) => Some(
            s.as_bytes()
                .to_vec(),
        ),
        Value::Nil => None,
        Value::Integer(i) => Some(
            i.to_string()
                .into_bytes(),
        ),
        Value::Number(n) => Some(
            n.to_string()
                .into_bytes(),
        ),
        _ => None,
    };

    Ok(DissectedPacket { frag_off, ip, ip6, tcp, udp, icmp, payload, ..DissectedPacket::default() })
}

/// Parses an optional Lua reconstruct options table (`keepsum`, `badsum`, `ip6_preserve_next`, `ip6_last_proto`).
pub fn parse_reconstruct_opts(lua: &Lua, val: Option<&Value>) -> mlua::Result<ReconstructOptions>
{
    let Some(val) = val
    else
    {
        return Ok(ReconstructOptions::default());
    };
    if val.is_nil()
    {
        return Ok(ReconstructOptions::default());
    }
    let Value::Table(tbl) = val
    else
    {
        return Err(mlua::Error::external("reconstruct options must be a table"));
    };

    let keepsum = parse_flag_value(&tbl.raw_get::<Value>("keepsum")?);
    let badsum = parse_flag_value(&tbl.raw_get::<Value>("badsum")?);
    let ip6_preserve_next = parse_flag_value(&tbl.raw_get::<Value>("ip6_preserve_next")?);
    let last_proto_val = tbl.raw_get::<Value>("ip6_last_proto")?;
    let ip6_last_proto =
        if last_proto_val.is_nil() { None } else { Some(optional_i64(lua, &last_proto_val) as u8) };

    Ok(ReconstructOptions { keepsum, badsum, ip6_preserve_next, ip6_last_proto })
}
