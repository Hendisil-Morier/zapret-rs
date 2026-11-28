//! Rust packet header / dissect struct to Lua table serializers (`*_to_lua`).

/// Standard IP address enum converted into wire-format Lua strings.
use std::net::IpAddr;

/// Core `mlua` Lua state and table builder handle.
use mlua::{Lua, Table};

/// Parsed L3/L4 header and packet structs.
use crate::packet::types::{DissectedPacket, IcmpHeader, Ipv4Header, Ipv6Header, TcpHeader, UdpHeader};

/// Serializes an [`Ipv4Header`] into a `zapret2`-compatible Lua `ip` table.
pub fn ipv4_to_lua(lua: &Lua, ip: &Ipv4Header) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 12)?;
    tbl.raw_set("ip_v", ip.version)?;
    tbl.raw_set("ip_hl", ip.header_len)?;
    tbl.raw_set("ip_tos", ip.tos)?;
    tbl.raw_set("ip_len", ip.total_len)?;
    tbl.raw_set("ip_id", ip.id)?;
    tbl.raw_set("ip_off", ip.frag_off)?;
    tbl.raw_set("ip_ttl", ip.ttl)?;
    tbl.raw_set("ip_p", ip.protocol)?;
    tbl.raw_set("ip_sum", ip.checksum)?;
    tbl.raw_set("ip_src", lua.create_string(ip.src)?)?;
    tbl.raw_set("ip_dst", lua.create_string(ip.dst)?)?;
    if !ip
        .options
        .is_empty()
    {
        tbl.raw_set("options", lua.create_string(&ip.options)?)?;
    }
    Ok(tbl)
}

/// Serializes an [`Ipv6Header`] and its `exthdr` list into a Lua `ip6` table.
pub fn ipv6_to_lua(lua: &Lua, ip6: &Ipv6Header) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 7)?;
    tbl.raw_set("ip6_flow", i64::from(ip6.flow))?;
    tbl.raw_set(
        "ip6_plen",
        i64::from(
            ip6.payload_len
                .unwrap_or(0),
        ),
    )?;
    tbl.raw_set("ip6_nxt", ip6.next_header)?;
    tbl.raw_set("ip6_hlim", ip6.hop_limit)?;
    tbl.raw_set("ip6_src", lua.create_string(ip6.src)?)?;
    tbl.raw_set("ip6_dst", lua.create_string(ip6.dst)?)?;

    let ext_arr = lua.create_table_with_capacity(
        ip6.exthdr
            .len(),
        0,
    )?;
    for (idx, ext) in ip6
        .exthdr
        .iter()
        .enumerate()
    {
        let item = lua.create_table_with_capacity(0, 3)?;
        item.raw_set("type", ext.header_type)?;
        item.raw_set("next", ext.next_header)?;
        item.raw_set("data", lua.create_string(&ext.data)?)?;
        ext_arr.raw_set(idx + 1, item)?;
    }
    tbl.raw_set("exthdr", ext_arr)?;

    Ok(tbl)
}

/// Serializes a [`TcpHeader`] into a Lua `tcp` table.
pub fn tcp_to_lua(lua: &Lua, tcp: &TcpHeader) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 11)?;
    tbl.raw_set("th_sport", tcp.s_port)?;
    tbl.raw_set("th_dport", tcp.d_port)?;
    tbl.raw_set("th_seq", i64::from(tcp.seq))?;
    tbl.raw_set("th_ack", i64::from(tcp.ack))?;
    tbl.raw_set("th_x2", tcp.reserved)?;
    tbl.raw_set("th_off", tcp.data_offset)?;
    tbl.raw_set("th_flags", tcp.flags)?;
    tbl.raw_set("th_win", tcp.window)?;
    tbl.raw_set("th_sum", tcp.checksum)?;
    tbl.raw_set("th_urp", tcp.urgent_ptr)?;

    let opts = lua.create_table_with_capacity(
        tcp.options
            .len(),
        0,
    )?;
    for (idx, opt) in tcp
        .options
        .iter()
        .enumerate()
    {
        let entry = lua.create_table_with_capacity(0, 2)?;
        entry.raw_set("kind", opt.kind)?;
        if let Some(data) = &opt.data
        {
            entry.raw_set("data", lua.create_string(data)?)?;
        }
        opts.raw_set(idx + 1, entry)?;
    }
    tbl.raw_set("options", opts)?;

    Ok(tbl)
}

/// Serializes a [`UdpHeader`] into a Lua `udp` table.
pub fn udp_to_lua(lua: &Lua, udp: &UdpHeader) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 4)?;
    tbl.raw_set("uh_sport", udp.s_port)?;
    tbl.raw_set("uh_dport", udp.d_port)?;
    tbl.raw_set("uh_ulen", udp.len)?;
    tbl.raw_set("uh_sum", udp.checksum)?;
    Ok(tbl)
}

/// Serializes an [`IcmpHeader`] into a Lua `icmp` table.
pub fn icmp_to_lua(lua: &Lua, icmp: &IcmpHeader) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 4)?;
    tbl.raw_set("icmp_type", icmp.icmp_type)?;
    tbl.raw_set("icmp_code", icmp.icmp_code)?;
    tbl.raw_set("icmp_cksum", icmp.checksum)?;
    tbl.raw_set("icmp_data", i64::from(icmp.data))?;
    Ok(tbl)
}

/// Serializes a complete [`DissectedPacket`] into a `zapret2`-compatible Lua `dis` table.
pub fn dissect_to_lua(lua: &Lua, dis: &DissectedPacket) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 11)?;
    tbl.raw_set("l4proto", dis.l4proto)?;
    tbl.raw_set("transport_len", dis.transport_len)?;
    tbl.raw_set("l3_len", dis.l3_len)?;
    tbl.raw_set("l4_len", dis.l4_len)?;

    if let Some(payload) = &dis.payload
    {
        tbl.raw_set("payload", lua.create_string(payload)?)?;
    }
    if let Some(frag_off) = dis.frag_off
    {
        tbl.raw_set("frag_off", frag_off)?;
    }
    if let Some(ip) = &dis.ip
    {
        tbl.raw_set("ip", ipv4_to_lua(lua, ip)?)?;
    }
    if let Some(ip6) = &dis.ip6
    {
        tbl.raw_set("ip6", ipv6_to_lua(lua, ip6)?)?;
    }
    if let Some(tcp) = &dis.tcp
    {
        tbl.raw_set("tcp", tcp_to_lua(lua, tcp)?)?;
    }
    if let Some(udp) = &dis.udp
    {
        tbl.raw_set("udp", udp_to_lua(lua, udp)?)?;
    }
    if let Some(icmp) = &dis.icmp
    {
        tbl.raw_set("icmp", icmp_to_lua(lua, icmp)?)?;
    }
    Ok(tbl)
}

/// Converts a Rust [`IpAddr`] into its 4-byte or 16-byte wire representation for Lua bindings.
pub fn ip_to_wire_bytes(ip: IpAddr) -> Vec<u8>
{
    match ip
    {
        IpAddr::V4(v4) => v4
            .octets()
            .to_vec(),
        IpAddr::V6(v6) => v6
            .octets()
            .to_vec(),
    }
}
