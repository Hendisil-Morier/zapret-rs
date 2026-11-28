//! Serializers building `zapret2`-compatible Lua `desync.track` and position tables.

/// Core `mlua` types for Lua table construction and registry lookups.
use mlua::{Lua, Table, Value};

/// Conntrack entry and bidirectional position types serialized to Lua tables.
use crate::conntrack::{CtrackEntry, CtrackPosition, CtrackPositions};
/// Protocol number constant distinguishing TCP-specific fields (`tcp` subtable).
use crate::packet::constants::IPPROTO_TCP;

/// Serializes one endpoint direction (`client` or `server`) into a Lua table (`lua_pushf_ctrack_pos`).
pub fn ctrack_pos_to_lua(lua: &Lua, pos: &CtrackPosition, ipproto: u8) -> mlua::Result<Table>
{
    let tbl = lua.create_table_with_capacity(0, 5)?;
    tbl.raw_set("pcounter", i64::try_from(pos.pcounter).unwrap_or(i64::MAX))?;
    tbl.raw_set("pdcounter", i64::try_from(pos.pdcounter).unwrap_or(i64::MAX))?;
    tbl.raw_set("pbcounter", i64::try_from(pos.pbcounter).unwrap_or(i64::MAX))?;
    if pos.ip6flow != 0
    {
        tbl.raw_set("ip6_flow", i64::from(pos.ip6flow))?;
    }

    if ipproto == IPPROTO_TCP
    {
        let tcp = lua.create_table_with_capacity(0, 11)?;
        tcp.raw_set("seq0", i64::from(pos.seq0))?;
        tcp.raw_set("seq", i64::from(pos.seq_last))?;
        tcp.raw_set("rseq", i64::from(pos.rseq()))?;
        tcp.raw_set("rseq_over_2G", pos.rseq_over_2g)?;
        tcp.raw_set("pos", i64::from(pos.rel_pos()))?;
        tcp.raw_set("uppos", i64::from(pos.rel_uppos()))?;
        tcp.raw_set("uppos_prev", i64::from(pos.rel_uppos_prev()))?;
        tcp.raw_set("winsize", i64::from(pos.winsize))?;
        tcp.raw_set("winsize_calc", i64::from(pos.winsize_calc))?;
        tcp.raw_set("scale", i64::from(pos.scale))?;
        tcp.raw_set("mss", i64::from(pos.mss))?;
        tbl.raw_set("tcp", tcp)?;
    }

    Ok(tbl)
}

/// Serializes a [`CtrackEntry`] (optionally using a frozen replay [`CtrackPositions`] snapshot) into
/// `desync.track`, matching `lua_push_ctrack` in `zapret2/nfq2/lua.c:1722-1777`.
///
/// When `direct_is_server` is `true` (`params.server ^ bIncoming`), `pos.direct` aliases
/// `pos.server` and `pos.reverse` aliases `pos.client`; otherwise they alias `client` and `server`.
pub fn ctrack_to_lua(
    lua: &Lua,
    entry: &CtrackEntry,
    tpos_override: Option<&CtrackPositions>,
    direct_is_server: bool,
) -> mlua::Result<Table>
{
    let tpos = tpos_override.unwrap_or(&entry.pos);
    let tbl = lua.create_table_with_capacity(0, 9)?;

    if entry.incoming_ttl != 0
    {
        tbl.raw_set("incoming_ttl", i64::from(entry.incoming_ttl))?;
    }
    tbl.raw_set(
        "l7proto",
        entry
            .l7proto
            .as_str(),
    )?;
    match &entry.hostname
    {
        Some(host) =>
        {
            tbl.raw_set("hostname", host.as_str())?;
            tbl.raw_set("hostname_is_ip", entry.hostname_is_ip)?;
        }
        None =>
        {
            tbl.raw_set("hostname", Value::Nil)?;
        }
    }

    if let Some(key) = &entry.lua_state
    {
        let state_tbl: Value = lua.registry_value(key)?;
        tbl.raw_set("lua_state", state_tbl)?;
    }
    tbl.raw_set("lua_in_cutoff", entry.lua_in_cutoff)?;
    tbl.raw_set("lua_out_cutoff", entry.lua_out_cutoff)?;
    tbl.raw_set(
        "t_start",
        entry
            .t_start
            .as_secs_f64(),
    )?;

    let pos_tbl = lua.create_table_with_capacity(0, 5)?;
    pos_tbl.raw_set(
        "dt",
        tpos.t_last
            .elapsed_secs_f64(entry.t_start),
    )?;

    let client_tbl = ctrack_pos_to_lua(lua, &tpos.client, tpos.ipproto)?;
    let server_tbl = ctrack_pos_to_lua(lua, &tpos.server, tpos.ipproto)?;
    pos_tbl.raw_set("client", client_tbl.clone())?;
    pos_tbl.raw_set("server", server_tbl.clone())?;
    if direct_is_server
    {
        pos_tbl.raw_set("direct", server_tbl)?;
        pos_tbl.raw_set("reverse", client_tbl)?;
    }
    else
    {
        pos_tbl.raw_set("direct", client_tbl)?;
        pos_tbl.raw_set("reverse", server_tbl)?;
    }

    tbl.raw_set("pos", pos_tbl)?;
    Ok(tbl)
}
