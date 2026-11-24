//! Serializers building `zapret2`-compatible Lua `desync`, `arg`, `range`, and `payload` tables.

/// Ordered map storing per-action string parameters (`desync.arg`).
use std::collections::BTreeMap;

/// Core `mlua` types for Lua state access, tables, and values.
use mlua::{Lua, Table, Value};

/// Profile, L7 payload/protocol, and packet range types serialized into Lua tables.
use crate::config::{
    DesyncProfile, L7Payload, L7Proto, PacketPos, PacketRange, l7_payload_names,
};
/// Conntrack entry and position snapshots serialized into `desync.track`.
use crate::conntrack::{CtrackEntry, CtrackPositions};
/// Conntrack-to-Lua table serializer.
use crate::lua::ctrack_encode::ctrack_to_lua;
/// Packet dissection to Lua table serializer.
use crate::lua::packet_encode::dissect_to_lua;
/// Default fallback TCP MSS constant (`DEFAULT_MSS` = 1220) when option MSS is missing.
use crate::packet::constants::DEFAULT_MSS;
/// Parsed wire packet representation passed into `desync.dis`.
use crate::packet::DissectedPacket;

/// Formats a unique instance identifier matching `desync_instance` in `zapret2/nfq2/lua.c`.
pub fn desync_instance_name(func: &str, profile_n: u32, func_n: u32) -> String {
    format!("{func}_{profile_n}_{func_n}")
}

/// Serializes one [`PacketPos`] into `{ mode = <char>, pos = <u32> }`.
fn packet_pos_to_lua(lua: &Lua, pos: PacketPos) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 2)?;
    let mut mode_buf = [0u8; 4];
    let mode_str: &str = pos.mode.as_char().encode_utf8(&mut mode_buf);
    tbl.raw_set("mode", mode_str)?;
    tbl.raw_set("pos", i64::from(pos.pos))?;
    Ok(tbl)
}

/// Serializes a [`PacketRange`] into `{ upper_cutoff, from, to }` matching `lua_pushf_range`.
pub fn packet_range_to_lua(lua: &Lua, range: PacketRange) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 3)?;
    tbl.raw_set("upper_cutoff", range.upper_cutoff)?;
    tbl.raw_set("from", packet_pos_to_lua(lua, range.from)?)?;
    tbl.raw_set("to", packet_pos_to_lua(lua, range.to)?)?;
    Ok(tbl)
}

/// Builds `{ [payload_name] = true }` matching `luacall_execution_plan`'s `payload` field.
pub fn payload_mask_to_lua_table(lua: &Lua, mask: u64) -> mlua::Result<Table> {
    let names = l7_payload_names(mask);
    let tbl = lua.create_table_with_capacity(0, names.len())?;
    for name in names {
        tbl.raw_set(name, true)?;
    }
    Ok(tbl)
}

/// Resolves `name` from `desync_tbl` first, falling back to Lua `_G`, matching `lua_push_blob`.
fn lookup_blob_value(lua: &Lua, desync_tbl: Option<&Table>, name: &str) -> mlua::Result<Value> {
    if let Some(desync) = desync_tbl {
        let val = desync.get::<Value>(name)?;
        if !val.is_nil() {
            return Ok(val);
        }
    }
    lua.globals().get::<Value>(name)
}

/// Computes raw byte length of a Lua value for `#blob` substitution (`lua_rawlen` semantics).
fn blob_byte_len(val: &Value) -> usize {
    match val {
        Value::String(s) => s.as_bytes().len(),
        Value::Integer(i) => i.to_string().len(),
        Value::Number(n) => n.to_string().len(),
        Value::Table(t) => t.raw_len(),
        _ => 0,
    }
}

/// Builds a Lua `arg` table with optional `%blob` and `#blob` substitution (`lua_pushf_args`).
///
/// Returns `Ok(None)` when a referenced `%blob` or `#blob` variable is missing from both
/// `desync_tbl` and Lua `_G`.
pub fn build_action_args_table(
    lua: &Lua,
    args: &BTreeMap<String, String>,
    desync_tbl: Option<&Table>,
    subst_prefix: bool,
) -> mlua::Result<Option<Table>> {
    let tbl = lua.create_table_with_capacity(0, args.len())?;

    for (key, val) in args {
        if !subst_prefix {
            tbl.raw_set(key.as_str(), val.as_str())?;
            continue;
        }

        if val.starts_with("\\%") || val.starts_with("\\#") {
            tbl.raw_set(key.as_str(), &val[1..])?;
        } else if let Some(blob_name) = val.strip_prefix('%') {
            let blob_val = lookup_blob_value(lua, desync_tbl, blob_name)?;
            if blob_val.is_nil() {
                eprintln!("blob '{blob_name}' unavailable");
                return Ok(None);
            }
            match blob_val {
                Value::Integer(i) => tbl.raw_set(key.as_str(), i.to_string())?,
                Value::Number(n) => tbl.raw_set(key.as_str(), n.to_string())?,
                other => tbl.raw_set(key.as_str(), other)?,
            }
        } else if let Some(blob_name) = val.strip_prefix('#') {
            let blob_val = lookup_blob_value(lua, desync_tbl, blob_name)?;
            if blob_val.is_nil() {
                eprintln!("blob '{blob_name}' unavailable");
                return Ok(None);
            }
            let len = blob_byte_len(&blob_val);
            tbl.raw_set(key.as_str(), len.to_string())?;
        } else {
            tbl.raw_set(key.as_str(), val.as_str())?;
        }
    }

    Ok(Some(tbl))
}

/// Input packet, profile, and optional conntrack/reassembly state serialized into `desync`.
pub struct DesyncTableInput<'a> {
    /// Dissected wire packet serialized into `desync.dis`.
    pub dis: &'a DissectedPacket,
    /// Matched desync profile supplying `profile_n`, `profile_name`, and `cookie`.
    pub profile: &'a DesyncProfile,
    /// `true` for inbound packets (`outgoing = false`), `false` for outbound packets.
    pub incoming: bool,
    /// Incoming network interface name, if known.
    pub ifin: Option<&'a str>,
    /// Outgoing network interface name, if known.
    pub ifout: Option<&'a str>,
    /// Firewall mark attached to the packet (`desync.fwmark`).
    pub fwmark: u32,
    /// Remote peer IPv4 address for `desync.target.ip`, when L3 is IPv4.
    pub target_ip4: Option<[u8; 4]>,
    /// Remote peer IPv6 address for `desync.target.ip6`, when L3 is IPv6.
    pub target_ip6: Option<[u8; 16]>,
    /// Remote peer transport port for `desync.target.port` (`0` omits field).
    pub target_port: u16,
    /// L7 payload classification name (`desync.l7payload`).
    pub l7payload: L7Payload,
    /// L7 protocol classification name (`desync.l7proto`).
    pub l7proto: L7Proto,
    /// Optional conntrack entry backing `desync.track`.
    pub track: Option<&'a CtrackEntry>,
    /// Optional frozen position snapshot overriding `track.pos` during replay.
    pub tpos: Option<&'a CtrackPositions>,
    /// Logical reverse flag (`direct_is_server`) controlling `track.pos.direct`/`reverse` aliasing.
    pub b_reverse: bool,
    /// Zero-based replay index within an active delayed-packet replay batch.
    pub replay_piece: usize,
    /// Total packets in the delayed replay batch (`0` when not replaying).
    pub replay_piece_count: usize,
    /// Byte offset within the reassembled stream corresponding to this segment (`reasm_offset`).
    pub reasm_offset: usize,
    /// Contiguous segment or reassembled client payload slice (`desync.reasm_data`).
    pub reasm_data: Option<&'a [u8]>,
    /// Decrypted QUIC handshake slice (`desync.decrypt_data`), when available.
    pub decrypt_data: Option<&'a [u8]>,
}

/// Builds the base `desync` Lua table shared across all action invocations for one packet.
pub fn build_desync_table(lua: &Lua, input: &DesyncTableInput<'_>) -> mlua::Result<Table> {
    let tbl = lua.create_table_with_capacity(0, 18)?;
    tbl.raw_set("dis", dissect_to_lua(lua, input.dis)?)?;
    match input.track {
        Some(entry) => {
            tbl.raw_set(
                "track",
                ctrack_to_lua(lua, entry, input.tpos, input.b_reverse)?,
            )?;
        }
        None => tbl.raw_set("track", Value::Nil)?,
    }
    tbl.raw_set("profile_n", i64::from(input.profile.index))?;
    if let Some(name) = &input.profile.name {
        tbl.raw_set("profile_name", name.as_str())?;
    }
    if let Some(cookie) = &input.profile.cookie {
        tbl.raw_set("cookie", cookie.as_str())?;
    }
    tbl.raw_set("outgoing", !input.incoming)?;
    if let Some(ifin) = input.ifin.filter(|s| !s.is_empty()) {
        tbl.raw_set("ifin", ifin)?;
    }
    if let Some(ifout) = input.ifout.filter(|s| !s.is_empty()) {
        tbl.raw_set("ifout", ifout)?;
    }
    tbl.raw_set("fwmark", i64::from(input.fwmark))?;

    let target = lua.create_table_with_capacity(0, 3)?;
    if input.target_port != 0 {
        target.raw_set("port", i64::from(input.target_port))?;
    }
    if let Some(ip4) = input.target_ip4 {
        target.raw_set("ip", lua.create_string(ip4)?)?;
    }
    if let Some(ip6) = input.target_ip6 {
        target.raw_set("ip6", lua.create_string(ip6)?)?;
    }
    tbl.raw_set("target", target)?;

    let is_replay = input.replay_piece_count != 0;
    tbl.raw_set("replay", is_replay)?;
    if is_replay {
        let piece_one_based = input.replay_piece.saturating_add(1);
        tbl.raw_set(
            "replay_piece",
            i64::try_from(piece_one_based).unwrap_or(i64::MAX),
        )?;
        tbl.raw_set(
            "replay_piece_count",
            i64::try_from(input.replay_piece_count).unwrap_or(i64::MAX),
        )?;
        tbl.raw_set("replay_piece_last", piece_one_based >= input.replay_piece_count)?;
    }
    tbl.raw_set("l7payload", input.l7payload.as_str())?;
    tbl.raw_set("l7proto", input.l7proto.as_str())?;
    tbl.raw_set(
        "reasm_offset",
        i64::try_from(input.reasm_offset).unwrap_or(i64::MAX),
    )?;
    if let Some(bytes) = input.reasm_data {
        tbl.raw_set("reasm_data", lua.create_string(bytes)?)?;
    }
    if let Some(bytes) = input.decrypt_data {
        tbl.raw_set("decrypt_data", lua.create_string(bytes)?)?;
    }
    if input.dis.tcp.is_some() {
        let positions = input.tpos.or_else(|| input.track.map(|e| &e.pos));
        let mss = match positions {
            Some(tp) if tp.client.mss != 0 && tp.server.mss != 0 => {
                i64::from(tp.client.mss.min(tp.server.mss))
            }
            _ => i64::from(DEFAULT_MSS),
        };
        tbl.raw_set("tcp_mss", mss)?;
    }

    Ok(tbl)
}
