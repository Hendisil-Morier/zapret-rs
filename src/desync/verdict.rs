//! Verdict aggregation, Lua return-value decoding, and baseline L7 payload classification.

/// Multi-return value container yielded by Lua desync callbacks.
use mlua::{MultiValue, Value};

/// Baseline L7 payload classification enum.
use crate::config::L7Payload;
/// ICMP error type constants and verdict action/flag bitmasks.
use crate::packet::constants::{
    ICMP_DEST_UNREACH, ICMP_PARAMETERPROB, ICMP_REDIRECT, ICMP_TIME_EXCEEDED, ICMP6_DST_UNREACH,
    ICMP6_PACKET_TOO_BIG, ICMP6_PARAM_PROB, ICMP6_TIME_EXCEEDED, VERDICT_DROP, VERDICT_MASK,
    VERDICT_MASK_VALID_LUA, VERDICT_MODIFY, VERDICT_PASS, VERDICT_PRESERVE_NEXT,
};
/// Wire packet dissection helper and container struct.
use crate::packet::{DissectedPacket, dissect_packet};

/// Combines two `zapret2` Lua verdicts (`DROP` > `MODIFY` > `PASS`), propagating `VERDICT_PRESERVE_NEXT`.
pub const fn aggregate_verdict(v1: u8, v2: u8) -> u8 {
    let mut action = v1 & VERDICT_MASK;
    match v2 & VERDICT_MASK {
        VERDICT_MODIFY => {
            if action == VERDICT_PASS {
                action = VERDICT_MODIFY;
            }
        }
        VERDICT_DROP => {
            action = VERDICT_DROP;
        }
        _ => {}
    }
    (v1 & !VERDICT_MASK) | action | (v2 & VERDICT_PRESERVE_NEXT)
}

/// Returns `true` if `icmp_type` is an ICMPv4 or ICMPv6 error carrying an embedded IP packet.
fn is_icmp_error_with_attached_ip(dis: &DissectedPacket, icmp_type: u8) -> bool {
    if dis.ip.is_some() {
        matches!(
            icmp_type,
            ICMP_DEST_UNREACH | ICMP_TIME_EXCEEDED | ICMP_PARAMETERPROB | ICMP_REDIRECT
        )
    } else if dis.ip6.is_some() {
        matches!(
            icmp_type,
            ICMP6_DST_UNREACH | ICMP6_PACKET_TOO_BIG | ICMP6_TIME_EXCEEDED | ICMP6_PARAM_PROB
        )
    } else {
        false
    }
}

/// Assigns baseline Milestone 2 [`L7Payload`] tags (`empty`, `unknown`, `ipv4`, `ipv6`, `icmp`).
pub fn classify_baseline_payload(dis: &DissectedPacket) -> L7Payload {
    // shortcut: full L7 DPI probes (HTTP/TLS/QUIC/etc.) land in Milestone 3.
    if dis.tcp.is_some() || dis.udp.is_some() {
        if dis.payload.as_deref().is_some_and(|p| !p.is_empty()) {
            L7Payload::Unknown
        } else {
            L7Payload::Empty
        }
    } else if let Some(icmp) = &dis.icmp {
        if is_icmp_error_with_attached_ip(dis, icmp.icmp_type)
            && let Some(attached) = dis.payload.as_deref()
        {
            let inner = dissect_packet(attached, true);
            if inner.ip.is_some() {
                return L7Payload::Ipv4;
            }
            if inner.ip6.is_some() {
                return L7Payload::Ipv6;
            }
        }
        L7Payload::Icmp
    } else {
        L7Payload::Unknown
    }
}

/// Validates and decodes Lua desync return values matching `desync_get_result` in `desync.c`.
pub(crate) fn parse_lua_verdict(values: &MultiValue) -> Result<u8, String> {
    if values.len() > 1 {
        return Err(format!(
            "desync function returned more than one result: {}",
            values.len()
        ));
    }
    let Some(first) = values.front() else {
        return Ok(VERDICT_PASS);
    };
    match first {
        Value::Nil => Ok(VERDICT_PASS),
        Value::Integer(v) => {
            if (v & !i64::from(VERDICT_MASK_VALID_LUA)) != 0 {
                return Err("desync function returned bad int result".to_owned());
            }
            Ok(*v as u8)
        }
        Value::Number(n) => {
            if !n.is_finite()
                || n.fract() != 0.0
                || *n < 0.0
                || *n > f64::from(VERDICT_MASK_VALID_LUA)
            {
                return Err("desync function returned bad int result".to_owned());
            }
            let v = *n as i64;
            if (v & !i64::from(VERDICT_MASK_VALID_LUA)) != 0 {
                return Err("desync function returned bad int result".to_owned());
            }
            Ok(v as u8)
        }
        _ => Err("desync function returned non-int result".to_owned()),
    }
}
