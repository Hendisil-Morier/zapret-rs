//! Verdict aggregation, Lua return-value decoding, context RAII guards, and conntrack helpers.

/// Interior mutability for clearing shared context and reading conntrack snapshots.
use std::cell::RefCell;
/// Standard IP address representation for target/destination endpoint extraction.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Reference counting for shared conntrack entries and context state handles.
use std::rc::Rc;

/// Multi-return value, function, userdata, and table container types used by Lua desync callbacks.
use mlua::{AnyUserData, Function, Lua, MultiValue, Table, Value};

/// Profile, action, range, L7 payload, and payload mask evaluation helpers.
use crate::config::{DesyncAction, DesyncProfile, L7Payload, l7_payload_matches};
/// Connection tracking entry, directional position snapshot, and TCP SYN/SYN-ACK helpers.
use crate::conntrack::{CtrackEntry, CtrackPosition, is_tcp_syn, is_tcp_synack};
/// Intercepted verdict decision enum returned to NFQUEUE.
use crate::intercepter::Decision;
/// Active Lua desync context state and table dissector helpers.
use crate::lua::{desync_api::DesyncContextState, packet_decode::lua_to_dissect};
/// ICMP error type constants, header lengths, and verdict action/flag bitmasks.
use crate::packet::constants::{
    ICMP_DEST_UNREACH, ICMP_PARAMETERPROB, ICMP_REDIRECT, ICMP_TIME_EXCEEDED, ICMP6_DST_UNREACH,
    ICMP6_PACKET_TOO_BIG, ICMP6_PARAM_PROB, ICMP6_TIME_EXCEEDED, IP_BASE_LEN, IP6_BASE_LEN,
    VERDICT_DROP, VERDICT_MASK, VERDICT_MASK_VALID_LUA, VERDICT_MODIFY, VERDICT_PASS,
    VERDICT_PRESERVE_NEXT,
};
/// Wire packet dissection, reconstruction options, and wire serializer.
use crate::packet::{DissectedPacket, ReconstructOptions, dissect_packet, reconstruct_packet};

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
pub(crate) fn is_icmp_error_with_attached_ip(dis: &DissectedPacket, icmp_type: u8) -> bool {
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

/// Assigns baseline [`L7Payload`] tags (`empty`, `unknown`, `ipv4`, `ipv6`, `icmp`).
pub fn classify_baseline_payload(dis: &DissectedPacket) -> L7Payload {
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

/// RAII guard clearing per-packet state on [`DesyncContextState`] even across early returns.
pub(crate) struct SessionCtxGuard<'a>(
    /// Reference to the shared context cell cleared on drop.
    pub(crate) &'a Rc<RefCell<DesyncContextState>>,
);

impl Drop for SessionCtxGuard<'_> {
    /// Resets per-packet context fields when profile evaluation finishes.
    fn drop(&mut self) {
        let mut state = self.0.borrow_mut();
        state.valid = false;
        state.cancel = false;
        state.profile = None;
        state.ctrack = None;
        state.raw_packet.clear();
        state.func.clear();
        state.instance.clear();
    }
}

/// RAII guard invalidating `ctx` immediately after each individual Lua callback returns.
pub(crate) struct ValidCtxGuard<'a>(
    /// Reference to the shared context cell whose `valid` flag is cleared on drop.
    pub(crate) &'a Rc<RefCell<DesyncContextState>>,
);

impl Drop for ValidCtxGuard<'_> {
    /// Marks `ctx` invalid so Lua cannot reuse a stashed context reference after returning.
    fn drop(&mut self) {
        self.0.borrow_mut().valid = false;
    }
}

/// Copies the packet sender's directional [`CtrackPosition`] (`server` if `b_reverse`, else `client`).
pub(crate) fn extract_pos_for_side(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    b_reverse: bool,
) -> Option<CtrackPosition> {
    let entry_rc = ctrack?;
    let entry = entry_rc.borrow();
    Some(if b_reverse {
        entry.pos.server
    } else {
        entry.pos.client
    })
}

/// Extracts either source (`from_src = true`) or destination (`from_src = false`) IP from `dis`.
pub(crate) fn extract_endpoint_ip(dis: &DissectedPacket, from_src: bool) -> Option<IpAddr> {
    if let Some(ip) = &dis.ip {
        Some(IpAddr::V4(Ipv4Addr::from(if from_src {
            ip.src
        } else {
            ip.dst
        })))
    } else {
        dis.ip6.as_ref().map(|ip6| {
            IpAddr::V6(Ipv6Addr::from(if from_src {
                ip6.src
            } else {
                ip6.dst
            }))
        })
    }
}

/// Applies `zapret2`'s Linux postnat conntrack teardown workaround on initial outgoing `VERDICT_DROP`.
///
/// Matches `ct_new_postnat_fix` in `zapret2/nfq2/desync.c:629-662`: rather than returning `NF_DROP`
/// on packet 1 of a flow or a stateless `SYN`/`SYN-ACK` (which causes Linux conntrack in postnat
/// chains to destroy the tuple), rewrites protocol to `255` and TTL/Hop Limit to `1` (`VERDICT_NOCSUM`).
pub(crate) fn ct_new_postnat_fix(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    server: bool,
    dis: &DissectedPacket,
    raw_pkt: &[u8],
) -> Decision {
    let first_tracked = ctrack.is_some_and(|rc| {
        let entry = rc.borrow();
        let pcounter = if server {
            entry.pos.server.pcounter
        } else {
            entry.pos.client.pcounter
        };
        pcounter == 1
    });
    let stateless_syn = ctrack.is_none()
        && dis
            .tcp
            .as_ref()
            .is_some_and(|tcp| is_tcp_syn(tcp.flags) || is_tcp_synack(tcp.flags));

    if !(first_tracked || stateless_syn) {
        return Decision::Drop;
    }

    let mut mod_pkt = raw_pkt.to_vec();
    if dis.ip.is_some() && mod_pkt.len() >= IP_BASE_LEN {
        mod_pkt[8] = 1;
        mod_pkt[9] = 255;
        return Decision::Replace(mod_pkt);
    }
    if dis.ip6.is_some() && mod_pkt.len() >= IP6_BASE_LEN {
        mod_pkt[6] = 255;
        mod_pkt[7] = 1;
        return Decision::Replace(mod_pkt);
    }
    Decision::Drop
}

/// Reads IPv4 `ttl` or IPv6 `hop_limit` from a dissected packet (`ttl46` in `darkmagic.c`).
pub(crate) fn extract_l3_ttl(dis: &DissectedPacket) -> u8 {
    if let Some(ip) = &dis.ip {
        ip.ttl
    } else if let Some(ip6) = &dis.ip6 {
        ip6.hop_limit
    } else {
        0
    }
}

/// Returns `true` if `instance` on `profile_n` has an active instance cutoff in direction `incoming`.
pub(crate) fn is_instance_cut_off(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    instance: &str,
    profile_n: u32,
    incoming: bool,
) -> bool {
    ctrack.is_some_and(|rc| rc.borrow().is_instance_cutoff(instance, profile_n, incoming))
}

/// Returns `true` when `action` satisfies instance cutoff, directional range, and payload filters.
pub(crate) fn action_is_runnable(
    action: &DesyncAction,
    profile_n: u32,
    instance: &str,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    pos_opt: Option<&CtrackPosition>,
    incoming: bool,
    l7payload: L7Payload,
) -> bool {
    if is_instance_cut_off(ctrack, instance, profile_n, incoming) {
        return false;
    }
    let range = if incoming {
        action.in_range
    } else {
        action.out_range
    };
    range.check_pos_range(pos_opt) && l7_payload_matches(l7payload, action.payload_mask)
}

/// Returns `true` when every action in `profile` is cut off by instance flags or packet range bounds.
pub(crate) fn all_actions_cut_off(
    profile: &DesyncProfile,
    instances: &[String],
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    pos_opt: Option<&CtrackPosition>,
    incoming: bool,
) -> bool {
    profile
        .actions
        .iter()
        .zip(instances.iter())
        .all(|(action, instance)| {
            let inst_cut = is_instance_cut_off(ctrack, instance, profile.index, incoming);
            let range = if incoming {
                action.in_range
            } else {
                action.out_range
            };
            inst_cut || range.check_pos_cutoff(pos_opt)
        })
}

/// Returns `true` when at least one profile action passes instance cutoff, range, and payload checks.
pub(crate) fn any_action_runnable(
    profile: &DesyncProfile,
    instances: &[String],
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    pos_opt: Option<&CtrackPosition>,
    incoming: bool,
    l7payload: L7Payload,
) -> bool {
    profile
        .actions
        .iter()
        .zip(instances.iter())
        .any(|(action, instance)| {
            action_is_runnable(
                action,
                profile.index,
                instance,
                ctrack,
                pos_opt,
                incoming,
                l7payload,
            )
        })
}

/// Arms `ctx.valid`, invokes a single Lua action callback, and clears `ctx.valid` before returning.
pub(crate) fn invoke_action_callback(
    ctx_state: &Rc<RefCell<DesyncContextState>>,
    func: &Function,
    ctx_ud: &AnyUserData,
    desync_tbl: &Table,
    func_n: u32,
    func_name: &str,
    instance: &str,
) -> Result<MultiValue, String> {
    {
        let mut state = ctx_state.borrow_mut();
        state.func_n = func_n;
        state.func.clear();
        state.func.push_str(func_name);
        state.instance.clear();
        state.instance.push_str(instance);
        state.valid = true;
    }
    let _valid_guard = ValidCtxGuard(ctx_state);
    func.call::<MultiValue>((ctx_ud.clone(), desync_tbl.clone()))
        .map_err(|e| format!("LUA ERROR: {e}"))
}

/// Resolves an aggregated Lua `VERDICT_*` bitmask into an NFQUEUE [`Decision`].
pub(crate) fn finalize_decision(
    lua: &Lua,
    desync_tbl: &Table,
    verdict: u8,
    raw_len: usize,
    debug: bool,
) -> Result<Decision, String> {
    match verdict & VERDICT_MASK {
        VERDICT_DROP => Ok(Decision::Drop),
        VERDICT_MODIFY => {
            let dis_val = desync_tbl
                .get::<Value>("dis")
                .map_err(|e| format!("failed to read modified desync.dis: {e}"))?;
            let Value::Table(dis_tbl) = dis_val else {
                return Err("dissect data is bad. VERDICT_MODIFY cancel".to_owned());
            };
            let mod_dis = lua_to_dissect(lua, &dis_tbl)
                .map_err(|e| format!("failed to decode modified desync.dis: {e}"))?;
            let opts = ReconstructOptions {
                keepsum: false,
                badsum: false,
                ip6_preserve_next: (verdict & VERDICT_PRESERVE_NEXT) != 0,
                ip6_last_proto: None,
            };
            let mod_bytes = reconstruct_packet(&mod_dis, &opts)
                .map_err(|e| format!("failed to reconstruct packet after VERDICT_MODIFY: {e}"))?;
            if debug {
                eprintln!(
                    "reconstructed packet due to VERDICT_MODIFY. size {raw_len} => {}",
                    mod_bytes.len()
                );
            }
            Ok(Decision::Replace(mod_bytes))
        }
        _ => Ok(Decision::Pass),
    }
}
