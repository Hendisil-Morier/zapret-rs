//! ICMP error relation tracking and raw non-TCP/UDP/ICMP packet desync processors.

/// Protocol and payload tags passed to profile matchers and `DesyncTableInput`.
use crate::config::{L7Payload, L7Proto, ProfileMatchInput};
/// Core desync engine dispatching profile actions on ICMP and raw IP packets.
use crate::desync::engine::DesyncEngine;
/// Play-state holder initialized from inherited flow or stateless packet endpoints.
use crate::desync::play::{PlayState, ReplayContext, profile_slot_by_id};
/// Full `dp_match` selector supporting dual-IP ipsets and hostlist/autohostlist rules.
use crate::desync::profile_state::{FullMatchInput, find_matching_profile};
/// Endpoint IP extractor and ICMP-attached inner IP error classifier.
use crate::desync::verdict::{extract_endpoint_ip, is_icmp_error_with_attached_ip};
/// Intercepted packet metadata and kernel verdict decision variants.
use crate::intercepter::{Decision, QueuedPacket};
/// Partial wire packet dissector used for attached inner packets inside ICMP errors.
use crate::packet::{DissectedPacket, dissect_packet};

/// Resolves cached `(hostname, is_ip)` from dst or src endpoint in `ipcache` when flow host is absent.
fn lookup_dual_ipcache_host(
    engine: &DesyncEngine,
    dis: &DissectedPacket,
) -> Option<(String, bool)> {
    let cache = engine.ipcache.borrow();
    if let Some(dst_ip) = extract_endpoint_ip(dis, false)
        && let Some((host, is_ip)) = cache.get_hostname(dst_ip)
    {
        return Some((host.to_owned(), is_ip));
    }
    if let Some(src_ip) = extract_endpoint_ip(dis, true)
        && let Some((host, is_ip)) = cache.get_hostname(src_ip)
    {
        return Some((host.to_owned(), is_ip));
    }
    None
}

/// Checks autohostlist membership for non-TCP/UDP paths (`dpi_desync_icmp_packet` / `ip_packet`).
fn autohostlist_allows(
    engine: &DesyncEngine,
    profile_idx: usize,
    hostname: Option<&str>,
    hostname_is_ip: bool,
    ctrack_check: Option<(bool, bool)>,
) -> bool {
    let Some(host) = hostname else {
        return true;
    };
    if engine.profile_runtimes[profile_idx].autolist.is_none() {
        return true;
    }
    if let Some((done, result)) = ctrack_check
        && done
    {
        return result;
    }
    engine.profile_runtimes[profile_idx]
        .hostlists
        .check(host, hostname_is_ip, false)
        .matched
}

/// Processes an ICMPv4 or ICMPv6 packet, inheriting parent flow state on RELATED error messages.
pub(crate) fn process_icmp_packet(
    engine: &DesyncEngine,
    pkt: &QueuedPacket<'_>,
    dis: &DissectedPacket,
) -> Decision {
    if dis.ip.is_some() == dis.ip6.is_some() {
        return Decision::Pass;
    }
    let Some(icmp) = &dis.icmp else {
        return Decision::Pass;
    };

    let mut l7payload = L7Payload::Icmp;
    let mut ctrack = None;
    let mut b_reverse = false;
    let mut inherited_prof_id = None;
    let mut inherited_l7proto = L7Proto::Unknown;
    let mut host = None;
    let mut host_is_ip = false;
    let mut ctrack_check = None;

    if is_icmp_error_with_attached_ip(dis, icmp.icmp_type)
        && let Some(attached) = dis.payload.as_deref()
    {
        let inner = dissect_packet(attached, true);
        if inner.ip.is_some() || inner.ip6.is_some() {
            l7payload = if inner.ip.is_some() {
                L7Payload::Ipv4
            } else {
                L7Payload::Ipv6
            };
            if let Some((entry_rc, rev)) = engine.runtime().conntrack().borrow().double_search(&inner)
            {
                b_reverse = !rev;
                let entry = entry_rc.borrow();
                inherited_prof_id = entry.profile_index;
                inherited_l7proto = entry.l7proto;
                host = entry.hostname.clone();
                host_is_ip = entry.hostname_is_ip;
                ctrack_check = Some((entry.check_done, entry.check_result));
                drop(entry);
                ctrack = Some(entry_rc);
            }
        }
    }

    let incoming = if ctrack.is_some() {
        b_reverse ^ engine.server
    } else {
        b_reverse = pkt.ifin.is_some_and(|s| !s.is_empty())
            && !pkt.ifout.is_some_and(|s| !s.is_empty());
        b_reverse
    };

    if host.is_none()
        && let Some((cached, is_ip)) = lookup_dual_ipcache_host(engine, dis)
    {
        host = Some(cached);
        host_is_ip = is_ip;
    }

    let Some(dst_ip) = extract_endpoint_ip(dis, false) else {
        return Decision::Pass;
    };
    let src_ip = extract_endpoint_ip(dis, true);

    let profile_idx = match inherited_prof_id
        .and_then(|id| profile_slot_by_id(&engine.profiles, id))
    {
        Some(idx) => Some(idx),
        None => {
            let match_input = FullMatchInput {
                base: ProfileMatchInput {
                    is_v6: dis.ip6.is_some(),
                    l4proto: dis.l4proto,
                    port: 0,
                    icmp_type: icmp.icmp_type,
                    icmp_code: icmp.icmp_code,
                    fwmark: pkt.mark,
                    l7proto: L7Proto::Unknown,
                },
                primary_ip: dst_ip,
                reverse_ip: src_ip,
                hostname: host.as_deref(),
                hostname_is_ip: host_is_ip,
            };
            let found =
                find_matching_profile(&engine.profiles, &engine.profile_runtimes, &match_input);
            if let (Some(idx), Some(rc)) = (found, &ctrack) {
                rc.borrow_mut().profile_index = Some(engine.profiles[idx].index);
            }
            found
        }
    };

    let Some(idx) = profile_idx else {
        return Decision::Pass;
    };
    if !autohostlist_allows(engine, idx, host.as_deref(), host_is_ip, ctrack_check) {
        return Decision::Pass;
    }

    let target_ip4 = dis.ip.as_ref().map(|ip| if incoming { ip.src } else { ip.dst });
    let target_ip6 = dis
        .ip6
        .as_ref()
        .map(|ip6| if incoming { ip6.src } else { ip6.dst });
    let ps = PlayState {
        profile_idx: Some(idx),
        ctrack: ctrack.clone(),
        ctrack_replay: ctrack,
        b_reverse,
        incoming,
        target_ip: if incoming {
            src_ip.unwrap_or(dst_ip)
        } else {
            dst_ip
        },
        target_ip4,
        target_ip6,
        target_port: 0,
        client_label: String::new(),
        l7proto: inherited_l7proto,
        l7payload,
        host: None,
        fwmark: pkt.mark,
    };

    engine.dispatch_state(&ReplayContext::live(), pkt, dis, &ps, None, None)
}

/// Processes non-TCP/UDP/ICMP raw IP packets without conntrack (`dpi_desync_ip_packet`).
pub(crate) fn process_raw_ip_packet(
    engine: &DesyncEngine,
    pkt: &QueuedPacket<'_>,
    dis: &DissectedPacket,
) -> Decision {
    if dis.ip.is_some() == dis.ip6.is_some() {
        return Decision::Pass;
    }
    let Some(dst_ip) = extract_endpoint_ip(dis, false) else {
        return Decision::Pass;
    };
    let src_ip = extract_endpoint_ip(dis, true);
    let (host, host_is_ip) = match lookup_dual_ipcache_host(engine, dis) {
        Some((h, is_ip)) => (Some(h), is_ip),
        None => (None, false),
    };

    let match_input = FullMatchInput {
        base: ProfileMatchInput {
            is_v6: dis.ip6.is_some(),
            l4proto: dis.l4proto,
            port: 0,
            icmp_type: 0xFF,
            icmp_code: 0xFF,
            fwmark: pkt.mark,
            l7proto: L7Proto::Unknown,
        },
        primary_ip: dst_ip,
        reverse_ip: src_ip,
        hostname: host.as_deref(),
        hostname_is_ip: host_is_ip,
    };
    let Some(idx) =
        find_matching_profile(&engine.profiles, &engine.profile_runtimes, &match_input)
    else {
        return Decision::Pass;
    };
    if !autohostlist_allows(engine, idx, host.as_deref(), host_is_ip, None) {
        return Decision::Pass;
    }

    let b_reverse =
        pkt.ifin.is_some_and(|s| !s.is_empty()) && !pkt.ifout.is_some_and(|s| !s.is_empty());
    let target_ip4 = dis
        .ip
        .as_ref()
        .map(|ip| if b_reverse { ip.src } else { ip.dst });
    let target_ip6 = dis
        .ip6
        .as_ref()
        .map(|ip6| if b_reverse { ip6.src } else { ip6.dst });
    let ps = PlayState {
        profile_idx: Some(idx),
        ctrack: None,
        ctrack_replay: None,
        b_reverse,
        incoming: b_reverse,
        target_ip: if b_reverse {
            src_ip.unwrap_or(dst_ip)
        } else {
            dst_ip
        },
        target_ip4,
        target_ip6,
        target_port: 0,
        client_label: String::new(),
        l7proto: L7Proto::Unknown,
        l7payload: L7Payload::Unknown,
        host: None,
        fwmark: pkt.mark,
    };

    engine.dispatch_state(&ReplayContext::live(), pkt, dis, &ps, None, None)
}
