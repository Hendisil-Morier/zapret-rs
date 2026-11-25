//! Dynamic profile rediscovery, IPCache hostname persistence, and autohostlist activation.

/// Profile matching inputs and L7 protocol discriminator (`L7Proto`).
use crate::config::{L7Proto, ProfileMatchInput};
/// Conntrack snapshot and retransmission-stop sentinel constant.
use crate::conntrack::{CtrackPositions, RETRANS_COUNTER_STOP};
/// Autohostlist UDP stall evaluator run once flow hostname/profile settles.
use crate::desync::autohost::{AutohostFailTarget, handle_udp_fail};
/// Borrowed engine services and mutable per-packet dispatch state.
use crate::desync::play::{EngineServices, PlayState};
/// Full `dp_match` selector and profile-change cutoff clearer.
use crate::desync::profile_state::{FullMatchInput, find_matching_profile, on_profile_changed};
/// UDP protocol constant triggering `handle_udp_fail`.
use crate::packet::constants::IPPROTO_UDP;
/// Dissected L3/L4 header fields used during rediscovery.
use crate::packet::DissectedPacket;
/// Host-to-IP normalization helper (`strip_host_to_ip`).
use crate::protocol::strip_host_to_ip;

/// Applies newly learned hostname/L7 tags, updates IPCache, and re-runs profile + autohostlist selection.
pub(crate) fn dp_rediscovery(
    svc: &EngineServices<'_>,
    ps: &mut PlayState,
    dis: &DissectedPacket,
    tpos_override: Option<&CtrackPositions>,
    now_sec: i64,
) -> bool {
    let (mut effective_host, mut effective_is_ip, mut discovered_hostname) =
        (None::<String>, false, false);

    if let Some(raw_host) = ps.host.take() {
        let (norm, is_ip) = strip_host_to_ip(&raw_host);
        if let Some(entry_rc) = &ps.ctrack_replay {
            let mut entry = entry_rc.borrow_mut();
            if let Some(prev) = &entry.hostname
                && (is_ip != entry.hostname_is_ip || norm != *prev)
            {
                entry.clear_hostname();
                entry.check_done = false;
                entry.hostname_ah_check = false;
            }
            if entry.hostname.is_none() {
                entry.hostname = Some(norm.clone());
                entry.hostname_is_ip = is_ip;
                svc.ipcache
                    .borrow_mut()
                    .put_hostname(ps.target_ip, &norm, is_ip, now_sec);
                discovered_hostname = true;
            }
        } else {
            discovered_hostname = true;
        }
        effective_host = Some(norm);
        effective_is_ip = is_ip;
    } else if let Some(entry_rc) = &ps.ctrack_replay {
        let entry = entry_rc.borrow();
        effective_host = entry.hostname.clone();
        effective_is_ip = entry.hostname_is_ip;
    } else if !ps.b_reverse
        && let Some((cached, is_ip)) = svc.ipcache.borrow().get_hostname(ps.target_ip)
    {
        effective_host = Some(cached.to_owned());
        effective_is_ip = is_ip;
    }

    let discovered_l7 = if let Some(entry_rc) = &ps.ctrack_replay {
        let mut entry = entry_rc.borrow_mut();
        if !entry.l7proto_discovered && entry.l7proto != L7Proto::Unknown {
            entry.l7proto_discovered = true;
            true
        } else {
            false
        }
    } else {
        ps.l7proto != L7Proto::Unknown
    };

    if discovered_l7 || discovered_hostname {
        let match_input = FullMatchInput {
            base: ProfileMatchInput {
                is_v6: dis.ip6.is_some(),
                l4proto: dis.l4proto,
                port: ps.target_port,
                icmp_type: 0xFF,
                icmp_code: 0xFF,
                fwmark: ps.fwmark,
                l7proto: ps.l7proto,
            },
            primary_ip: ps.target_ip,
            reverse_ip: None,
            hostname: effective_host.as_deref(),
            hostname_is_ip: effective_is_ip,
        };
        let prev_idx = ps.profile_idx;
        let next_idx = find_matching_profile(svc.profiles, svc.profile_runtimes, &match_input);
        ps.profile_idx = next_idx;
        if let Some(entry_rc) = &ps.ctrack_replay {
            entry_rc.borrow_mut().profile_index = next_idx.map(|i| svc.profiles[i].index);
        }
        if next_idx != prev_idx {
            on_profile_changed(ps.ctrack_replay.as_ref());
        }
    }

    let (mut check_done, mut check_result, mut check_excluded) = match &ps.ctrack_replay {
        Some(rc) => {
            let e = rc.borrow();
            (e.check_done, e.check_result, e.check_excluded)
        }
        None => (false, false, false),
    };

    if let (Some(host), Some(idx)) = (effective_host.as_deref(), ps.profile_idx)
        && svc.profile_runtimes[idx].autolist.is_some()
    {
        if !check_done {
            let outcome = svc.profile_runtimes[idx]
                .hostlists
                .check(host, effective_is_ip, false);
            check_result = outcome.matched;
            check_excluded = outcome.excluded;
            check_done = true;
            if let Some(entry_rc) = &ps.ctrack_replay {
                let mut e = entry_rc.borrow_mut();
                e.check_done = check_done;
                e.check_result = check_result;
                e.check_excluded = check_excluded;
            }
        }
        if let Some(entry_rc) = &ps.ctrack_replay {
            let mut e = entry_rc.borrow_mut();
            if check_result {
                if dis.tcp.is_some() {
                    e.req_retrans_counter = RETRANS_COUNTER_STOP;
                }
            } else {
                e.hostname_ah_check = !check_excluded;
                if dis.tcp.is_some() && !e.hostname_ah_check {
                    e.req_retrans_counter = RETRANS_COUNTER_STOP;
                }
            }
        }
    }

    if dis.l4proto == IPPROTO_UDP {
        let fail_tgt = ps.profile_idx.map(|i| AutohostFailTarget {
            profile: svc.profiles[i].as_ref(),
            runtime: &svc.profile_runtimes[i],
            server: svc.server,
            client_label: &ps.client_label,
            debug_log: svc.hostlist_auto_debug,
        });
        handle_udp_fail(ps.ctrack_replay.as_ref(), tpos_override, fail_tgt.as_ref());
    }

    !(check_done && !check_result)
}
