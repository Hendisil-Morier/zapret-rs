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
/// Dissected L3/L4 header fields used during rediscovery.
use crate::packet::DissectedPacket;
/// UDP protocol constant triggering `handle_udp_fail`.
use crate::packet::constants::IPPROTO_UDP;
/// Host-to-IP normalization helper (`strip_host_to_ip`).
use crate::protocol::strip_host_to_ip;

/// Marks L7 discovery once on `ctrack_replay` or returns whether stateless `ps.l7proto` is known.
fn consume_discovered_l7(ps: &PlayState) -> bool
{
    let Some(entry_rc) = &ps.ctrack_replay
    else
    {
        return ps.l7proto != L7Proto::Unknown;
    };
    let mut entry = entry_rc.borrow_mut();
    if !entry.l7proto_discovered && entry.l7proto != L7Proto::Unknown
    {
        entry.l7proto_discovered = true;
        true
    }
    else
    {
        false
    }
}

/// Applies newly extracted `ps.host` to conntrack/IPCache, returning `(effective_host, is_ip, changed)`.
fn ingest_discovered_hostname(
    svc: &EngineServices<'_>,
    ps: &mut PlayState,
    now_sec: i64,
) -> (Option<String>, bool, bool)
{
    let Some(raw_host) = ps.host.take()
    else
    {
        return (None, false, false);
    };
    let (norm, is_ip) = strip_host_to_ip(&raw_host);
    let mut discovered_hostname = false;
    if let Some(entry_rc) = &ps.ctrack_replay
    {
        let mut entry = entry_rc.borrow_mut();
        if let Some(prev) = &entry.hostname
            && (is_ip != entry.hostname_is_ip || norm != *prev)
        {
            entry.clear_hostname();
            entry.check_done = false;
            entry.hostname_ah_check = false;
        }
        if entry.hostname.is_none()
        {
            entry.hostname = Some(norm.clone());
            entry.hostname_is_ip = is_ip;
            svc.ipcache.borrow_mut().put_hostname(ps.target_ip, &norm, is_ip, now_sec);
            discovered_hostname = true;
        }
    }
    else
    {
        discovered_hostname = true;
    }
    (Some(norm), is_ip, discovered_hostname)
}

/// Checks `autolist` membership for `idx`, caching outcome on conntrack and updating retrans suppression.
fn evaluate_autolist_membership(
    svc: &EngineServices<'_>,
    ps: &PlayState,
    idx: usize,
    effective_host: Option<&str>,
    effective_is_ip: bool,
    is_tcp: bool,
    state: &mut (bool, bool, bool),
)
{
    let (check_done, check_result, check_excluded) = state;
    if !*check_done
    {
        let owned_host;
        let host_str = match effective_host
        {
            Some(h) => h,
            None =>
            {
                let Some(rc) = &ps.ctrack_replay
                else
                {
                    return;
                };
                let Some(h) = rc.borrow().hostname.clone()
                else
                {
                    return;
                };
                owned_host = h;
                &owned_host
            }
        };
        let is_ip = effective_is_ip || ps.ctrack_replay.as_ref().is_some_and(|rc| rc.borrow().hostname_is_ip);
        let outcome = svc.profile_runtimes[idx].hostlists.check(host_str, is_ip, false);
        *check_result = outcome.matched;
        *check_excluded = outcome.excluded;
        *check_done = true;
        if let Some(entry_rc) = &ps.ctrack_replay
        {
            let mut e = entry_rc.borrow_mut();
            e.check_done = true;
            e.check_result = *check_result;
            e.check_excluded = *check_excluded;
        }
    }
    if let Some(entry_rc) = &ps.ctrack_replay
    {
        let mut e = entry_rc.borrow_mut();
        if *check_result
        {
            if is_tcp
            {
                e.req_retrans_counter = RETRANS_COUNTER_STOP;
            }
        }
        else
        {
            e.hostname_ah_check = !*check_excluded;
            if is_tcp && !e.hostname_ah_check
            {
                e.req_retrans_counter = RETRANS_COUNTER_STOP;
            }
        }
    }
}

/// Applies newly learned hostname/L7 tags, updates IPCache, and re-runs profile + autohostlist selection.
pub(crate) fn dp_rediscovery(
    svc: &EngineServices<'_>,
    ps: &mut PlayState,
    dis: &DissectedPacket,
    tpos_override: Option<&CtrackPositions>,
    now_sec: i64,
) -> bool
{
    let discovered_l7 = consume_discovered_l7(ps);
    let (mut effective_host, mut effective_is_ip, discovered_hostname) =
        ingest_discovered_hostname(svc, ps, now_sec);

    let (mut check_state, entry_has_host) = match &ps.ctrack_replay
    {
        Some(rc) =>
        {
            let e = rc.borrow();
            ((e.check_done, e.check_result, e.check_excluded), e.hostname.is_some())
        }
        None => ((false, false, false), false),
    };

    let needs_autolist_check =
        !check_state.0 && ps.profile_idx.is_some_and(|i| svc.profile_runtimes[i].autolist.is_some());
    if effective_host.is_none() && (discovered_l7 || needs_autolist_check)
    {
        if let Some(entry_rc) = &ps.ctrack_replay
        {
            let entry = entry_rc.borrow();
            effective_host = entry.hostname.clone();
            effective_is_ip = entry.hostname_is_ip;
        }
        else if !ps.b_reverse
            && let Some((cached, is_ip)) = svc.ipcache.borrow().get_hostname(ps.target_ip)
        {
            effective_host = Some(cached.to_owned());
            effective_is_ip = is_ip;
        }
    }

    if discovered_l7 || discovered_hostname
    {
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
        if let Some(entry_rc) = &ps.ctrack_replay
        {
            let mut entry = entry_rc.borrow_mut();
            entry.profile_searched = true;
            entry.profile_index = next_idx.map(|i| svc.profiles[i].index);
        }
        if next_idx != prev_idx
        {
            on_profile_changed(ps.ctrack_replay.as_ref());
            check_state = (false, false, false);
        }
    }

    if let Some(idx) = ps.profile_idx
        && svc.profile_runtimes[idx].autolist.is_some()
        && (effective_host.is_some() || entry_has_host)
    {
        evaluate_autolist_membership(
            svc,
            ps,
            idx,
            effective_host.as_deref(),
            effective_is_ip,
            dis.tcp.is_some(),
            &mut check_state,
        );
    }

    if dis.l4proto == IPPROTO_UDP
    {
        let fail_tgt = ps.profile_idx.map(|i| AutohostFailTarget {
            profile_slot: i,
            profile: svc.profiles[i].as_ref(),
            runtime: &svc.profile_runtimes[i],
            server: svc.server,
            client_label: &ps.client_label,
            debug_log: svc.hostlist_auto_debug,
            target_endpoint: (ps.target_ip, ps.target_port),
            auto_confirm: None,
        });
        handle_udp_fail(ps.ctrack_replay.as_ref(), tpos_override, fail_tgt.as_ref());
    }

    !(check_state.0 && !check_state.1)
}
