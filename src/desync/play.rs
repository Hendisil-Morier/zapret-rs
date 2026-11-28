//! Shared packet dispatch prolog and dynamic L7/hostname profile rediscovery.

/// Interior mutability for borrowing conntrack entries and `IpCache`.
use std::cell::RefCell;
/// Formatted client `ip:port` endpoint labels passed into autohostlist logs.
use std::net::{IpAddr, SocketAddr};
/// Single-thread reference counting for sharing `CtrackEntry` handles.
use std::rc::Rc;

/// Profile filter types, L7 protocol/payload tags, and runtime profile selection inputs.
use crate::config::{DesyncProfile, L7Payload, L7Proto, ProfileMatchInput};
/// Conntrack pool, per-flow state, and directional position snapshot types.
use crate::conntrack::{ConntrackPool, CtrackEntry, CtrackPositions};
/// Profile runtime registry and full `dp_match` profile selector.
use crate::desync::profile_state::{FullMatchInput, ProfileRuntime, find_matching_profile};
/// Endpoint IP and L3 TTL extractors shared with the core desync dispatcher.
use crate::desync::verdict::{extract_endpoint_ip, extract_l3_ttl};
/// Hostlist checks and DNS/TTL IPCache lookups.
use crate::lists::IpCache;
/// Dissected packet header fields used for endpoint, port, and TTL extraction.
use crate::packet::DissectedPacket;
/// High-level per-packet outcome classification recorded by the desync engine.
pub use crate::telemetry::PacketOutcome;
/// Monotonic boottime timestamp passed through from `DesyncEngine::process_packet`.
use crate::timer::MonotonicTime;

/// Contextual parameters distinguishing live packet handling from delayed-queue replay.
pub(crate) struct ReplayContext<'a>
{
    /// Zero-based index within an active replay batch.
    pub(crate) replay_piece: usize,
    /// Total delayed packets in the batch (`0` during live packet interception).
    pub(crate) replay_piece_count: usize,
    /// Cumulative payload byte offset across replayed delayed pieces.
    pub(crate) reasm_offset: usize,
    /// Frozen position snapshot captured when the delayed segment originally arrived.
    pub(crate) tpos: Option<&'a CtrackPositions>,
}

impl ReplayContext<'_>
{
    /// Returns an inactive [`ReplayContext`] used for normal live packet processing.
    pub(crate) const fn live() -> Self
    {
        Self { replay_piece: 0, replay_piece_count: 0, reasm_offset: 0, tpos: None }
    }

    /// Returns `true` when executing inside `replay_delayed_queue`.
    pub(crate) const fn is_replay(&self) -> bool
    {
        self.replay_piece_count != 0
    }
}

/// Borrowed global engine runtime services passed into [`play_prolog`] and [`dp_rediscovery`].
pub(crate) struct EngineServices<'a>
{
    /// Active `zapret2` desync profiles configured by the user.
    pub(crate) profiles: &'a [Rc<DesyncProfile>],
    /// Parallel runtime hostlists, ipsets, and failure pools indexed identically to `profiles`.
    pub(crate) profile_runtimes: &'a [ProfileRuntime],
    /// Global conntrack pool protecting live flows.
    pub(crate) conntrack: &'a RefCell<ConntrackPool>,
    /// Global DNS hostname and incoming TTL cache.
    pub(crate) ipcache: &'a RefCell<IpCache>,
    /// Embedded Lua state required when creating per-connection `lua_state` tables.
    pub(crate) lua: &'a mlua::Lua,
    /// Disable connection tracking (`--ctrack-disable`).
    pub(crate) ctrack_disable: bool,
    /// Server-mode direction flag (`--server`).
    pub(crate) server: bool,
    /// Optional autohostlist failure debug log path.
    pub(crate) hostlist_auto_debug: Option<&'a std::path::Path>,
    /// Optional non-blocking active DPI confirmation worker (`confirm_block`).
    pub(crate) auto_confirm: Option<&'a crate::desync::auto_confirm::AutoConfirmWorker>,
}

/// Mutable per-packet routing, target, L7, and conntrack state across TCP/UDP processing.
pub(crate) struct PlayState
{
    /// Matched 0-based index into `EngineServices::profiles` (`None` until matched).
    pub(crate) profile_idx: Option<usize>,
    /// Live flow entry (`None` during delayed-packet replay, matching `desync.c`).
    pub(crate) ctrack: Option<Rc<RefCell<CtrackEntry>>>,
    /// Flow entry exposed to `desync.track` and rediscovery (present in both live and replay).
    pub(crate) ctrack_replay: Option<Rc<RefCell<CtrackEntry>>>,
    /// Logical flow reverse direction (`true` = server -> client, `false` = client -> server).
    pub(crate) b_reverse: bool,
    /// Local host direction (`bReverseFixed = b_reverse ^ server`).
    pub(crate) incoming: bool,
    /// Target remote IPv4/IPv6 endpoint selected via `incoming`.
    pub(crate) target_ip: IpAddr,
    /// Optional raw 4-byte IPv4 target address for `desync.target.ip`.
    pub(crate) target_ip4: Option<[u8; 4]>,
    /// Optional raw 16-byte IPv6 target address for `desync.target.ip6`.
    pub(crate) target_ip6: Option<[u8; 16]>,
    /// Resolved remote transport port (`desync.target.port`).
    pub(crate) target_port: u16,
    /// Formatted `client_ip:client_port` string for autohostlist debug diagnostics.
    pub(crate) client_label: String,
    /// Discovered flow L7 protocol tag.
    pub(crate) l7proto: L7Proto,
    /// Discovered per-packet L7 payload tag.
    pub(crate) l7payload: L7Payload,
    /// Newly extracted hostname or DNS-cached hostname for this packet/flow.
    pub(crate) host: Option<String>,
    /// Packet netfilter mark carried through into profile matching and `desync.fwmark`.
    pub(crate) fwmark: u32,
}

/// Formats an `ip:port` endpoint string for autohostlist failure debug logging.
fn format_client_label(dis: &DissectedPacket, b_reverse: bool) -> String
{
    let from_src = !b_reverse;
    let Some(ip) = extract_endpoint_ip(dis, from_src)
    else
    {
        return String::new();
    };
    let port = if let Some(tcp) = &dis.tcp
    {
        if from_src { tcp.s_port } else { tcp.d_port }
    }
    else if let Some(udp) = &dis.udp
    {
        if from_src { udp.s_port } else { udp.d_port }
    }
    else
    {
        0
    };
    SocketAddr::new(ip, port).to_string()
}

/// Resolves 1-based `profile.index` to 0-based slice index inside `profiles`.
pub(crate) fn profile_slot_by_id(profiles: &[Rc<DesyncProfile>], id: u32) -> Option<usize>
{
    profiles
        .iter()
        .position(|p| p.index == id)
}

/// Resolved conntrack handles and packet direction flags produced by endpoint resolution.
struct ResolvedCtrackEndpoints
{
    /// Live conntrack handle when processing a non-replayed packet (`None` on replays).
    ctrack: Option<Rc<RefCell<CtrackEntry>>>,
    /// Conntrack handle readable during both live and replayed packet inspection.
    ctrack_replay: Option<Rc<RefCell<CtrackEntry>>>,
    /// Whether the matched flow is in the server-to-client direction.
    b_reverse: bool,
    /// Effective incoming direction flag after accounting for server mode.
    incoming: bool,
}

/// Resolves live/replay conntrack handles and direction flags for packet processing.
fn resolve_ctrack_endpoints(
    svc: &EngineServices<'_>,
    replay: &ReplayContext<'_>,
    dis: &DissectedPacket,
    ifin: Option<&str>,
    ifout: Option<&str>,
    now: MonotonicTime,
) -> Option<ResolvedCtrackEndpoints>
{
    if replay.is_replay()
    {
        let (entry_rc, rev) = svc
            .conntrack
            .borrow()
            .double_search(dis)?;
        if rev
        {
            return None;
        }
        return Some(ResolvedCtrackEndpoints {
            ctrack: None,
            ctrack_replay: Some(entry_rc),
            b_reverse: rev,
            incoming: rev ^ svc.server,
        });
    }
    let hit = if !svc.ctrack_disable
    {
        let mut pool = svc
            .conntrack
            .borrow_mut();
        if pool.purge_rate_limited(now.sec) > 0
        {
            svc.lua
                .expire_registry_values();
        }
        match pool.feed(Some(svc.lua), dis, now)
        {
            Ok(found) => found,
            Err(err) =>
            {
                eprintln!("conntrack ERROR: {err}. skipping conntrack for packet.");
                None
            }
        }
    }
    else
    {
        None
    };
    Some(match hit
    {
        Some((rc, rev)) => ResolvedCtrackEndpoints {
            ctrack: Some(Rc::clone(&rc)),
            ctrack_replay: Some(rc),
            b_reverse: rev,
            incoming: rev ^ svc.server,
        },
        None =>
        {
            let inc = ifin.is_some_and(|s| !s.is_empty()) && !ifout.is_some_and(|s| !s.is_empty());
            ResolvedCtrackEndpoints { ctrack: None, ctrack_replay: None, b_reverse: inc, incoming: inc }
        }
    })
}

/// Inputs needed to resolve a cached or initial matching profile for a packet.
struct InitialProfileLookup<'a>
{
    /// Shared engine services holding profiles, runtimes, and IP cache.
    svc: &'a EngineServices<'a>,
    /// Conntrack handle readable during live and replay lookups.
    ctrack_replay: Option<&'a Rc<RefCell<CtrackEntry>>>,
    /// Replay state distinguishing live discovery from chunked replays.
    replay: &'a ReplayContext<'a>,
    /// Dissected L3/L4 packet headers.
    dis: &'a DissectedPacket,
    /// Remote endpoint IP address used for IP cache and ipset matching.
    target_ip: IpAddr,
    /// Remote endpoint transport port.
    target_port: u16,
    /// Whether the matched flow is in the server-to-client direction.
    b_reverse: bool,
    /// Packet firewall mark matched against profile filters.
    fwmark: u32,
}

/// Resolves cached or initial matching profile index and populates tracked hostname if absent.
fn resolve_initial_profile(lookup: &InitialProfileLookup<'_>, l7proto: &mut L7Proto) -> Option<usize>
{
    let InitialProfileLookup { svc, ctrack_replay, replay, dis, target_ip, target_port, b_reverse, fwmark } =
        *lookup;
    let mut host = None;
    let mut host_is_ip = false;
    let mut cached_prof_id = None;
    let mut prof_searched = false;
    if let Some(entry_rc) = ctrack_replay
    {
        let mut entry = entry_rc.borrow_mut();
        *l7proto = entry.l7proto;
        cached_prof_id = entry.profile_index;
        prof_searched = entry.profile_searched;
        if !replay.is_replay()
            && entry
                .hostname
                .is_none()
            && !b_reverse
            && let Some((cached, is_ip)) = svc
                .ipcache
                .borrow()
                .get_hostname(target_ip)
        {
            entry.hostname = Some(cached.to_owned());
            entry.hostname_is_ip = is_ip;
        }
        if cached_prof_id.is_none() && !prof_searched
        {
            host = entry
                .hostname
                .clone();
            host_is_ip = entry.hostname_is_ip;
        }
    }
    else if !b_reverse
        && let Some((cached, is_ip)) = svc
            .ipcache
            .borrow()
            .get_hostname(target_ip)
    {
        host = Some(cached.to_owned());
        host_is_ip = is_ip;
    }

    if let Some(id) = cached_prof_id
        && let Some(idx) = profile_slot_by_id(svc.profiles, id)
    {
        return Some(idx);
    }
    if prof_searched
    {
        return None;
    }

    let match_input = FullMatchInput {
        base: ProfileMatchInput {
            is_v6: dis
                .ip6
                .is_some(),
            l4proto: dis.l4proto,
            port: target_port,
            icmp_type: 0xFF,
            icmp_code: 0xFF,
            fwmark,
            l7proto: *l7proto,
        },
        primary_ip: target_ip,
        reverse_ip: None,
        hostname: host.as_deref(),
        hostname_is_ip: host_is_ip,
    };
    let found = find_matching_profile(svc.profiles, svc.profile_runtimes, &match_input);
    if let Some(entry_rc) = ctrack_replay
    {
        let mut entry = entry_rc.borrow_mut();
        entry.profile_searched = true;
        entry.profile_index = found.map(|idx| svc.profiles[idx].index);
    }
    found
}

/// Synchronizes incoming server TTL between [`IpCache`] and live conntrack entries.
fn sync_ipcache_ttl(
    svc: &EngineServices<'_>,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    dis: &DissectedPacket,
    target_ip: IpAddr,
    iface: &str,
    incoming: bool,
    now_sec: i64,
)
{
    if incoming
    {
        let mut ttl = extract_l3_ttl(dis);
        svc.ipcache
            .borrow_mut()
            .update_ttl(target_ip, iface, &mut ttl, svc.server, now_sec);
        if let Some(entry_rc) = ctrack
        {
            let mut entry = entry_rc.borrow_mut();
            if entry.incoming_ttl == 0
            {
                entry.incoming_ttl = ttl;
            }
        }
    }
    else if let Some(entry_rc) = ctrack
    {
        let mut entry = entry_rc.borrow_mut();
        if entry.incoming_ttl == 0
            && let Some(ttl) = svc
                .ipcache
                .borrow()
                .get_ttl(target_ip, iface, svc.server)
        {
            entry.incoming_ttl = ttl;
        }
    }
}

/// Initializes conntrack, direction, TTL/hostname IPCache, and initial profile selection (`play_prolog`).
pub(crate) fn play_prolog(
    svc: &EngineServices<'_>,
    replay: &ReplayContext<'_>,
    dis: &DissectedPacket,
    ifin: Option<&str>,
    ifout: Option<&str>,
    fwmark: u32,
    now: MonotonicTime,
) -> Option<PlayState>
{
    if dis
        .ip
        .is_some()
        == dis
            .ip6
            .is_some()
    {
        return None;
    }
    let has_payload = dis
        .payload
        .as_deref()
        .is_some_and(|p| !p.is_empty());
    let mut l7proto = L7Proto::Unknown;
    let l7payload = if has_payload { L7Payload::Unknown } else { L7Payload::Empty };

    let ResolvedCtrackEndpoints { ctrack, ctrack_replay, b_reverse, incoming } =
        resolve_ctrack_endpoints(svc, replay, dis, ifin, ifout, now)?;

    let target_ip4 = dis
        .ip
        .as_ref()
        .map(|ip| if incoming { ip.src } else { ip.dst });
    let target_ip6 = dis
        .ip6
        .as_ref()
        .map(|ip6| if incoming { ip6.src } else { ip6.dst });
    let target_ip = extract_endpoint_ip(dis, incoming)?;
    let port_from_src = incoming ^ svc.server;
    let target_port = dis
        .tcp
        .as_ref()
        .map(|tcp| if port_from_src { tcp.s_port } else { tcp.d_port })
        .or_else(|| {
            dis.udp
                .as_ref()
                .map(|udp| if port_from_src { udp.s_port } else { udp.d_port })
        })
        .unwrap_or(0);

    let profile_idx = resolve_initial_profile(
        &InitialProfileLookup {
            svc,
            ctrack_replay: ctrack_replay.as_ref(),
            replay,
            dis,
            target_ip,
            target_port,
            b_reverse,
            fwmark,
        },
        &mut l7proto,
    );

    if !replay.is_replay()
    {
        if let Some(idx) = profile_idx
        {
            svc.profile_runtimes[idx]
                .fail_pool
                .borrow_mut()
                .purge_rate_limited(now.sec);
        }
        let iface = if incoming { ifin.unwrap_or("") } else { ifout.unwrap_or("") };
        sync_ipcache_ttl(svc, ctrack.as_ref(), dis, target_ip, iface, incoming, now.sec);
    }

    Some(PlayState {
        profile_idx,
        ctrack,
        ctrack_replay,
        b_reverse,
        incoming,
        target_ip,
        target_ip4,
        target_ip6,
        target_port,
        client_label: if svc
            .hostlist_auto_debug
            .is_some()
        {
            format_client_label(dis, b_reverse)
        }
        else
        {
            String::new()
        },
        l7proto,
        l7payload,
        host: None,
        fwmark,
    })
}
