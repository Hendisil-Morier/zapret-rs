//! Autohostlist TCP/UDP failure triggers, fail-pool promotion, and synthetic RST injection.

/// Interior mutability for safely dropping `CtrackEntry` borrows prior to raw packet emission.
use std::cell::RefCell;
/// Optional path to `--hostlist-auto-debug`.
use std::path::Path;
/// Single-thread reference counting for shared [`CtrackEntry`] and [`PacketSender`] handles.
use std::rc::Rc;

/// Profile thresholds and L7 protocol identifiers attached to failure debug entries.
use crate::config::{DesyncProfile, L7Payload, L7Proto};
/// Conntrack entry and frozen position snapshots checked by failure heuristics.
use crate::conntrack::{CtrackEntry, CtrackPositions};
/// Shared runtime profile state holding fail counters and writable autolist handle.
use crate::desync::profile_state::ProfileRuntime;
/// Source/destination IP extraction shared with `verdict`.
use crate::desync::verdict::extract_endpoint_ip;
/// Autohostlist failure counters, trigger predicates, and self-append helpers.
use crate::lists::{
    AutoHostlistRecordCtx, check_tcp_incoming_trigger, check_tcp_retrans_trigger,
    check_udp_trigger, record_autohost_failure, reset_autohost_failure,
};
/// TCP protocol number, header base size, and `TH_RST` control flag constant.
use crate::packet::constants::{IPPROTO_TCP, TCP_BASE_LEN, TH_RST};
/// Wire header structs and packet serializer used for synthetic TCP RST generation.
use crate::packet::{
    DissectedPacket, Ipv4Header, Ipv6Header, ReconstructOptions, TcpHeader, reconstruct_packet,
};
/// Abstract raw packet sender injecting synthetic `TH_RST` frames on retrans fail.
use crate::rawsend::PacketSender;
/// Boottime monotonic seconds clock for autohostlist sliding windows.
use crate::timer::boottime_secs;

/// Synthesizes a swapped header-only TCP RST response for retrans-threshold teardown (`auto_hostlist_retrans`).
pub(crate) fn build_retrans_rst_packet(
    dis: &DissectedPacket,
    server_winsize: u16,
    server_ip6flow: u32,
) -> Option<Vec<u8>> {
    let tcp = dis.tcp.as_ref()?;
    let rst_tcp = TcpHeader {
        s_port: tcp.d_port,
        d_port: tcp.s_port,
        seq: tcp.ack,
        ack: tcp.seq,
        reserved: tcp.reserved,
        data_offset: (TCP_BASE_LEN / 4) as u8,
        flags: TH_RST,
        window: server_winsize,
        checksum: 0,
        urgent_ptr: tcp.urgent_ptr,
        options: Vec::new(),
    };

    let rst_dis = if let Some(ip) = &dis.ip {
        DissectedPacket {
            ip: Some(Ipv4Header {
                version: ip.version,
                header_len: 5,
                tos: ip.tos,
                total_len: 40,
                id: 0,
                frag_off: ip.frag_off,
                ttl: ip.ttl,
                protocol: IPPROTO_TCP,
                checksum: 0,
                src: ip.dst,
                dst: ip.src,
                options: Vec::new(),
            }),
            tcp: Some(rst_tcp),
            ..DissectedPacket::default()
        }
    } else if let Some(ip6) = &dis.ip6 {
        DissectedPacket {
            ip6: Some(Ipv6Header {
                flow: if server_ip6flow != 0 {
                    server_ip6flow
                } else {
                    0x6000_0000
                },
                payload_len: Some(TCP_BASE_LEN as u16),
                next_header: IPPROTO_TCP,
                hop_limit: ip6.hop_limit,
                src: ip6.dst,
                dst: ip6.src,
                exthdr: Vec::new(),
            }),
            tcp: Some(rst_tcp),
            ..DissectedPacket::default()
        }
    } else {
        return None;
    };

    reconstruct_packet(&rst_dis, &ReconstructOptions::default()).ok()
}

/// Shared profile target and diagnostic metadata passed into autohostlist failure handlers.
pub(crate) struct AutohostFailTarget<'a> {
    /// Active desync profile owning the autohostlist thresholds and name.
    pub(crate) profile: &'a DesyncProfile,
    /// Profile runtime holding failure counters and writable autohostlist handle.
    pub(crate) runtime: &'a ProfileRuntime,
    /// Server-mode direction flag (`--server`, disables client autohostlist detection).
    pub(crate) server: bool,
    /// Formatted `client_ip:client_port` string written into debug log entries.
    pub(crate) client_label: &'a str,
    /// Optional path to `--hostlist-auto-debug`.
    pub(crate) debug_log: Option<&'a Path>,
}

/// Applies the `Option<bool>` trigger outcome from any TCP/UDP failure detector to `target`.
fn apply_autohost_outcome(
    target: &AutohostFailTarget<'_>,
    hostname: Option<&str>,
    host_is_ip: bool,
    l7proto: L7Proto,
    trigger: Option<bool>,
) {
    let (Some(host), Some(is_fail)) = (hostname, trigger) else {
        return;
    };
    if is_fail {
        record_profile_failure(target, host, host_is_ip, l7proto);
    } else {
        reset_profile_failure(target, host, l7proto);
    }
}

/// Handles outgoing TCP retransmission failure checks, optional RST injection, and autohostlist recording.
pub(crate) fn handle_tcp_retrans_fail(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    dis: &DissectedPacket,
    target: Option<&AutohostFailTarget<'_>>,
    ifin: Option<&str>,
    sender: &Rc<RefCell<dyn PacketSender>>,
) {
    let (Some(entry_rc), Some(tgt)) = (ctrack, target) else {
        return;
    };
    if tgt.server || tgt.runtime.autolist.is_none() {
        return;
    }

    let (trigger, hostname, host_is_ip, l7proto, winsize, ip6flow, client_ip) = {
        let mut entry = entry_rc.borrow_mut();
        let trigger =
            check_tcp_retrans_trigger(&mut entry, &tgt.profile.lists.hostlist_auto_settings);
        let client_ip = extract_endpoint_ip(dis, true);
        (
            trigger,
            entry.hostname.clone(),
            entry.hostname_is_ip,
            entry.l7proto,
            entry.pos.server.winsize,
            entry.pos.server.ip6flow,
            client_ip,
        )
    };

    if trigger == Some(true)
        && tgt.profile.lists.hostlist_auto_settings.retrans_reset
        && let (Some(dst_ip), Some(rst_pkt)) =
            (client_ip, build_retrans_rst_packet(dis, winsize, ip6flow))
    {
        let _ = sender.borrow_mut().send(dst_ip, 0, ifin, &rst_pkt);
    }

    apply_autohost_outcome(tgt, hostname.as_deref(), host_is_ip, l7proto, trigger);
}

/// Evaluates incoming server TCP RST / HTTP 302-307 redirect failure triggers (`dpi_desync_tcp_packet_play`).
pub(crate) fn handle_tcp_incoming_fail(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    dis: &DissectedPacket,
    l7payload: L7Payload,
    target: Option<&AutohostFailTarget<'_>>,
) {
    let (Some(entry_rc), Some(tgt)) = (ctrack, target) else {
        return;
    };
    if tgt.server || tgt.runtime.autolist.is_none() {
        return;
    }
    let Some(tcp) = &dis.tcp else {
        return;
    };

    let (trigger, hostname, host_is_ip, l7proto) = {
        let mut entry = entry_rc.borrow_mut();
        let trigger = check_tcp_incoming_trigger(
            &mut entry,
            tcp.flags,
            dis.payload.as_deref(),
            l7payload,
            &tgt.profile.lists.hostlist_auto_settings,
        );
        (
            trigger,
            entry.hostname.clone(),
            entry.hostname_is_ip,
            entry.l7proto,
        )
    };

    apply_autohost_outcome(tgt, hostname.as_deref(), host_is_ip, l7proto, trigger);
}

/// Evaluates unidirectional UDP packet thresholds for autohostlist promotion (`process_udp_fail`).
pub(crate) fn handle_udp_fail(
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    tpos_override: Option<&CtrackPositions>,
    target: Option<&AutohostFailTarget<'_>>,
) {
    let (Some(entry_rc), Some(tgt)) = (ctrack, target) else {
        return;
    };
    if tgt.server || tgt.runtime.autolist.is_none() {
        return;
    }

    let (trigger, hostname, host_is_ip, l7proto) = {
        let mut entry = entry_rc.borrow_mut();
        let snapshot = tpos_override.copied().unwrap_or(entry.pos);
        let trigger = check_udp_trigger(
            &mut entry,
            &snapshot,
            &tgt.profile.lists.hostlist_auto_settings,
        );
        (
            trigger,
            entry.hostname.clone(),
            entry.hostname_is_ip,
            entry.l7proto,
        )
    };

    apply_autohost_outcome(tgt, hostname.as_deref(), host_is_ip, l7proto, trigger);
}

/// Records an autohostlist failure against `target` and promotes `host` when threshold is reached.
fn record_profile_failure(
    target: &AutohostFailTarget<'_>,
    host: &str,
    host_is_ip: bool,
    l7proto: L7Proto,
) {
    let Some(autolist_file) = &target.runtime.autolist else {
        return;
    };
    let mut pool = target.runtime.fail_pool.borrow_mut();
    let mut ctx = AutoHostlistRecordCtx {
        settings: &target.profile.lists.hostlist_auto_settings,
        fail_pool: &mut pool,
        hostlists: &target.runtime.hostlists,
        autolist_file,
        debug_log: target.debug_log,
        profile_n: target.profile.index,
        profile_name: target.profile.name.as_deref().unwrap_or("noname"),
        client_label: target.client_label,
        l7proto,
        now_sec: boottime_secs(),
    };
    let _ = record_autohost_failure(&mut ctx, host, host_is_ip);
}

/// Clears any active autohostlist fail counter for `host` after healthy response traffic.
fn reset_profile_failure(target: &AutohostFailTarget<'_>, host: &str, l7proto: L7Proto) {
    let mut pool = target.runtime.fail_pool.borrow_mut();
    let _ = reset_autohost_failure(
        &mut pool,
        host,
        target.debug_log,
        target.profile.index,
        target.profile.name.as_deref().unwrap_or("noname"),
        target.client_label,
        l7proto,
    );
}
