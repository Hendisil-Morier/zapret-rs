//! Autohostlist failure counters, TCP/UDP failure triggers, and persistent self-append logic.

/// Interior mutability for updating the profile's shared autohostlist file in place.
use std::cell::RefCell;
/// Map keying failed hostnames to their fixed-window counter and expiration second.
use std::collections::HashMap;
/// Optional autohostlist debug log file path.
use std::path::Path;
/// Shared reference handle to the profile's autohostlist [`HostlistFile`].
use std::rc::Rc;

/// L7 payload and protocol discriminators used in HTTP redirect triggers and debug log lines.
use crate::config::{L7Payload, L7Proto};
/// Conntrack flow, directional position, and retransmission-sentinel types.
use crate::conntrack::{ConnState, CtrackEntry, CtrackPosition, CtrackPositions, RETRANS_COUNTER_STOP};
/// Persistent list-file append, timestamped debug log, and mtime signature refresh helpers.
use crate::lists::file_loader::{
    FileModSig, append_timestamped_debug_log, append_to_list_file,
};
/// Hostlist collections and underlying file-backed hostname pools.
use crate::lists::hostlist::{HostlistCollection, HostlistFile};
/// TCP RST wire flag constant matching `TH_RST` in `zapret2`.
use crate::packet::constants::{IPPROTO_TCP, TH_RST};
/// HTTP 302/307 off-SLD/off-IP DPI redirect classifier.
use crate::protocol::http_reply_looks_like_dpi_redirect;

/// Minimum allowed `--hostlist-auto-fail-threshold` (`1`).
pub const MIN_AUTOHOSTLIST_FAIL_THRESHOLD: u32 = 1;
/// Maximum allowed `--hostlist-auto-fail-threshold` (`20`).
pub const MAX_AUTOHOSTLIST_FAIL_THRESHOLD: u32 = 20;
/// Minimum allowed `--hostlist-auto-retrans-threshold` (`2`).
pub const MIN_AUTOHOSTLIST_RETRANS_THRESHOLD: u8 = 2;
/// Maximum allowed `--hostlist-auto-retrans-threshold` (`10`).
pub const MAX_AUTOHOSTLIST_RETRANS_THRESHOLD: u8 = 10;

/// Per-profile autohostlist thresholds and heuristic parameters matching `zapret2/nfq2/desync.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoHostlistSettings {
    /// Number of failures within `fail_time_sec` required before appending a host (`3`).
    pub fail_threshold: u32,
    /// Non-refreshed sliding expiration window in seconds from the first failure (`60`).
    pub fail_time_sec: i64,
    /// Outgoing TCP retransmission count triggering a failure (`3`).
    pub retrans_threshold: u8,
    /// Maximum initial relative TCP sequence window watched for retransmissions (`32768`).
    pub retrans_maxseq: u32,
    /// Whether hitting `retrans_threshold` should trigger a synthetic TCP RST (`true`).
    pub retrans_reset: bool,
    /// Maximum initial relative server TCP sequence watched for RST/302/307 failures (`4096`).
    pub incoming_maxseq: u32,
    /// Minimum outgoing UDP packet count required to declare a UDP stall failure (`4`, `0` disables).
    pub udp_out: u64,
    /// Maximum incoming UDP packet count still considered a UDP failure (`1`).
    pub udp_in: u64,
}

impl Default for AutoHostlistSettings {
    fn default() -> Self {
        Self {
            fail_threshold: 3,
            fail_time_sec: 60,
            retrans_threshold: 3,
            retrans_maxseq: 32_768,
            retrans_reset: true,
            incoming_maxseq: 4_096,
            udp_out: 4,
            udp_in: 1,
        }
    }
}

impl AutoHostlistSettings {
    /// Validates CLI/TOML threshold bounds matching `nfqws.c`.
    pub fn validate(&self) -> Result<(), &'static str> {
        let valid_fail = MIN_AUTOHOSTLIST_FAIL_THRESHOLD..=MAX_AUTOHOSTLIST_FAIL_THRESHOLD;
        let valid_retrans = MIN_AUTOHOSTLIST_RETRANS_THRESHOLD..=MAX_AUTOHOSTLIST_RETRANS_THRESHOLD;
        if !valid_fail.contains(&self.fail_threshold) {
            return Err("auto hostlist fail threshold must be in 1..=20");
        }
        if self.fail_time_sec < 1 {
            return Err("auto hostlist fail time must be >= 1");
        }
        if !valid_retrans.contains(&self.retrans_threshold) {
            return Err("auto hostlist retrans threshold must be in 2..=10");
        }
        Ok(())
    }
}

/// Active failure counter entry for one hostname inside [`HostFailPool`] (`hostfail_pool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFailEntry {
    /// Number of observed failures since initial insertion.
    pub counter: u32,
    /// Fixed monotonic boottime expiration second (`initial_now + fail_time_sec`).
    pub expire_sec: i64,
}

/// Time-windowed per-profile failure counter map (`hostfail_pool` in `pools.c`).
#[derive(Debug)]
pub struct HostFailPool {
    /// Active failure counters keyed by lowercase hostname.
    entries: HashMap<String, HostFailEntry>,
    /// Boottime second of the previous purge sweep (`purge_prev`).
    last_purge_sec: i64,
}

impl Default for HostFailPool {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            last_purge_sec: i64::MIN,
        }
    }
}

impl HostFailPool {
    /// Creates an empty [`HostFailPool`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of tracked hostnames in this pool.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when no failure entries are active.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Looks up the active counter record for `host` (`HostFailPoolFind`).
    pub fn get(&self, host: &str) -> Option<&HostFailEntry> {
        self.entries.get(host)
    }

    /// Removes `host` from the pool, returning `true` if an entry existed (`HostFailPoolDel`).
    pub fn reset(&mut self, host: &str) -> bool {
        self.entries.remove(host).is_some()
    }

    /// Increments the failure count for `host` without refreshing its initial expiration timestamp.
    pub fn record_failure(&mut self, host: &str, fail_time_sec: i64, now_sec: i64) -> u32 {
        if self.entries.get(host).is_some_and(|e| now_sec >= e.expire_sec) {
            self.entries.remove(host);
        }
        let expire_sec = now_sec.saturating_add(fail_time_sec);
        let entry = self
            .entries
            .entry(host.to_owned())
            .or_insert(HostFailEntry { counter: 0, expire_sec });
        entry.counter = entry.counter.saturating_add(1);
        entry.counter
    }

    /// Evicts all expired failure entries where `now_sec >= expire_sec` (`HostFailPoolPurge`).
    pub fn purge(&mut self, now_sec: i64) {
        self.entries.retain(|_, entry| now_sec < entry.expire_sec);
    }

    /// Runs [`Self::purge`] at most once per boottime second (`HostFailPoolPurgeRateLimited`).
    pub fn purge_rate_limited(&mut self, now_sec: i64) {
        if self.last_purge_sec != now_sec {
            self.purge(now_sec);
            self.last_purge_sec = now_sec;
        }
    }
}

/// High-level action taken by [`record_autohost_failure`] or [`reset_autohost_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoHostlistAction {
    /// No tracking or state transition applied.
    Ignored,
    /// Failure incremented to `count` below `fail_threshold`.
    FailCounted(u32),
    /// Threshold reached and hostname appended to the autohostlist pool and backing file.
    AddedToList,
    /// Threshold reached but hostname was already matched or excluded/exempted by profile hostlists.
    SkippedDuplicateOrExempt,
    /// Existing failure counter cleared due to healthy connection progress.
    ResetOnSuccess,
}

/// Returns `true` when wrapping 32-bit sequence `s` lies in `[s1, s2]` (`seq_within` in `helpers.c`).
pub const fn seq_within(s: u32, s1: u32, s2: u32) -> bool {
    (s2 >= s1 && s >= s1 && s <= s2) || (s2 < s1 && (s <= s2 || s >= s1))
}

/// Returns `true` when the latest outgoing TCP segment overlaps previously sent data (`is_retransmission`).
pub const fn is_tcp_retransmission(pos: &CtrackPosition) -> bool {
    pos.is_retransmission()
}

/// Borrowed profile context passed when recording or resetting autohostlist failures.
pub struct AutoHostlistRecordCtx<'a> {
    /// Active autohostlist thresholds for the profile.
    pub settings: &'a AutoHostlistSettings,
    /// Profile-local failure counter map.
    pub fail_pool: &'a mut HostFailPool,
    /// Profile include/exclude hostlist collection (containing `autolist_file`).
    pub hostlists: &'a HostlistCollection,
    /// Backing `--hostlist-auto` file wrapper updated in place on threshold hit.
    pub autolist_file: &'a Rc<RefCell<HostlistFile>>,
    /// Optional path to `--hostlist-auto-debug` file.
    pub debug_log: Option<&'a Path>,
    /// 1-based profile index for debug messages.
    pub profile_n: u32,
    /// Profile display name (or `"noname"`).
    pub profile_name: &'a str,
    /// Formatted client `ip:port` string when debug logging is enabled.
    pub client_label: &'a str,
    /// Connection L7 protocol tag.
    pub l7proto: L7Proto,
    /// Current monotonic boottime second.
    pub now_sec: i64,
}

impl AutoHostlistRecordCtx<'_> {
    /// Logs a profile-scoped event line if `self.debug_log` is configured.
    fn log(&self, hostname: &str, detail: &str) {
        log_autohost_detail(
            self.debug_log,
            hostname,
            (self.profile_n, self.profile_name, self.client_label, self.l7proto),
            detail,
        );
    }
}

/// Writes one formatted autohostlist diagnostic entry when `debug_log` is configured.
fn log_autohost_detail(
    debug_log: Option<&Path>,
    hostname: &str,
    meta: (u32, &str, &str, L7Proto),
    detail: &str,
) {
    let Some(path) = debug_log else {
        return;
    };
    let (profile_n, profile_name, client_label, l7proto) = meta;
    let line = format!(
        "{hostname} : profile {profile_n} ({profile_name}) : client {client_label} : proto {} : {detail}",
        l7proto.as_str()
    );
    let _ = append_timestamped_debug_log(path, &line);
}

/// Clears any pending failure counter for `hostname` upon healthy traffic progress.
pub fn reset_autohost_failure(
    fail_pool: &mut HostFailPool,
    hostname: &str,
    debug_log: Option<&Path>,
    profile_n: u32,
    profile_name: &str,
    client_label: &str,
    l7proto: L7Proto,
) -> AutoHostlistAction {
    if fail_pool.reset(hostname) {
        let detail = "fail counter reset. website is working.";
        log_autohost_detail(debug_log, hostname, (profile_n, profile_name, client_label, l7proto), detail);
        AutoHostlistAction::ResetOnSuccess
    } else {
        AutoHostlistAction::Ignored
    }
}

/// Records one detected failure for `hostname` and promotes it when `fail_threshold` is reached.
///
/// Mirrors `auto_hostlist_failed` in `zapret2/nfq2/desync.c:439-486`.
pub fn record_autohost_failure(
    ctx: &mut AutoHostlistRecordCtx<'_>,
    hostname: &str,
    no_subdomains: bool,
) -> AutoHostlistAction {
    let count = ctx
        .fail_pool
        .record_failure(hostname, ctx.settings.fail_time_sec, ctx.now_sec);
    ctx.log(hostname, &format!("fail counter {count}/{}", ctx.settings.fail_threshold));
    if count < ctx.settings.fail_threshold {
        return AutoHostlistAction::FailCounted(count);
    }

    ctx.fail_pool.reset(hostname);
    let outcome = ctx.hostlists.check(hostname, no_subdomains, false);
    if outcome.matched || outcome.excluded {
        ctx.log(hostname, "NOT adding, duplicate detected");
        return AutoHostlistAction::SkippedDuplicateOrExempt;
    }

    if let Some(path) = ctx.autolist_file.borrow().path.clone() {
        ctx.log(hostname, &format!("adding to {}", path.display()));
    }
    let mut auto = ctx.autolist_file.borrow_mut();
    auto.pool.add_host(hostname, 0);
    if let Some(path) = auto.path.clone() {
        if let Err(err) = append_to_list_file(&path, hostname) {
            eprintln!("write to auto hostlist '{}': {err}", path.display());
        } else if let Ok(sig) = FileModSig::read(&path) {
            auto.mod_sig = sig;
        }
    }

    AutoHostlistAction::AddedToList
}

/// Evaluates an outgoing payload segment for TCP retransmission failures (`auto_hostlist_retrans`).
pub fn check_tcp_retrans_trigger(entry: &mut CtrackEntry, settings: &AutoHostlistSettings) -> Option<bool> {
    if !entry.hostname_ah_check || entry.failure_detect_finalized || entry.req_retrans_counter == RETRANS_COUNTER_STOP {
        return None;
    }

    if entry.pos.ipproto == IPPROTO_TCP && entry.pos.state != ConnState::Syn {
        let client = &entry.pos.client;
        let max_seq = client.seq0.wrapping_add(settings.retrans_maxseq);
        if !seq_within(client.seq_last, client.seq0, max_seq) {
            entry.failure_detect_finalized = true;
            entry.req_retrans_counter = RETRANS_COUNTER_STOP;
            return Some(false);
        }
        if !is_tcp_retransmission(client) {
            return None;
        }
    }

    entry.req_retrans_counter = entry.req_retrans_counter.saturating_add(1);
    if entry.req_retrans_counter >= settings.retrans_threshold {
        entry.req_retrans_counter = RETRANS_COUNTER_STOP;
        entry.failure_detect_finalized = true;
        return Some(true);
    }
    None
}

/// Evaluates an incoming server TCP segment for RST or HTTP 302/307 DPI redirect failures.
pub fn check_tcp_incoming_trigger(
    entry: &mut CtrackEntry,
    tcp_flags: u8,
    payload: Option<&[u8]>,
    l7payload: L7Payload,
    settings: &AutoHostlistSettings,
) -> Option<bool> {
    if !entry.hostname_ah_check || entry.failure_detect_finalized || settings.incoming_maxseq == 0 {
        return None;
    }

    let server = &entry.pos.server;
    if server.seq_last.wrapping_sub(server.seq0) == 0 {
        return None;
    }
    if !seq_within(
        server.seq_last,
        server.seq0.wrapping_add(1),
        server.seq0.wrapping_add(settings.incoming_maxseq),
    ) {
        entry.failure_detect_finalized = true;
        return Some(false);
    }

    let is_fail = (tcp_flags & TH_RST) != 0
        || (l7payload == L7Payload::HttpReply
            && match (payload, entry.hostname.as_deref()) {
                (Some(data), Some(host)) if !data.is_empty() => {
                    http_reply_looks_like_dpi_redirect(data, host, entry.hostname_is_ip)
                }
                _ => false,
            });
    if !is_fail {
        return None;
    }
    entry.failure_detect_finalized = true;
    Some(true)
}

/// Evaluates UDP packet counters for unidirectional client stalls vs server replies (`process_udp_fail`).
pub fn check_udp_trigger(
    entry: &mut CtrackEntry,
    tpos: &CtrackPositions,
    settings: &AutoHostlistSettings,
) -> Option<bool> {
    if entry.hostname.is_none() || !entry.hostname_ah_check || entry.failure_detect_finalized || settings.udp_out == 0 {
        return None;
    }
    if tpos.server.pcounter > settings.udp_in {
        entry.failure_detect_finalized = true;
        Some(false)
    } else if tpos.client.pcounter >= settings.udp_out {
        entry.failure_detect_finalized = true;
        Some(true)
    } else {
        None
    }
}
