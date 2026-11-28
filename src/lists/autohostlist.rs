//! Autohostlist failure counters, burst coalescing, sibling propagation, and self-append logic.

/// Interior mutability for updating the profile's shared autohostlist file in place.
use std::cell::RefCell;
/// Optional autohostlist debug log file path.
use std::path::Path;
/// Shared reference handle to the profile's autohostlist [`HostlistFile`].
use std::rc::Rc;

/// Persistent list-file append, timestamped debug log, and mtime signature refresh helpers.
use crate::lists::file_loader::{FileModSig, append_timestamped_debug_log, append_to_list_file};
/// Bounded per-profile failure counter pool (`HostFailPool`).
use crate::lists::hostfail::HostFailPool;
/// Hostlist collections and underlying file-backed hostname pools.
use crate::lists::hostlist::{HostlistCollection, HostlistFile};
/// L7 protocol tag and wire hostname sanitizer preventing directive injection.
use crate::protocol::{L7Proto, sanitize_wire_hostname};

/// Default maximum in-memory and appended entries permitted in a `--hostlist-auto` pool.
pub const DEFAULT_MAX_AUTOHOSTLIST_ENTRIES: usize = 65_536;

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
pub struct AutoHostlistSettings
{
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
    /// Maximum initial relative server TCP sequence watched for RST/Alert/FIN/HTTP failures (`4096`).
    pub incoming_maxseq: u32,
    /// Minimum outgoing UDP packet count required to declare a UDP stall failure (`4`, `0` disables).
    pub udp_out: u64,
    /// Maximum incoming UDP packet count still considered a UDP failure (`1`).
    pub udp_in: u64,
    /// Minimum seconds between counted failures for the same hostname to coalesce parallel bursts (`2`, `0` disables).
    pub fail_cooldown_sec: i64,
    /// Distinct failing subdomains inside `fail_time_sec` required to promote their safe parent domain (`2`, `0` disables).
    pub sibling_threshold: u32,
    /// Run a non-blocking background TCP/TLS/HTTP confirmation probe before/alongside passive promotion (`false`).
    pub confirm_block: bool,
}

impl Default for AutoHostlistSettings
{
    fn default() -> Self
    {
        Self {
            fail_threshold: 3,
            fail_time_sec: 60,
            retrans_threshold: 3,
            retrans_maxseq: 32_768,
            retrans_reset: true,
            incoming_maxseq: 4_096,
            udp_out: 4,
            udp_in: 1,
            fail_cooldown_sec: 2,
            sibling_threshold: 2,
            confirm_block: false,
        }
    }
}

impl AutoHostlistSettings
{
    /// Validates CLI/TOML threshold bounds matching `nfqws.c`.
    pub fn validate(&self) -> Result<(), &'static str>
    {
        let valid_fail = MIN_AUTOHOSTLIST_FAIL_THRESHOLD..=MAX_AUTOHOSTLIST_FAIL_THRESHOLD;
        let valid_retrans = MIN_AUTOHOSTLIST_RETRANS_THRESHOLD..=MAX_AUTOHOSTLIST_RETRANS_THRESHOLD;
        if !valid_fail.contains(&self.fail_threshold)
        {
            return Err("auto hostlist fail threshold must be in 1..=20");
        }
        if self.fail_time_sec < 1
        {
            return Err("auto hostlist fail time must be >= 1");
        }
        if !valid_retrans.contains(&self.retrans_threshold)
        {
            return Err("auto hostlist retrans threshold must be in 2..=10");
        }
        if self.fail_cooldown_sec < 0
        {
            return Err("auto hostlist fail cooldown must be >= 0");
        }
        if self.sibling_threshold == 1
        {
            return Err("auto hostlist sibling threshold must be 0 or >= 2");
        }
        Ok(())
    }
}

/// High-level action taken by [`record_autohost_failure`] or [`reset_autohost_failure`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoHostlistAction
{
    /// No tracking or state transition applied (invalid host, cap reached, or burst-coalesced).
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

/// Borrowed profile context passed when recording or promoting autohostlist failures.
pub struct AutoHostlistRecordCtx<'a>
{
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

impl AutoHostlistRecordCtx<'_>
{
    /// Logs a profile-scoped event line if `self.debug_log` is configured.
    fn log(&self, hostname: &str, detail: &str)
    {
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
)
{
    let Some(path) = debug_log
    else
    {
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
) -> AutoHostlistAction
{
    if fail_pool.reset(hostname)
    {
        let detail = "fail counter reset. website is working.";
        log_autohost_detail(debug_log, hostname, (profile_n, profile_name, client_label, l7proto), detail);
        AutoHostlistAction::ResetOnSuccess
    }
    else
    {
        AutoHostlistAction::Ignored
    }
}

/// Promotes sanitized `clean_host` into `ctx.autolist_file` after duplicate, exempt, and cap checks.
pub fn promote_autohost(
    ctx: &AutoHostlistRecordCtx<'_>,
    clean_host: &str,
    no_subdomains: bool,
) -> AutoHostlistAction
{
    let outcome = ctx.hostlists.check(clean_host, no_subdomains, false);
    if outcome.matched || outcome.excluded
    {
        ctx.log(clean_host, "NOT adding, duplicate detected");
        return AutoHostlistAction::SkippedDuplicateOrExempt;
    }

    let (at_cap, auto_path) = {
        let auto = ctx.autolist_file.borrow();
        (auto.pool.len() >= DEFAULT_MAX_AUTOHOSTLIST_ENTRIES, auto.path.clone())
    };
    if at_cap
    {
        ctx.log(clean_host, "NOT adding, autohostlist entry limit reached");
        return AutoHostlistAction::Ignored;
    }
    if let Some(path) = auto_path.as_ref()
    {
        ctx.log(clean_host, &format!("adding to {}", path.display()));
    }
    let mut auto = ctx.autolist_file.borrow_mut();
    auto.pool.add_host(clean_host, 0);
    if let Some(path) = auto_path
    {
        if let Err(err) = append_to_list_file(&path, clean_host)
        {
            eprintln!("write to auto hostlist '{}': {err}", path.display());
        }
        else if let Ok(sig) = FileModSig::read(&path)
        {
            auto.mod_sig = sig;
        }
    }

    AutoHostlistAction::AddedToList
}

/// Records one detected failure for `hostname` and promotes it (or a failing sibling parent) at threshold.
///
/// Mirrors `auto_hostlist_failed` in `zapret2/nfq2/desync.c:439-486` with cooldown and sibling rollups.
pub fn record_autohost_failure(
    ctx: &mut AutoHostlistRecordCtx<'_>,
    hostname: &str,
    no_subdomains: bool,
) -> AutoHostlistAction
{
    let Some(clean_host) = sanitize_wire_hostname(hostname)
    else
    {
        return AutoHostlistAction::Ignored;
    };
    let count = ctx.fail_pool.record_failure_with_cooldown(
        &clean_host,
        ctx.settings.fail_time_sec,
        ctx.settings.fail_cooldown_sec,
        ctx.now_sec,
    );
    if count == 0
    {
        return AutoHostlistAction::Ignored;
    }
    ctx.log(&clean_host, &format!("fail counter {count}/{}", ctx.settings.fail_threshold));

    if !no_subdomains
        && ctx.settings.sibling_threshold >= 2
        && let Some(parent) = ctx.fail_pool.record_sibling_failure(
            &clean_host,
            ctx.settings.fail_time_sec,
            ctx.settings.sibling_threshold,
            ctx.now_sec,
        )
        && promote_autohost(ctx, &parent, false) == AutoHostlistAction::AddedToList
    {
        ctx.fail_pool.reset(&clean_host);
        return AutoHostlistAction::AddedToList;
    }

    if count < ctx.settings.fail_threshold
    {
        return AutoHostlistAction::FailCounted(count);
    }

    ctx.fail_pool.reset(&clean_host);
    promote_autohost(ctx, &clean_host, no_subdomains)
}
