//! Bounded per-profile autohostlist failure tracking pool (`hostfail_pool` in `pools.c`).

/// Map storing active per-hostname failure counters keyed by sanitized lowercase host.
use std::collections::HashMap;
/// IP literal parser used to exclude bare IP addresses from parent-domain collapsing.
use std::net::IpAddr;

/// Public-suffix-safe second/third-level domain finder shared with protocol helpers.
use crate::protocol::{find_nld, sanitize_wire_hostname};

/// Default maximum tracked hostnames inside a single [`HostFailPool`].
pub const DEFAULT_MAX_HOSTFAIL_ENTRIES: usize = 16_384;
/// Maximum distinct failing subdomains retained per parent domain before cap stops growing.
const MAX_SIBLINGS_PER_PARENT: usize = 16;

/// Trailing generic second-level labels frequently used under two-letter country TLDs (`co.uk`, `com.au`, etc.).
const GENERIC_CCTLD_SLDS: &[&str] = &[
    "co", "com", "net", "org", "gov", "edu", "ac", "mil", "nom", "gob", "or", "ne", "gr", "ed", "go", "lg",
    "pp", "msk", "spb",
];

/// Multi-tenant SaaS/CDN root domains whose subdomains must never collapse into a wildcard parent rule.
const MULTI_TENANT_PARENTS: &[&str] = &[
    "github.io",
    "gitlab.io",
    "pages.dev",
    "workers.dev",
    "blogspot.com",
    "herokuapp.com",
    "appspot.com",
    "amazonaws.com",
    "cloudfront.net",
    "fastly.net",
    "akamaiedge.net",
    "azurewebsites.net",
];

/// Derives a safe parent domain for sibling subdomain consolidation (e.g. `a.site.com` -> `site.com`).
///
/// Avoids over-broad collapse onto two-label country SLDs (`co.uk`) or multi-tenant CDN/PaaS roots (`github.io`).
pub fn safe_parent_domain(host: &str) -> Option<&str>
{
    if host.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    let (n2_off, _) = find_nld(host.as_bytes(), 2)?;
    if n2_off == 0
    {
        return None;
    }
    let two_label = &host[n2_off..];
    if let Some((sld, tld)) = two_label.split_once('.')
        && tld.len() == 2
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && GENERIC_CCTLD_SLDS.contains(&sld)
    {
        let (n3_off, _) = find_nld(host.as_bytes(), 3)?;
        return (n3_off > 0).then(|| &host[n3_off..]);
    }
    if MULTI_TENANT_PARENTS.contains(&two_label)
    {
        return None;
    }
    Some(two_label)
}

/// Active failure counter entry for one hostname inside [`HostFailPool`] (`hostfail_pool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFailEntry
{
    /// Number of observed failures since initial insertion.
    pub counter: u32,
    /// Fixed monotonic boottime expiration second (`initial_now + fail_time_sec`).
    pub expire_sec: i64,
    /// Monotonic boottime second when the most recent failure was counted (for burst coalescing).
    pub last_fail_sec: i64,
}

/// Bounded set of distinct failing child subdomains under one parent domain within a time window.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SiblingFailEntry
{
    /// Distinct lowercase child hostnames that failed inside `[initial_now, expire_sec)`.
    subs: Vec<String>,
    /// Fixed monotonic boottime expiration second matching `fail_time_sec`.
    expire_sec: i64,
}

/// Time-windowed, capacity-bounded per-profile failure counter map (`hostfail_pool` in `pools.c`).
#[derive(Debug)]
pub struct HostFailPool
{
    /// Active failure counters keyed by lowercase hostname.
    entries: HashMap<String, HostFailEntry>,
    /// Active sibling-domain failure sets keyed by safe parent domain.
    siblings: HashMap<String, SiblingFailEntry>,
    /// Boottime second of the previous purge sweep (`purge_prev`).
    last_purge_sec: i64,
    /// Maximum tracked entries retained before purging and evicting the oldest record.
    max_entries: usize,
}

impl Default for HostFailPool
{
    fn default() -> Self
    {
        Self::with_max_entries(DEFAULT_MAX_HOSTFAIL_ENTRIES)
    }
}

impl HostFailPool
{
    /// Creates an empty [`HostFailPool`] with the default entry limit.
    pub fn new() -> Self
    {
        Self::default()
    }

    /// Creates an empty [`HostFailPool`] capped at `max_entries` simultaneous keys.
    pub fn with_max_entries(max_entries: usize) -> Self
    {
        Self {
            entries: HashMap::new(),
            siblings: HashMap::new(),
            last_purge_sec: i64::MIN,
            max_entries: max_entries.max(1),
        }
    }

    /// Returns the number of tracked hostnames in this pool.
    pub fn len(&self) -> usize
    {
        self.entries.len()
    }

    /// Returns `true` when no failure entries are active.
    pub fn is_empty(&self) -> bool
    {
        self.entries.is_empty()
    }

    /// Looks up the active counter record for `host` (`HostFailPoolFind`).
    pub fn get(&self, host: &str) -> Option<&HostFailEntry>
    {
        self.entries.get(host)
    }

    /// Removes `host` from active fail counters and any tracked sibling list, returning `true` if present.
    pub fn reset(&mut self, host: &str) -> bool
    {
        if let Some(parent) = safe_parent_domain(host)
            && let Some(sib) = self.siblings.get_mut(parent)
        {
            sib.subs.retain(|sub| sub != host);
            if sib.subs.is_empty()
            {
                self.siblings.remove(parent);
            }
        }
        self.entries.remove(host).is_some()
    }

    /// Increments the failure count for sanitized `host` with zero cooldown (`record_failure` parity).
    pub fn record_failure(&mut self, host: &str, fail_time_sec: i64, now_sec: i64) -> u32
    {
        self.record_failure_with_cooldown(host, fail_time_sec, 0, now_sec)
    }

    /// Increments the failure count for sanitized `host`, coalescing bursts within `cooldown_sec`.
    pub fn record_failure_with_cooldown(
        &mut self,
        host: &str,
        fail_time_sec: i64,
        cooldown_sec: i64,
        now_sec: i64,
    ) -> u32
    {
        let Some(clean) = sanitize_wire_hostname(host)
        else
        {
            return 0;
        };
        if self.entries.get(&clean).is_some_and(|e| now_sec >= e.expire_sec)
        {
            self.entries.remove(&clean);
        }
        if let Some(existing) = self.entries.get(&clean)
            && cooldown_sec > 0
            && now_sec >= existing.last_fail_sec
            && now_sec.saturating_sub(existing.last_fail_sec) < cooldown_sec
        {
            return 0;
        }
        if !self.entries.contains_key(&clean) && self.entries.len() >= self.max_entries
        {
            self.purge(now_sec);
            while self.entries.len() >= self.max_entries
            {
                let oldest = self
                    .entries
                    .iter()
                    .min_by(|(ka, va), (kb, vb)| va.expire_sec.cmp(&vb.expire_sec).then_with(|| ka.cmp(kb)))
                    .map(|(k, _)| k.clone());
                let Some(evict_key) = oldest
                else
                {
                    break;
                };
                self.entries.remove(&evict_key);
            }
        }
        let expire_sec = now_sec.saturating_add(fail_time_sec);
        if let Some(entry) = self.entries.get_mut(&clean)
        {
            entry.counter = entry.counter.saturating_add(1);
            entry.last_fail_sec = now_sec;
            entry.counter
        }
        else
        {
            self.entries.insert(clean, HostFailEntry { counter: 1, expire_sec, last_fail_sec: now_sec });
            1
        }
    }

    /// Tracks `child_host` under its safe parent domain and returns the parent once `sibling_threshold` distinct children fail.
    pub fn record_sibling_failure(
        &mut self,
        child_host: &str,
        fail_time_sec: i64,
        sibling_threshold: u32,
        now_sec: i64,
    ) -> Option<String>
    {
        if sibling_threshold < 2
        {
            return None;
        }
        let parent = safe_parent_domain(child_host)?.to_owned();
        if self.siblings.get(&parent).is_some_and(|s| now_sec >= s.expire_sec)
        {
            self.siblings.remove(&parent);
        }
        if !self.siblings.contains_key(&parent) && self.siblings.len() >= self.max_entries
        {
            self.purge(now_sec);
            if self.siblings.len() >= self.max_entries
            {
                return None;
            }
        }
        let expire_sec = now_sec.saturating_add(fail_time_sec);
        let entry = self
            .siblings
            .entry(parent.clone())
            .or_insert_with(|| SiblingFailEntry { subs: Vec::new(), expire_sec });
        if entry.subs.len() < MAX_SIBLINGS_PER_PARENT && !entry.subs.iter().any(|s| s == child_host)
        {
            entry.subs.push(child_host.to_owned());
        }
        if entry.subs.len() as u32 >= sibling_threshold
        {
            self.siblings.remove(&parent);
            Some(parent)
        }
        else
        {
            None
        }
    }

    /// Evicts all expired failure and sibling entries where `now_sec >= expire_sec` (`HostFailPoolPurge`).
    pub fn purge(&mut self, now_sec: i64)
    {
        self.entries.retain(|_, entry| now_sec < entry.expire_sec);
        self.siblings.retain(|_, entry| now_sec < entry.expire_sec);
    }

    /// Runs [`Self::purge`] at most once per boottime second (`HostFailPoolPurgeRateLimited`).
    pub fn purge_rate_limited(&mut self, now_sec: i64)
    {
        if self.last_purge_sec != now_sec
        {
            self.purge(now_sec);
            self.last_purge_sec = now_sec;
        }
    }
}
