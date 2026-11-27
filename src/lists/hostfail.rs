//! Bounded per-profile autohostlist failure tracking pool (`hostfail_pool` in `pools.c`).

/// Map storing active per-hostname failure counters keyed by sanitized lowercase host.
use std::collections::HashMap;

/// Capacity cap and wire hostname sanitizer shared with hostlist pools.
use crate::lists::host_sanitize::{DEFAULT_MAX_HOSTFAIL_ENTRIES, sanitize_wire_hostname};

/// Active failure counter entry for one hostname inside [`HostFailPool`] (`hostfail_pool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFailEntry {
    /// Number of observed failures since initial insertion.
    pub counter: u32,
    /// Fixed monotonic boottime expiration second (`initial_now + fail_time_sec`).
    pub expire_sec: i64,
}

/// Time-windowed, capacity-bounded per-profile failure counter map (`hostfail_pool` in `pools.c`).
#[derive(Debug)]
pub struct HostFailPool {
    /// Active failure counters keyed by lowercase hostname.
    entries: HashMap<String, HostFailEntry>,
    /// Boottime second of the previous purge sweep (`purge_prev`).
    last_purge_sec: i64,
    /// Maximum tracked entries retained before purging and evicting the oldest record.
    max_entries: usize,
}

impl Default for HostFailPool {
    fn default() -> Self {
        Self::with_max_entries(DEFAULT_MAX_HOSTFAIL_ENTRIES)
    }
}

impl HostFailPool {
    /// Creates an empty [`HostFailPool`] with the default entry limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates an empty [`HostFailPool`] capped at `max_entries` simultaneous keys.
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            last_purge_sec: i64::MIN,
            max_entries: max_entries.max(1),
        }
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

    /// Increments the failure count for sanitized `host` without refreshing its initial expiration.
    pub fn record_failure(&mut self, host: &str, fail_time_sec: i64, now_sec: i64) -> u32 {
        let Some(clean) = sanitize_wire_hostname(host) else {
            return 0;
        };
        if self.entries.get(&clean).is_some_and(|e| now_sec >= e.expire_sec) {
            self.entries.remove(&clean);
        }
        if !self.entries.contains_key(&clean) && self.entries.len() >= self.max_entries {
            self.purge(now_sec);
            while self.entries.len() >= self.max_entries {
                let oldest = self
                    .entries
                    .iter()
                    .min_by(|(ka, va), (kb, vb)| va.expire_sec.cmp(&vb.expire_sec).then_with(|| ka.cmp(kb)))
                    .map(|(k, _)| k.clone());
                let Some(evict_key) = oldest else {
                    break;
                };
                self.entries.remove(&evict_key);
            }
        }
        let expire_sec = now_sec.saturating_add(fail_time_sec);
        let entry = self
            .entries
            .entry(clean)
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
