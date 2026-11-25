//! Rate-limited, TTL-expiring `(ip, iface)` cache for DNS hostnames and incoming TTLs.

/// Hash map storing per-endpoint cached hostnames and observed hop limits.
use std::collections::HashMap;
/// Unified IPv4/IPv6 key component (`ip4if` / `ip6if` in `pools.h`).
use std::net::IpAddr;

/// Default IPCache entry lifetime in seconds (`DEFAULT_IPCACHE_LIFETIME` = `7200`).
pub const DEFAULT_IPCACHE_LIFETIME_SEC: i64 = 7200;
/// Default maximum cached `(ip, iface)` entries retained concurrently (`0` disables cap).
pub const DEFAULT_IPCACHE_MAX_ENTRIES: usize = 65_536;

/// Cached metadata associated with one remote IP (and interface for TTL entries) (`ip_cache_item`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpCacheEntry {
    /// Monotonic boottime timestamp in seconds of the most recent access (`last`).
    pub last_sec: i64,
    /// Optional learned hostname associated with this IP (populated via DNS responses).
    pub hostname: Option<String>,
    /// `true` when `hostname` represents a literal IP address string.
    pub hostname_is_ip: bool,
    /// Cached incoming IPv4 TTL or IPv6 Hop Limit (`0` when unset).
    pub ttl: u8,
}

/// Time-expiring dual-stack IP cache keyed by `(IpAddr, iface)` (`ip_cache`).
#[derive(Debug)]
pub struct IpCache {
    /// Stored entries keyed by remote IP address and interface name (`""` for global hostname keys).
    entries: HashMap<(IpAddr, String), IpCacheEntry>,
    /// Entry expiration lifetime in seconds (`0` disables expiration).
    lifetime_sec: i64,
    /// Maximum cached `(ip, iface)` entries retained concurrently (`0` disables cap).
    max_entries: usize,
    /// Whether DNS-derived hostname caching is enabled (`params.cache_hostname`).
    cache_hostname: bool,
    /// Boottime second of the last executed purge sweep (`ipcache_purge_prev`).
    last_purge_sec: i64,
}

impl Default for IpCache {
    fn default() -> Self {
        Self::new(DEFAULT_IPCACHE_LIFETIME_SEC, false)
    }
}

impl IpCache {
    /// Creates an [`IpCache`] configured with `lifetime_sec` (`0` = never expire) and `cache_hostname`.
    pub fn new(lifetime_sec: i64, cache_hostname: bool) -> Self {
        Self {
            entries: HashMap::new(),
            lifetime_sec: lifetime_sec.max(0),
            max_entries: DEFAULT_IPCACHE_MAX_ENTRIES,
            cache_hostname,
            last_purge_sec: i64::MIN,
        }
    }

    /// Returns the configured maximum cached entry capacity (`0` = unbounded).
    pub const fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Configures the maximum cached `(ip, iface)` entry limit (`0` = unbounded).
    pub fn set_max_entries(&mut self, max_entries: usize) {
        self.max_entries = max_entries;
    }

    /// Returns the configured expiration lifetime in seconds (`0` disables expiry).
    pub fn lifetime_sec(&self) -> i64 {
        self.lifetime_sec
    }

    /// Returns whether hostname caching (`--ipcache-hostname`) is enabled.
    pub fn cache_hostname(&self) -> bool {
        self.cache_hostname
    }

    /// Returns the number of active cached `(ip, iface)` entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` when the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Removes all entries from the cache (`ipcacheDestroy`).
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Looks up an entry by `(addr, iface)` without refreshing its timestamp (`ipcacheFind`).
    pub fn find(&self, addr: IpAddr, iface: &str) -> Option<&IpCacheEntry> {
        self.entries.get(&(addr, iface.to_owned()))
    }

    /// Refreshes or inserts an entry for `(addr, iface)`, returning `None` if at capacity after expiry sweep.
    pub fn try_touch(&mut self, addr: IpAddr, iface: &str, now_sec: i64) -> Option<&mut IpCacheEntry> {
        let key = (addr, iface.to_owned());
        if !self.entries.contains_key(&key)
            && self.max_entries > 0
            && self.entries.len() >= self.max_entries
        {
            self.purge_rate_limited(now_sec);
            if self.entries.len() >= self.max_entries {
                return None;
            }
        }
        let entry = self.entries.entry(key).or_insert_with(|| IpCacheEntry {
            last_sec: now_sec,
            hostname: None,
            hostname_is_ip: false,
            ttl: 0,
        });
        entry.last_sec = now_sec;
        Some(entry)
    }

    /// Returns the entry for `(addr, iface)` after inserting/refreshing `last_sec` (`ipcacheTouch`).
    ///
    /// Evicts expired entries (or one existing entry when full) to uphold `max_entries`.
    pub fn touch(&mut self, addr: IpAddr, iface: &str, now_sec: i64) -> &mut IpCacheEntry {
        let key = (addr, iface.to_owned());
        if !self.entries.contains_key(&key)
            && self.max_entries > 0
            && self.entries.len() >= self.max_entries
        {
            self.purge_rate_limited(now_sec);
            if self.entries.len() >= self.max_entries
                && let Some(evict_key) = self.entries.keys().next().cloned()
            {
                self.entries.remove(&evict_key);
            }
        }
        let entry = self.entries.entry(key).or_insert_with(|| IpCacheEntry {
            last_sec: now_sec,
            hostname: None,
            hostname_is_ip: false,
            ttl: 0,
        });
        entry.last_sec = now_sec;
        entry
    }

    /// Caches `hostname` under global key `(addr, "")` when `cache_hostname` is enabled (`ipcache_put_hostname`).
    pub fn put_hostname(
        &mut self,
        addr: IpAddr,
        hostname: &str,
        hostname_is_ip: bool,
        now_sec: i64,
    ) {
        if !self.cache_hostname {
            return;
        }
        let Some(entry) = self.try_touch(addr, "", now_sec) else {
            return;
        };
        if entry.hostname.as_deref() != Some(hostname) {
            entry.hostname = Some(hostname.to_owned());
            entry.hostname_is_ip = hostname_is_ip;
        }
    }

    /// Retrieves a cached hostname for `addr` under global key `(addr, "")` (`ipcache_get_hostname`).
    pub fn get_hostname(&self, addr: IpAddr) -> Option<(&str, bool)> {
        if !self.cache_hostname {
            return None;
        }
        let entry = self.find(addr, "")?;
        entry
            .hostname
            .as_deref()
            .map(|h| (h, entry.hostname_is_ip))
    }

    /// Updates cached `(addr, iface)` TTL from `incoming_ttl`, or populates `incoming_ttl` from cache.
    ///
    /// Matches `ipcache_update_ttl` in `zapret2/nfq2/desync.c:780-810`: inactive in `server_mode`.
    pub fn update_ttl(
        &mut self,
        addr: IpAddr,
        iface: &str,
        incoming_ttl: &mut u8,
        server_mode: bool,
        now_sec: i64,
    ) {
        if server_mode {
            return;
        }
        if *incoming_ttl != 0 {
            if let Some(entry) = self.try_touch(addr, iface, now_sec) {
                entry.ttl = *incoming_ttl;
            }
        } else if let Some(cached) = self.get_ttl(addr, iface, server_mode) {
            *incoming_ttl = cached;
        }
    }

    /// Looks up a non-zero cached TTL for `(addr, iface)` in client mode (`ipcache_get_ttl`).
    pub fn get_ttl(&self, addr: IpAddr, iface: &str, server_mode: bool) -> Option<u8> {
        if server_mode {
            return None;
        }
        self.find(addr, iface)
            .map(|e| e.ttl)
            .filter(|&ttl| ttl != 0)
    }

    /// Evicts entries whose `last_sec + lifetime_sec <= now_sec` when `lifetime_sec > 0`.
    pub fn purge(&mut self, now_sec: i64) {
        if self.lifetime_sec == 0 {
            return;
        }
        let lifetime = self.lifetime_sec;
        self.entries
            .retain(|_, entry| now_sec < entry.last_sec.saturating_add(lifetime));
    }

    /// Runs [`Self::purge`] at most once per monotonic boottime second (`ipcachePurgeRateLimited`).
    pub fn purge_rate_limited(&mut self, now_sec: i64) {
        if self.last_purge_sec != now_sec {
            self.purge(now_sec);
            self.last_purge_sec = now_sec;
        }
    }
}
