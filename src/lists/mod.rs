//! Gzip/plain list loading, domain hostlists, disjoint CIDR IPsets, and TTL IPCache.

/// Plaintext/gzip streaming list readers, modification signatures, and append/debug-log writers.
pub mod file_loader;
/// Domain hostlist pools, `^`/`!` matching flags, reload checks, and include/exclude collections.
pub mod hostlist;
/// Time-expiring dual-stack `(ip, iface)` hostname and incoming-TTL cache.
pub mod ipcache;
/// Disjoint IPv4/IPv6 CIDR prefix sets, gzip/plain ipset loaders, and dual-IP collections.
pub mod ipset;

pub use file_loader::{
    FileModSig, append_timestamped_debug_log, append_to_list_file, file_is_readable,
    parse_list_line_token, read_list_lines,
};
pub use hostlist::{
    EMPTY_AUTOLIST_SENTINEL, HOSTLIST_FLAG_EXEMPT, HOSTLIST_FLAG_STRICT_MATCH,
    HostlistCheckOutcome, HostlistCollection, HostlistFile, HostlistPool, HostlistRef,
    HostlistSearchResult,
};
pub use ipcache::{DEFAULT_IPCACHE_LIFETIME_SEC, IpCache, IpCacheEntry};
pub use ipset::{IpSet, IpsetCollection, IpsetFile, parse_cidr4, parse_cidr6};
