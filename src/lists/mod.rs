//! Gzip/plain list loading, domain hostlists, autohostlists, disjoint CIDR IPsets, and TTL IPCache.

/// Autohostlist failure counters, TCP/UDP failure triggers, and persistent self-append helpers.
pub mod autohostlist;
/// Plaintext/gzip streaming list readers, modification signatures, and append/debug-log writers.
pub mod file_loader;
/// Domain hostlist pools, `^`/`!` matching flags, reload checks, and include/exclude collections.
pub mod hostlist;
/// Time-expiring dual-stack `(ip, iface)` hostname and incoming-TTL cache.
pub mod ipcache;
/// Disjoint IPv4/IPv6 CIDR prefix sets, gzip/plain ipset loaders, and dual-IP collections.
pub mod ipset;

pub use autohostlist::{
    AutoHostlistAction, AutoHostlistRecordCtx, AutoHostlistSettings, HostFailEntry, HostFailPool,
    MAX_AUTOHOSTLIST_FAIL_THRESHOLD, MAX_AUTOHOSTLIST_RETRANS_THRESHOLD,
    MIN_AUTOHOSTLIST_FAIL_THRESHOLD, MIN_AUTOHOSTLIST_RETRANS_THRESHOLD,
    check_tcp_incoming_trigger, check_tcp_retrans_trigger, check_udp_trigger,
    is_tcp_retransmission, record_autohost_failure, reset_autohost_failure, seq_within,
};

pub use file_loader::{
    FileModSig, append_timestamped_debug_log, append_to_list_file, detect_gzip_and_rewind,
    file_is_readable, parse_list_line_token, read_list_lines,
};
pub use hostlist::{
    EMPTY_AUTOLIST_SENTINEL, HOSTLIST_FLAG_EXEMPT, HOSTLIST_FLAG_STRICT_MATCH,
    HostlistCheckOutcome, HostlistCollection, HostlistFile, HostlistPool, HostlistRef,
    HostlistSearchResult,
};
pub use ipcache::{DEFAULT_IPCACHE_LIFETIME_SEC, DEFAULT_IPCACHE_MAX_ENTRIES, IpCache, IpCacheEntry};
pub use ipset::{IpSet, IpsetCollection, IpsetFile, parse_cidr4, parse_cidr6};
