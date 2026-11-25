//! Companion CLI utilities ported from `zapret2` (`ip2net` and `mdig`).

/// IPv4/IPv6 single-address and CIDR subnet aggregator (`zapret2/ip2net`).
pub mod ip2net;
/// `mdig` configuration, domain validation helpers, and `libc::getaddrinfo` backend.
pub mod mdig_backend;
/// RFC 1035 DNS binary query constructor and reply parser for `mdig`.
pub mod mdig_dns;
/// Multi-threaded domain resolver worker pool, IP/CIDR filter, and stats tracking for `mdig`.
pub mod mdig_resolver;
/// Strategy candidate catalog ported from `zapret2/blockcheck2.d/standard/*.sh`.
pub mod strat_catalog;
/// Strategy ranking, minimal cross-domain set cover, and `nfqws2.toml` serialization.
pub mod strat_toml;

/// Public API re-exports for `ip2net` configuration, validation, and streaming execution.
pub use ip2net::{
    Ip2NetConfig, Ip2NetError, Ip2NetFamily, parse_prefix_length, parse_v4_threshold,
    parse_v6_threshold, run_ip2net,
};
/// Public API re-exports for `mdig` configuration, validation helpers, and resolver backends.
pub use mdig_backend::{
    DEFAULT_EAGAIN_ATTEMPTS, DEFAULT_EAGAIN_DELAY_MS, DEFAULT_MDIG_THREADS, DnsResolver,
    LibcResolver, MAX_EAGAIN_ATTEMPTS, MAX_EAGAIN_DELAY_MS, MAX_MDIG_THREADS, MdigConfig,
    MdigConfigError, ResolveError, beautify_invalid_domain, is_valid_domain,
};
/// Public API re-exports for `mdig` binary DNS query building and reply parsing.
pub use mdig_dns::{
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, MDIG_DNS_REPLY_MAX, MdigDnsError, MdigFamily,
    build_dns_query, build_dns_query_with_id, parse_dns_reply, read_and_parse_dns_reply,
};
/// Public API re-exports for `mdig` multi-threaded domain resolution and synchronized outputs.
pub use mdig_resolver::{MdigOutputs, run_mdig_resolver};
/// Public API re-exports for `strat_finder` strategy catalog expansion.
pub use strat_catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Public API re-exports for `strat_finder` ranking, set cover, and TOML rendering.
pub use strat_toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, TomlRenderOptions, rank_matches,
    render_nfqws2_toml, select_minimal_cover,
};
