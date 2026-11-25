//! Companion CLI utilities ported from `zapret2` (`ip2net` and `mdig`).

/// IPv4/IPv6 single-address and CIDR subnet aggregator (`zapret2/ip2net`).
pub mod ip2net;

/// Public API re-exports for `ip2net` configuration, validation, and streaming execution.
pub use ip2net::{
    Ip2NetConfig, Ip2NetError, Ip2NetFamily, parse_prefix_length, parse_v4_threshold,
    parse_v6_threshold, run_ip2net,
};
