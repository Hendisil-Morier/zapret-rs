//! `mdig` multi-threaded DNS resolver, RFC 1035 query/reply codec, and CLI runner.

/// `mdig` configuration, domain validation helpers, and `libc::getaddrinfo` backend.
pub mod backend;
/// Shared `mdig` CLI runner (`run_mdig_cli`).
pub mod cli;
/// RFC 1035 DNS binary query constructor and reply parser for `mdig`.
pub mod dns;
/// Multi-threaded domain resolver worker pool, IP/CIDR filter, and stats tracking for `mdig`.
pub mod resolver;

/// Public API re-exports for `mdig` configuration, validation helpers, and resolver backends.
pub use backend::{
    DEFAULT_EAGAIN_ATTEMPTS, DEFAULT_EAGAIN_DELAY_MS, DEFAULT_MDIG_THREADS, DnsResolver,
    LibcResolver, MAX_EAGAIN_ATTEMPTS, MAX_EAGAIN_DELAY_MS, MAX_MDIG_THREADS, MdigConfig,
    MdigConfigError, ResolveError, beautify_invalid_domain, is_valid_domain,
};
/// Public API re-export for the shared `mdig` CLI entry point.
pub use cli::run_mdig_cli;
/// Public API re-exports for `mdig` binary DNS query building and reply parsing.
pub use dns::{
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, MDIG_DNS_REPLY_MAX, MdigDnsError, MdigFamily,
    build_dns_query, build_dns_query_with_id, parse_dns_reply, read_and_parse_dns_reply,
};
/// Public API re-exports for `mdig` multi-threaded domain resolution and synchronized outputs.
pub use resolver::{MdigOutputs, run_mdig_resolver};
