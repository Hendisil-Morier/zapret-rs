//! Companion CLI utilities and daemon/finder entry points (`nfqws2`, `ip2net`, `mdig`, `strat_finder`).

/// Shared `nfqws2` daemon CLI runner (`run_nfqws2_cli`).
pub mod daemon_cli;
/// Linux `nfqws2` NFQUEUE daemon startup and event loop runtime.
#[cfg(target_os = "linux")]
pub mod daemon_runtime;
/// OS-agnostic firewall rule backend contract and target port collector.
pub mod firewall;
/// Self-installing CLI (`install` / `uninstall`) for binary, Lua scripts, caps, and systemd.
pub mod installer;
/// IPv4/IPv6 single-address and CIDR subnet aggregator (`zapret2/ip2net`).
pub mod ip2net;
/// Shared `ip2net` CLI runner (`run_ip2net_cli`).
pub mod ip2net_cli;
/// Compile-time bundled Lua scripts and fallback extractor into user/system data paths.
pub mod lua_bundle;
/// `mdig` configuration, domain validation helpers, and `libc::getaddrinfo` backend.
pub mod mdig_backend;
/// Shared `mdig` CLI runner (`run_mdig_cli`).
pub mod mdig_cli;
/// BusyBox-style multicall dispatcher mapping `argv[0]` symlinks and subcommands to applets.
pub mod multicall;
/// RFC 1035 DNS binary query constructor and reply parser for `mdig`.
pub mod mdig_dns;
/// Multi-threaded domain resolver worker pool, IP/CIDR filter, and stats tracking for `mdig`.
pub mod mdig_resolver;
/// Timed `curl` samples (connect, first byte, throughput) for before/after speed comparison.
pub mod speed_probe;
/// Strategy candidate catalog ported from `zapret2/blockcheck2.d/standard/*.sh`.
pub mod strat_catalog;
/// Shared CLI runner powering both `nfqws2 --strat-finder` and the standalone `strat_finder` binary.
pub mod strat_cli;
/// Interactive terminal setup wizard for `strat_finder`.
pub mod strat_interactive;
/// Windows WinDivert filter-expression [`FirewallBackend`] implementation.
#[cfg(windows)]
pub mod strat_windivert;
/// Temporary `nftables` NFQUEUE rule management with RAII teardown (`zapret_strat_finder`).
pub mod strat_nft;
/// HTTP/TLS/QUIC connectivity probe backends (`curl` + mockable trait).
pub mod strat_probe;
/// In-process NFQUEUE desync worker thread and multi-domain strategy scan orchestrator.
pub mod strat_runner;
/// Strategy ranking, minimal cross-domain set cover, and `nfqws2.toml` serialization.
pub mod strat_toml;
/// Non-destructive `nfqws2.toml` profile merging and hostlist domain extraction helpers.
pub mod strat_merge;

/// Public API re-exports for self-installation (`install` / `uninstall`) and systemd rendering.
pub use installer::{
    SYMLINK_NAMES, render_systemd_service, run_install_cli, run_uninstall_cli,
};
/// Public API re-exports for `ip2net` configuration, validation, and streaming execution.
pub use ip2net::{
    Ip2NetConfig, Ip2NetError, Ip2NetFamily, parse_prefix_length, parse_v4_threshold,
    parse_v6_threshold, run_ip2net,
};
/// Public API re-export for the shared `ip2net` CLI entry point.
pub use ip2net_cli::run_ip2net_cli;
/// Public API re-exports for `mdig` configuration, validation helpers, and resolver backends.
pub use mdig_backend::{
    DEFAULT_EAGAIN_ATTEMPTS, DEFAULT_EAGAIN_DELAY_MS, DEFAULT_MDIG_THREADS, DnsResolver,
    LibcResolver, MAX_EAGAIN_ATTEMPTS, MAX_EAGAIN_DELAY_MS, MAX_MDIG_THREADS, MdigConfig,
    MdigConfigError, ResolveError, beautify_invalid_domain, is_valid_domain,
};
/// Public API re-export for the shared `mdig` CLI entry point.
pub use mdig_cli::run_mdig_cli;
/// Public API re-exports for multicall `argv[0]` symlink and subcommand routing.
pub use multicall::{
    MulticallApplet, dispatch_headless_applet, resolve_argv0_applet, resolve_multicall,
    resolve_subcommand_applet,
};
/// Public API re-exports for `mdig` binary DNS query building and reply parsing.
pub use mdig_dns::{
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, MDIG_DNS_REPLY_MAX, MdigDnsError, MdigFamily,
    build_dns_query, build_dns_query_with_id, parse_dns_reply, read_and_parse_dns_reply,
};
/// Public API re-exports for `mdig` multi-threaded domain resolution and synchronized outputs.
pub use mdig_resolver::{MdigOutputs, run_mdig_resolver};
/// Public API re-exports for timed speed samples and their fixed control target.
pub use speed_probe::{
    CONTROL_HOST, SpeedSample, SpeedTarget, control_target, domain_target, measure,
    parse_timing_lines,
};
/// Public API re-exports for `strat_finder` strategy catalog expansion.
pub use strat_catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Public API re-exports for `strat_finder` CLI entry point and `nfqws2 --strat-finder` dispatch.
pub use strat_cli::{
    DEFAULT_STRAT_QNUM, StratFinderCli, extract_strat_finder_args, run_strat_finder,
    run_strat_finder_cli,
};
/// Public API re-exports for `strat_finder` interactive terminal wizard and config path defaults.
pub use strat_interactive::{
    InteractiveDefaults, InteractiveSelections, default_output_config_path, expand_tilde,
    normalize_domain, prompt_interactive_wizard,
};
/// Public API re-exports for compile-time bundled Lua scripts, discovery, and XDG extraction.
pub use lua_bundle::{
    BUNDLED_LUA_SCRIPTS, default_user_lua_dir, detect_lua_dir, extract_bundled_lua,
    resolve_lua_scripts,
};
/// Public API re-exports for OS-agnostic firewall backend traits and port collection.
pub use firewall::{FirewallBackend, FirewallHandle, collect_config_ports};
/// Public API re-exports for Windows WinDivert filter [`FirewallBackend`].
#[cfg(windows)]
pub use strat_windivert::{WinDivertFilterGuard, WinDivertFirewallBackend, build_windivert_filter};
/// Public API re-export for the shared `nfqws2` daemon CLI entry point.
pub use daemon_cli::run_nfqws2_cli;
/// Public API re-exports for `strat_finder` temporary `nftables` firewall management.
pub use strat_nft::{
    NftFirewallBackend, NftQueueGuard, STRAT_FINDER_NFT_TABLE, build_nft_cleanup_cmd,
    is_nft_perm_denied, sudo_needs_password,
};
/// Public API re-exports for `strat_finder` connectivity probes and outcome classification.
pub use strat_probe::{
    CurlProbeBackend, PROBE_WRITE_OUT, ProbeBackend, ProbeOutcome, ProbeRequest,
    classify_curl_output, is_spoof_redirect,
};
/// Public API re-exports for `strat_finder` NFQUEUE worker and multi-domain scan orchestration.
pub use strat_runner::{
    InProcessWorkerHandle, ProgressEvent, ScanConfig, ScanReport, StrategyApplier,
    TargetScanResult, run_scan,
};
/// Public API re-exports for `strat_finder` ranking, set cover, and TOML rendering.
pub use strat_toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, TomlRenderOptions, rank_matches,
    render_nfqws2_toml, select_minimal_cover, write_config_nofollow,
};
/// Public API re-exports for non-destructive `nfqws2.toml` merging and domain extraction.
pub use strat_merge::{
    DEFAULT_AUTOHOSTLIST_FILE, DomainScope, extract_hostlist_domains, merge_nfqws2_toml,
    render_nfqws2_toml_scoped,
};
