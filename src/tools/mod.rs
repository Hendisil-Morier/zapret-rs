//! Companion CLI utilities and daemon/finder entry points (`nfqws2`, `ip2net`, `mdig`, `strat_finder`).

/// Daemon CLI dispatcher and Linux/Windows event-loop runtimes.
pub mod daemon;
/// OS-level DNS and encrypted DNS (DoH/DoT) preset manager and CLI (`dns`).
pub mod dns;
/// Self-installing CLI (`install` / `uninstall`) for binary, Lua scripts, caps, and systemd.
pub mod installer;
/// IPv4/IPv6 single-address and CIDR subnet aggregator (`zapret2/ip2net`).
pub mod ip2net;
/// Shared `ip2net` CLI runner (`run_ip2net_cli`).
pub mod ip2net_cli;
/// Compile-time bundled Lua scripts and fallback extractor into user/system data paths.
pub mod lua_bundle;
/// Multi-threaded DNS resolver, RFC 1035 query/reply codec, and `mdig` CLI runner.
pub mod mdig;
/// BusyBox-style multicall dispatcher mapping `argv[0]` symlinks and subcommands to applets.
pub mod multicall;
/// Timed `curl` samples (connect, first byte, throughput) for before/after speed comparison.
pub mod speed_probe;
/// Strategy finder (`strat_finder`), firewall rule backends, TOML renderer, and merge helpers.
pub mod strat;

/// Public API re-export for the shared `nfqws2` daemon CLI entry point.
pub use daemon::run_nfqws2_cli;
/// Public API re-exports for OS DNS/DoH preset status, apply, and CLI runner.
pub use dns::{DnsPreset, DnsStatus, apply_dns_preset, detect_dns_status, run_dns_cli};
/// Public API re-exports for `install` / `uninstall` CLI commands and systemd unit rendering.
pub use installer::{SYMLINK_NAMES, render_systemd_service, run_install_cli, run_uninstall_cli};
/// Public API re-exports for `ip2net` configuration, validation, and streaming execution.
pub use ip2net::{
    Ip2NetConfig, Ip2NetError, Ip2NetFamily, parse_prefix_length, parse_v4_threshold,
    parse_v6_threshold, run_ip2net,
};
/// Public API re-export for the shared `ip2net` CLI entry point.
pub use ip2net_cli::run_ip2net_cli;
/// Public API re-exports for compile-time bundled Lua scripts, discovery, and XDG extraction.
pub use lua_bundle::{
    BUNDLED_LUA_SCRIPTS, default_user_lua_dir, detect_lua_dir, extract_bundled_lua,
    resolve_lua_scripts,
};
/// Public API re-exports for `mdig` configuration, DNS codec, resolver, and CLI entry point.
pub use mdig::{
    DEFAULT_EAGAIN_ATTEMPTS, DEFAULT_EAGAIN_DELAY_MS, DEFAULT_MDIG_THREADS, DNS_CLASS_IN,
    DNS_TYPE_A, DNS_TYPE_AAAA, DnsResolver, LibcResolver, MAX_EAGAIN_ATTEMPTS,
    MAX_EAGAIN_DELAY_MS, MAX_MDIG_THREADS, MDIG_DNS_REPLY_MAX, MdigConfig, MdigConfigError,
    MdigDnsError, MdigFamily, MdigOutputs, ResolveError, beautify_invalid_domain,
    build_dns_query, build_dns_query_with_id, is_valid_domain, parse_dns_reply,
    read_and_parse_dns_reply, run_mdig_cli, run_mdig_resolver,
};
/// Public API re-exports for multicall applet resolution and headless CLI dispatch.
pub use multicall::{
    MulticallApplet, dispatch_headless_applet, resolve_argv0_applet, resolve_multicall,
    resolve_subcommand_applet,
};
/// Public API re-exports for timed speed samples and their fixed control target.
pub use speed_probe::{
    CONTROL_HOST, SpeedSample, SpeedTarget, control_target, domain_target, measure,
    parse_timing_lines,
};
/// Public API re-exports for `strat_finder`, firewall backends, TOML rendering, and profile merge.
pub use strat::{
    CoveredProfile, CurlProbeBackend, DEFAULT_AUTOHOSTLIST_FILE, DEFAULT_STRAT_QNUM, DomainScope,
    DomainStrategies,
    FirewallBackend, FirewallHandle, InProcessWorkerHandle, InteractiveDefaults,
    InteractiveSelections, IpFamily, NftFirewallBackend, NftQueueGuard, PROBE_WRITE_OUT,
    ProbeBackend, ProbeOutcome, ProbeProtocol, ProbeRequest, ProgressEvent,
    STRAT_FINDER_NFT_TABLE, ScanConfig, ScanLevel, ScanReport, StratFinderCli, StrategyApplier,
    StrategyMatch, StrategySpec, TargetScanResult, TomlRenderOptions, UnsupportedFirewallBackend,
    active_firewall_backend, build_catalog,
    build_nft_cleanup_cmd, classify_curl_output, collect_config_ports, default_output_config_path,
    expand_tilde, extract_hostlist_domains, extract_strat_finder_args, format_resolve_arg,
    is_nft_perm_denied,
    is_spoof_redirect, merge_nfqws2_toml, normalize_domain, prioritize_sticky, prompt_interactive_wizard,
    rank_matches, render_nfqws2_toml, render_nfqws2_toml_scoped, run_scan, run_strat_finder,
    run_strat_finder_cli, select_minimal_cover, sudo_needs_password, write_config_nofollow,
};
/// Public API re-exports for Windows WinDivert filter [`FirewallBackend`].
#[cfg(windows)]
pub use strat::{WinDivertFilterGuard, WinDivertFirewallBackend, build_windivert_filter};
