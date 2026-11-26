//! Strategy finder (`strat_finder`), firewall rule backends, TOML renderer, and merge helpers.

/// Strategy candidate catalog ported from `zapret2/blockcheck2.d/standard/*.sh`.
pub mod catalog;
/// Shared CLI runner powering both `nfqws2 --strat-finder` and the standalone `strat_finder` binary.
pub mod cli;
/// OS-agnostic firewall rule backend contract and target port collector.
pub mod firewall;
/// Interactive terminal setup wizard for `strat_finder`.
pub mod interactive;
/// Non-destructive `nfqws2.toml` profile merging, slot scoping, and hostlist domain extraction helpers.
pub mod merge;
/// Temporary `nftables` NFQUEUE rule management with RAII teardown (`zapret_strat_finder`).
pub mod nft;
/// HTTP/TLS/QUIC connectivity probe backends (`curl` + mockable trait).
pub mod probe;
/// In-process NFQUEUE desync worker thread and multi-domain strategy scan orchestrator.
pub mod runner;
/// Strategy ranking, minimal cross-domain set cover, and `nfqws2.toml` serialization.
pub mod toml;
/// Windows WinDivert filter-expression [`FirewallBackend`] implementation.
#[cfg(windows)]
pub mod windivert;
/// In-process packet-interception worker thread and [`StrategyApplier`] handle.
pub mod worker;

/// Public API re-exports for `strat_finder` strategy catalog expansion.
pub use catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Public API re-exports for `strat_finder` CLI entry point and `nfqws2 --strat-finder` dispatch.
pub use cli::{
    DEFAULT_STRAT_QNUM, StratFinderCli, extract_strat_finder_args, run_strat_finder,
    run_strat_finder_cli,
};
/// Public API re-exports for OS-agnostic firewall backend traits and port collection.
pub use firewall::{FirewallBackend, FirewallHandle, collect_config_ports};
/// Public API re-exports for `strat_finder` interactive terminal wizard and config path defaults.
pub use interactive::{
    InteractiveDefaults, InteractiveSelections, default_output_config_path, expand_tilde,
    normalize_domain, prompt_interactive_wizard,
};
/// Public API re-exports for non-destructive `nfqws2.toml` merging and domain extraction.
pub use merge::{
    DEFAULT_AUTOHOSTLIST_FILE, DomainScope, extract_hostlist_domains, merge_nfqws2_toml,
    render_nfqws2_toml_scoped,
};
/// Public API re-exports for `strat_finder` temporary `nftables` firewall management.
pub use nft::{
    NftFirewallBackend, NftQueueGuard, STRAT_FINDER_NFT_TABLE, build_nft_cleanup_cmd,
    is_nft_perm_denied, sudo_needs_password,
};
/// Public API re-exports for `strat_finder` connectivity probes and outcome classification.
pub use probe::{
    CurlProbeBackend, PROBE_WRITE_OUT, ProbeBackend, ProbeOutcome, ProbeRequest,
    classify_curl_output, is_spoof_redirect,
};
/// Public API re-exports for `strat_finder` multi-domain scan orchestration.
pub use runner::{ProgressEvent, ScanConfig, ScanReport, TargetScanResult, run_scan};
/// Public API re-exports for `strat_finder` in-process worker handle and applier trait.
pub use worker::{InProcessWorkerHandle, StrategyApplier};
/// Public API re-exports for `strat_finder` ranking, set cover, and TOML rendering.
pub use toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, TomlRenderOptions, rank_matches,
    render_nfqws2_toml, select_minimal_cover, write_config_nofollow,
};
/// Public API re-exports for Windows WinDivert filter [`FirewallBackend`].
#[cfg(windows)]
pub use windivert::{WinDivertFilterGuard, WinDivertFirewallBackend, build_windivert_filter};
