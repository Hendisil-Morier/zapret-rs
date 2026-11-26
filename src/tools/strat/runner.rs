//! Multi-domain strategy scan orchestrator and minimal cross-domain set-cover builder.

/// Deduplicated port collection helpers when installing temporary firewall rules.
use std::collections::BTreeSet;
/// Lock-free shutdown flag polled by the scan loop.
use std::sync::atomic::{AtomicBool, Ordering};
/// Request timeout duration.
use std::time::Duration;

/// Strategy catalog definitions and expansion function.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Connectivity probe traits and classified outcomes.
use crate::tools::strat::probe::{ProbeBackend, ProbeOutcome, ProbeRequest};
/// Ranking and minimal cross-domain set cover types and algorithms.
use crate::tools::strat::toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, rank_matches, select_minimal_cover,
};
/// Abstract profile-application handle decoupling scan orchestration from live sockets.
use crate::tools::strat::worker::StrategyApplier;

/// Configuration controlling a multi-domain strategy discovery run.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Target hostnames to test (e.g., `["youtube.com", "discord.com"]`).
    pub domains: Vec<String>,
    /// Application protocols to sweep for each domain.
    pub protos: Vec<ProbeProtocol>,
    /// IP address families to test (`[V4]`, `[V6]`, or `[V4, V6]`).
    pub families: Vec<IpFamily>,
    /// Candidate expansion level (`Quick`, `Standard`, `Force`).
    pub level: ScanLevel,
    /// Per-request probe timeout.
    pub timeout: Duration,
    /// Stop testing additional strategies for a target after the first working one passes.
    pub stop_on_first: bool,
    /// Sweep strategies even when direct baseline probing succeeds (useful for verification).
    pub force_blocked: bool,
}

impl ScanConfig {
    /// Returns deduplicated TCP and UDP ports required for temporary `nftables` queue rules.
    pub fn required_ports(&self) -> (Vec<u16>, Vec<u16>) {
        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        for &proto in &self.protos {
            if proto.is_udp() {
                udp.insert(proto.default_port());
            } else {
                tcp.insert(proto.default_port());
            }
        }
        (tcp.into_iter().collect(), udp.into_iter().collect())
    }
}

/// Scan results recorded for one `(domain, proto, ipv)` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScanResult {
    /// Target domain name.
    pub domain: String,
    /// Target protocol.
    pub proto: ProbeProtocol,
    /// Target IP family.
    pub ipv: IpFamily,
    /// Direct baseline probe result with no desync active.
    pub baseline: ProbeOutcome,
    /// `true` when the sweep was skipped because direct baseline access succeeded.
    pub skipped_unblocked: bool,
    /// Number of candidate strategies probed for this target.
    pub tested_count: usize,
    /// Passing strategies sorted by lowest weight then lowest latency.
    pub matches: Vec<StrategyMatch>,
}

/// Complete report returned by [`run_scan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    /// Per-target scan outcomes in execution order.
    pub targets: Vec<TargetScanResult>,
    /// Minimal cross-domain profile cover computed over all targets with passing strategies.
    pub cover: Vec<CoveredProfile>,
    /// `true` if the scan stopped early due to a shutdown signal (`SIGINT`/`SIGTERM`).
    pub interrupted: bool,
}

/// Progress notifications emitted during [`run_scan`] for terminal or structured logging.
#[derive(Debug, Clone)]
pub enum ProgressEvent<'a> {
    /// HTTP/3 probing was requested but skipped because the backend lacks HTTP/3 support.
    Http3Unavailable,
    /// Direct baseline probe completed for one target.
    Baseline {
        /// Target domain name.
        domain: &'a str,
        /// Target protocol.
        proto: ProbeProtocol,
        /// Target IP family.
        ipv: IpFamily,
        /// Observed baseline outcome.
        outcome: &'a ProbeOutcome,
    },
    /// One strategy candidate was probed for the current target.
    Candidate {
        /// Target domain name.
        domain: &'a str,
        /// 1-based candidate index within the current target's catalog.
        index: usize,
        /// Total candidates in the current target's catalog.
        total: usize,
        /// Candidate strategy tested.
        strategy: &'a StrategySpec,
        /// Observed probe outcome with this strategy active.
        outcome: &'a ProbeOutcome,
    },
}

/// Executes baseline checks, in-process strategy sweeps, ranking, and minimal cross-domain cover.
pub fn run_scan<P, A, F>(
    cfg: &ScanConfig,
    probe: &P,
    applier: &mut A,
    stop: &AtomicBool,
    mut on_event: F,
) -> Result<ScanReport, String>
where
    P: ProbeBackend,
    A: StrategyApplier,
    F: FnMut(ProgressEvent<'_>),
{
    let http3_ok = if cfg.protos.contains(&ProbeProtocol::Http3) {
        let supported = probe.supports_http3();
        if !supported {
            on_event(ProgressEvent::Http3Unavailable);
        }
        supported
    } else {
        false
    };

    let mut targets = Vec::new();
    let mut domain_strategies = Vec::new();
    let mut interrupted = false;

    'outer: for domain in &cfg.domains {
        for &ipv in &cfg.families {
            for &proto in &cfg.protos {
                if proto == ProbeProtocol::Http3 && !http3_ok {
                    continue;
                }
                if stop.load(Ordering::Acquire) {
                    interrupted = true;
                    break 'outer;
                }

                applier.clear()?;
                let req = ProbeRequest {
                    domain: domain.clone(),
                    proto,
                    ipv,
                    timeout: cfg.timeout,
                };
                let baseline = probe.probe(&req);
                on_event(ProgressEvent::Baseline { domain, proto, ipv, outcome: &baseline });

                if baseline.is_success() && !cfg.force_blocked {
                    targets.push(TargetScanResult {
                        domain: domain.clone(), proto, ipv, baseline,
                        skipped_unblocked: true, tested_count: 0, matches: Vec::new(),
                    });
                    continue;
                }

                let catalog = build_catalog(proto, cfg.level, ipv);
                let total = catalog.len();
                let mut matches = Vec::new();
                let mut tested_count = 0usize;

                for (idx, spec) in catalog.iter().enumerate() {
                    if stop.load(Ordering::Acquire) {
                        interrupted = true;
                        break;
                    }
                    applier.apply_profiles(vec![spec.to_profile(1, &[])])?;
                    let outcome = probe.probe(&req);
                    tested_count += 1;
                    on_event(ProgressEvent::Candidate { domain, index: idx + 1, total, strategy: spec, outcome: &outcome });
                    if let Some(latency_ms) = outcome.latency_ms() {
                        matches.push(StrategyMatch { strategy: spec.clone(), latency_ms });
                        if cfg.stop_on_first {
                            break;
                        }
                    }
                }

                let _ = applier.clear();
                rank_matches(&mut matches);
                if !matches.is_empty() {
                    domain_strategies.push(DomainStrategies { domain: domain.clone(), proto, ipv, matches: matches.clone() });
                }
                targets.push(TargetScanResult {
                    domain: domain.clone(), proto, ipv, baseline,
                    skipped_unblocked: false, tested_count, matches,
                });
                if interrupted {
                    break 'outer;
                }
            }
        }
    }

    let _ = applier.clear();
    let cover = select_minimal_cover(&domain_strategies);
    Ok(ScanReport { targets, cover, interrupted })
}
