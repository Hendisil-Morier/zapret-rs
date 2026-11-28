//! Multi-domain strategy scan orchestrator and minimal cross-domain set-cover builder.

/// Deduplicated port collection helpers when installing temporary firewall rules.
use std::collections::BTreeSet;
/// Lock-free shutdown flag polled by the scan loop.
use std::sync::atomic::{AtomicBool, Ordering};
/// Request timeout duration.
use std::time::Duration;

/// Strategy catalog definitions and expansion function.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Connectivity probe traits and request models.
use crate::tools::strat::probe::{ProbeBackend, ProbeRequest};
/// Classified probe outcomes.
use crate::tools::strat::probe_classify::ProbeOutcome;
/// Ranking and minimal cross-domain set cover types and algorithms.
use crate::tools::strat::toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, rank_matches, select_minimal_cover,
};
/// Abstract profile-application handle decoupling scan orchestration from live sockets.
use crate::tools::strat::worker::StrategyApplier;

/// Configuration controlling a multi-domain strategy discovery run.
#[derive(Debug, Clone)]
pub struct ScanConfig
{
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

impl ScanConfig
{
    /// Returns deduplicated TCP and UDP ports required for temporary `nftables` queue rules.
    pub fn required_ports(&self) -> (Vec<u16>, Vec<u16>)
    {
        let mut tcp = BTreeSet::new();
        let mut udp = BTreeSet::new();
        for &proto in &self.protos
        {
            if proto.is_udp()
            {
                udp.insert(proto.default_port());
            }
            else
            {
                tcp.insert(proto.default_port());
            }
        }
        (
            tcp.into_iter()
                .collect(),
            udp.into_iter()
                .collect(),
        )
    }
}

/// Scan results recorded for one `(domain, proto, ipv)` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetScanResult
{
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
pub struct ScanReport
{
    /// Per-target scan outcomes in execution order.
    pub targets: Vec<TargetScanResult>,
    /// Minimal cross-domain profile cover computed over all targets with passing strategies.
    pub cover: Vec<CoveredProfile>,
    /// `true` if the scan stopped early due to a shutdown signal (`SIGINT`/`SIGTERM`).
    pub interrupted: bool,
}

/// Progress notifications emitted during [`run_scan`] for terminal or structured logging.
#[derive(Debug, Clone)]
pub enum ProgressEvent<'a>
{
    /// HTTP/3 probing was requested but skipped because the backend lacks HTTP/3 support.
    Http3Unavailable,
    /// Direct baseline probe completed for one target.
    Baseline
    {
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
    Candidate
    {
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

/// Extracts the strategy suffix after `<proto>:<ipv>:` (e.g. `"tls13:ipv4:multisplit:1"` -> `"multisplit:1"`).
fn strategy_suffix(id: &str) -> &str
{
    id.split_once(':')
        .and_then(|(_, rest)| rest.split_once(':'))
        .map_or(id, |(_, suffix)| suffix)
}

/// Promotes strategies that already worked on earlier targets to the front of `catalog`.
///
/// Exact `(ipv, suffix)` matches come first, followed by cross-family `suffix` matches, while
/// preserving relative catalog order within each tier so final weight/latency ranking is unaffected.
pub fn prioritize_sticky(catalog: Vec<StrategySpec>, sticky: &[(IpFamily, String)]) -> Vec<StrategySpec>
{
    if sticky.is_empty()
    {
        return catalog;
    }
    let (mut same_family, mut cross_family, mut rest) = (Vec::new(), Vec::new(), Vec::new());
    for spec in catalog
    {
        let suffix = strategy_suffix(&spec.id);
        if sticky
            .iter()
            .any(|(ipv, s)| *ipv == spec.ipv && s == suffix)
        {
            same_family.push(spec);
        }
        else if sticky
            .iter()
            .any(|(_, s)| s == suffix)
        {
            cross_family.push(spec);
        }
        else
        {
            rest.push(spec);
        }
    }
    same_family.extend(cross_family);
    same_family.extend(rest);
    same_family
}

/// Builds baseline probe requests and collects initial reachability statuses per `(domain, ipv, proto)`.
fn collect_baseline_targets<P, A, F>(
    cfg: &ScanConfig,
    probe: &P,
    applier: &mut A,
    http3_ok: bool,
    on_event: &mut F,
) -> Result<(Vec<ProbeRequest>, Vec<TargetScanResult>), String>
where
    P: ProbeBackend,
    A: StrategyApplier,
    F: FnMut(ProgressEvent<'_>),
{
    let mut target_reqs = Vec::new();
    for domain in &cfg.domains
    {
        for &ipv in &cfg.families
        {
            for &proto in &cfg.protos
            {
                if proto != ProbeProtocol::Http3 || http3_ok
                {
                    target_reqs.push(ProbeRequest {
                        domain: domain.clone(),
                        proto,
                        ipv,
                        timeout: cfg.timeout,
                    });
                }
            }
        }
    }

    applier.clear()?;
    let baselines = if target_reqs.is_empty() { Vec::new() } else { probe.probe_batch(&target_reqs) };
    let targets = target_reqs
        .iter()
        .zip(baselines)
        .map(|(req, baseline)| {
            on_event(ProgressEvent::Baseline {
                domain: &req.domain,
                proto: req.proto,
                ipv: req.ipv,
                outcome: &baseline,
            });
            let skipped_unblocked = baseline.is_success() && !cfg.force_blocked;
            TargetScanResult {
                domain: req
                    .domain
                    .clone(),
                proto: req.proto,
                ipv: req.ipv,
                baseline,
                skipped_unblocked,
                tested_count: 0,
                matches: Vec::new(),
            }
        })
        .collect();
    Ok((target_reqs, targets))
}

/// Ranks per-target strategy matches and selects the minimal cross-domain covering set.
fn finalize_scan_report(mut targets: Vec<TargetScanResult>, interrupted: bool) -> ScanReport
{
    let mut domain_strategies = Vec::new();
    for t in &mut targets
    {
        rank_matches(&mut t.matches);
        if !t
            .matches
            .is_empty()
        {
            domain_strategies.push(DomainStrategies {
                domain: t
                    .domain
                    .clone(),
                proto: t.proto,
                ipv: t.ipv,
                matches: t
                    .matches
                    .clone(),
            });
        }
    }
    let cover = select_minimal_cover(&domain_strategies);
    ScanReport { targets, cover, interrupted }
}

/// Executes parallel baseline checks, sticky strategy sweeps, ranking, and minimal cross-domain cover.
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
    let http3_ok = if cfg
        .protos
        .contains(&ProbeProtocol::Http3)
    {
        let supported = probe.supports_http3();
        if !supported
        {
            on_event(ProgressEvent::Http3Unavailable);
        }
        supported
    }
    else
    {
        false
    };

    if stop.load(Ordering::Acquire)
    {
        let _ = applier.clear();
        return Ok(ScanReport { targets: Vec::new(), cover: Vec::new(), interrupted: true });
    }

    let (target_reqs, mut targets) = collect_baseline_targets(cfg, probe, applier, http3_ok, &mut on_event)?;

    let mut sticky: Vec<(IpFamily, String)> = Vec::new();
    let mut interrupted = false;

    'groups: for &ipv in &cfg.families
    {
        for &proto in &cfg.protos
        {
            if proto == ProbeProtocol::Http3 && !http3_ok
            {
                continue;
            }
            let mut active: Vec<usize> = (0..targets.len())
                .filter(|&i| {
                    !targets[i].skipped_unblocked && targets[i].ipv == ipv && targets[i].proto == proto
                })
                .collect();
            if active.is_empty()
            {
                continue;
            }

            let catalog = prioritize_sticky(build_catalog(proto, cfg.level, ipv), &sticky);
            let total = catalog.len();

            for (idx, spec) in catalog
                .iter()
                .enumerate()
            {
                if active.is_empty()
                {
                    break;
                }
                if stop.load(Ordering::Acquire)
                {
                    interrupted = true;
                    break 'groups;
                }
                applier.apply_profiles(vec![spec.to_profile(1, &[])])?;
                let batch_reqs: Vec<ProbeRequest> = active
                    .iter()
                    .map(|&si| target_reqs[si].clone())
                    .collect();
                let outcomes = probe.probe_batch(&batch_reqs);
                let mut next_active = Vec::with_capacity(active.len());

                for (slot_idx, outcome) in active
                    .into_iter()
                    .zip(outcomes)
                {
                    let t = &mut targets[slot_idx];
                    t.tested_count += 1;
                    on_event(ProgressEvent::Candidate {
                        domain: &t.domain,
                        index: idx + 1,
                        total,
                        strategy: spec,
                        outcome: &outcome,
                    });
                    if let Some(latency_ms) = outcome.latency_ms()
                    {
                        let entry = (spec.ipv, strategy_suffix(&spec.id).to_owned());
                        if !sticky.contains(&entry)
                        {
                            sticky.push(entry);
                        }
                        t.matches
                            .push(StrategyMatch { strategy: spec.clone(), latency_ms });
                        if cfg.stop_on_first
                        {
                            continue;
                        }
                    }
                    next_active.push(slot_idx);
                }
                active = next_active;
            }
        }
    }

    let _ = applier.clear();
    Ok(finalize_scan_report(targets, interrupted))
}
