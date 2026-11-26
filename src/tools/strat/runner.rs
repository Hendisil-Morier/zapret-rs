//! In-process NFQUEUE desync worker thread and multi-domain strategy scan orchestrator.

/// Single-threaded interior mutability sharing [`DesyncEngine`] between poll callbacks.
#[cfg(target_os = "linux")]
use std::cell::RefCell;
/// Deduplicated port collection helpers when installing temporary firewall rules.
use std::collections::BTreeSet;
/// Lock-free shutdown flags polled by both the scan loop and NFQUEUE worker thread.
use std::sync::Arc;
/// Atomic shutdown signaling between coordinator and worker thread.
use std::sync::atomic::{AtomicBool, Ordering};
/// Synchronous command and ACK channels between coordinator and NFQUEUE worker.
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
/// Background worker thread handle joined on drop.
use std::thread::{self, JoinHandle};
/// Poll wakeup cadence and request timeout duration.
use std::time::Duration;

/// Application and profile configuration types applied to the in-process engine.
use crate::config::{AppConfig, DesyncProfile};
/// Stateful DPI desync engine whose profiles are hot-swapped between candidates.
#[cfg(target_os = "linux")]
use crate::desync::DesyncEngine;
/// Tuned Linux NFQUEUE catcher bound once for the entire scan session.
#[cfg(target_os = "linux")]
use crate::intercepter::QueueCatcher;
/// Strategy catalog definitions and expansion function.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec, build_catalog};
/// Connectivity probe traits and classified outcomes.
use crate::tools::strat::probe::{ProbeBackend, ProbeOutcome, ProbeRequest};
/// Ranking and minimal cross-domain set cover types and algorithms.
use crate::tools::strat::toml::{
    CoveredProfile, DomainStrategies, StrategyMatch, rank_matches, select_minimal_cover,
};

/// Poll wakeup interval used by the worker thread to service profile-swap commands promptly.
#[cfg(target_os = "linux")]
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(15);

/// Control commands delivered from the scan coordinator to the NFQUEUE worker thread.
enum WorkerCmd {
    /// Atomically replace active engine profiles and clear conntrack/ipcache, then reply on `ack`.
    Swap {
        /// New active profiles (`empty` puts the worker into pass-through mode).
        profiles: Vec<DesyncProfile>,
        /// Synchronous ACK channel returning `Ok(())` or a Lua validation/load error message.
        ack: SyncSender<Result<(), String>>,
    },
    /// Stop the `QueueCatcher` poll loop and exit the worker thread cleanly.
    Shutdown,
}

/// Abstract profile-application handle decoupling scan orchestration from live NFQUEUE sockets.
pub trait StrategyApplier {
    /// Installs `profiles` as the active desync set and waits until the swap takes effect.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String>;

    /// Clears all active desync profiles (pass-through mode for baseline probing).
    fn clear(&mut self) -> Result<(), String> {
        self.apply_profiles(Vec::new())
    }
}

/// Live [`StrategyApplier`] owning a persistent background NFQUEUE + [`DesyncEngine`] worker thread.
pub struct InProcessWorkerHandle {
    /// Channel sending profile swap and shutdown commands to the worker.
    cmd_tx: Option<Sender<WorkerCmd>>,
    /// Local stop flag shared with the worker's `QueueCatcher::run_until` loop.
    worker_stop: Arc<AtomicBool>,
    /// Background thread handle joined on drop.
    join: Option<JoinHandle<()>>,
}

impl InProcessWorkerHandle {
    /// Spawns the persistent NFQUEUE worker thread, initializing `QueueCatcher` and `DesyncEngine` once.
    ///
    /// Blocks until the worker confirms both NFQUEUE bind and Lua startup succeeded, or returns
    /// the initialization error immediately without leaking a running thread.
    pub fn spawn(base_config: AppConfig, global_stop: &'static AtomicBool) -> Result<Self, String> {
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let worker_stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&worker_stop);

        let join = thread::Builder::new()
            .name("strat-finder-nfq".to_owned())
            .spawn(move || {
                run_worker_thread(base_config, cmd_rx, ready_tx, stop_clone, global_stop);
            })
            .map_err(|err| format!("failed to spawn NFQUEUE worker thread: {err}"))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                cmd_tx: Some(cmd_tx),
                worker_stop,
                join: Some(join),
            }),
            Ok(Err(err)) => {
                let _ = join.join();
                Err(err)
            }
            Err(_) => {
                let _ = join.join();
                Err("NFQUEUE worker thread exited unexpectedly during startup".to_owned())
            }
        }
    }
}

impl StrategyApplier for InProcessWorkerHandle {
    /// Sends `profiles` to the worker thread and blocks until `DesyncEngine::replace_profiles` finishes.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String> {
        let Some(tx) = &self.cmd_tx else {
            return Err("NFQUEUE worker is already shut down".to_owned());
        };
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        tx.send(WorkerCmd::Swap { profiles, ack: ack_tx })
            .map_err(|_| "NFQUEUE worker channel closed".to_owned())?;
        ack_rx
            .recv()
            .map_err(|_| "NFQUEUE worker terminated before acknowledging profile swap".to_owned())?
    }
}

impl Drop for InProcessWorkerHandle {
    /// Signals the worker thread to exit and joins it so `QueueCatcher` unbinds cleanly.
    fn drop(&mut self) {
        self.worker_stop.store(true, Ordering::Release);
        if let Some(tx) = self.cmd_tx.take() {
            let _ = tx.send(WorkerCmd::Shutdown);
        }
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

/// Executes the single-threaded NFQUEUE capture + LuaJIT desync loop inside the worker thread.
/// Runs the Linux NFQUEUE worker loop servicing profile-swap commands.
#[cfg(target_os = "linux")]
fn run_worker_thread(
    base_config: AppConfig,
    cmd_rx: Receiver<WorkerCmd>,
    ready_tx: SyncSender<Result<(), String>>,
    worker_stop: Arc<AtomicBool>,
    global_stop: &'static AtomicBool,
) {
    let mut catcher = match QueueCatcher::bind(base_config.to_queue_config()) {
        Ok(c) => c,
        Err(err) => {
            let _ = ready_tx.send(Err(format!("failed to bind NFQUEUE: {err}")));
            return;
        }
    };
    let engine = match DesyncEngine::new(&base_config) {
        Ok(e) => RefCell::new(e),
        Err(err) => {
            let _ = ready_tx.send(Err(format!("failed to initialize Lua desync engine: {err}")));
            return;
        }
    };
    if ready_tx.send(Ok(())).is_err() {
        return;
    }

    let loop_stop = Arc::new(AtomicBool::new(false));
    let _ = catcher.run_until(
        &loop_stop,
        || {
            if worker_stop.load(Ordering::Acquire) || global_stop.load(Ordering::Acquire) {
                loop_stop.store(true, Ordering::Release);
                return Some(Duration::ZERO);
            }
            loop {
                match cmd_rx.try_recv() {
                    Ok(WorkerCmd::Swap { profiles, ack }) => {
                        let res = engine
                            .borrow_mut()
                            .replace_profiles(profiles)
                            .map_err(|err| err.to_string());
                        let _ = ack.send(res);
                    }
                    Ok(WorkerCmd::Shutdown) | Err(mpsc::TryRecvError::Disconnected) => {
                        loop_stop.store(true, Ordering::Release);
                        return Some(Duration::ZERO);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }
            Some(WORKER_POLL_INTERVAL)
        },
        |pkt| engine.borrow().process_packet(pkt),
    );
}

/// Non-Linux stub reporting that live packet interception is not yet implemented.
#[cfg(not(target_os = "linux"))]
fn run_worker_thread(
    _base: AppConfig, _rx: Receiver<WorkerCmd>, ready_tx: SyncSender<Result<(), String>>,
    _wstop: Arc<AtomicBool>, _gstop: &'static AtomicBool,
) {
    let _ = ready_tx.send(Err("live packet interception is not yet implemented on this OS".to_owned()));
}

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
