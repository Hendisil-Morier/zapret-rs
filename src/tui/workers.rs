//! Background strategy finder and live `nfqws2` worker handles managed by the TUI runner.

/// Path types for resolving relative config references and Lua directories.
use std::path::{Path, PathBuf};
/// Shared atomic flags and channels coordinating background workers with the UI loop.
use std::sync::Arc;
/// Lock-free cancellation flags for background scan and live daemon threads.
use std::sync::atomic::{AtomicBool, Ordering};
/// Event channel streaming [`ScanUiEvent`] from the background scan thread.
use std::sync::mpsc::{self, Receiver};
/// Background worker threads for strategy scanning and live `nfqws2` packet processing.
use std::thread::{self, JoinHandle};
/// Poll interval for the live `nfqws2` daemon loop.
#[cfg(any(target_os = "linux", windows))]
use std::time::Duration;

/// Configuration models parsed for live scanning and live `nfqws2` execution.
use crate::config::{AppConfig, LuaInitEntry};
/// Core stateful DPI desync engine and packet loop bound by Tab 2.
#[cfg(any(target_os = "linux", windows))]
use crate::desync::DesyncEngine;
/// Packet decision and borrowed queued metadata passed to worker telemetry dispatch.
#[cfg(any(target_os = "linux", windows))]
use crate::intercepter::{Decision, QueuedPacket};
/// OS-agnostic packet interception loop trait.
#[cfg(windows)]
use crate::intercepter::PacketIntercepter;
/// NFQUEUE catcher bound by the live Tab 2 daemon thread on Linux.
#[cfg(target_os = "linux")]
use crate::intercepter::QueueCatcher;
/// WinDivert intercepter bound by the live Tab 2 daemon thread on Windows.
#[cfg(windows)]
use crate::intercepter::WinDivertIntercepter;
/// Strategy finder backends, worker handle, orchestrator, and TOML renderer.
use crate::tools::{
    CurlProbeBackend, FirewallHandle, InProcessWorkerHandle, ProgressEvent, ScanConfig,
    TomlRenderOptions, collect_config_ports, render_nfqws2_toml_scoped, resolve_lua_scripts,
    run_scan,
};
/// WinDivert filter-expression builder used by the live Tab 2 daemon thread on Windows.
#[cfg(windows)]
use crate::tools::build_windivert_filter;
/// Shared telemetry counters and serializable packet record.
use crate::telemetry::{PacketCounters, PacketRecord};
/// Verdict tag and packet record builder used by the live capture loop.
#[cfg(any(target_os = "linux", windows))]
use crate::telemetry::{PacketVerdict, build_packet_record};
/// Application state read/updated when spawning workers.
use crate::tui::state::AppState;
/// Status, active tab, and scan event types.
use crate::tui::types::{ActiveTab, FinderStatus, RunStatus, ScanUiEvent};

/// Active background strategy finder scan owned by the TUI event loop.
pub(crate) struct ActiveScan {
    /// Cancellation flag shared with [`run_scan`].
    pub(crate) stop: Arc<AtomicBool>,
    /// Event stream consumed by the TUI loop.
    pub(crate) rx: Receiver<ScanUiEvent>,
    /// Worker thread handle joined on completion/cancel.
    pub(crate) join: Option<JoinHandle<()>>,
    /// Temporary `nftables` rule guard dropped when the scan ends.
    pub(crate) fw_guard: Option<Box<dyn FirewallHandle>>,
}

impl ActiveScan {
    /// Signals cancellation, joins the scan thread, and tears down temporary `nftables` rules.
    pub(crate) fn shutdown<F: FnOnce(Box<dyn FirewallHandle>)>(&mut self, drop_fw: F) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        if let Some(guard) = self.fw_guard.take() {
            drop_fw(guard);
        }
    }
}

/// Active live `nfqws2` NFQUEUE + LuaJIT desync engine running on Tab 2.
pub(crate) struct ActiveDaemon {
    /// Stop flag observed by `QueueCatcher::run_until`.
    pub(crate) stop: Arc<AtomicBool>,
    /// Gates `Pass` packet dissection/capture to avoid formatting records while Tab 2 is unviewed or paused.
    pub(crate) capture_enabled: Arc<AtomicBool>,
    /// Bounded non-blocking stream of all captured [`PacketRecord`] items.
    pub(crate) pkt_rx: Receiver<PacketRecord>,
    /// Dedicated non-blocking stream of `MODIFY`/`DROP` records so `PASS` bursts never drop them.
    pub(crate) desync_rx: Receiver<PacketRecord>,
    /// Daemon thread handle joined on stop/exit.
    pub(crate) join: Option<JoinHandle<()>>,
    /// Temporary `nftables` rule guard dropped when the daemon stops.
    pub(crate) fw_guard: Option<Box<dyn FirewallHandle>>,
}

impl ActiveDaemon {
    /// Signals stop, joins the NFQUEUE thread, and removes temporary `nftables` rules.
    pub(crate) fn shutdown<F: FnOnce(Box<dyn FirewallHandle>)>(&mut self, drop_fw: F) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        if let Some(guard) = self.fw_guard.take() {
            drop_fw(guard);
        }
    }
}

/// Formats a platform-appropriate missing-privilege error message for Tab 1/Tab 2 workers.
fn missing_privs_error(exe_path: &str) -> String {
    #[cfg(windows)]
    {
        let _ = exe_path;
        "Administrator privileges required (right-click zapret-rs.exe -> Run as administrator)".to_owned()
    }
    #[cfg(not(windows))]
    {
        format!("missing CAP_NET_ADMIN/CAP_NET_RAW (run: sudo setcap cap_net_admin,cap_net_raw+ep {exe_path})")
    }
}

/// Validates network capabilities, scan domains/options, and Lua script discovery before launching a scan.
pub(crate) fn validate_scan_prereqs(state: &AppState) -> Result<(ScanConfig, Vec<PathBuf>), String> {
    if !state.has_net_caps {
        return Err(missing_privs_error(&state.exe_path));
    }
    let scan_cfg = state.build_scan_config()?;
    let lua_opt = if state.lua_dir_input.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(state.lua_dir_input.trim()))
    };
    let lua_scripts = resolve_lua_scripts(lua_opt.as_deref())?;
    Ok((scan_cfg, lua_scripts))
}

/// Starts a background strategy finder scan, invoking `install_fw` when `nftables` is enabled.
pub(crate) fn start_finder_scan<F>(state: &mut AppState, install_fw: F) -> Result<ActiveScan, String>
where
    F: FnOnce(u16, u32, &[u16], &[u16]) -> std::io::Result<Box<dyn FirewallHandle>>,
{
    let (scan_cfg, lua_scripts) = validate_scan_prereqs(state)?;

    let (tcp_ports, udp_ports) = scan_cfg.required_ports();
    let fw_guard = if state.no_nft {
        None
    } else {
        Some(
            install_fw(state.finder_qnum, state.fwmark, &tcp_ports, &udp_ports)
                .map_err(|err| format!("{err}"))?,
        )
    };

    let (tx, rx) = mpsc::channel::<ScanUiEvent>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let (qnum, fwmark, domain_scope) = (state.finder_qnum, state.fwmark, state.domain_scope);

    // Static stop flag for `InProcessWorkerHandle::spawn` (worker exits cleanly when dropped).
    static NEVER_STOP: AtomicBool = AtomicBool::new(false);

    let join = thread::Builder::new()
        .name("tui-strat-scan".to_owned())
        .spawn(move || {
            let mut base_cfg = AppConfig { qnum, fwmark, ..AppConfig::default() };
            base_cfg.ipcache.hostname = true;
            base_cfg.lua_init = lua_scripts.iter().cloned().map(LuaInitEntry::File).collect();
            let mut worker = match InProcessWorkerHandle::spawn(base_cfg, &NEVER_STOP) {
                Ok(w) => w,
                Err(err) => { let _ = tx.send(ScanUiEvent::Failed(err)); return; }
            };
            let _ = tx.send(ScanUiEvent::Notice(format!("[worker] {}", worker.capture_spec())));
            let probe = CurlProbeBackend::default();
            let scan_res = run_scan(&scan_cfg, &probe, &mut worker, &stop_bg, |ev| match ev {
                ProgressEvent::Http3Unavailable => {
                    let _ = tx.send(ScanUiEvent::Notice("[warn] curl lacks HTTP3 support; skipping http3".to_owned()));
                }
                ProgressEvent::Baseline { domain, proto, ipv, outcome } => {
                    let _ = tx.send(ScanUiEvent::Baseline {
                        domain: domain.to_owned(), proto, ipv,
                        summary: outcome.summary(), skipped: outcome.is_success(),
                    });
                }
                ProgressEvent::Candidate { domain, index, total, strategy, outcome } => {
                    let _ = tx.send(ScanUiEvent::Candidate {
                        domain: domain.to_owned(), index, total,
                        strategy_id: strategy.id.clone(), passed: outcome.is_success(), summary: outcome.summary(),
                    });
                }
            });
            let _ = tx.send(ScanUiEvent::Notice(format!("[worker] {}", worker.stats_summary())));
            match scan_res {
                Ok(report) => {
                    let rendered_toml = if report.cover.is_empty() {
                        String::new()
                    } else {
                        render_nfqws2_toml_scoped(
                            &report.cover,
                            &TomlRenderOptions { qnum: 200, fwmark, lua_init: lua_scripts },
                            domain_scope,
                        )
                    };
                    let _ = tx.send(ScanUiEvent::Completed { report, rendered_toml });
                }
                Err(err) => { let _ = tx.send(ScanUiEvent::Failed(err)); }
            }
        })
        .map_err(|err| format!("failed to spawn scan thread: {err}"))?;

    state.finder_status = FinderStatus::Scanning;
    state.targets.clear();
    state.cover.clear();
    state.progress_done = 0;
    state.progress_total = 0;
    state.progress_label = "Starting scan...".to_owned();
    state.status_banner = "Scan running. Press 'x' or Esc to stop.".to_owned();
    Ok(ActiveScan { stop, rx, join: Some(join), fw_guard })
}

/// Dispatches one live Tab 2 packet and skips `build_packet_record` unless actively inspected.
#[cfg(any(target_os = "linux", windows))]
fn dispatch_live_worker_packet(
    engine: &DesyncEngine,
    counters: &PacketCounters,
    pass_seen: &mut u64,
    capture_enabled: &AtomicBool,
    desync_tx: &mpsc::SyncSender<PacketRecord>,
    pkt_tx: &mpsc::SyncSender<PacketRecord>,
    pkt: &QueuedPacket<'_>,
) -> Decision {
    let (decision, outcome) = engine.process_packet_traced(pkt);
    let (seq, verdict) = counters.record_outcome(&outcome);
    let inspecting = capture_enabled.load(Ordering::Relaxed);
    if !inspecting {
        return decision;
    }
    if verdict == PacketVerdict::Pass {
        let idx = *pass_seen;
        *pass_seen = idx.wrapping_add(1);
        if !idx.is_multiple_of(10) {
            return decision;
        }
        let _ = pkt_tx.try_send(build_packet_record(seq, pkt, &outcome));
    } else {
        // Route `REASM`/`MODIFY`/`DESYNC` to a dedicated channel so `PASS` bursts never drop them.
        let _ = desync_tx.try_send(build_packet_record(seq, pkt, &outcome));
    }
    decision
}

/// Starts the live in-process `nfqws2` NFQUEUE worker for Tab 2 using `state.active_toml`.
pub(crate) fn start_live_daemon<F>(state: &mut AppState, install_fw: F) -> Result<ActiveDaemon, String>
where
    F: FnOnce(u16, u32, &[u16], &[u16]) -> std::io::Result<Box<dyn FirewallHandle>>,
{
    if !state.has_net_caps {
        return Err(missing_privs_error(&state.exe_path));
    }
    if state.active_toml.trim().is_empty() {
        return Err("no active nfqws2.toml loaded (run Strategy Finder or press 'l' to load a file)".to_owned());
    }
    let base_dir = Path::new(&state.output_path).parent();
    let cfg = AppConfig::from_toml_str(&state.active_toml, base_dir)
        .map_err(|err| format!("invalid nfqws2.toml: {err}"))?;
    let (tcp_ports, udp_ports) = collect_config_ports(&cfg);
    let (qnum, fwmark) = (cfg.qnum, cfg.fwmark);

    let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
    let (pkt_tx, pkt_rx) = mpsc::sync_channel::<PacketRecord>(512);
    let (desync_tx, desync_rx) = mpsc::sync_channel::<PacketRecord>(256);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let capture_enabled = Arc::new(AtomicBool::new(
        state.tab == ActiveTab::Run && !state.inspector.paused,
    ));
    let capture_bg = Arc::clone(&capture_enabled);
    let counters: Arc<PacketCounters> = Arc::clone(&state.counters);

    let join = thread::Builder::new()
        .name("tui-nfqws2-live".to_owned())
        .spawn(move || {
            #[cfg(target_os = "linux")]
            {
                let mut catcher = match QueueCatcher::bind(cfg.to_queue_config()) {
                    Ok(c) => c,
                    Err(err) => { let _ = ready_tx.send(Err(format!("NFQUEUE bind failed: {err}"))); return; }
                };
                let engine = match DesyncEngine::new(&cfg) {
                    Ok(e) => e,
                    Err(err) => { let _ = ready_tx.send(Err(format!("Lua engine init failed: {err}"))); return; }
                };
                let _ = ready_tx.send(Ok(()));
                let mut pass_seen = 0u64;
                let _ = catcher.run_until(
                    &stop_bg,
                    || Some(Duration::from_millis(50)),
                    |pkt| {
                        dispatch_live_worker_packet(
                            &engine,
                            &counters,
                            &mut pass_seen,
                            &capture_bg,
                            &desync_tx,
                            &pkt_tx,
                            pkt,
                        )
                    },
                );
            }
            #[cfg(windows)]
            {
                let (tcp_ports, udp_ports) = collect_config_ports(&cfg);
                let filter = build_windivert_filter(&tcp_ports, &udp_ports);
                let mut catcher = match WinDivertIntercepter::bind(&filter) {
                    Ok(c) => c,
                    Err(err) => { let _ = ready_tx.send(Err(format!("WinDivert bind failed: {err}"))); return; }
                };
                let engine = match DesyncEngine::new(&cfg) {
                    Ok(e) => e,
                    Err(err) => { let _ = ready_tx.send(Err(format!("Lua engine init failed: {err}"))); return; }
                };
                let _ = ready_tx.send(Ok(()));
                let mut pass_seen = 0u64;
                let _ = catcher.run_until(
                    &stop_bg,
                    || Some(Duration::from_millis(50)),
                    |pkt| {
                        dispatch_live_worker_packet(
                            &engine,
                            &counters,
                            &mut pass_seen,
                            &capture_bg,
                            &desync_tx,
                            &pkt_tx,
                            pkt,
                        )
                    },
                );
            }
            #[cfg(not(any(target_os = "linux", windows)))]
            {
                let _ = (&cfg, &stop_bg, &capture_bg, &counters, &pkt_tx, &desync_tx);
                let _ = ready_tx.send(Err(
                    "live packet interception is not yet implemented on this OS".to_owned(),
                ));
            }
        })
        .map_err(|err| format!("failed to spawn live daemon thread: {err}"))?;

    match ready_rx.recv() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => { let _ = join.join(); return Err(err); }
        Err(_) => { let _ = join.join(); return Err("live daemon thread exited during startup".to_owned()); }
    }

    let fw_guard = if state.no_nft {
        None
    } else {
        match install_fw(qnum, fwmark, &tcp_ports, &udp_ports) {
            Ok(g) => Some(g),
            Err(err) => {
                stop.store(true, Ordering::Release);
                let _ = join.join();
                return Err(format!("{err}"));
            }
        }
    };

    state.run_status = RunStatus::Running;
    let engine = crate::tui::tabs::ENGINE_LABEL;
    state.push_run_log(format!(
        "[start] {engine} active (queue {qnum}, fwmark 0x{fwmark:08x}, {} profiles)",
        state.parsed_profiles.len()
    ));
    state.status_banner =
        format!("{engine} is running. Press 'f' to filter, 'd' for detail, 'x' to stop.");
    Ok(ActiveDaemon { stop, capture_enabled, pkt_rx, desync_rx, join: Some(join), fw_guard })
}
