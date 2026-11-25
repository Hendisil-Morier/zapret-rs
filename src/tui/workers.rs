//! Background strategy finder and live `nfqws2` worker handles managed by the TUI runner.

/// Deduplicated TCP/UDP port collection when starting the live `nfqws2` engine.
use std::collections::BTreeSet;
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
use std::time::Duration;

/// Configuration models parsed for live scanning and live `nfqws2` execution.
use crate::config::{AppConfig, LuaInitEntry};
/// Core stateful DPI desync engine run live on Tab 2.
use crate::desync::DesyncEngine;
/// NFQUEUE catcher and packet verdict enum counted on Tab 2.
use crate::intercepter::{Decision, QueueCatcher};
/// Strategy finder backends, worker handle, orchestrator, and TOML renderer.
use crate::tools::{
    CurlProbeBackend, FirewallHandle, InProcessWorkerHandle, ProgressEvent, TomlRenderOptions,
    render_nfqws2_toml, resolve_lua_scripts, run_scan,
};
/// Application state read/updated when spawning workers.
use crate::tui::state::AppState;
/// Status, telemetry counter, and scan event types.
use crate::tui::types::{FinderStatus, PacketCounters, RunStatus, ScanUiEvent};

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

/// Collects deduplicated TCP and UDP ports referenced by `cfg.profiles` (defaults to 80/443).
fn collect_config_ports(cfg: &AppConfig) -> (Vec<u16>, Vec<u16>) {
    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();
    for p in &cfg.profiles {
        for pf in &p.filter_tcp {
            if !pf.neg && pf.from > 0 && pf.from == pf.to {
                tcp.insert(pf.from);
            }
        }
        for pf in &p.filter_udp {
            if !pf.neg && pf.from > 0 && pf.from == pf.to {
                udp.insert(pf.from);
            }
        }
    }
    if tcp.is_empty() && udp.is_empty() {
        tcp.insert(80);
        tcp.insert(443);
        udp.insert(443);
    }
    (tcp.into_iter().collect(), udp.into_iter().collect())
}

/// Starts a background strategy finder scan, invoking `install_fw` when `nftables` is enabled.
pub(crate) fn start_finder_scan<F>(state: &mut AppState, install_fw: F) -> Result<ActiveScan, String>
where
    F: FnOnce(u16, u32, &[u16], &[u16]) -> std::io::Result<Box<dyn FirewallHandle>>,
{
    if !state.has_net_caps {
        return Err(format!(
            "missing CAP_NET_ADMIN/CAP_NET_RAW (run: sudo setcap cap_net_admin,cap_net_raw+ep {})",
            state.exe_path
        ));
    }
    let scan_cfg = state.build_scan_config()?;
    let lua_opt = if state.lua_dir_input.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(state.lua_dir_input.trim()))
    };
    let lua_scripts = resolve_lua_scripts(lua_opt.as_deref())?;

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
    let (qnum, fwmark) = (state.finder_qnum, state.fwmark);

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
            let probe = CurlProbeBackend::default();
            match run_scan(&scan_cfg, &probe, &mut worker, &stop_bg, |ev| match ev {
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
            }) {
                Ok(report) => {
                    let rendered_toml = if report.cover.is_empty() {
                        String::new()
                    } else {
                        render_nfqws2_toml(&report.cover, &TomlRenderOptions { qnum: 200, fwmark, lua_init: lua_scripts })
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

/// Starts the live in-process `nfqws2` NFQUEUE worker for Tab 2 using `state.active_toml`.
pub(crate) fn start_live_daemon<F>(state: &mut AppState, install_fw: F) -> Result<ActiveDaemon, String>
where
    F: FnOnce(u16, u32, &[u16], &[u16]) -> std::io::Result<Box<dyn FirewallHandle>>,
{
    if !state.has_net_caps {
        return Err(format!(
            "missing CAP_NET_ADMIN/CAP_NET_RAW (run: sudo setcap cap_net_admin,cap_net_raw+ep {})",
            state.exe_path
        ));
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
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let counters: Arc<PacketCounters> = Arc::clone(&state.counters);

    let join = thread::Builder::new()
        .name("tui-nfqws2-live".to_owned())
        .spawn(move || {
            let mut catcher = match QueueCatcher::bind(cfg.to_queue_config()) {
                Ok(c) => c,
                Err(err) => { let _ = ready_tx.send(Err(format!("NFQUEUE bind failed: {err}"))); return; }
            };
            let engine = match DesyncEngine::new(&cfg) {
                Ok(e) => e,
                Err(err) => { let _ = ready_tx.send(Err(format!("Lua engine init failed: {err}"))); return; }
            };
            let _ = ready_tx.send(Ok(()));
            let _ = catcher.run_until(
                &stop_bg,
                || Some(Duration::from_millis(50)),
                |pkt| {
                    let decision = engine.process_packet(pkt);
                    counters.total.fetch_add(1, Ordering::Relaxed);
                    match &decision {
                        Decision::Pass => { counters.passed.fetch_add(1, Ordering::Relaxed); }
                        Decision::Replace(_) => { counters.modified.fetch_add(1, Ordering::Relaxed); }
                        Decision::Drop => { counters.dropped.fetch_add(1, Ordering::Relaxed); }
                    }
                    decision
                },
            );
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
    state.push_run_log(format!(
        "[start] nfqws2 active on queue {qnum} (fwmark 0x{fwmark:08x}, {} profiles)",
        state.parsed_profiles.len()
    ));
    state.status_banner = "nfqws2 is running. Press 'r' or 'x' to stop.".to_owned();
    Ok(ActiveDaemon { stop, join: Some(join), fw_guard })
}
