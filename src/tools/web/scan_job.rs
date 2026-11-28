//! Background Strategy Finder scan job coordinator streaming live progress over SSE.

/// Lock-free scan cancellation flag shared with [`run_scan`].
use std::sync::atomic::{AtomicBool, Ordering};
/// Shared scan progress state protected across HTTP pollers and worker thread.
use std::sync::{Arc, Mutex};
/// Background worker thread running [`InProcessWorkerHandle`] and [`run_scan`].
use std::thread::{self, JoinHandle};
/// Per-probe timeout duration constructed from fractional UI seconds.
use std::time::Duration;

/// Application config defaults for the in-process packet desync worker.
use crate::config::{AppConfig, LuaInitEntry};
/// Default interception fwmark constant shared with `nfqws2`.
use crate::intercepter::DEFAULT_DESYNC_FWMARK;
/// Capability/Admin check guarding live capture scans before opening sockets.
use crate::runtime::has_packet_capture_privileges;
/// Bundled Lua discovery, strategy catalog, non-interactive firewall backend, scanner, and TOML renderer.
use crate::tools::lua_bundle::resolve_lua_scripts;
/// Linux `nftables` backend invoked strictly non-interactively from web HTTP worker threads.
#[cfg(target_os = "linux")]
use crate::tools::strat::NftFirewallBackend;
/// Active non-Linux firewall backend selector.
#[cfg(not(target_os = "linux"))]
use crate::tools::strat::active_firewall_backend;
/// Range/host-validated domain parser and strategy scan builders.
use crate::tools::strat::{
    CurlProbeBackend, DEFAULT_STRAT_QNUM, DomainScope, InProcessWorkerHandle, IpFamily, ProbeProtocol,
    ProgressEvent, ScanConfig, ScanLevel, TomlRenderOptions, parse_clean_domain, render_nfqws2_toml_scoped,
    run_scan,
};
/// Web runtime paths (`config`, `lua_dir`) passed into scan execution.
use crate::tools::web::cli::WebConfig;
/// SSE broadcaster used to push real-time scan events to connected browsers.
use crate::tools::web::ipc_bridge::WebIpcBridge;

/// Maximum log lines kept in the latest scan snapshot.
const MAX_SCAN_LOGS: usize = 120;

/// Incoming JSON payload triggering `POST /api/scan/start`.
#[derive(Debug, serde::Deserialize)]
pub struct ScanStartPayload
{
    /// Target hostnames list (comma/whitespace separated or array).
    pub domains: Vec<String>,
    /// Protocol names (`"http"`, `"tls12"`, `"tls13"`, `"http3"`).
    #[serde(default)]
    pub protos: Vec<String>,
    /// Thoroughness (`"quick"`, `"standard"`, `"force"`).
    #[serde(default)]
    pub level: Option<String>,
    /// Stop on first working strategy per target.
    #[serde(default = "default_true")]
    pub stop_on_first: bool,
    /// Optional per-probe timeout in seconds (defaults to `2.0`).
    #[serde(default)]
    pub timeout_secs: Option<f64>,
}

const fn default_true() -> bool
{
    true
}

/// Summary row for one scanned `(domain, proto, ipv)` target.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ScanTargetSummary
{
    /// Target domain hostname.
    pub domain: String,
    /// Protocol label (`http`, `tls12`, `tls13`, `http3`).
    pub proto: String,
    /// IP family label (`ipv4`, `ipv6`).
    pub ipv: String,
    /// Direct baseline probe summary.
    pub baseline: String,
    /// True when baseline passed and strategy sweep was skipped.
    pub skipped: bool,
    /// Winning strategy ID if found.
    pub best_strategy: Option<String>,
    /// Winning strategy latency in milliseconds if found.
    pub best_latency_ms: Option<u64>,
}

/// Live or completed Strategy Finder snapshot served by `GET /api/scan` and `event: scan`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WebScanSnapshot
{
    /// Lifecycle phase (`"idle"`, `"running"`, `"done"`, `"error"`).
    pub status: String,
    /// Current candidate step index.
    pub progress_done: usize,
    /// Total candidates in current protocol catalog.
    pub progress_total: usize,
    /// Concise status headline displayed above the progress bar.
    pub label: String,
    /// Recent diagnostic/pass log lines.
    pub logs: Vec<String>,
    /// Completed target summaries.
    pub targets: Vec<ScanTargetSummary>,
    /// Rendered scoped `nfqws2.toml` ready for review or Save & Apply.
    pub rendered_toml: String,
    /// Optional failure message when `status == "error"`.
    pub error: Option<String>,
}

impl Default for WebScanSnapshot
{
    /// Returns an idle scan state.
    fn default() -> Self
    {
        Self {
            status: "idle".to_owned(),
            progress_done: 0,
            progress_total: 0,
            label: "Ready to scan".to_owned(),
            logs: Vec::new(),
            targets: Vec::new(),
            rendered_toml: String::new(),
            error: None,
        }
    }
}

/// Shared coordinator managing a single background web-triggered Strategy Finder run.
#[derive(Default)]
pub struct WebScanJob
{
    /// Latest snapshot readable synchronously via `GET /api/scan`.
    state: Arc<Mutex<WebScanSnapshot>>,
    /// Active cancellation flag checked by [`run_scan`].
    stop_flag: Mutex<Option<Arc<AtomicBool>>>,
    /// Worker thread handle replaced cleanly when the next scan starts.
    join: Mutex<Option<JoinHandle<()>>>,
}

impl WebScanJob
{
    /// Returns a cloned snapshot of the current/last Strategy Finder run.
    pub fn snapshot(&self) -> WebScanSnapshot
    {
        self.state.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Requests cancellation of an active scan, returning `true` when one was running.
    pub fn stop(&self) -> bool
    {
        if let Ok(guard) = self.stop_flag.lock()
            && let Some(flag) = guard.as_ref()
        {
            flag.store(true, Ordering::Release);
            return true;
        }
        false
    }

    /// Validates options, checks privileges/Lua, atomically claims the scan slot, and starts worker.
    pub fn start(
        &self,
        req: ScanStartPayload,
        cfg: &WebConfig,
        ipc: &Arc<WebIpcBridge>,
    ) -> Result<WebScanSnapshot, (u16, String)>
    {
        if !has_packet_capture_privileges().unwrap_or(false)
        {
            return Err((403, "web process lacks packet capture / administrator privileges".to_owned()));
        }
        let domains: Vec<String> = req.domains.iter().filter_map(|d| parse_clean_domain(d)).collect();
        if domains.is_empty()
        {
            return Err((400, "enter at least one valid domain".to_owned()));
        }
        let protos = parse_protos(&req.protos).map_err(|e| (400, e))?;
        let level: ScanLevel = req.level.as_deref().unwrap_or("standard").parse().map_err(|e| (400, e))?;
        let secs = req.timeout_secs.unwrap_or(2.0);
        if !secs.is_finite() || secs <= 0.0
        {
            return Err((400, "invalid scan timeout".to_owned()));
        }
        let lua_scripts = resolve_lua_scripts(cfg.lua_dir.as_deref()).map_err(|e| (400, e))?;

        let initial = WebScanSnapshot {
            status: "running".to_owned(),
            label: "Starting scan...".to_owned(),
            ..WebScanSnapshot::default()
        };
        {
            let mut guard = self.state.lock().map_err(|_| (500, "scan lock poisoned".to_owned()))?;
            if guard.status == "running"
            {
                return Err((409, "a scan is already running".to_owned()));
            }
            *guard = initial.clone();
        }
        let release_claim = |msg: &str| {
            if let Ok(mut guard) = self.state.lock()
            {
                guard.status = "failed".to_owned();
                guard.error = Some(msg.to_owned());
            }
        };

        if let Ok(mut j) = self.join.lock()
            && let Some(old) = j.take()
        {
            let _ = old.join();
        }

        let scan_cfg = ScanConfig {
            domains,
            protos,
            families: vec![IpFamily::V4],
            level,
            timeout: Duration::from_secs_f64(secs.clamp(0.2, 60.0)),
            stop_on_first: req.stop_on_first,
            force_blocked: false,
        };
        let (tcp, udp) = scan_cfg.required_ports();
        #[cfg(target_os = "linux")]
        let fw_res = NftFirewallBackend::default().install_non_interactive(
            DEFAULT_STRAT_QNUM,
            DEFAULT_DESYNC_FWMARK,
            &tcp,
            &udp,
        );
        #[cfg(not(target_os = "linux"))]
        let fw_res = active_firewall_backend().install(DEFAULT_STRAT_QNUM, DEFAULT_DESYNC_FWMARK, &tcp, &udp);
        let fw_guard = match fw_res
        {
            Ok(g) => g,
            Err(e) =>
            {
                let code = if e.kind() == std::io::ErrorKind::PermissionDenied { 403 } else { 500 };
                let msg = format!("firewall setup failed: {e}");
                release_claim(&msg);
                return Err((code, msg));
            }
        };

        let stop = Arc::new(AtomicBool::new(false));
        if let Ok(mut f) = self.stop_flag.lock()
        {
            *f = Some(Arc::clone(&stop));
        }

        ipc.emit_event("scan", &initial);

        let state_bg = Arc::clone(&self.state);
        let ipc_bg = Arc::clone(ipc);
        let handle = match thread::Builder::new()
            .name("zapret-web-scan".to_owned())
            .spawn(move || run_scan_worker(scan_cfg, lua_scripts, fw_guard, stop, state_bg, ipc_bg))
        {
            Ok(h) => h,
            Err(e) =>
            {
                let msg = format!("failed to spawn scan thread: {e}");
                release_claim(&msg);
                return Err((500, msg));
            }
        };
        if let Ok(mut j) = self.join.lock()
        {
            *j = Some(handle);
        }
        Ok(initial)
    }
}

/// Parses requested protocol identifiers or returns defaults (`http,tls12,tls13`).
fn parse_protos(raw: &[String]) -> Result<Vec<ProbeProtocol>, String>
{
    if raw.is_empty()
    {
        return Ok(vec![ProbeProtocol::Http, ProbeProtocol::Tls12, ProbeProtocol::Tls13]);
    }
    let mut out = Vec::new();
    for item in raw
    {
        let p: ProbeProtocol = item.parse()?;
        if !out.contains(&p)
        {
            out.push(p);
        }
    }
    Ok(out)
}

/// Appends one line to capped `logs` and broadcasts the current scan snapshot.
fn push_scan_log(st: &mut WebScanSnapshot, line: String)
{
    if st.logs.len() >= MAX_SCAN_LOGS
    {
        st.logs.remove(0);
    }
    st.logs.push(line);
}

/// Updates live scan snapshot state and pushes an SSE `scan` event for each progress callback.
fn record_scan_progress(ev: ProgressEvent<'_>, state: &Arc<Mutex<WebScanSnapshot>>, ipc: &WebIpcBridge)
{
    let Ok(mut st) = state.lock()
    else
    {
        return;
    };
    match ev
    {
        ProgressEvent::Http3Unavailable =>
        {
            push_scan_log(&mut st, "[warn] curl lacks HTTP/3 support; skipping http3".to_owned());
        }
        ProgressEvent::Baseline { domain, proto, ipv, outcome } =>
        {
            let tag = if outcome.is_success() { "reachable (skip)" } else { "blocked" };
            st.label = format!("Baseline {domain} ({proto}/{ipv}): {}", outcome.summary());
            push_scan_log(
                &mut st,
                format!("[baseline] {domain} ({proto}/{ipv}) -> {} [{tag}]", outcome.summary()),
            );
        }
        ProgressEvent::Candidate { domain, index, total, strategy, outcome } =>
        {
            st.progress_done = index;
            st.progress_total = total;
            st.label = format!("{domain} [{index}/{total}] {}", strategy.id);
            if outcome.is_success()
            {
                push_scan_log(
                    &mut st,
                    format!("[PASS {index}/{total}] {domain} :: {} -> {}", strategy.id, outcome.summary()),
                );
            }
        }
    }
    ipc.emit_event("scan", &*st);
}

/// Renders minimal covering `nfqws2.toml` and stores final scan target summaries into shared state.
fn finalize_scan_snapshot(
    report: crate::tools::strat::ScanReport,
    lua_scripts: Vec<std::path::PathBuf>,
    state: &Arc<Mutex<WebScanSnapshot>>,
    ipc: &WebIpcBridge,
)
{
    let rendered_toml = if report.cover.is_empty()
    {
        String::new()
    }
    else
    {
        render_nfqws2_toml_scoped(
            &report.cover,
            &TomlRenderOptions { qnum: 200, fwmark: DEFAULT_DESYNC_FWMARK, lua_init: lua_scripts },
            DomainScope::ScannedOnly,
        )
    };
    if let Ok(mut st) = state.lock()
    {
        st.status = "done".to_owned();
        st.progress_done = st.progress_total;
        st.label = if report.interrupted
        {
            format!("Stopped early: {} covering profile(s)", report.cover.len())
        }
        else
        {
            format!("Done: {} minimal covering profile(s)", report.cover.len())
        };
        st.targets = report
            .targets
            .iter()
            .map(|t| ScanTargetSummary {
                domain: t.domain.clone(),
                proto: t.proto.as_str().to_owned(),
                ipv: t.ipv.as_str().to_owned(),
                baseline: t.baseline.summary(),
                skipped: t.skipped_unblocked,
                best_strategy: t.matches.first().map(|m| m.strategy.id.clone()),
                best_latency_ms: t.matches.first().map(|m| m.latency_ms),
            })
            .collect();
        st.rendered_toml = rendered_toml;
        ipc.emit_event("scan", &*st);
    }
}

/// Runs the background capture worker, firewall guard lifetime, and scan orchestration.
fn run_scan_worker(
    scan_cfg: ScanConfig,
    lua_scripts: Vec<std::path::PathBuf>,
    fw_guard: Box<dyn crate::tools::FirewallHandle>,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<WebScanSnapshot>>,
    ipc: Arc<WebIpcBridge>,
)
{
    static NEVER_STOP: AtomicBool = AtomicBool::new(false);
    let mut base_cfg =
        AppConfig { qnum: DEFAULT_STRAT_QNUM, fwmark: DEFAULT_DESYNC_FWMARK, ..AppConfig::default() };
    base_cfg.ipcache.hostname = true;
    base_cfg.lua_init = lua_scripts.iter().cloned().map(LuaInitEntry::File).collect();

    let mut worker = match InProcessWorkerHandle::spawn(base_cfg, &NEVER_STOP)
    {
        Ok(w) => w,
        Err(err) =>
        {
            drop(fw_guard);
            finish_scan_error(&state, &ipc, err);
            return;
        }
    };
    let probe = CurlProbeBackend::default();
    let res = run_scan(&scan_cfg, &probe, &mut worker, &stop, |ev| {
        record_scan_progress(ev, &state, &ipc);
    });
    drop(worker);
    drop(fw_guard);

    match res
    {
        Ok(report) => finalize_scan_snapshot(report, lua_scripts, &state, &ipc),
        Err(err) => finish_scan_error(&state, &ipc, err),
    }
}

/// Records scan failure state and emits final SSE `scan` event.
fn finish_scan_error(state: &Arc<Mutex<WebScanSnapshot>>, ipc: &WebIpcBridge, err: String)
{
    if let Ok(mut st) = state.lock()
    {
        st.status = "error".to_owned();
        st.label = format!("Error: {err}");
        st.error = Some(err.clone());
        push_scan_log(&mut st, format!("[error] {err}"));
        ipc.emit_event("scan", &*st);
    }
}
