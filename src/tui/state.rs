//! Mutable `zapret-rs` TUI application state and pure keyboard/event state transitions.

/// Bounded ring buffers for live scan and daemon log panels.
use std::collections::VecDeque;
/// Path handling for config files, Lua directories, and executable paths.
use std::path::PathBuf;
/// Lock-free shared packet counters updated by the live NFQUEUE daemon thread.
use std::sync::Arc;
/// Default probe timeout for strategy finder scans launched from the TUI.
use std::time::Duration;

/// Keyboard event primitives handled by [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Validated `nfqws2` configuration model loaded by the Run and Config tabs.
use crate::config::AppConfig;
/// Default desync fwmark constant shared across tabs.
use crate::intercepter::DEFAULT_DESYNC_FWMARK;
/// Capability verification helper for the Diagnostics panel.
use crate::runtime::{CAP_MASK_NET, has_effective_caps};
/// Strategy catalog, TOML renderer, interactive path helpers, and firewall script preview.
use crate::tools::{
    CoveredProfile, DEFAULT_STRAT_QNUM, NftFirewallBackend, ProbeProtocol, ScanConfig, ScanLevel,
    TargetScanResult, default_output_config_path, detect_lua_dir, expand_tilde, normalize_domain,
};
/// Live packet inspector state for Tab 2.
use crate::tui::inspect::PacketInspectorState;
/// Floating capability-grant and `sudo` password modal state.
use crate::tui::modal::{AuthModal, ModalKeyResult, ModalPurpose};
/// Shared TUI enums, telemetry counters, and worker event types.
use crate::tui::types::{
    ActiveTab, AppAction, FinderField, FinderStatus, IpMode, PacketCounters, RunStatus, ScanUiEvent,
};

/// Maximum number of log lines retained in each scrollable log panel.
const MAX_LOG_LINES: usize = 200;

/// Complete mutable state of the `zapret-rs` TUI application.
pub struct AppState {
    /// Currently visible top-level tab.
    pub tab: ActiveTab,
    /// Selected row index within [`FinderField::ALL`].
    pub focus_idx: usize,
    /// `true` while typing into a focused text field.
    pub editing_text: bool,
    /// Comma/space-separated target domains input buffer.
    pub domains_input: String,
    /// Enabled HTTP (TCP 80) protocol checkbox.
    pub proto_http: bool,
    /// Enabled TLS 1.2 (TCP 443) protocol checkbox.
    pub proto_tls12: bool,
    /// Enabled TLS 1.3 (TCP 443) protocol checkbox.
    pub proto_tls13: bool,
    /// Enabled HTTP/3 QUIC (UDP 443) protocol checkbox.
    pub proto_http3: bool,
    /// Selected IP family mode.
    pub ip_mode: IpMode,
    /// Selected scan thoroughness level.
    pub level: ScanLevel,
    /// Stop sweeping a target on first working strategy.
    pub stop_on_first: bool,
    /// Skip automatic `nftables` setup/teardown.
    pub no_nft: bool,
    /// Lua scripts directory input buffer.
    pub lua_dir_input: String,
    /// Destination/loaded `nfqws2.toml` path input buffer.
    pub output_path: String,
    /// NFQUEUE number used during strategy finder scans.
    pub finder_qnum: u16,
    /// Firewall mark used for loop prevention.
    pub fwmark: u32,
    /// Current Finder background task status.
    pub finder_status: FinderStatus,
    /// Current progress numerator within the active target sweep.
    pub progress_done: usize,
    /// Current progress denominator within the active target sweep.
    pub progress_total: usize,
    /// Human-readable status label inside the progress gauge.
    pub progress_label: String,
    /// Per-target completed results shown in the Finder table.
    pub targets: Vec<TargetScanResult>,
    /// Minimal cross-domain profile cover from the latest scan.
    pub cover: Vec<CoveredProfile>,
    /// Recent strategy finder log messages.
    pub finder_logs: VecDeque<String>,
    /// Current live `nfqws2` daemon status on Tab 2.
    pub run_status: RunStatus,
    /// Lock-free packet counters shared with the live `nfqws2` worker thread.
    pub counters: Arc<PacketCounters>,
    /// Recent live `nfqws2` daemon log lines.
    pub run_logs: VecDeque<String>,
    /// Active TOML text shown in Tab 3 and executed by Tab 2.
    pub active_toml: String,
    /// Parsed profile names summary for the active TOML (`empty` when invalid/empty).
    pub parsed_profiles: Vec<String>,
    /// Vertical scroll offset inside Tab 3's TOML preview pane.
    pub toml_scroll: u16,
    /// Effective UID captured at startup for diagnostics.
    pub uid: u32,
    /// Whether `CAP_NET_ADMIN|CAP_NET_RAW` are active in the current process.
    pub has_net_caps: bool,
    /// Current executable path displayed in `setcap` guidance.
    pub exe_path: String,
    /// Transient footer notification line.
    pub status_banner: String,
    /// Active floating capability-grant / `sudo` authentication modal, when visible.
    pub modal: Option<AuthModal>,
    /// Live packet inspector table, filter, pause toggle, and detail popup state on Tab 2.
    pub inspector: PacketInspectorState,
}

impl AppState {
    /// Initializes TUI state with auto-detected Lua directory, capability snapshot, and optional config.
    pub fn new(initial_config: Option<PathBuf>, initial_lua_dir: Option<PathBuf>, no_nft: bool) -> Self {
        let lua_dir = initial_lua_dir
            .or_else(|| detect_lua_dir(None))
            .map_or_else(String::new, |p| p.display().to_string());
        let output_path = initial_config
            .clone()
            .unwrap_or_else(default_output_config_path)
            .display()
            .to_string();
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        let uid = unsafe { libc::geteuid() };
        let has_net_caps = has_effective_caps(CAP_MASK_NET).unwrap_or(false);
        let exe_path = std::env::current_exe()
            .ok()
            .map_or_else(|| "./target/release/zapret-rs".to_owned(), |p| p.display().to_string());

        let mut state = Self {
            tab: ActiveTab::Finder, focus_idx: 0, editing_text: false,
            domains_input: String::new(),
            proto_http: true, proto_tls12: true, proto_tls13: true, proto_http3: true,
            ip_mode: IpMode::V4, level: ScanLevel::Quick, stop_on_first: true, no_nft,
            lua_dir_input: lua_dir, output_path,
            finder_qnum: DEFAULT_STRAT_QNUM, fwmark: DEFAULT_DESYNC_FWMARK,
            finder_status: FinderStatus::Idle, progress_done: 0, progress_total: 0,
            progress_label: "Idle: enter domain(s) and press 'r' to scan".to_owned(),
            targets: Vec::new(), cover: Vec::new(), finder_logs: VecDeque::new(),
            run_status: RunStatus::Stopped, counters: Arc::new(PacketCounters::default()),
            run_logs: VecDeque::new(), active_toml: String::new(),
            parsed_profiles: Vec::new(), toml_scroll: 0, uid, has_net_caps, exe_path,
            status_banner: "Ready. Use 1/2/3 or Tab to switch views, 'q' to quit.".to_owned(),
            modal: None,
            inspector: PacketInspectorState::default(),
        };
        let cfg_path = expand_tilde(&state.output_path);
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            state.set_active_toml(text);
            state.status_banner = format!("Loaded {}", cfg_path.display());
        }
        state
    }

    /// Returns the currently focused [`FinderField`].
    pub fn focused_field(&self) -> FinderField {
        FinderField::ALL[self.focus_idx.min(FinderField::ALL.len() - 1)]
    }

    /// Appends a bounded line to the Finder log buffer.
    pub fn push_finder_log(&mut self, msg: impl Into<String>) {
        if self.finder_logs.len() >= MAX_LOG_LINES { self.finder_logs.pop_front(); }
        self.finder_logs.push_back(msg.into());
    }

    /// Appends a bounded line to the Run daemon log buffer.
    pub fn push_run_log(&mut self, msg: impl Into<String>) {
        if self.run_logs.len() >= MAX_LOG_LINES { self.run_logs.pop_front(); }
        self.run_logs.push_back(msg.into());
    }

    /// Updates `active_toml` and refreshes `parsed_profiles` summary if the TOML parses cleanly.
    pub fn set_active_toml(&mut self, toml: String) {
        self.parsed_profiles = match AppConfig::from_toml_str(&toml, None) {
            Ok(cfg) => cfg.profiles.iter().map(|p| p.name.clone().unwrap_or_else(|| format!("profile #{}", p.index))).collect(),
            Err(_) => Vec::new(),
        };
        self.active_toml = toml;
        self.toml_scroll = 0;
    }

    /// Returns the currently selected protocol list from the Finder checkboxes.
    pub fn selected_protos(&self) -> Vec<ProbeProtocol> {
        let mut out = Vec::new();
        if self.proto_http { out.push(ProbeProtocol::Http); }
        if self.proto_tls12 { out.push(ProbeProtocol::Tls12); }
        if self.proto_tls13 { out.push(ProbeProtocol::Tls13); }
        if self.proto_http3 { out.push(ProbeProtocol::Http3); }
        out
    }

    /// Validates Finder form fields and constructs a [`ScanConfig`].
    pub fn build_scan_config(&self) -> Result<ScanConfig, String> {
        let domains: Vec<String> = self.domains_input.split(|c: char| c.is_whitespace() || c == ',').filter_map(normalize_domain).collect();
        if domains.is_empty() {
            return Err("enter at least one domain first (focus Domains, press Enter)".to_owned());
        }
        let protos = self.selected_protos();
        if protos.is_empty() {
            return Err("enable at least one protocol checkbox".to_owned());
        }
        Ok(ScanConfig {
            domains, protos, families: self.ip_mode.families(), level: self.level,
            timeout: Duration::from_secs(3), stop_on_first: self.stop_on_first, force_blocked: false,
        })
    }

    /// Renders the `nftables` ruleset preview matching the current Finder ports and queue settings.
    pub fn nft_preview_script(&self) -> String {
        let cfg = ScanConfig {
            domains: Vec::new(), protos: self.selected_protos(), families: self.ip_mode.families(),
            level: self.level, timeout: Duration::from_secs(3), stop_on_first: self.stop_on_first, force_blocked: false,
        };
        let (tcp, udp) = cfg.required_ports();
        NftFirewallBackend::build_nft_script(self.finder_qnum, self.fwmark, &tcp, &udp)
    }

    /// Applies one background [`ScanUiEvent`] to live progress, results table, logs, and TOML.
    pub fn apply_scan_event(&mut self, event: ScanUiEvent) {
        match event {
            ScanUiEvent::Baseline { domain, proto, ipv, summary, skipped } => {
                let tag = if skipped { "reachable (skip)" } else { "blocked" };
                self.progress_label = format!("Baseline {domain} ({proto}/{ipv}): {summary}");
                self.push_finder_log(format!("[baseline] {domain} ({proto}/{ipv}) -> {summary} [{tag}]"));
            }
            ScanUiEvent::Candidate { domain, index, total, strategy_id, passed, summary } => {
                self.progress_done = index;
                self.progress_total = total;
                self.progress_label = format!("{domain} [{index}/{total}] {strategy_id}");
                if passed {
                    self.push_finder_log(format!("[PASS {index}/{total}] {domain} :: {strategy_id} -> {summary}"));
                }
            }
            ScanUiEvent::Notice(msg) => self.push_finder_log(msg),
            ScanUiEvent::Completed { report, rendered_toml } => {
                let n_cover = report.cover.len();
                self.targets = report.targets;
                self.cover = report.cover;
                self.finder_status = FinderStatus::Done;
                self.progress_done = self.progress_total;
                if !rendered_toml.is_empty() {
                    self.set_active_toml(rendered_toml);
                }
                self.progress_label = if report.interrupted {
                    format!("Stopped early: {n_cover} covering profile(s)")
                } else {
                    format!("Done: {n_cover} minimal covering profile(s)")
                };
                self.status_banner = if n_cover > 0 {
                    format!("Found {n_cover} profile(s). Press 's' to save or 'a' to open Run tab.")
                } else {
                    "Scan finished. No blocked domains needed bypass (or none matched).".to_owned()
                };
            }
            ScanUiEvent::Failed(err) => {
                self.finder_status = FinderStatus::Error(err.clone());
                self.progress_label = format!("Error: {err}");
                self.status_banner = format!("Scan error: {err}");
                self.push_finder_log(format!("[error] {err}"));
            }
        }
    }

    /// Opens the centered floating modal for granting `CAP_NET_ADMIN|CAP_NET_RAW`.
    pub fn open_caps_modal(&mut self) {
        let cmd = format!("sudo setcap cap_net_admin,cap_net_raw+ep {}", self.exe_path);
        self.modal = Some(AuthModal::open(ModalPurpose::GrantCaps, cmd));
    }

    /// Processes a terminal key press and returns any side-effect [`AppAction`] for the runner.
    pub fn handle_key(&mut self, key: KeyEvent) -> AppAction {
        if let Some(modal) = self.modal.as_mut() {
            return match modal.handle_key(key) {
                ModalKeyResult::KeepOpen => AppAction::None,
                ModalKeyResult::Close => { self.modal = None; AppAction::None }
                ModalKeyResult::Submit => AppAction::SubmitModal,
            };
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return AppAction::Quit;
        }
        if self.editing_text {
            return self.handle_text_edit_key(key.code);
        }
        match key.code {
            KeyCode::Char('q') => return AppAction::Quit,
            KeyCode::Char('g') if !self.has_net_caps => { self.open_caps_modal(); return AppAction::None; }
            KeyCode::Char('1') => { self.tab = ActiveTab::Finder; return AppAction::None; }
            KeyCode::Char('2') => { self.tab = ActiveTab::Run; return AppAction::None; }
            KeyCode::Char('3') => { self.tab = ActiveTab::Config; return AppAction::None; }
            KeyCode::Tab => { self.tab = self.tab.next(); return AppAction::None; }
            KeyCode::BackTab => { self.tab = self.tab.prev(); return AppAction::None; }
            _ => {}
        }
        match self.tab {
            ActiveTab::Finder => self.handle_finder_key(key.code),
            ActiveTab::Run => self.handle_run_key(key.code),
            ActiveTab::Config => self.handle_config_key(key.code),
        }
    }

    /// Edits the active text field buffer while [`AppState::editing_text`] is `true`.
    fn handle_text_edit_key(&mut self, code: KeyCode) -> AppAction {
        let buf = match self.focused_field() {
            FinderField::Domains => &mut self.domains_input,
            FinderField::LuaDir => &mut self.lua_dir_input,
            FinderField::OutputPath => &mut self.output_path,
            _ => { self.editing_text = false; return AppAction::None; }
        };
        match code {
            KeyCode::Esc | KeyCode::Enter => { self.editing_text = false; self.status_banner = "Field updated.".to_owned(); }
            KeyCode::Backspace => { buf.pop(); }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        AppAction::None
    }

    /// Handles navigation, toggling, scan control, and config handoff on the Strategy Finder tab.
    fn handle_finder_key(&mut self, code: KeyCode) -> AppAction {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.focus_idx = if self.focus_idx == 0 { FinderField::ALL.len() - 1 } else { self.focus_idx - 1 };
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.focus_idx = (self.focus_idx + 1) % FinderField::ALL.len();
            }
            KeyCode::Enter | KeyCode::Char(' ') => match self.focused_field() {
                f if f.is_text() => {
                    self.editing_text = true;
                    self.status_banner = "Editing field: press Enter or Esc when done.".to_owned();
                }
                FinderField::ProtoHttp => self.proto_http = !self.proto_http,
                FinderField::ProtoTls12 => self.proto_tls12 = !self.proto_tls12,
                FinderField::ProtoTls13 => self.proto_tls13 = !self.proto_tls13,
                FinderField::ProtoHttp3 => self.proto_http3 = !self.proto_http3,
                FinderField::IpMode => self.ip_mode = self.ip_mode.next(),
                FinderField::Level => {
                    self.level = match self.level {
                        ScanLevel::Quick => ScanLevel::Standard,
                        ScanLevel::Standard => ScanLevel::Force,
                        ScanLevel::Force => ScanLevel::Quick,
                    };
                }
                FinderField::StopOnFirst => self.stop_on_first = !self.stop_on_first,
                FinderField::NoNft => self.no_nft = !self.no_nft,
                _ => {}
            },
            KeyCode::Char('r') if self.finder_status != FinderStatus::Scanning => return AppAction::StartScan,
            KeyCode::Char('x') | KeyCode::Esc if self.finder_status == FinderStatus::Scanning => return AppAction::StopScan,
            KeyCode::Char('s') => return AppAction::SaveConfig,
            KeyCode::Char('a') => {
                if self.active_toml.is_empty() {
                    self.status_banner = "No generated config yet: run a scan or load a file first.".to_owned();
                } else {
                    self.tab = ActiveTab::Run;
                    self.status_banner = "Active config ready on Run tab. Press 'r' to start nfqws2.".to_owned();
                }
            }
            _ => {}
        }
        AppAction::None
    }

    /// Handles start/stop, config reload, counter reset, and live packet inspection on Tab 2.
    fn handle_run_key(&mut self, code: KeyCode) -> AppAction {
        if let Some(msg) = self.inspector.handle_key(code) {
            if !msg.is_empty() { self.status_banner = msg; }
            return AppAction::None;
        }
        match code {
            KeyCode::Char('r') | KeyCode::Enter => {
                if self.run_status == RunStatus::Running { AppAction::StopDaemon } else { AppAction::StartDaemon }
            }
            KeyCode::Char('x') if self.run_status == RunStatus::Running => AppAction::StopDaemon,
            KeyCode::Char('l') => AppAction::ReloadConfig,
            KeyCode::Char('c') => {
                self.counters.reset();
                self.inspector.clear();
                self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Handles TOML preview scrolling, saving, and reloading on the Config & Diagnostics tab.
    fn handle_config_key(&mut self, code: KeyCode) -> AppAction {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.toml_scroll = self.toml_scroll.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => self.toml_scroll = self.toml_scroll.saturating_add(1),
            KeyCode::PageUp => self.toml_scroll = self.toml_scroll.saturating_sub(10),
            KeyCode::PageDown => self.toml_scroll = self.toml_scroll.saturating_add(10),
            KeyCode::Char('s') => return AppAction::SaveConfig,
            KeyCode::Char('l') => return AppAction::ReloadConfig,
            _ => {}
        }
        AppAction::None
    }
}
