//! Mutable `zapret-rs` TUI application state and pure keyboard/event state transitions.

/// Bounded ring buffers for live scan and daemon log panels.
use std::collections::VecDeque;
/// Path handling for config files, Lua directories, control sockets, and executable paths.
use std::path::PathBuf;
/// Lock-free shared packet counters updated by the live NFQUEUE daemon or remote subscriber thread.
use std::sync::Arc;

/// Keyboard event primitives handled by [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Validated `nfqws2` configuration model loaded by the Run and Config tabs.
use crate::config::AppConfig;
/// Default desync fwmark constant shared across tabs.
use crate::intercepter::DEFAULT_DESYNC_FWMARK;
/// Capability verification helper for the Diagnostics panel.
use crate::runtime::{CAP_MASK_NET, has_effective_caps};
/// Lock-free packet counter type shared across Tab 2 sessions.
use crate::telemetry::PacketCounters;
/// Strategy catalog, scan level, and interactive path helpers.
use crate::tools::{
    CoveredProfile, DEFAULT_STRAT_QNUM, ScanLevel, TargetScanResult, default_output_config_path,
    detect_lua_dir, expand_tilde,
};
/// Live packet inspector state for Tab 2.
use crate::tui::inspect::PacketInspectorState;
/// Floating capability-grant, `sudo` auth, and daemon-stop confirmation modal state.
use crate::tui::modal::{AuthModal, ModalKeyResult, ModalPurpose};
/// Attached background `nfqws2` daemon metadata shown on Tab 2.
use crate::tui::remote::RemoteDaemonMeta;
/// Shared TUI enums and worker event types.
use crate::tui::types::{ActiveTab, AppAction, FinderField, FinderStatus, IpMode, RunStatus};

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
    /// Explicit `--control-socket` override passed into the TUI CLI, if any.
    pub control_socket_override: Option<PathBuf>,
    /// Auto-detected running daemon socket path ready to attach when stopped.
    pub detected_socket: Option<PathBuf>,
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
    /// Current live `nfqws2` daemon or remote attach status on Tab 2.
    pub run_status: RunStatus,
    /// Active remote daemon metadata while `run_status == RunStatus::Attached`.
    pub remote_meta: Option<RemoteDaemonMeta>,
    /// Lock-free packet counters shared with local worker or remote subscriber thread.
    pub counters: Arc<PacketCounters>,
    /// Recent live `nfqws2` daemon log lines.
    pub run_logs: VecDeque<String>,
    /// Active TOML text shown in Tab 3 and executed by Tab 2.
    pub active_toml: String,
    /// Parsed profile names summary for the active TOML (`empty` when invalid/empty).
    pub parsed_profiles: Vec<String>,
    /// Parse error message for `active_toml` when non-empty and invalid (`None` when valid/empty).
    pub toml_error: Option<String>,
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
    /// Active floating capability-grant / `sudo` / stop-confirm modal, when visible.
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
            tab: ActiveTab::Finder,
            focus_idx: 0,
            editing_text: false,
            domains_input: String::new(),
            proto_http: true,
            proto_tls12: true,
            proto_tls13: true,
            proto_http3: true,
            ip_mode: IpMode::V4,
            level: ScanLevel::Quick,
            stop_on_first: true,
            no_nft,
            lua_dir_input: lua_dir,
            output_path,
            control_socket_override: None,
            detected_socket: None,
            finder_qnum: DEFAULT_STRAT_QNUM,
            fwmark: DEFAULT_DESYNC_FWMARK,
            finder_status: FinderStatus::Idle,
            progress_done: 0,
            progress_total: 0,
            progress_label: "Idle: enter domain(s) and press 'r' to scan".to_owned(),
            targets: Vec::new(),
            cover: Vec::new(),
            finder_logs: VecDeque::new(),
            run_status: RunStatus::Stopped,
            remote_meta: None,
            counters: Arc::new(PacketCounters::default()),
            run_logs: VecDeque::new(),
            active_toml: String::new(),
            parsed_profiles: Vec::new(),
            toml_error: None,
            toml_scroll: 0,
            uid,
            has_net_caps,
            exe_path,
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
        if self.finder_logs.len() >= MAX_LOG_LINES {
            self.finder_logs.pop_front();
        }
        self.finder_logs.push_back(msg.into());
    }

    /// Appends a bounded line to the Run daemon log buffer.
    pub fn push_run_log(&mut self, msg: impl Into<String>) {
        if self.run_logs.len() >= MAX_LOG_LINES {
            self.run_logs.pop_front();
        }
        self.run_logs.push_back(msg.into());
    }

    /// Transitions Tab 2 into [`RunStatus::Attached`] with `meta` and logs attachment.
    pub fn set_attached(&mut self, meta: RemoteDaemonMeta) {
        let log_line = format!(
            "[attach] connected to PID {} on queue {} ({}, {} profiles)",
            meta.pid,
            meta.qnum,
            meta.socket_path.display(),
            meta.profile_names.len()
        );
        self.status_banner =
            "Attached to nfqws2. Press 'x' to detach, 'l' to reload lists, 'S' to stop daemon."
                .to_owned();
        self.detected_socket = Some(meta.socket_path.clone());
        self.remote_meta = Some(meta);
        self.run_status = RunStatus::Attached;
        self.push_run_log(log_line);
    }

    /// Transitions Tab 2 back from [`RunStatus::Attached`] to [`RunStatus::Stopped`].
    pub fn set_detached(&mut self, log_line: String, banner: String) {
        self.remote_meta = None;
        self.run_status = RunStatus::Stopped;
        self.push_run_log(log_line);
        self.status_banner = banner;
    }

    /// Updates `active_toml` and refreshes `parsed_profiles` and `toml_error` validation state.
    pub fn set_active_toml(&mut self, toml: String) {
        if toml.trim().is_empty() {
            self.parsed_profiles.clear();
            self.toml_error = None;
        } else {
            match AppConfig::from_toml_str(&toml, None) {
                Ok(cfg) => {
                    self.parsed_profiles = cfg
                        .profiles
                        .iter()
                        .map(|p| p.name.clone().unwrap_or_else(|| format!("profile #{}", p.index)))
                        .collect();
                    self.toml_error = None;
                }
                Err(err) => {
                    self.parsed_profiles.clear();
                    self.toml_error = Some(err.to_string());
                }
            }
        }
        self.active_toml = toml;
        self.toml_scroll = 0;
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
                ModalKeyResult::Close => {
                    self.modal = None;
                    AppAction::None
                }
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
            KeyCode::Char('g') if !self.has_net_caps => {
                self.open_caps_modal();
                return AppAction::None;
            }
            KeyCode::Char('1') => {
                self.tab = ActiveTab::Finder;
                return AppAction::None;
            }
            KeyCode::Char('2') => {
                self.tab = ActiveTab::Run;
                return AppAction::None;
            }
            KeyCode::Char('3') => {
                self.tab = ActiveTab::Config;
                return AppAction::None;
            }
            KeyCode::Tab => {
                self.tab = self.tab.next();
                return AppAction::None;
            }
            KeyCode::BackTab => {
                self.tab = self.tab.prev();
                return AppAction::None;
            }
            _ => {}
        }
        match self.tab {
            ActiveTab::Finder => self.handle_finder_key(key.code),
            ActiveTab::Run => self.handle_run_key(key.code),
            ActiveTab::Config => self.handle_config_key(key.code),
        }
    }

    /// Handles start/attach, detach/stop, remote commands, counter reset, and inspector keys on Tab 2.
    fn handle_run_key(&mut self, code: KeyCode) -> AppAction {
        if let Some(msg) = self.inspector.handle_key(code) {
            if !msg.is_empty() {
                self.status_banner = msg;
            }
            return AppAction::None;
        }
        if self.run_status == RunStatus::Attached {
            return match code {
                KeyCode::Char('x') => AppAction::DetachDaemon,
                KeyCode::Char('l') => AppAction::ReloadRemoteLists,
                KeyCode::Char('S') => {
                    let pid_label = self
                        .remote_meta
                        .as_ref()
                        .map_or_else(|| "remote".to_owned(), |m| format!("PID {}", m.pid));
                    let preview = format!("stop nfqws2 ({pid_label}) via control socket");
                    self.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmStopDaemon, preview));
                    AppAction::None
                }
                KeyCode::Char('c') => {
                    self.inspector.clear();
                    self.status_banner = "Inspector buffer cleared.".to_owned();
                    AppAction::None
                }
                _ => AppAction::None,
            };
        }
        match code {
            KeyCode::Char('r') | KeyCode::Enter => {
                if self.run_status == RunStatus::Running {
                    AppAction::StopDaemon
                } else {
                    AppAction::StartDaemon
                }
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

    /// Handles TOML preview scrolling, editing, saving, and reloading on the Config & Diagnostics tab.
    fn handle_config_key(&mut self, code: KeyCode) -> AppAction {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.toml_scroll = self.toml_scroll.saturating_sub(1),
            KeyCode::Down | KeyCode::Char('j') => {
                self.toml_scroll = self.toml_scroll.saturating_add(1);
            }
            KeyCode::PageUp => self.toml_scroll = self.toml_scroll.saturating_sub(10),
            KeyCode::PageDown => self.toml_scroll = self.toml_scroll.saturating_add(10),
            KeyCode::Char('e') | KeyCode::Enter => return AppAction::EditConfig,
            KeyCode::Char('s') => return AppAction::SaveConfig,
            KeyCode::Char('l') => return AppAction::ReloadConfig,
            _ => {}
        }
        AppAction::None
    }
}
