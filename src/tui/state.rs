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
/// OS-agnostic UID and packet-capture privilege helpers for the Diagnostics panel.
use crate::runtime::{current_uid_or_zero, has_packet_capture_privileges};
/// Lock-free packet counter type shared across Tab 2 sessions.
use crate::telemetry::PacketCounters;
/// Strategy catalog, scan level, and interactive path helpers.
use crate::tools::{
    CoveredProfile, DEFAULT_STRAT_QNUM, DomainScope, ScanLevel, TargetScanResult,
    default_output_config_path, detect_lua_dir, expand_tilde,
};
/// Live packet inspector state for Tab 2.
use crate::tui::inspect::PacketInspectorState;
/// Before/after speed comparison state for Tab 4.
use crate::tui::speed::SpeedState;
/// Floating capability-grant, `sudo` auth, and daemon-stop confirmation modal state.
use crate::tui::modal::{AuthModal, ModalKeyResult, ModalPurpose};
/// Attached background `nfqws2` daemon metadata shown on Tab 2.
use crate::tui::remote::RemoteDaemonMeta;
/// Configurable color theme palette and `theme.toml` load/save helpers.
use crate::tui::theme_config::{Theme, resolve_theme};
/// Shared TUI enums and worker event types.
use crate::tui::types::{
    ActiveTab, AppAction, FinderField, FinderHoverState, FinderStatus, IpMode, PanelFocusState,
    PostCapsAction, RunStatus,
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
    /// Byte cursor position within the active text-field buffer (clamped to buffer length on each edit).
    pub text_cursor: usize,
    /// Horizontal character scroll offset for browsing long unfocused/view-mode Tab 1 text fields.
    pub text_scroll: usize,
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
    /// Domain scoping mode applied when generating `nfqws2.toml` profiles from a scan.
    pub domain_scope: DomainScope,
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
    /// When `true`, automatically re-attaches if a daemon socket reappears after unexpected loss.
    pub auto_reattach: bool,
    /// Lock-free packet counters shared with local worker or remote subscriber thread.
    pub counters: Arc<PacketCounters>,
    /// Local display baseline subtracted from [`Self::counters`] after pressing `c` while attached.
    pub counter_baseline: (u64, u64, u64, u64, u64),
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
    /// `true` while the centered `?` keybindings popup is open.
    pub help_open: bool,
    /// Action automatically resumed once capability grant triggers a seamless restart.
    pub pending_caps_action: Option<PostCapsAction>,
    /// Dwell timer and visibility state for Tab 1's 1-second option explanation tooltip.
    pub finder_hover: FinderHoverState,
    /// Per-tab focused panel and scroll offsets switched via `Tab` / `Shift+Tab`.
    pub focus: PanelFocusState,
    /// Active configurable TUI color palette (`neon` by default, or from `theme.toml`).
    pub theme: Theme,
    /// Live packet inspector table, filter, pause toggle, and detail popup state on Tab 2.
    pub inspector: PacketInspectorState,
    /// Before/after speed comparison results and phase on Tab 4.
    pub speed: SpeedState,
    /// Stashed `(previous_toml, scan_toml)` awaiting user merge confirmation after a scan.
    pub pending_merge: Option<(String, String)>,
    /// Unique resolved `hostlist_auto` file paths referenced by `active_toml`.
    pub autohostlist_paths: Vec<PathBuf>,
    /// Learned domain entries currently loaded from `autohostlist_paths`.
    pub autohostlist_entries: Vec<String>,
    /// Cached operational health checks displayed on Tab 5 (`Status`).
    pub status_checks: Vec<crate::tui::status_check::ComponentCheck>,
    /// Selected row index inside Tab 5's component status table.
    pub status_selected: usize,
    /// Horizontal scroll offset for the selected Tab 5 `Summary` cell.
    pub status_hscroll: usize,
    /// Selected OS DNS/DoH preset cycled on Tab 5 (`n`) and applied on confirm (`a`).
    pub dns_preset: crate::tools::DnsPreset,
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
        let uid = current_uid_or_zero();
        let has_net_caps = has_packet_capture_privileges().unwrap_or(false);
        let exe_path = std::env::current_exe()
            .ok()
            .map_or_else(|| "./target/release/zapret-rs".to_owned(), |p| p.display().to_string());

        let (theme, theme_warn) = resolve_theme(None);

        let mut state = Self {
            tab: ActiveTab::Finder,
            focus_idx: 0,
            editing_text: false,
            text_cursor: 0,
            text_scroll: 0,
            domains_input: String::new(),
            proto_http: true, proto_tls12: true, proto_tls13: true, proto_http3: true,
            ip_mode: IpMode::V4,
            level: ScanLevel::Quick,
            stop_on_first: true,
            no_nft,
            lua_dir_input: lua_dir,
            output_path,
            domain_scope: DomainScope::default(),
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
            auto_reattach: true,
            counters: Arc::new(PacketCounters::default()),
            counter_baseline: (0, 0, 0, 0, 0),
            run_logs: VecDeque::new(),
            active_toml: String::new(),
            parsed_profiles: Vec::new(),
            toml_error: None,
            toml_scroll: 0,
            uid,
            has_net_caps,
            exe_path, status_banner: "Ready. Press '?' for keybindings.".to_owned(),
            modal: None, help_open: false, pending_caps_action: None,
            finder_hover: FinderHoverState::default(), focus: PanelFocusState::default(), theme,
            inspector: PacketInspectorState::default(), speed: SpeedState::default(),
            pending_merge: None, autohostlist_paths: Vec::new(), autohostlist_entries: Vec::new(),
            status_checks: Vec::new(), status_selected: 0, status_hscroll: 0, dns_preset: crate::tools::DnsPreset::Cloudflare,
        };
        let cfg_path = expand_tilde(&state.output_path);
        if let Ok(text) = std::fs::read_to_string(&cfg_path) {
            state.set_active_toml(text);
            state.status_banner = format!("Loaded {}", cfg_path.display());
        }
        if let Some(warn) = theme_warn {
            state.status_banner = warn;
        }
        state
    }

    /// Returns the currently focused [`FinderField`].
    pub fn focused_field(&self) -> FinderField {
        FinderField::ALL[self.focus_idx.min(FinderField::ALL.len() - 1)]
    }

    /// Pushes `msg` into a bounded [`VecDeque`], evicting the oldest line once full.
    fn push_bounded_log(buf: &mut VecDeque<String>, msg: String) {
        if buf.len() >= MAX_LOG_LINES {
            buf.pop_front();
        }
        buf.push_back(msg);
    }

    /// Appends a bounded line to the Finder log buffer.
    pub fn push_finder_log(&mut self, msg: impl Into<String>) {
        Self::push_bounded_log(&mut self.finder_logs, msg.into());
    }

    /// Appends a bounded line to the Run daemon log buffer.
    pub fn push_run_log(&mut self, msg: impl Into<String>) {
        Self::push_bounded_log(&mut self.run_logs, msg.into());
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
        self.auto_reattach = true;
        self.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
    }

    /// Transitions Tab 2 back from [`RunStatus::Attached`] to [`RunStatus::Stopped`].
    pub fn set_detached(&mut self, log_line: String, banner: String) {
        self.remote_meta = None;
        self.run_status = RunStatus::Stopped;
        self.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
        self.status_banner = banner;
    }

    /// Returns `(total, passed, reassembled, modified, desynced)` minus [`Self::counter_baseline`].
    pub fn visible_counters(&self) -> (u64, u64, u64, u64, u64) {
        let (s0, s1, s2, s3, s4) = self.counters.snapshot();
        let (b0, b1, b2, b3, b4) = self.counter_baseline;
        if s0 < b0 || s1 < b1 || s2 < b2 || s3 < b3 || s4 < b4 {
            return (s0, s1, s2, s3, s4);
        }
        (s0 - b0, s1 - b1, s2 - b2, s3 - b3, s4 - b4)
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
        self.refresh_autohostlist();
    }

    /// Opens the centered floating modal for granting `CAP_NET_ADMIN|CAP_NET_RAW`.
    pub fn open_caps_modal(&mut self) {
        self.open_caps_modal_for(None);
    }

    /// Opens the capability-grant modal and remembers any `action` to resume after restart.
    pub fn open_caps_modal_for(&mut self, action: Option<PostCapsAction>) {
        self.pending_caps_action = action;
        self.modal = Some(if cfg!(windows) {
            AuthModal::confirm(ModalPurpose::GrantCaps, "Right-click zapret-rs.exe -> Run as administrator".to_owned())
        } else {
            AuthModal::open(ModalPurpose::GrantCaps, format!("sudo setcap cap_net_admin,cap_net_raw+ep {}", self.exe_path))
        });
    }

    /// Processes a terminal key press and returns any side-effect [`AppAction`] for the runner.
    pub fn handle_key(&mut self, key: KeyEvent) -> AppAction {
        if let Some(modal) = self.modal.as_mut() {
            let purpose = modal.purpose;
            return match modal.handle_key(key) {
                ModalKeyResult::KeepOpen => AppAction::None,
                ModalKeyResult::Close => {
                    self.modal = None;
                    self.pending_caps_action = None;
                    if purpose == ModalPurpose::ConfirmMergeConfig {
                        self.pending_merge = None;
                        self.status_banner = "Kept new scan config only (press 's' to save).".to_owned();
                    }
                    self.reset_finder_hover();
                    AppAction::None
                }
                ModalKeyResult::Submit if purpose == ModalPurpose::ConfirmSpeedTest => {
                    self.modal = None;
                    AppAction::RunSpeedTest
                }
                ModalKeyResult::Submit => AppAction::SubmitModal,
                ModalKeyResult::KeepExisting => {
                    self.modal = None;
                    if let Some((prev, _)) = self.pending_merge.take() { self.set_active_toml(prev); }
                    self.status_banner = "Kept existing config (discarded new scan).".to_owned();
                    self.reset_finder_hover();
                    AppAction::None
                }
            };
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return AppAction::Quit;
        }
        if self.help_open {
            if matches!(key.code, KeyCode::Esc | KeyCode::Char('?' | 'q') | KeyCode::Enter) {
                self.help_open = false;
                self.reset_finder_hover();
            }
            return AppAction::None;
        }
        if self.editing_text {
            return self.handle_text_edit_key(key.code);
        }
        if self.inspector.filter_editing {
            return self.handle_run_key(key.code);
        }
        if let Some(action) = self.handle_global_key(key.code) {
            return action;
        }
        match self.tab {
            ActiveTab::Finder => self.handle_finder_key(key.code),
            ActiveTab::Run => self.handle_run_key(key.code),
            ActiveTab::Config => self.handle_config_key(key.code),
            ActiveTab::Speed => self.handle_speed_key(key.code),
            ActiveTab::Status => self.handle_status_key(key.code),
        }
    }
}
