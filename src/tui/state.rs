//! Mutable `zapret-rs` TUI application state and pure keyboard/event state transitions.

/// Bounded ring buffers for live scan and daemon log panels.
use std::collections::VecDeque;
/// Path handling for config files, Lua directories, control sockets, and executable paths.
use std::path::PathBuf;

/// Keyboard event primitives handled by [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// Interactive path expansion for loading initial `nfqws2.toml`.
use crate::tools::expand_tilde;
/// Live packet inspector state for Tab 2.
use crate::tui::inspect::PacketInspectorState;
/// Before/after speed comparison state for Tab 4.
use crate::tui::speed::SpeedState;
/// Floating capability-grant, `sudo` auth, and daemon-stop confirmation modal state.
use crate::tui::modal::{AuthModal, ModalKeyResult, ModalPurpose};
/// Centered plain-text domain/web prompt modal state.
use crate::tui::prompt_modal::{PromptKeyResult, PromptModal};
/// Tab 1, Tab 2, Tab 3, and Tab 5 state sub-structs extracted from [`AppState`].
use crate::tui::tab_states::{ConfigTabState, FinderState, RunState, StatusTabState};
/// Configurable color theme palette and `theme.toml` load/save helpers.
use crate::tui::theme_config::{Theme, resolve_theme};
/// Shared TUI enums and worker event types.
use crate::tui::types::{ActiveTab, AppAction, FinderField, PanelFocusState, PostCapsAction};

/// Maximum number of log lines retained in each scrollable log panel.
const MAX_LOG_LINES: usize = 200;

/// Top-level TUI application container combining UI chrome with per-tab domain sub-states.
pub struct AppState {
    /// Currently visible top-level tab.
    pub tab: ActiveTab,
    /// Transient footer notification line.
    pub status_banner: String,
    /// Active floating capability-grant / `sudo` / stop-confirm modal, when visible.
    pub modal: Option<AuthModal>,
    /// `true` while the centered `?` keybindings popup is open.
    pub help_open: bool,
    /// Action automatically resumed once capability grant triggers a seamless restart.
    pub pending_caps_action: Option<PostCapsAction>,
    /// Per-tab focused panel and scroll offsets switched via `Tab` / `Shift+Tab`.
    pub focus: PanelFocusState,
    /// Active configurable TUI color palette (`neon` by default, or from `theme.toml`).
    pub theme: Theme,
    /// Tab 1 (`Strategy Finder`) form inputs, scan configuration, progress, results, and log state.
    pub finder: FinderState,
    /// Tab 2 daemon session status, counters, socket override, and logs.
    pub run: RunState,
    /// Tab 3 active TOML, profile summary, pending merge, and domain lists.
    pub config: ConfigTabState,
    /// Live packet inspector table, filter, pause toggle, and detail popup state on Tab 2.
    pub inspector: PacketInspectorState,
    /// Before/after speed comparison results and phase on Tab 4.
    pub speed: SpeedState,
    /// Active centered plain-text input modal (Blacklist / Auto Hostlist / Web UI).
    pub prompt_modal: Option<PromptModal>,
    /// Active in-TUI Web UI `(url, pairing_passcode)` when running; `None` when stopped.
    pub web_status: Option<(String, String)>,
    /// Tab 5 operational diagnostics table, DNS preset, and process privilege state.
    pub status: StatusTabState,
}

impl AppState {
    /// Initializes TUI state with auto-detected Lua directory, capability snapshot, and optional config.
    pub fn new(initial_config: Option<PathBuf>, initial_lua_dir: Option<PathBuf>, no_nft: bool) -> Self {
        let (theme, theme_warn) = resolve_theme(None);
        let finder = FinderState::from_cli(initial_config, initial_lua_dir, no_nft);

        let mut state = Self {
            tab: ActiveTab::Finder,
            status_banner: "Ready. Press '?' for keybindings.".to_owned(),
            modal: None,
            help_open: false,
            pending_caps_action: None,
            focus: PanelFocusState::default(),
            theme,
            finder,
            run: RunState::default(),
            config: ConfigTabState::default(),
            inspector: PacketInspectorState::default(),
            speed: SpeedState::default(),
            prompt_modal: None,
            web_status: None,
            status: StatusTabState::default(),
        };
        let cfg_path = expand_tilde(&state.finder.output_path);
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
        FinderField::ALL[self.finder.focus_idx.min(FinderField::ALL.len() - 1)]
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
        Self::push_bounded_log(&mut self.finder.logs, msg.into());
    }

    /// Appends a bounded line to the Run daemon log buffer.
    pub fn push_run_log(&mut self, msg: impl Into<String>) {
        Self::push_bounded_log(&mut self.run.logs, msg.into());
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
            AuthModal::open(ModalPurpose::GrantCaps, format!("sudo setcap cap_net_admin,cap_net_raw+ep {}", self.status.exe_path))
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
                        self.config.pending_merge = None;
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
                    if let Some((prev, _)) = self.config.pending_merge.take() { self.set_active_toml(prev); }
                    self.status_banner = "Kept existing config (discarded new scan).".to_owned();
                    self.reset_finder_hover();
                    AppAction::None
                }
            };
        }
        if let Some(prompt) = self.prompt_modal.as_mut() {
            return match prompt.handle_key(key) {
                PromptKeyResult::KeepOpen => AppAction::None,
                PromptKeyResult::Close => { self.prompt_modal = None; AppAction::None }
                PromptKeyResult::Submit => AppAction::SubmitPrompt,
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
        if self.finder.editing_text {
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
