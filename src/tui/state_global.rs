//! Global hotkeys shared by every tab: help popup, quit, tab switching, panel focus, and themes.

/// Key codes matched against the global binding table.
use crossterm::event::KeyCode;

/// Domain and Web UI launcher modal state opened from global (`W`) or Tab 3 (`b`/`a`/`d`).
use crate::tui::prompt_modal::{PromptKind, PromptModal};
/// Attached background `nfqws2` daemon metadata stored when attaching from Tab 2.
use crate::tui::remote::RemoteDaemonMeta;
/// Mutable application state receiving global hotkey effects.
use crate::tui::state::AppState;
/// Theme persistence helper bound to the `T` key.
use crate::tui::theme_config::save_theme_to_default_path;
/// Navigation enums and the side-effect action returned to the runner.
use crate::tui::types::{ActiveTab, AppAction, RunStatus};

impl AppState {
    /// Handles a key that means the same on every tab; returns `None` when `code` is not global.
    ///
    /// `t` and `T` are ignored while the packet detail popup is open so they cannot change the
    /// theme underneath it, and `?` is ignored there for the same reason.
    pub(crate) fn handle_global_key(&mut self, code: KeyCode) -> Option<AppAction> {
        let detail_open = self.inspector.detail_open;
        match code {
            KeyCode::Char('?') if !detail_open => {
                self.help_open = true;
                self.dismiss_finder_hover();
            }
            KeyCode::Char('q') => return Some(AppAction::Quit),
            KeyCode::Char('g') if !self.status.has_net_caps => self.open_caps_modal(),
            KeyCode::Char('1') => return Some(self.switch_tab(ActiveTab::Finder)),
            KeyCode::Char('2') => return Some(self.switch_tab(ActiveTab::Run)),
            KeyCode::Char('3') => return Some(self.switch_tab(ActiveTab::Config)),
            KeyCode::Char('4') => return Some(self.switch_tab(ActiveTab::Speed)),
            KeyCode::Char('5') => return Some(self.switch_tab(ActiveTab::Status)),
            KeyCode::Char('6') => return Some(self.switch_tab(ActiveTab::Hostlist)),
            KeyCode::Tab => return Some(self.cycle_panel_focus(true)),
            KeyCode::BackTab => return Some(self.cycle_panel_focus(false)),
            KeyCode::Char('t') if !detail_open => {
                self.theme = self.theme.next_preset();
                self.status_banner =
                    format!("Theme: {} (press 'T' to save theme.toml)", self.theme.name);
            }
            KeyCode::Char('T') if !detail_open => {
                self.status_banner = match save_theme_to_default_path(&self.theme) {
                    Ok(path) => {
                        format!("Saved theme '{}' to {}", self.theme.name, path.display())
                    }
                    Err(err) => format!("Save theme failed: {err}"),
                };
            }
            KeyCode::Char('W') if !detail_open => {
                if self.web_status.is_some() {
                    return Some(AppAction::StopWebUi);
                }
                self.prompt_modal = Some(PromptModal::open(PromptKind::LaunchWebUi));
                self.dismiss_finder_hover();
            }
            KeyCode::Char('y') if !detail_open && self.web_status.is_some() => {
                return Some(AppAction::CopyWebPasscode);
            }
            KeyCode::Char('o') if !detail_open && self.web_status.is_some() => {
                return Some(AppAction::OpenWebUi);
            }
            _ => return None,
        }
        Some(AppAction::None)
    }

    /// Switches top-level tab, refreshing Tab 5/6 state and resetting tooltips cleanly.
    fn switch_tab(&mut self, tab: ActiveTab) -> AppAction {
        self.tab = tab;
        if tab == ActiveTab::Status {
            self.refresh_status_checks();
        } else if tab == ActiveTab::Hostlist {
            self.refresh_autohostlist();
        }
        self.reset_finder_hover();
        AppAction::None
    }

    /// Cycles focused panel inside the active tab (`Tab` / `Shift+Tab`) and updates tooltip state.
    fn cycle_panel_focus(&mut self, forward: bool) -> AppAction {
        if self.tab == ActiveTab::Hostlist {
            self.hostlist.toggle_focus();
        } else {
            self.focus.cycle(self.tab, forward);
        }
        self.reset_finder_hover();
        AppAction::None
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
        self.run.detected_socket = Some(meta.socket_path.clone());
        self.run.remote_meta = Some(meta);
        self.run.status = RunStatus::Attached;
        self.run.auto_reattach = true;
        self.run.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
    }

    /// Transitions Tab 2 back from [`RunStatus::Attached`] to [`RunStatus::Stopped`].
    pub fn set_detached(&mut self, log_line: String, banner: String) {
        self.run.remote_meta = None;
        self.run.status = RunStatus::Stopped;
        self.run.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
        self.status_banner = banner;
    }

    /// Returns `(total, passed, reassembled, modified, desynced)` minus [`Self::counter_baseline`].
    pub fn visible_counters(&self) -> (u64, u64, u64, u64, u64) {
        let (s0, s1, s2, s3, s4) = self.run.counters.snapshot();
        let (b0, b1, b2, b3, b4) = self.run.counter_baseline;
        if s0 < b0 || s1 < b1 || s2 < b2 || s3 < b3 || s4 < b4 {
            return (s0, s1, s2, s3, s4);
        }
        (s0 - b0, s1 - b1, s2 - b2, s3 - b3, s4 - b4)
    }
}
