//! Tab 2 (Run `nfqws2`) and Tab 3 (Config & Diagnostics) keyboard handlers for [`AppState`].

/// Keyboard key codes handled on Tab 2 and Tab 3.
use crossterm::event::KeyCode;

/// Floating confirmation modal built when stopping an attached daemon (`S`).
use crate::tui::modal::{AuthModal, ModalPurpose};
/// Application state updated by Run and Config key handlers.
use crate::tui::state::AppState;
/// Tab focus enums, scroll helpers, action results, and daemon run lifecycle states.
use crate::tui::types::{
    AppAction, ConfigFocus, RunFocus, RunStatus, adjust_log_scroll, adjust_pane_scroll,
};

impl AppState {
    /// Handles start/attach, detach/stop, remote commands, log scroll, and inspector keys on Tab 2.
    pub(crate) fn handle_run_key(&mut self, code: KeyCode) -> AppAction {
        if !self.inspector.detail_open
            && !self.inspector.filter_editing
            && self.focus.run == RunFocus::Log
            && adjust_log_scroll(&mut self.focus.run_log_scroll, self.run_logs.len(), code)
        {
            return AppAction::None;
        }
        if let Some(msg) = self.inspector.handle_key(code) {
            if !msg.is_empty() {
                self.status_banner = msg;
            }
            return AppAction::None;
        }
        if self.run_status == RunStatus::Attached {
            return match code {
                KeyCode::Char('x') => AppAction::DetachDaemon,
                KeyCode::Char('R') => AppAction::RestartDaemon,
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
                    self.counter_baseline = self.counters.snapshot();
                    self.inspector.clear();
                    self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
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
            KeyCode::Char('R') => AppAction::RestartDaemon,
            KeyCode::Char('l') => AppAction::ReloadConfig,
            KeyCode::Char('c') => {
                self.counters.reset();
                self.counter_baseline = (0, 0, 0, 0, 0);
                self.inspector.clear();
                self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Handles TOML or `nftables` preview scrolling, editing, saving, and reloading on Tab 3.
    pub(crate) fn handle_config_key(&mut self, code: KeyCode) -> AppAction {
        let scroll = match self.focus.config {
            ConfigFocus::Toml => &mut self.toml_scroll,
            ConfigFocus::Nft => &mut self.focus.nft_scroll,
        };
        if adjust_pane_scroll(scroll, code) {
            return AppAction::None;
        }
        match code {
            KeyCode::Char('e') | KeyCode::Enter => return AppAction::EditConfig,
            KeyCode::Char('p') => return AppAction::PushConfigToDaemon,
            KeyCode::Char('s') => return AppAction::SaveConfig,
            KeyCode::Char('l') => return AppAction::ReloadConfig,
            _ => {}
        }
        AppAction::None
    }
}
