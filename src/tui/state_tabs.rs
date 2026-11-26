//! Tab 2 (Run `nfqws2`), Tab 3 (Config & Auto Hostlist), and Tab 4 (Speed Test) handlers.

/// Ordered deduplication when loading learned domains across `hostlist_auto` files.
use std::collections::BTreeSet;
/// Non-blocking file read for refreshing Tab 3's `Auto Hostlist` pane.
use std::fs;
/// Path resolution relative to `nfqws2.toml`'s parent directory.
use std::path::PathBuf;

/// Keyboard key codes handled on Tab 2, Tab 3, and Tab 4.
use crossterm::event::KeyCode;

/// Validated `AppConfig` parser used to locate configured `hostlist_auto` paths.
use crate::config::AppConfig;
/// `~/` path expansion shared with Tab 1 and config saving.
use crate::tools::expand_tilde;

/// Floating confirmation modal built when stopping an attached daemon (`S`).
use crate::tui::modal::{AuthModal, ModalPurpose};
/// Tab 4 target builder used to populate the speed confirmation preview.
use crate::tui::speed::{build_targets, effective_speed_domains};
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

    /// Handles TOML, `nftables`, and `Auto Hostlist` scrolling, editing, saving, and reloading on Tab 3.
    pub(crate) fn handle_config_key(&mut self, code: KeyCode) -> AppAction {
        let scroll = match self.focus.config {
            ConfigFocus::Toml => &mut self.toml_scroll,
            ConfigFocus::Nft => &mut self.focus.nft_scroll,
            ConfigFocus::AutoHostlist => &mut self.focus.autolist_scroll,
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

    /// Re-reads `hostlist_auto` paths and learned domain lines referenced by `active_toml`.
    pub fn refresh_autohostlist(&mut self) {
        self.autohostlist_paths.clear();
        self.autohostlist_entries.clear();
        if self.active_toml.trim().is_empty() {
            return;
        }
        let cfg_path = expand_tilde(&self.output_path);
        let Ok(cfg) = AppConfig::from_toml_str(&self.active_toml, cfg_path.parent()) else {
            return;
        };
        let mut seen_paths: Vec<PathBuf> = Vec::new();
        for p in &cfg.profiles {
            if let Some(path) = &p.lists.hostlist_auto
                && !seen_paths.contains(path)
            {
                seen_paths.push(path.clone());
            }
        }
        let mut domains = BTreeSet::new();
        for path in &seen_paths {
            if let Ok(text) = fs::read_to_string(path) {
                for line in text.lines() {
                    let trimmed = line.trim();
                    if !trimmed.is_empty() && !trimmed.starts_with('#') {
                        domains.insert(trimmed.to_owned());
                    }
                }
            }
        }
        self.autohostlist_paths = seen_paths;
        self.autohostlist_entries = domains.into_iter().collect();
    }

    /// Handles start, cancel, navigation, and clear keys on Tab 4 (Speed Test).
    pub(crate) fn handle_speed_key(&mut self, code: KeyCode) -> AppAction {
        match code {
            KeyCode::Up | KeyCode::Char('k') => self.speed.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.speed.move_selection(1),
            KeyCode::Char('x') | KeyCode::Esc if self.speed.phase.is_running() => {
                return AppAction::CancelSpeedTest;
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                if self.speed.phase.is_running() {
                    self.status_banner = "Speed comparison already in progress.".to_owned();
                } else {
                    let eff = effective_speed_domains(&self.domains_input, &self.active_toml);
                    let count = build_targets(&eff).len();
                    let preview = format!("stop nfqws2 -> measure {count} target(s) -> start nfqws2 -> re-measure");
                    self.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmSpeedTest, preview));
                }
            }
            KeyCode::Char('c') => {
                if self.speed.phase.is_running() {
                    self.status_banner = "Cannot clear results while speed test is running.".to_owned();
                } else {
                    self.speed.clear();
                    self.status_banner = "Speed test results cleared.".to_owned();
                }
            }
            _ => {}
        }
        AppAction::None
    }

    /// Re-runs all Tab 5 operational health checks and clamps the selected row index.
    pub fn refresh_status_checks(&mut self) {
        self.status_checks = crate::tui::status_check::collect_component_statuses(self);
        if !self.status_checks.is_empty() {
            self.status_selected = self.status_selected.min(self.status_checks.len() - 1);
        } else {
            self.status_selected = 0;
        }
    }

    /// Handles navigation and refresh (`r`) keys on Tab 5 (`Status`).
    pub(crate) fn handle_status_key(&mut self, code: KeyCode) -> AppAction {
        let len = self.status_checks.len();
        match code {
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                self.status_selected = self.status_selected.saturating_sub(1);
                self.status_hscroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                self.status_selected = (self.status_selected + 1).min(len - 1);
                self.status_hscroll = 0;
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.status_hscroll = self.status_hscroll.saturating_sub(4);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.status_hscroll = self.status_hscroll.saturating_add(4);
            }
            KeyCode::Home => {
                self.status_selected = 0;
                self.status_hscroll = 0;
            }
            KeyCode::Char('r') | KeyCode::Enter => {
                self.refresh_status_checks();
                self.status_banner = "Refreshed operational component checks.".to_owned();
            }
            KeyCode::Char('d') => {
                self.status_banner = match crate::tui::debug_report::export_debug_report(self) {
                    Ok(path) => format!("Exported debug report to {}", path.display()),
                    Err(err) => format!("Debug export failed: {err}"),
                };
            }
            _ => {}
        }
        AppAction::None
    }
}
