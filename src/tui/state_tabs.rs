//! Tab 2 (Run `nfqws2`), Tab 3 (Config), and Tab 4 (Speed Test) keyboard handlers.

/// Ordered deduplication when loading learned domains across `hostlist_auto` files.
use std::collections::BTreeSet;

/// Keyboard key codes handled on Tab 2, Tab 3, and Tab 4.
use crossterm::event::KeyCode;

/// Validated `AppConfig` parser used to locate configured `hostlist_auto` paths.
use crate::config::AppConfig;
/// `~/` path expansion and shared blacklist/autohostlist helpers.
use crate::tools::{
    configured_autohostlist_paths, expand_tilde, extract_exclude_domains, read_hostlist_lines,
};

/// Floating confirmation modal built when stopping an attached daemon (`S`).
use crate::tui::modal::{AuthModal, ModalPurpose};
/// Tab 4 target builder used to populate the speed confirmation preview.
use crate::tui::speed::{build_scoped_targets, effective_speed_domains};
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
            && adjust_log_scroll(&mut self.focus.run_log_scroll, self.run.logs.len(), code)
        {
            return AppAction::None;
        }
        if let Some(msg) = self.inspector.handle_key(code) {
            if !msg.is_empty() {
                self.status_banner = msg;
            }
            return AppAction::None;
        }
        if self.run.status == RunStatus::Attached {
            return match code {
                KeyCode::Char('x') => AppAction::DetachDaemon,
                KeyCode::Char('R') => AppAction::RestartDaemon,
                KeyCode::Char('l') => AppAction::ReloadRemoteLists,
                KeyCode::Char('S') => {
                    let pid_label = self
                        .run.remote_meta
                        .as_ref()
                        .map_or_else(|| "remote".to_owned(), |m| format!("PID {}", m.pid));
                    let preview = format!("stop nfqws2 ({pid_label}) via control socket");
                    self.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmStopDaemon, preview));
                    AppAction::None
                }
                KeyCode::Char('c') => {
                    self.run.counter_baseline = self.run.counters.snapshot();
                    self.inspector.clear();
                    self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
                    AppAction::None
                }
                _ => AppAction::None,
            };
        }
        match code {
            KeyCode::Char('r') | KeyCode::Enter => {
                if self.run.status == RunStatus::Running {
                    AppAction::StopDaemon
                } else {
                    AppAction::StartDaemon
                }
            }
            KeyCode::Char('x') if self.run.status == RunStatus::Running => AppAction::StopDaemon,
            KeyCode::Char('R') => AppAction::RestartDaemon,
            KeyCode::Char('l') => AppAction::ReloadConfig,
            KeyCode::Char('c') => {
                self.run.counters.reset();
                self.run.counter_baseline = (0, 0, 0, 0, 0);
                self.inspector.clear();
                self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
                AppAction::None
            }
            _ => AppAction::None,
        }
    }

    /// Handles TOML and `nftables` scrolling, editing, saving, and reloading on Tab 3.
    pub(crate) fn handle_config_key(&mut self, code: KeyCode) -> AppAction {
        let scroll = match self.focus.config {
            ConfigFocus::Toml => &mut self.config.toml_scroll,
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

    /// Re-reads `hostlist_auto` paths, learned domains, and `hostlist_exclude` blacklist entries.
    pub fn refresh_autohostlist(&mut self) {
        self.config.autohostlist_paths.clear();
        self.config.autohostlist_entries.clear();
        self.config.exclude_entries.clear();
        if self.config.active_toml.trim().is_empty() {
            self.hostlist.clamp_selection(&self.config);
            return;
        }
        let cfg_path = expand_tilde(&self.finder.output_path);
        let Ok(cfg) = AppConfig::from_toml_str(&self.config.active_toml, cfg_path.parent()) else {
            self.hostlist.clamp_selection(&self.config);
            return;
        };
        let seen_paths = configured_autohostlist_paths(&cfg);
        let mut domains = BTreeSet::new();
        for path in &seen_paths {
            for line in read_hostlist_lines(path) {
                domains.insert(line);
            }
        }
        self.config.autohostlist_paths = seen_paths;
        self.config.autohostlist_entries = domains.into_iter().collect();
        self.config.exclude_entries = extract_exclude_domains(&cfg);
        self.hostlist.clamp_selection(&self.config);
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
                    let eff = effective_speed_domains(&self.finder.domains_input, &self.config.active_toml);
                    let count = build_scoped_targets(&eff, &self.finder.ip_mode.families()).len();
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
        self.status.checks = crate::tui::status_check::collect_component_statuses(self);
        if !self.status.checks.is_empty() {
            self.status.selected = self.status.selected.min(self.status.checks.len() - 1);
        } else {
            self.status.selected = 0;
        }
    }

    /// Updates `active_toml` and refreshes `parsed_profiles` and `toml_error` validation state.
    pub fn set_active_toml(&mut self, toml: String) {
        if toml.trim().is_empty() {
            self.config.parsed_profiles.clear();
            self.config.toml_error = None;
        } else {
            match AppConfig::from_toml_str(&toml, None) {
                Ok(cfg) => {
                    self.config.parsed_profiles = cfg
                        .profiles
                        .iter()
                        .map(|p| p.name.clone().unwrap_or_else(|| format!("profile #{}", p.index)))
                        .collect();
                    self.config.toml_error = None;
                }
                Err(err) => {
                    self.config.parsed_profiles.clear();
                    self.config.toml_error = Some(err.to_string());
                }
            }
        }
        self.config.active_toml = toml;
        self.config.toml_scroll = 0;
        self.refresh_autohostlist();
    }

    /// Handles navigation and refresh (`r`) keys on Tab 5 (`Status`).
    pub(crate) fn handle_status_key(&mut self, code: KeyCode) -> AppAction {
        let len = self.status.checks.len();
        match code {
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                self.status.selected = self.status.selected.saturating_sub(1);
                self.status.hscroll = 0;
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                self.status.selected = (self.status.selected + 1).min(len - 1);
                self.status.hscroll = 0;
            }
            KeyCode::Left | KeyCode::Char('h') => {
                self.status.hscroll = self.status.hscroll.saturating_sub(4);
            }
            KeyCode::Right | KeyCode::Char('l') => {
                self.status.hscroll = self.status.hscroll.saturating_add(4);
            }
            KeyCode::Home => {
                self.status.selected = 0;
                self.status.hscroll = 0;
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
            KeyCode::Char('n') => {
                self.status.dns_preset = self.status.dns_preset.next();
                self.refresh_status_checks();
                self.status_banner = format!(
                    "DNS preset: {} (press 'a' to apply)",
                    self.status.dns_preset.label()
                );
            }
            KeyCode::Char('a') => {
                self.modal = Some(AuthModal::confirm(
                    ModalPurpose::ConfirmApplyDns,
                    self.status.dns_preset.command_preview(),
                ));
            }
            _ => {}
        }
        AppAction::None
    }
}
