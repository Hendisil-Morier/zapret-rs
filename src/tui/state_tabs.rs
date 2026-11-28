//! Tab 2 (Run `nfqws2`), Tab 3 (Config), and Tab 4 (Speed Test) keyboard handlers.

/// Ordered deduplication when loading learned domains across `hostlist_auto` files.
use std::collections::BTreeSet;

/// Keyboard events handled on Tab 2, Tab 3, Tab 4, and Tab 5.
use crossterm::event::KeyEvent;

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
    AppAction, ConfigFocus, RunFocus, RunStatus, adjust_log_scroll_key, adjust_pane_scroll_key,
};

impl AppState
{
    /// Handles start/attach, detach/stop, remote commands, log scroll, and inspector keys on Tab 2.
    pub(crate) fn handle_run_key(&mut self, key: KeyEvent) -> AppAction
    {
        let nav = &self.keybinds.nav;
        if !self.inspector.detail_open
            && !self.inspector.filter_editing
            && self.focus.run == RunFocus::Log
            && adjust_log_scroll_key(&mut self.focus.run_log_scroll, self.run.logs.len(), key, nav)
        {
            return AppAction::None;
        }
        if let Some(msg) = self.inspector.handle_key_with_binds(key, &self.keybinds)
        {
            if !msg.is_empty()
            {
                self.status_banner = msg;
            }
            return AppAction::None;
        }
        let r = &self.keybinds.run;
        if self.run.status == RunStatus::Attached
        {
            if r.stop_or_detach.contains(key)
            {
                return AppAction::DetachDaemon;
            }
            if r.restart.contains(key)
            {
                return AppAction::RestartDaemon;
            }
            if r.reload.contains(key)
            {
                return AppAction::ReloadRemoteLists;
            }
            if r.stop_attached.contains(key)
            {
                let pid_label = self
                    .run
                    .remote_meta
                    .as_ref()
                    .map_or_else(|| "remote".to_owned(), |m| format!("PID {}", m.pid));
                let preview = format!("stop nfqws2 ({pid_label}) via control socket");
                self.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmStopDaemon, preview));
                return AppAction::None;
            }
            if r.clear.contains(key)
            {
                self.run.counter_baseline = self.run.counters.snapshot();
                self.inspector.clear();
                self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
            }
            return AppAction::None;
        }
        if r.start_stop.contains(key)
        {
            return if self.run.status == RunStatus::Running
            {
                AppAction::StopDaemon
            }
            else
            {
                AppAction::StartDaemon
            };
        }
        if self.run.status == RunStatus::Running && r.stop_or_detach.contains(key)
        {
            return AppAction::StopDaemon;
        }
        if r.restart.contains(key)
        {
            return AppAction::RestartDaemon;
        }
        if r.reload.contains(key)
        {
            return AppAction::ReloadConfig;
        }
        if r.clear.contains(key)
        {
            self.run.counters.reset();
            self.run.counter_baseline = (0, 0, 0, 0, 0);
            self.inspector.clear();
            self.status_banner = "Packet counters and inspector buffer cleared.".to_owned();
        }
        AppAction::None
    }

    /// Handles TOML and `nftables` scrolling, editing, saving, and reloading on Tab 3.
    pub(crate) fn handle_config_key(&mut self, key: KeyEvent) -> AppAction
    {
        let nav = self.keybinds.nav.clone();
        let scroll = match self.focus.config
        {
            ConfigFocus::Toml => &mut self.config.toml_scroll,
            ConfigFocus::Nft => &mut self.focus.nft_scroll,
        };
        if adjust_pane_scroll_key(scroll, key, &nav)
        {
            return AppAction::None;
        }
        let cfg_keys = &self.keybinds.config;
        if cfg_keys.edit.contains(key)
        {
            return AppAction::EditConfig;
        }
        if cfg_keys.push.contains(key)
        {
            return AppAction::PushConfigToDaemon;
        }
        if cfg_keys.save.contains(key)
        {
            return AppAction::SaveConfig;
        }
        if cfg_keys.reload.contains(key)
        {
            return AppAction::ReloadConfig;
        }
        AppAction::None
    }

    /// Re-reads `hostlist_auto` paths, learned domains, and `hostlist_exclude` blacklist entries.
    pub fn refresh_autohostlist(&mut self)
    {
        self.config.autohostlist_paths.clear();
        self.config.autohostlist_entries.clear();
        self.config.exclude_entries.clear();
        if self.config.active_toml.trim().is_empty()
        {
            self.hostlist.clamp_selection(&self.config);
            return;
        }
        let cfg_path = expand_tilde(&self.finder.output_path);
        let Ok(cfg) = AppConfig::from_toml_str(&self.config.active_toml, cfg_path.parent())
        else
        {
            self.hostlist.clamp_selection(&self.config);
            return;
        };
        let seen_paths = configured_autohostlist_paths(&cfg);
        let mut domains = BTreeSet::new();
        for path in &seen_paths
        {
            for line in read_hostlist_lines(path)
            {
                domains.insert(line);
            }
        }
        self.config.autohostlist_paths = seen_paths;
        self.config.autohostlist_entries = domains.into_iter().collect();
        self.config.exclude_entries = extract_exclude_domains(&cfg);
        self.hostlist.clamp_selection(&self.config);
    }

    /// Handles start, cancel, navigation, and clear keys on Tab 4 (Speed Test).
    pub(crate) fn handle_speed_key(&mut self, key: KeyEvent) -> AppAction
    {
        let nav = &self.keybinds.nav;
        let spd = &self.keybinds.speed;
        if nav.up.contains(key)
        {
            self.speed.move_selection(-1);
        }
        else if nav.down.contains(key)
        {
            self.speed.move_selection(1);
        }
        else if self.speed.phase.is_running() && spd.cancel.contains(key)
        {
            return AppAction::CancelSpeedTest;
        }
        else if spd.start.contains(key)
        {
            if self.speed.phase.is_running()
            {
                self.status_banner = "Speed comparison already in progress.".to_owned();
            }
            else
            {
                let eff = effective_speed_domains(&self.finder.domains_input, &self.config.active_toml);
                let count = build_scoped_targets(&eff, &self.finder.ip_mode.families()).len();
                let preview =
                    format!("stop nfqws2 -> measure {count} target(s) -> start nfqws2 -> re-measure");
                self.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmSpeedTest, preview));
            }
        }
        else if spd.clear.contains(key)
        {
            if self.speed.phase.is_running()
            {
                self.status_banner = "Cannot clear results while speed test is running.".to_owned();
            }
            else
            {
                self.speed.clear();
                self.status_banner = "Speed test results cleared.".to_owned();
            }
        }
        AppAction::None
    }

    /// Re-runs all Tab 5 operational health checks and clamps the selected row index.
    pub fn refresh_status_checks(&mut self)
    {
        self.status.checks = crate::tui::status_check::collect_component_statuses(self);
        if !self.status.checks.is_empty()
        {
            self.status.selected = self.status.selected.min(self.status.checks.len() - 1);
        }
        else
        {
            self.status.selected = 0;
        }
    }

    /// Updates `active_toml` and refreshes `parsed_profiles` and `toml_error` validation state.
    pub fn set_active_toml(&mut self, toml: String)
    {
        if toml.trim().is_empty()
        {
            self.config.parsed_profiles.clear();
            self.config.toml_error = None;
        }
        else
        {
            match AppConfig::from_toml_str(&toml, None)
            {
                Ok(cfg) =>
                {
                    self.config.parsed_profiles = cfg
                        .profiles
                        .iter()
                        .map(|p| p.name.clone().unwrap_or_else(|| format!("profile #{}", p.index)))
                        .collect();
                    self.config.toml_error = None;
                }
                Err(err) =>
                {
                    self.config.parsed_profiles.clear();
                    self.config.toml_error = Some(err.to_string());
                }
            }
        }
        self.config.active_toml = toml;
        self.config.toml_scroll = 0;
        self.refresh_autohostlist();
    }

    /// Handles navigation and action keys on Tab 5 (`Status`).
    pub(crate) fn handle_status_key(&mut self, key: KeyEvent) -> AppAction
    {
        let len = self.status.checks.len();
        let nav = &self.keybinds.nav;
        let st = &self.keybinds.status;
        if len > 0 && nav.up.contains(key)
        {
            self.status.selected = self.status.selected.saturating_sub(1);
            self.status.hscroll = 0;
        }
        else if len > 0 && nav.down.contains(key)
        {
            self.status.selected = (self.status.selected + 1).min(len - 1);
            self.status.hscroll = 0;
        }
        else if nav.left.contains(key)
        {
            self.status.hscroll = self.status.hscroll.saturating_sub(4);
        }
        else if nav.right.contains(key)
        {
            self.status.hscroll = self.status.hscroll.saturating_add(4);
        }
        else if nav.home.contains(key)
        {
            self.status.selected = 0;
            self.status.hscroll = 0;
        }
        else if st.refresh.contains(key)
        {
            self.refresh_status_checks();
            self.status_banner = "Refreshed operational component checks.".to_owned();
        }
        else if st.export_debug.contains(key)
        {
            self.status_banner = match crate::tui::debug_report::export_debug_report(self)
            {
                Ok(path) => format!("Exported debug report to {}", path.display()),
                Err(err) => format!("Debug export failed: {err}"),
            };
        }
        else if st.next_dns.contains(key)
        {
            self.status.dns_preset = self.status.dns_preset.next();
            let apply_key = self.keybinds.status.apply_dns.primary_label();
            self.refresh_status_checks();
            self.status_banner =
                format!("DNS preset: {} (press '{}' to apply)", self.status.dns_preset.label(), apply_key);
        }
        else if st.apply_dns.contains(key)
        {
            self.modal = Some(AuthModal::confirm(
                ModalPurpose::ConfirmApplyDns,
                self.status.dns_preset.command_preview(),
            ));
        }
        AppAction::None
    }
}
