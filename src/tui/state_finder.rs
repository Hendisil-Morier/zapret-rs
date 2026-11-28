//! Tab 1 Strategy Finder key handling, scan configuration builder, and event application.

/// Default probe timeout and clock instant for focus-dwell help popups.
use std::time::{Duration, Instant};

/// Keyboard key codes and events handled inside the Strategy Finder form and text editor.
use crossterm::event::{KeyCode, KeyEvent};

/// Strategy catalog, active OS firewall backend, scan settings, and domain normalization.
use crate::tools::{ProbeProtocol, ScanConfig, ScanLevel, active_firewall_backend, normalize_domain};
/// Application state updated by Strategy Finder actions and worker progress events.
use crate::tui::state::AppState;
/// Navigation, form descriptors, dwell delay, action results, and background scan events.
use crate::tui::types::{
    ActiveTab, AppAction, FINDER_HOVER_DELAY, FinderField, FinderFocus, FinderStatus, ScanUiEvent,
    adjust_log_scroll_key, step_selection,
};

impl AppState
{
    /// Returns the currently selected protocol list from the Finder checkboxes.
    pub fn selected_protos(&self) -> Vec<ProbeProtocol>
    {
        let mut out = Vec::new();
        if self.finder.proto_http
        {
            out.push(ProbeProtocol::Http);
        }
        if self.finder.proto_tls12
        {
            out.push(ProbeProtocol::Tls12);
        }
        if self.finder.proto_tls13
        {
            out.push(ProbeProtocol::Tls13);
        }
        if self.finder.proto_http3
        {
            out.push(ProbeProtocol::Http3);
        }
        out
    }

    /// Validates Finder form fields and constructs a [`ScanConfig`].
    pub fn build_scan_config(&self) -> Result<ScanConfig, String>
    {
        let domains: Vec<String> = self
            .finder
            .domains_input
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(normalize_domain)
            .collect();
        if domains.is_empty()
        {
            return Err("enter at least one domain first (focus Domains, press Enter)".to_owned());
        }
        let protos = self.selected_protos();
        if protos.is_empty()
        {
            return Err("enable at least one protocol checkbox".to_owned());
        }
        Ok(ScanConfig {
            domains,
            protos,
            families: self.finder.ip_mode.families(),
            level: self.finder.level,
            timeout: Duration::from_secs(2),
            stop_on_first: self.finder.stop_on_first,
            force_blocked: false,
        })
    }

    /// Renders the active OS firewall backend's `(panel_title, filter_text)` preview for Tab 3.
    pub fn filter_preview(&self) -> (&'static str, String)
    {
        let cfg = ScanConfig {
            domains: Vec::new(),
            protos: self.selected_protos(),
            families: self.finder.ip_mode.families(),
            level: self.finder.level,
            timeout: Duration::from_secs(2),
            stop_on_first: self.finder.stop_on_first,
            force_blocked: false,
        };
        let (tcp, udp) = cfg.required_ports();
        let backend = active_firewall_backend();
        (backend.preview_title(), backend.preview_filter(self.finder.qnum, self.finder.fwmark, &tcp, &udp))
    }

    /// Applies one background [`ScanUiEvent`] to live progress, results table, logs, and TOML.
    pub fn apply_scan_event(&mut self, event: ScanUiEvent)
    {
        match event
        {
            ScanUiEvent::Baseline { domain, proto, ipv, summary, skipped } =>
            {
                let tag = if skipped { "reachable (skip)" } else { "blocked" };
                self.finder.progress_label = format!("Baseline {domain} ({proto}/{ipv}): {summary}");
                self.push_finder_log(format!("[baseline] {domain} ({proto}/{ipv}) -> {summary} [{tag}]"));
            }
            ScanUiEvent::Candidate { domain, index, total, strategy_id, passed, summary } =>
            {
                self.finder.progress_done = index;
                self.finder.progress_total = total;
                self.finder.progress_label = format!("{domain} [{index}/{total}] {strategy_id}");
                if passed
                {
                    self.push_finder_log(format!(
                        "[PASS {index}/{total}] {domain} :: {strategy_id} -> {summary}"
                    ));
                }
            }
            ScanUiEvent::Notice(msg) => self.push_finder_log(msg),
            ScanUiEvent::Completed { report, rendered_toml } =>
            {
                let n_cover = report.cover.len();
                self.finder.targets = report.targets;
                self.finder.cover = report.cover;
                self.focus.finder_results_sel = 0;
                self.finder.status = FinderStatus::Done;
                self.finder.progress_done = self.finder.progress_total;
                if !rendered_toml.is_empty()
                {
                    if !self.config.parsed_profiles.is_empty() && self.config.toml_error.is_none()
                    {
                        self.config.pending_merge =
                            Some((self.config.active_toml.clone(), rendered_toml.clone()));
                    }
                    else
                    {
                        self.config.pending_merge = None;
                    }
                    self.set_active_toml(rendered_toml);
                }
                self.finder.progress_label = if report.interrupted
                {
                    format!("Stopped early: {n_cover} covering profile(s)")
                }
                else
                {
                    format!("Done: {n_cover} minimal covering profile(s)")
                };
                self.status_banner = if n_cover > 0
                {
                    format!("Found {n_cover} profile(s). Press 's' to save or 'a' to open Run tab.")
                }
                else
                {
                    "Scan finished. No blocked domains needed bypass (or none matched).".to_owned()
                };
            }
            ScanUiEvent::Failed(err) =>
            {
                self.finder.status = FinderStatus::Error(err.clone());
                self.finder.progress_label = format!("Error: {err}");
                self.status_banner = format!("Scan error: {err}");
                self.push_finder_log(format!("[error] {err}"));
            }
        }
    }

    /// Hides the option tooltip and restarts the 1-second dwell timer from now.
    pub fn reset_finder_hover(&mut self)
    {
        self.finder.hover.open = false;
        self.finder.hover.since = Some(Instant::now());
    }

    /// Hides the option tooltip and pauses the dwell timer until the user interacts again.
    pub fn dismiss_finder_hover(&mut self)
    {
        self.finder.hover.open = false;
        self.finder.hover.since = None;
    }

    /// Opens the Tab 1 option explanation popup once focus rests idle for [`FINDER_HOVER_DELAY`].
    pub fn poll_finder_hover(&mut self, now: Instant)
    {
        if self.tab != ActiveTab::Finder
            || self.focus.finder != FinderFocus::Setup
            || self.modal.is_some()
            || self.help_open
            || self.finder.editing_text
            || self.finder.status == FinderStatus::Scanning
        {
            self.finder.hover.open = false;
            return;
        }
        if !self.finder.hover.open
            && let Some(since) = self.finder.hover.since
            && now.saturating_duration_since(since) >= FINDER_HOVER_DELAY
        {
            self.finder.hover.open = true;
        }
    }

    /// Moves Tab 1 Setup form focus up (`delta < 0`) or down (`delta > 0`) cyclically.
    pub(crate) fn step_finder_setup_focus(&mut self, forward: bool)
    {
        self.finder.focus_idx = if forward
        {
            (self.finder.focus_idx + 1) % FinderField::ALL.len()
        }
        else if self.finder.focus_idx == 0
        {
            FinderField::ALL.len() - 1
        }
        else
        {
            self.finder.focus_idx - 1
        };
        self.finder.text_scroll = 0;
        self.reset_finder_hover();
    }

    /// Handles vertical/page navigation for whichever Tab 1 panel currently owns focus.
    fn handle_finder_nav(&mut self, key: KeyEvent) -> bool
    {
        let nav = &self.keybinds.nav;
        match self.focus.finder
        {
            FinderFocus::Setup =>
            {
                if nav.up.contains(key)
                {
                    self.step_finder_setup_focus(false);
                    true
                }
                else if nav.down.contains(key)
                {
                    self.step_finder_setup_focus(true);
                    true
                }
                else if self.focused_field().is_text()
                    && (nav.left.contains(key)
                        || nav.right.contains(key)
                        || nav.home.contains(key)
                        || nav.end.contains(key))
                    && !matches!(key.code, KeyCode::Char('h' | 'l'))
                {
                    let cap = self.focused_text_buf_len().saturating_sub(16);
                    if nav.left.contains(key)
                    {
                        self.finder.text_scroll = self.finder.text_scroll.saturating_sub(1);
                    }
                    else if nav.right.contains(key)
                    {
                        self.finder.text_scroll = (self.finder.text_scroll + 1).min(cap);
                    }
                    else if nav.home.contains(key)
                    {
                        self.finder.text_scroll = 0;
                    }
                    else if nav.end.contains(key)
                    {
                        self.finder.text_scroll = cap;
                    }
                    self.reset_finder_hover();
                    true
                }
                else
                {
                    false
                }
            }
            FinderFocus::Results =>
            {
                let Some(delta) = nav.vertical_delta(key, 5)
                else
                {
                    return false;
                };
                self.focus.finder_results_sel =
                    step_selection(self.focus.finder_results_sel, self.finder.targets.len(), delta);
                true
            }
            FinderFocus::Log =>
            {
                let nav = self.keybinds.nav.clone();
                adjust_log_scroll_key(&mut self.focus.finder_log_scroll, self.finder.logs.len(), key, &nav)
            }
        }
    }

    /// Returns character count of the currently focused text field (`0` for non-text fields).
    fn focused_text_buf_len(&self) -> usize
    {
        match self.focused_field()
        {
            FinderField::Domains => self.finder.domains_input.chars().count(),
            FinderField::LuaDir => self.finder.lua_dir_input.chars().count(),
            FinderField::OutputPath => self.finder.output_path.chars().count(),
            _ => 0,
        }
    }

    /// Returns a mutable reference to the active text field buffer, or `None` for non-text fields.
    fn focused_text_buf_mut(&mut self) -> Option<&mut String>
    {
        match self.focused_field()
        {
            FinderField::Domains => Some(&mut self.finder.domains_input),
            FinderField::LuaDir => Some(&mut self.finder.lua_dir_input),
            FinderField::OutputPath => Some(&mut self.finder.output_path),
            _ => None,
        }
    }

    /// Edits the active text field buffer while [`AppState::editing_text`] is `true`.
    ///
    /// Supports Left/Right arrow cursor movement, Home/End jump-to-boundary,
    /// mid-string insertion, and Delete-at-cursor via Backspace, so long domain
    /// lists remain fully navigable even when they overflow the visible column.
    pub(crate) fn handle_text_edit_key(&mut self, code: KeyCode) -> AppAction
    {
        if matches!(code, KeyCode::Esc | KeyCode::Enter)
        {
            self.finder.editing_text = false;
            self.status_banner = "Field updated.".to_owned();
            self.reset_finder_hover();
            return AppAction::None;
        }
        let pos = self.finder.text_cursor;
        let Some(buf) = self.focused_text_buf_mut()
        else
        {
            self.finder.editing_text = false;
            self.reset_finder_hover();
            return AppAction::None;
        };
        let next_cursor = match code
        {
            KeyCode::Backspace if pos > 0 =>
            {
                let prev = buf[..pos].char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                buf.remove(prev);
                Some(prev)
            }
            KeyCode::Delete if pos < buf.len() =>
            {
                buf.remove(pos);
                None
            }
            KeyCode::Left if pos > 0 =>
            {
                Some(buf[..pos].char_indices().next_back().map(|(i, _)| i).unwrap_or(0))
            }
            KeyCode::Right if pos < buf.len() =>
            {
                Some(buf[pos..].char_indices().nth(1).map(|(i, _)| pos + i).unwrap_or(buf.len()))
            }
            KeyCode::Home => Some(0),
            KeyCode::End => Some(buf.len()),
            KeyCode::Char(c) =>
            {
                buf.insert(pos, c);
                Some(pos + c.len_utf8())
            }
            _ => None,
        };
        if let Some(cursor) = next_cursor
        {
            self.finder.text_cursor = cursor;
        }
        AppAction::None
    }

    /// Handles navigation, toggling, scan control, and config handoff on the Strategy Finder tab.
    pub(crate) fn handle_finder_key(&mut self, key: KeyEvent) -> AppAction
    {
        if self.handle_finder_nav(key)
        {
            return AppAction::None;
        }
        let f = &self.keybinds.finder;
        if self.finder.status != FinderStatus::Scanning
            && self.finder.hover.open
            && f.dismiss_hover.contains(key)
        {
            self.dismiss_finder_hover();
        }
        else if self.focus.finder == FinderFocus::Setup && f.activate.contains(key)
        {
            self.activate_focused_finder_field();
        }
        else if self.finder.status != FinderStatus::Scanning && f.start_scan.contains(key)
        {
            self.dismiss_finder_hover();
            return AppAction::StartScan;
        }
        else if self.finder.status == FinderStatus::Scanning && f.stop_scan.contains(key)
        {
            return AppAction::StopScan;
        }
        else if f.save_toml.contains(key)
        {
            self.dismiss_finder_hover();
            return AppAction::SaveConfig;
        }
        else if f.open_run_tab.contains(key)
        {
            if self.config.active_toml.is_empty()
            {
                self.status_banner = "No generated config yet: run a scan or load a file first.".to_owned();
            }
            else
            {
                self.tab = ActiveTab::Run;
                let start_lbl = self.keybinds.run.start_stop.primary_label();
                self.reset_finder_hover();
                self.status_banner = format!(
                    "Active config ready on Run tab. Press '{start_lbl}' to start {}.",
                    crate::tui::tabs::ENGINE_LABEL
                );
            }
        }
        AppAction::None
    }

    /// Toggles the focused Strategy Finder option or enters text-editing mode for text fields.
    pub(crate) fn activate_focused_finder_field(&mut self)
    {
        self.reset_finder_hover();
        if let Some(len) = self.focused_text_buf_mut().map(|buf| buf.len())
        {
            self.finder.editing_text = true;
            self.finder.text_cursor = len;
            self.dismiss_finder_hover();
            self.status_banner =
                "Editing field: Left/Right move cursor, Home/End jump, Del deletes forward, Enter/Esc done."
                    .to_owned();
            return;
        }
        match self.focused_field()
        {
            FinderField::ProtoHttp => self.finder.proto_http = !self.finder.proto_http,
            FinderField::ProtoTls12 => self.finder.proto_tls12 = !self.finder.proto_tls12,
            FinderField::ProtoTls13 => self.finder.proto_tls13 = !self.finder.proto_tls13,
            FinderField::ProtoHttp3 => self.finder.proto_http3 = !self.finder.proto_http3,
            FinderField::IpMode => self.finder.ip_mode = self.finder.ip_mode.next(),
            FinderField::Level =>
            {
                self.finder.level = match self.finder.level
                {
                    ScanLevel::Quick => ScanLevel::Standard,
                    ScanLevel::Standard => ScanLevel::Force,
                    ScanLevel::Force => ScanLevel::Quick,
                };
            }
            FinderField::StopOnFirst => self.finder.stop_on_first = !self.finder.stop_on_first,
            FinderField::NoNft => self.finder.no_nft = !self.finder.no_nft,
            FinderField::DomainScope => self.finder.domain_scope = self.finder.domain_scope.next(),
            _ =>
            {}
        }
    }
}
