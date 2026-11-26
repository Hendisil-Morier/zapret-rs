//! Tab 1 Strategy Finder key handling, scan configuration builder, and event application.

/// Default probe timeout and clock instant for focus-dwell help popups.
use std::time::{Duration, Instant};

/// Keyboard key codes handled inside the Strategy Finder form and text editor.
use crossterm::event::KeyCode;

/// Strategy catalog, `nftables` preview generator, scan settings, and domain normalization.
use crate::tools::{NftFirewallBackend, ProbeProtocol, ScanConfig, ScanLevel, normalize_domain};
/// Application state updated by Strategy Finder actions and worker progress events.
use crate::tui::state::AppState;
/// Navigation, form descriptors, dwell delay, action results, and background scan events.
use crate::tui::types::{
    ActiveTab, AppAction, FINDER_HOVER_DELAY, FinderField, FinderFocus, FinderStatus, ScanUiEvent,
    adjust_log_scroll,
};

impl AppState {
    /// Returns the currently selected protocol list from the Finder checkboxes.
    pub fn selected_protos(&self) -> Vec<ProbeProtocol> {
        let mut out = Vec::new();
        if self.proto_http {
            out.push(ProbeProtocol::Http);
        }
        if self.proto_tls12 {
            out.push(ProbeProtocol::Tls12);
        }
        if self.proto_tls13 {
            out.push(ProbeProtocol::Tls13);
        }
        if self.proto_http3 {
            out.push(ProbeProtocol::Http3);
        }
        out
    }

    /// Validates Finder form fields and constructs a [`ScanConfig`].
    pub fn build_scan_config(&self) -> Result<ScanConfig, String> {
        let domains: Vec<String> = self
            .domains_input
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(normalize_domain)
            .collect();
        if domains.is_empty() {
            return Err("enter at least one domain first (focus Domains, press Enter)".to_owned());
        }
        let protos = self.selected_protos();
        if protos.is_empty() {
            return Err("enable at least one protocol checkbox".to_owned());
        }
        Ok(ScanConfig {
            domains,
            protos,
            families: self.ip_mode.families(),
            level: self.level,
            timeout: Duration::from_secs(3),
            stop_on_first: self.stop_on_first,
            force_blocked: false,
        })
    }

    /// Renders the `nftables` ruleset preview matching the current Finder ports and queue settings.
    pub fn nft_preview_script(&self) -> String {
        let cfg = ScanConfig {
            domains: Vec::new(),
            protos: self.selected_protos(),
            families: self.ip_mode.families(),
            level: self.level,
            timeout: Duration::from_secs(3),
            stop_on_first: self.stop_on_first,
            force_blocked: false,
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
                    self.push_finder_log(format!(
                        "[PASS {index}/{total}] {domain} :: {strategy_id} -> {summary}"
                    ));
                }
            }
            ScanUiEvent::Notice(msg) => self.push_finder_log(msg),
            ScanUiEvent::Completed { report, rendered_toml } => {
                let n_cover = report.cover.len();
                self.targets = report.targets;
                self.cover = report.cover;
                self.focus.finder_results_sel = 0;
                self.finder_status = FinderStatus::Done;
                self.progress_done = self.progress_total;
                if !rendered_toml.is_empty() {
                    if !self.parsed_profiles.is_empty() && self.toml_error.is_none() {
                        self.pending_merge =
                            Some((self.active_toml.clone(), rendered_toml.clone()));
                    } else {
                        self.pending_merge = None;
                    }
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

    /// Hides the option tooltip and restarts the 1-second dwell timer from now.
    pub fn reset_finder_hover(&mut self) {
        self.finder_hover.open = false;
        self.finder_hover.since = Some(Instant::now());
    }

    /// Hides the option tooltip and pauses the dwell timer until the user interacts again.
    pub fn dismiss_finder_hover(&mut self) {
        self.finder_hover.open = false;
        self.finder_hover.since = None;
    }

    /// Opens the Tab 1 option explanation popup once focus rests idle for [`FINDER_HOVER_DELAY`].
    pub fn poll_finder_hover(&mut self, now: Instant) {
        if self.tab != ActiveTab::Finder
            || self.focus.finder != FinderFocus::Setup
            || self.modal.is_some()
            || self.help_open
            || self.editing_text
            || self.finder_status == FinderStatus::Scanning
        {
            self.finder_hover.open = false;
            return;
        }
        if !self.finder_hover.open
            && let Some(since) = self.finder_hover.since
            && now.saturating_duration_since(since) >= FINDER_HOVER_DELAY
        {
            self.finder_hover.open = true;
        }
    }

    /// Handles vertical/page navigation for whichever Tab 1 panel currently owns focus.
    fn handle_finder_nav(&mut self, code: KeyCode) -> bool {
        match self.focus.finder {
            FinderFocus::Setup => match code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.focus_idx = if self.focus_idx == 0 {
                        FinderField::ALL.len() - 1
                    } else {
                        self.focus_idx - 1
                    };
                    self.text_scroll = 0;
                    self.reset_finder_hover();
                    true
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.focus_idx = (self.focus_idx + 1) % FinderField::ALL.len();
                    self.text_scroll = 0;
                    self.reset_finder_hover();
                    true
                }
                KeyCode::Left | KeyCode::Right | KeyCode::Home | KeyCode::End
                    if self.focused_field().is_text() =>
                {
                    let len = self.focused_text_buf_len();
                    let cap = len.saturating_sub(16);
                    match code {
                        KeyCode::Left => self.text_scroll = self.text_scroll.saturating_sub(1),
                        KeyCode::Right => self.text_scroll = (self.text_scroll + 1).min(cap),
                        KeyCode::Home => self.text_scroll = 0,
                        KeyCode::End => self.text_scroll = cap,
                        _ => {}
                    }
                    self.reset_finder_hover();
                    true
                }
                _ => false,
            },
            FinderFocus::Results => {
                let last = self.targets.len().saturating_sub(1);
                let sel = &mut self.focus.finder_results_sel;
                match code {
                    KeyCode::Up | KeyCode::Char('k') => *sel = sel.saturating_sub(1),
                    KeyCode::Down | KeyCode::Char('j') if !self.targets.is_empty() => {
                        *sel = (*sel + 1).min(last);
                    }
                    KeyCode::PageUp => *sel = sel.saturating_sub(5),
                    KeyCode::PageDown if !self.targets.is_empty() => *sel = (*sel + 5).min(last),
                    KeyCode::Home => *sel = 0,
                    KeyCode::End if !self.targets.is_empty() => *sel = last,
                    _ => return false,
                }
                true
            }
            FinderFocus::Log => {
                adjust_log_scroll(&mut self.focus.finder_log_scroll, self.finder_logs.len(), code)
            }
        }
    }

    /// Returns character count of the currently focused text field (`0` for non-text fields).
    fn focused_text_buf_len(&self) -> usize {
        match self.focused_field() {
            FinderField::Domains => self.domains_input.chars().count(),
            FinderField::LuaDir => self.lua_dir_input.chars().count(),
            FinderField::OutputPath => self.output_path.chars().count(),
            _ => 0,
        }
    }

    /// Returns a mutable reference to the active text field buffer, or `None` for non-text fields.
    fn focused_text_buf_mut(&mut self) -> Option<&mut String> {
        match self.focused_field() {
            FinderField::Domains => Some(&mut self.domains_input),
            FinderField::LuaDir => Some(&mut self.lua_dir_input),
            FinderField::OutputPath => Some(&mut self.output_path),
            _ => None,
        }
    }

    /// Edits the active text field buffer while [`AppState::editing_text`] is `true`.
    ///
    /// Supports Left/Right arrow cursor movement, Home/End jump-to-boundary,
    /// mid-string insertion, and Delete-at-cursor via Backspace, so long domain
    /// lists remain fully navigable even when they overflow the visible column.
    pub(crate) fn handle_text_edit_key(&mut self, code: KeyCode) -> AppAction {
        if matches!(code, KeyCode::Esc | KeyCode::Enter) {
            self.editing_text = false;
            self.status_banner = "Field updated.".to_owned();
            self.reset_finder_hover();
            return AppAction::None;
        }
        let pos = self.text_cursor;
        let Some(buf) = self.focused_text_buf_mut() else {
            self.editing_text = false;
            self.reset_finder_hover();
            return AppAction::None;
        };
        let next_cursor = match code {
            KeyCode::Backspace if pos > 0 => {
                let prev = buf[..pos].char_indices().next_back().map(|(i, _)| i).unwrap_or(0);
                buf.remove(prev);
                Some(prev)
            }
            KeyCode::Delete if pos < buf.len() => {
                buf.remove(pos);
                None
            }
            KeyCode::Left if pos > 0 => {
                Some(buf[..pos].char_indices().next_back().map(|(i, _)| i).unwrap_or(0))
            }
            KeyCode::Right if pos < buf.len() => {
                Some(buf[pos..].char_indices().nth(1).map(|(i, _)| pos + i).unwrap_or(buf.len()))
            }
            KeyCode::Home => Some(0),
            KeyCode::End => Some(buf.len()),
            KeyCode::Char(c) => {
                buf.insert(pos, c);
                Some(pos + c.len_utf8())
            }
            _ => None,
        };
        if let Some(cursor) = next_cursor {
            self.text_cursor = cursor;
        }
        AppAction::None
    }

    /// Handles navigation, toggling, scan control, and config handoff on the Strategy Finder tab.
    pub(crate) fn handle_finder_key(&mut self, code: KeyCode) -> AppAction {
        if self.handle_finder_nav(code) {
            return AppAction::None;
        }
        match code {
            KeyCode::Esc if self.finder_status != FinderStatus::Scanning && self.finder_hover.open => {
                self.dismiss_finder_hover();
            }
            KeyCode::Enter | KeyCode::Char(' ') if self.focus.finder == FinderFocus::Setup => {
                self.activate_focused_finder_field();
            }
            KeyCode::Char('r') if self.finder_status != FinderStatus::Scanning => {
                self.dismiss_finder_hover();
                return AppAction::StartScan;
            }
            KeyCode::Char('x') | KeyCode::Esc if self.finder_status == FinderStatus::Scanning => {
                return AppAction::StopScan;
            }
            KeyCode::Char('s') => {
                self.dismiss_finder_hover();
                return AppAction::SaveConfig;
            }
            KeyCode::Char('a') => {
                if self.active_toml.is_empty() {
                    self.status_banner =
                        "No generated config yet: run a scan or load a file first.".to_owned();
                } else {
                    self.tab = ActiveTab::Run;
                    self.reset_finder_hover();
                    self.status_banner =
                        "Active config ready on Run tab. Press 'r' to start nfqws2.".to_owned();
                }
            }
            _ => {}
        }
        AppAction::None
    }

    /// Toggles the focused Strategy Finder option or enters text-editing mode for text fields.
    fn activate_focused_finder_field(&mut self) {
        self.reset_finder_hover();
        if let Some(len) = self.focused_text_buf_mut().map(|buf| buf.len()) {
            self.editing_text = true;
            self.text_cursor = len;
            self.dismiss_finder_hover();
            self.status_banner = "Editing field: Left/Right move cursor, Home/End jump, Del deletes forward, Enter/Esc done.".to_owned();
            return;
        }
        match self.focused_field() {
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
            FinderField::DomainScope => self.domain_scope = self.domain_scope.next(),
            _ => {}
        }
    }
}
