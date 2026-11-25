//! Tab 1 Strategy Finder key handling, scan configuration builder, and event application.

/// Default probe timeout for strategy finder scans launched from the TUI.
use std::time::Duration;

/// Keyboard key codes handled inside the Strategy Finder form and text editor.
use crossterm::event::KeyCode;

/// Strategy catalog, `nftables` preview generator, scan settings, and domain normalization.
use crate::tools::{NftFirewallBackend, ProbeProtocol, ScanConfig, ScanLevel, normalize_domain};
/// Application state updated by Strategy Finder actions and worker progress events.
use crate::tui::state::AppState;
/// Navigation, form descriptors, action results, and background scan event payloads.
use crate::tui::types::{ActiveTab, AppAction, FinderField, FinderStatus, ScanUiEvent};

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
                self.finder_status = FinderStatus::Done;
                self.progress_done = self.progress_total;
                if !rendered_toml.is_empty() {
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

    /// Edits the active text field buffer while [`AppState::editing_text`] is `true`.
    pub(crate) fn handle_text_edit_key(&mut self, code: KeyCode) -> AppAction {
        let buf = match self.focused_field() {
            FinderField::Domains => &mut self.domains_input,
            FinderField::LuaDir => &mut self.lua_dir_input,
            FinderField::OutputPath => &mut self.output_path,
            _ => {
                self.editing_text = false;
                return AppAction::None;
            }
        };
        match code {
            KeyCode::Esc | KeyCode::Enter => {
                self.editing_text = false;
                self.status_banner = "Field updated.".to_owned();
            }
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            _ => {}
        }
        AppAction::None
    }

    /// Handles navigation, toggling, scan control, and config handoff on the Strategy Finder tab.
    pub(crate) fn handle_finder_key(&mut self, code: KeyCode) -> AppAction {
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.focus_idx =
                    if self.focus_idx == 0 { FinderField::ALL.len() - 1 } else { self.focus_idx - 1 };
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.focus_idx = (self.focus_idx + 1) % FinderField::ALL.len();
            }
            KeyCode::Enter | KeyCode::Char(' ') => match self.focused_field() {
                f if f.is_text() => {
                    self.editing_text = true;
                    self.status_banner = "Editing field: press Enter or Esc when done.".to_owned();
                }
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
                _ => {}
            },
            KeyCode::Char('r') if self.finder_status != FinderStatus::Scanning => {
                return AppAction::StartScan;
            }
            KeyCode::Char('x') | KeyCode::Esc if self.finder_status == FinderStatus::Scanning => {
                return AppAction::StopScan;
            }
            KeyCode::Char('s') => return AppAction::SaveConfig,
            KeyCode::Char('a') => {
                if self.active_toml.is_empty() {
                    self.status_banner =
                        "No generated config yet: run a scan or load a file first.".to_owned();
                } else {
                    self.tab = ActiveTab::Run;
                    self.status_banner =
                        "Active config ready on Run tab. Press 'r' to start nfqws2.".to_owned();
                }
            }
            _ => {}
        }
        AppAction::None
    }
}
