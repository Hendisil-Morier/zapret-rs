//! Tab 1 Strategy Finder key handling, scan configuration builder, and event application.

/// Default probe timeout and clock instant for focus-dwell help popups.
use std::time::{Duration, Instant};

/// Strategy catalog, active OS firewall backend, scan settings, and domain normalization.
use crate::tools::{ProbeProtocol, ScanConfig, active_firewall_backend, normalize_domain};
/// Application state updated by Strategy Finder actions and worker progress events.
use crate::tui::state::AppState;
/// Navigation, dwell delay, panel focus, and background scan event types.
use crate::tui::types::{ActiveTab, FINDER_HOVER_DELAY, FinderFocus, FinderStatus, ScanUiEvent};

impl AppState
{
    /// Returns the currently selected protocol list from the Finder checkboxes.
    pub fn selected_protos(&self) -> Vec<ProbeProtocol>
    {
        let mut out = Vec::new();
        if self
            .finder
            .proto_http
        {
            out.push(ProbeProtocol::Http);
        }
        if self
            .finder
            .proto_tls12
        {
            out.push(ProbeProtocol::Tls12);
        }
        if self
            .finder
            .proto_tls13
        {
            out.push(ProbeProtocol::Tls13);
        }
        if self
            .finder
            .proto_http3
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
            families: self
                .finder
                .ip_mode
                .families(),
            level: self
                .finder
                .level,
            timeout: Duration::from_secs(2),
            stop_on_first: self
                .finder
                .stop_on_first,
            force_blocked: false,
        })
    }

    /// Renders the active OS firewall backend's `(panel_title, filter_text)` preview for Tab 3.
    pub fn filter_preview(&self) -> (&'static str, String)
    {
        let cfg = ScanConfig {
            domains: Vec::new(),
            protos: self.selected_protos(),
            families: self
                .finder
                .ip_mode
                .families(),
            level: self
                .finder
                .level,
            timeout: Duration::from_secs(2),
            stop_on_first: self
                .finder
                .stop_on_first,
            force_blocked: false,
        };
        let (tcp, udp) = cfg.required_ports();
        let backend = active_firewall_backend();
        (
            backend.preview_title(),
            backend.preview_filter(
                self.finder
                    .qnum,
                self.finder
                    .fwmark,
                &tcp,
                &udp,
            ),
        )
    }

    /// Applies one background [`ScanUiEvent`] to live progress, results table, logs, and TOML.
    pub fn apply_scan_event(&mut self, event: ScanUiEvent)
    {
        match event
        {
            ScanUiEvent::Baseline { domain, proto, ipv, summary, skipped } =>
            {
                let tag = if skipped { "reachable (skip)" } else { "blocked" };
                self.finder
                    .progress_label = format!("Baseline {domain} ({proto}/{ipv}): {summary}");
                self.push_finder_log(format!("[baseline] {domain} ({proto}/{ipv}) -> {summary} [{tag}]"));
            }
            ScanUiEvent::Candidate { domain, index, total, strategy_id, passed, summary } =>
            {
                self.finder
                    .progress_done = index;
                self.finder
                    .progress_total = total;
                self.finder
                    .progress_label = format!("{domain} [{index}/{total}] {strategy_id}");
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
                let n_cover = report
                    .cover
                    .len();
                self.finder
                    .targets = report.targets;
                self.finder
                    .cover = report.cover;
                self.focus
                    .finder_results_sel = 0;
                self.finder
                    .status = FinderStatus::Done;
                self.finder
                    .progress_done = self
                    .finder
                    .progress_total;
                if !rendered_toml.is_empty()
                {
                    if !self
                        .config
                        .parsed_profiles
                        .is_empty()
                        && self
                            .config
                            .toml_error
                            .is_none()
                    {
                        self.config
                            .pending_merge = Some((
                            self.config
                                .active_toml
                                .clone(),
                            rendered_toml.clone(),
                        ));
                    }
                    else
                    {
                        self.config
                            .pending_merge = None;
                    }
                    self.set_active_toml(rendered_toml);
                }
                self.finder
                    .progress_label = if report.interrupted
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
                self.finder
                    .status = FinderStatus::Error(err.clone());
                self.finder
                    .progress_label = format!("Error: {err}");
                self.status_banner = format!("Scan error: {err}");
                self.push_finder_log(format!("[error] {err}"));
            }
        }
    }

    /// Hides the option tooltip and restarts the 1-second dwell timer from now.
    pub fn reset_finder_hover(&mut self)
    {
        self.finder
            .hover
            .open = false;
        self.finder
            .hover
            .since = Some(Instant::now());
    }

    /// Hides the option tooltip and pauses the dwell timer until the user interacts again.
    pub fn dismiss_finder_hover(&mut self)
    {
        self.finder
            .hover
            .open = false;
        self.finder
            .hover
            .since = None;
    }

    /// Opens the Tab 1 option explanation popup once focus rests idle for [`FINDER_HOVER_DELAY`].
    pub fn poll_finder_hover(&mut self, now: Instant)
    {
        if self.tab != ActiveTab::Finder
            || self
                .focus
                .finder
                != FinderFocus::Setup
            || self
                .modal
                .is_some()
            || self.help_open
            || self
                .finder
                .editing_text
            || self
                .finder
                .status
                == FinderStatus::Scanning
        {
            self.finder
                .hover
                .open = false;
            return;
        }
        if !self
            .finder
            .hover
            .open
            && let Some(since) = self
                .finder
                .hover
                .since
            && now.saturating_duration_since(since) >= FINDER_HOVER_DELAY
        {
            self.finder
                .hover
                .open = true;
        }
    }
}
