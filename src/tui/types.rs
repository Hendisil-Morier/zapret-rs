//! Data types, navigation enums, and worker events for the `zapret-rs` TUI.

/// Timing primitives for tracking 1-second Strategy Finder focus dwell tooltips.
use std::time::{Duration, Instant};

/// Keyboard key codes handled by shared panel scroll helpers.
use crossterm::event::KeyCode;
/// Serialization support for preserving navigation state across seamless `setcap` restarts.
use serde::{Deserialize, Serialize};

/// Strategy catalog enums and completed scan reports forwarded into UI events.
use crate::tools::{IpFamily, ProbeProtocol, ScanReport};

/// Top-level navigation tabs, defined in their own module and re-exported here for existing paths.
pub use crate::tui::tabs::ActiveTab;

/// Interactive form rows on the Strategy Finder tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinderField {
    /// Comma- or space-separated target domains.
    Domains,
    /// Plaintext HTTP (TCP 80) toggle.
    ProtoHttp,
    /// HTTPS TLS 1.2 (TCP 443) toggle.
    ProtoTls12,
    /// HTTPS TLS 1.3 (TCP 443) toggle.
    ProtoTls13,
    /// HTTP/3 QUIC (UDP 443) toggle.
    ProtoHttp3,
    /// IP version selector (`4`, `6`, `46`).
    IpMode,
    /// Scan thoroughness selector (`quick`, `standard`, `force`).
    Level,
    /// Stop on first working strategy per domain toggle.
    StopOnFirst,
    /// Skip automatic `nftables` rule installation toggle.
    NoNft,
    /// Lua scripts directory text field (`zapret-lib.lua`, `zapret-antidpi.lua`).
    LuaDir,
    /// Output `nfqws2.toml` path text field.
    OutputPath,
    /// Domain matching scope for generated profiles (`Scanned Only`, `All Domains`, `Auto Hostlist`).
    DomainScope,
}

impl FinderField {
    /// Ordered list of all form rows rendered on the Strategy Finder tab.
    pub const ALL: &'static [Self] = &[
        Self::Domains, Self::ProtoHttp, Self::ProtoTls12, Self::ProtoTls13, Self::ProtoHttp3,
        Self::IpMode, Self::Level, Self::StopOnFirst, Self::NoNft, Self::LuaDir, Self::OutputPath,
        Self::DomainScope,
    ];

    /// Returns `true` when this row accepts free-form text input.
    pub const fn is_text(self) -> bool {
        matches!(self, Self::Domains | Self::LuaDir | Self::OutputPath)
    }

    /// Returns a concise `(title, explanation)` pair displayed in the focus-dwell help popup.
    pub const fn description(self) -> (&'static str, &'static str) {
        match self {
            Self::Domains => (
                "Target Domains",
                "Comma- or space-separated hostnames to test (e.g. example.com). Omit https:// and press Enter to edit. Use Left/Right arrows to move the cursor, Home/End to jump, Delete to remove the char under the cursor.",
            ),
            Self::ProtoHttp => (
                "HTTP (TCP 80)",
                "Probes plaintext HTTP on port 80 and searches HTTP DPI desync techniques such as methodeol or host splitting.",
            ),
            Self::ProtoTls12 => (
                "TLS 1.2 (TCP 443)",
                "Probes HTTPS TLS 1.2 ClientHello handshakes on TCP port 443 to find working SNI/record desync strategies.",
            ),
            Self::ProtoTls13 => (
                "TLS 1.3 (TCP 443)",
                "Probes HTTPS TLS 1.3 ClientHello handshakes on TCP port 443, including split and multidisorder variants.",
            ),
            Self::ProtoHttp3 => (
                "HTTP/3 QUIC (UDP 443)",
                "Probes HTTP/3 QUIC Initial packets on UDP port 443 when supported by curl, testing UDP DPI desync methods.",
            ),
            Self::IpMode => (
                "IP Version",
                "Cycles target address families between IPv4 (4), IPv6 (6), and dual-stack (46). Press Enter or Space to switch.",
            ),
            Self::Level => (
                "Scan Level",
                "Sets catalog depth: quick runs top strategies fast, standard widens variants, and force tries every strategy.",
            ),
            Self::StopOnFirst => (
                "Stop On First",
                "When checked ([x]), stops sweeping a target once one strategy works; uncheck ([ ]) to measure every candidate.",
            ),
            Self::NoNft => (
                "Manual nft (--no-nft)",
                "When unchecked ([ ]), installs temporary nftables queue rules automatically. Check ([x]) to supply rules yourself.",
            ),
            Self::LuaDir => (
                "Lua Directory",
                "Folder containing zapret-lib.lua and zapret-antidpi.lua referenced by generated nfqws2.toml files.",
            ),
            Self::OutputPath => (
                "Config Path",
                "Destination nfqws2.toml path written on save ('s') and loaded by Tab 2 and Tab 3 (supports ~/ expansion).",
            ),
            Self::DomainScope => (
                "Domain Scope",
                "Scanned Only restricts profiles to listed domains; All Domains applies to all sites on those ports; Auto Hostlist learns blocked domains automatically.",
            ),
        }
    }
}

/// Focus dwell duration on a Strategy Finder row before opening its explanation popup.
pub const FINDER_HOVER_DELAY: Duration = Duration::from_secs(1);

/// Tracks how long focus has rested on the active [`FinderField`] for contextual help display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinderHoverState {
    /// Instant when focus settled on the current option (`None` while dismissed or paused).
    pub since: Option<Instant>,
    /// `true` while the floating explanation tooltip is visible on Tab 1.
    pub open: bool,
}

impl Default for FinderHoverState {
    /// Arms the 1-second hover timer on startup so resting on the initial option shows its hint.
    fn default() -> Self {
        Self { since: Some(Instant::now()), open: false }
    }
}

/// IP address family mode selectable in the Finder form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IpMode {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
    /// Both IPv4 and IPv6.
    Both,
}

impl IpMode {
    /// Cycles through `V4 -> V6 -> Both -> V4`.
    pub const fn next(self) -> Self {
        match self { Self::V4 => Self::V6, Self::V6 => Self::Both, Self::Both => Self::V4 }
    }

    /// Returns a compact display label for the form row.
    pub const fn label(self) -> &'static str {
        match self { Self::V4 => "IPv4 (4)", Self::V6 => "IPv6 (6)", Self::Both => "IPv4 + IPv6 (46)" }
    }

    /// Expands this mode into concrete [`IpFamily`] targets.
    pub fn families(self) -> Vec<IpFamily> {
        match self {
            Self::V4 => vec![IpFamily::V4],
            Self::V6 => vec![IpFamily::V6],
            Self::Both => vec![IpFamily::V4, IpFamily::V6],
        }
    }
}

/// Lifecycle state of the background strategy scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FinderStatus {
    /// Ready to configure and launch a scan.
    Idle,
    /// Scan is currently executing in the background thread.
    Scanning,
    /// Scan completed (possibly interrupted with partial results).
    Done,
    /// Scan failed to start or encountered a fatal error.
    Error(String),
}

/// Lifecycle state of the live `nfqws2` desync engine or remote attach session on Tab 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    /// Engine is stopped and not attached to a daemon socket.
    Stopped,
    /// In-process engine is intercepting and desyncing packets.
    Running,
    /// Attached to an external `nfqws2` daemon over its local Unix control socket.
    Attached,
    /// Engine failed to start, attach, or stopped with an error.
    Error(String),
}

/// Progress messages streamed from the background scan thread to the TUI event loop.
#[derive(Debug, Clone)]
pub enum ScanUiEvent {
    /// Baseline connectivity probe completed for one target.
    Baseline {
        /// Target domain.
        domain: String,
        /// Target protocol.
        proto: ProbeProtocol,
        /// Target IP family.
        ipv: IpFamily,
        /// Formatted outcome summary.
        summary: String,
        /// `true` if direct access worked and sweep will be skipped.
        skipped: bool,
    },
    /// One strategy candidate finished probing.
    Candidate {
        /// Target domain.
        domain: String,
        /// 1-based candidate index.
        index: usize,
        /// Total candidates in this target's catalog.
        total: usize,
        /// Candidate strategy ID.
        strategy_id: String,
        /// `true` when the strategy passed.
        passed: bool,
        /// Formatted probe summary.
        summary: String,
    },
    /// Non-fatal informational or warning line (e.g., HTTP/3 skipped).
    Notice(String),
    /// Scan completed with full/partial report and rendered `nfqws2.toml`.
    Completed {
        /// Completed scan report.
        report: ScanReport,
        /// Rendered `nfqws2.toml` for `report.cover` (empty if no matches).
        rendered_toml: String,
    },
    /// Scan aborted with an error message.
    Failed(String),
}

/// Side-effectful actions requested by [`crate::tui::AppState::handle_key`] and executed by the runner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppAction {
    /// Pure UI state change; no external side effect required.
    None,
    /// Exit the TUI cleanly, tearing down workers and temporary `nftables` rules.
    Quit,
    /// Start a live strategy scan using the current Finder form settings.
    StartScan,
    /// Cancel an active strategy scan.
    StopScan,
    /// Write `active_toml` to `output_path` via `O_NOFOLLOW`.
    SaveConfig,
    /// Start the live in-process `nfqws2` engine or attach to an existing daemon socket.
    StartDaemon,
    /// Stop the live in-process `nfqws2` engine.
    StopDaemon,
    /// Detach cleanly from an attached remote daemon while leaving it running.
    DetachDaemon,
    /// Request list reload (`hostlist`/`ipset`) on an attached remote daemon.
    ReloadRemoteLists,
    /// Request remote daemon shutdown over the control socket after user confirmation.
    StopRemoteDaemon,
    /// Stop the running daemon, wait for it to exit, then start it again (`R` on Tab 2).
    RestartDaemon,
    /// Reload `output_path` from disk into `active_toml`.
    ReloadConfig,
    /// Open `output_path` in `$VISUAL`/`$EDITOR` (seeding a starter file if missing), then reload.
    EditConfig,
    /// Push validated `active_toml` from Tab 3 to an attached remote daemon (`reload_config`).
    PushConfigToDaemon,
    /// Execute the active floating [`crate::tui::AuthModal`] action (`Enter` pressed).
    SubmitModal,
    /// Run the confirmed before/after speed comparison on Tab 4.
    RunSpeedTest,
    /// Cancel an in-flight before/after speed comparison on Tab 4 (`x` or `Esc`).
    CancelSpeedTest,
}

/// Action deferred until after a seamless `setcap` capability-grant restart finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostCapsAction {
    /// Automatically resume launching the Strategy Finder scan on Tab 1.
    StartScan,
    /// Automatically resume launching the local `nfqws2` engine on Tab 2.
    StartDaemon,
}

/// Focused panel within Tab 1 (Strategy Finder) cycled with `Tab` / `Shift+Tab`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FinderFocus {
    /// Left Strategy Setup interactive form.
    #[default]
    Setup,
    /// Top-right completed strategy scan Results table.
    Results,
    /// Bottom-right Live Scan Log feed.
    Log,
}

/// Focused panel within Tab 2 (Run `nfqws2`) cycled with `Tab` / `Shift+Tab`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RunFocus {
    /// Center Packet Inspector table.
    #[default]
    Inspector,
    /// Bottom Daemon Log feed.
    Log,
}

/// Focused panel within Tab 3 (Config & Diagnostics) cycled with `Tab` / `Shift+Tab`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigFocus {
    /// Left scrollable `nfqws2.toml` viewer.
    #[default]
    Toml,
    /// Top-right scrollable temporary `nftables` ruleset preview.
    Nft,
}

/// Per-tab focused panel and scroll offsets updated via `Tab`, `BackTab`, and vertical keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PanelFocusState {
    /// Active panel on Tab 1.
    pub finder: FinderFocus,
    /// Active panel on Tab 2.
    pub run: RunFocus,
    /// Active panel on Tab 3.
    pub config: ConfigFocus,
    /// Selected row index inside Tab 1's `Results` table.
    pub finder_results_sel: usize,
    /// Lines scrolled up from the tail inside Tab 1's `Live Scan Log`.
    pub finder_log_scroll: u16,
    /// Lines scrolled up from the tail inside Tab 2's `Daemon Log`.
    pub run_log_scroll: u16,
    /// Top visible line inside Tab 3's `Temporary nftables Script` pane.
    pub nft_scroll: u16,
}

impl PanelFocusState {
    /// Advances panel focus cyclically within `tab` (`Tab` forward, `Shift+Tab` backward).
    pub fn cycle(&mut self, tab: ActiveTab, forward: bool) {
        match tab {
            ActiveTab::Finder => {
                self.finder = match (self.finder, forward) {
                    (FinderFocus::Setup, true) | (FinderFocus::Log, false) => FinderFocus::Results,
                    (FinderFocus::Results, true) | (FinderFocus::Setup, false) => FinderFocus::Log,
                    (FinderFocus::Log, true) | (FinderFocus::Results, false) => FinderFocus::Setup,
                };
            }
            ActiveTab::Run => {
                self.run = match self.run {
                    RunFocus::Inspector => RunFocus::Log,
                    RunFocus::Log => RunFocus::Inspector,
                };
            }
            ActiveTab::Config => {
                self.config = match self.config {
                    ConfigFocus::Toml => ConfigFocus::Nft,
                    ConfigFocus::Nft => ConfigFocus::Toml,
                };
            }
            ActiveTab::Speed => {}
        }
    }
}

/// Adjusts a bottom-anchored log scroll offset (`0` = live tail) for vertical navigation keys.
pub fn adjust_log_scroll(scroll: &mut u16, total_len: usize, code: KeyCode) -> bool {
    let cap = u16::try_from(total_len.saturating_sub(1)).unwrap_or(u16::MAX);
    match code {
        KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_add(1).min(cap),
        KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_sub(1),
        KeyCode::PageUp => *scroll = scroll.saturating_add(5).min(cap),
        KeyCode::PageDown => *scroll = scroll.saturating_sub(5),
        KeyCode::End => *scroll = 0,
        _ => return false,
    }
    true
}

/// Adjusts a top-anchored preview scroll offset (`0` = top) for vertical navigation keys.
pub fn adjust_pane_scroll(scroll: &mut u16, code: KeyCode) -> bool {
    match code {
        KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
        KeyCode::PageUp => *scroll = scroll.saturating_sub(10),
        KeyCode::PageDown => *scroll = scroll.saturating_add(10),
        KeyCode::Home => *scroll = 0,
        _ => return false,
    }
    true
}
