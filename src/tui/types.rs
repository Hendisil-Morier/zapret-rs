//! Data types, navigation enums, telemetry counters, and worker events for the `zapret-rs` TUI.

/// Lock-free 64-bit packet counters updated by the live NFQUEUE worker thread.
use std::sync::atomic::{AtomicU64, Ordering};

/// Strategy catalog enums and completed scan reports forwarded into UI events.
use crate::tools::{IpFamily, ProbeProtocol, ScanReport};

/// Top-level navigation tabs in the `zapret-rs` TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveTab {
    /// Tab 1: interactive strategy discovery form, live sweep progress, and results table.
    Finder,
    /// Tab 2: live in-process `nfqws2` engine controller with real-time packet counters.
    Run,
    /// Tab 3: scrollable `nfqws2.toml` viewer, `nftables` preview, and capability diagnostics.
    Config,
}

impl ActiveTab {
    /// Returns the 0-based tab index for `ratatui::widgets::Tabs`.
    pub const fn index(self) -> usize {
        match self { Self::Finder => 0, Self::Run => 1, Self::Config => 2 }
    }

    /// Advances to the next tab cyclically.
    pub const fn next(self) -> Self {
        match self { Self::Finder => Self::Run, Self::Run => Self::Config, Self::Config => Self::Finder }
    }

    /// Moves to the previous tab cyclically.
    pub const fn prev(self) -> Self {
        match self { Self::Finder => Self::Config, Self::Run => Self::Finder, Self::Config => Self::Run }
    }
}

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
}

impl FinderField {
    /// Ordered list of all form rows rendered on the Strategy Finder tab.
    pub const ALL: &'static [Self] = &[
        Self::Domains, Self::ProtoHttp, Self::ProtoTls12, Self::ProtoTls13, Self::ProtoHttp3,
        Self::IpMode, Self::Level, Self::StopOnFirst, Self::NoNft, Self::LuaDir, Self::OutputPath,
    ];

    /// Returns `true` when this row accepts free-form text input.
    pub const fn is_text(self) -> bool {
        matches!(self, Self::Domains | Self::LuaDir | Self::OutputPath)
    }
}

/// IP address family mode selectable in the Finder form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// Lifecycle state of the live `nfqws2` desync engine on Tab 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunStatus {
    /// Engine is stopped.
    Stopped,
    /// Engine is intercepting and desyncing packets.
    Running,
    /// Engine failed to start or stopped with an error.
    Error(String),
}

/// Lock-free packet verdict counters updated by the live `nfqws2` worker thread.
#[derive(Debug, Default)]
pub struct PacketCounters {
    /// Total packets dispatched to [`crate::desync::DesyncEngine::process_packet`].
    pub total: AtomicU64,
    /// Packets returned with `Decision::Pass`.
    pub passed: AtomicU64,
    /// Packets returned with `Decision::Replace`.
    pub modified: AtomicU64,
    /// Packets returned with `Decision::Drop`.
    pub dropped: AtomicU64,
}

impl PacketCounters {
    /// Returns a consistent snapshot `(total, passed, modified, dropped)`.
    pub fn snapshot(&self) -> (u64, u64, u64, u64) {
        (
            self.total.load(Ordering::Relaxed),
            self.passed.load(Ordering::Relaxed),
            self.modified.load(Ordering::Relaxed),
            self.dropped.load(Ordering::Relaxed),
        )
    }

    /// Resets all packet counters back to zero.
    pub fn reset(&self) {
        self.total.store(0, Ordering::Relaxed);
        self.passed.store(0, Ordering::Relaxed);
        self.modified.store(0, Ordering::Relaxed);
        self.dropped.store(0, Ordering::Relaxed);
    }
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
    /// Start the live in-process `nfqws2` engine using `active_toml`.
    StartDaemon,
    /// Stop the live in-process `nfqws2` engine.
    StopDaemon,
    /// Reload `output_path` from disk into `active_toml`.
    ReloadConfig,
    /// Open `output_path` in `$VISUAL`/`$EDITOR` (seeding a starter file if missing), then reload.
    EditConfig,
    /// Execute the active floating [`crate::tui::AuthModal`] action (`Enter` pressed).
    SubmitModal,
}
