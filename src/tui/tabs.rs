//! Top-level navigation tabs of the `zapret-rs` TUI.

/// Serialization support for preserving the active tab across seamless `setcap` restarts.
use serde::{Deserialize, Serialize};

/// Top-level navigation tabs in the `zapret-rs` TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveTab {
    /// Tab 1: interactive strategy discovery form, live sweep progress, and results table.
    Finder,
    /// Tab 2: live in-process `nfqws2` engine controller with real-time packet counters.
    Run,
    /// Tab 3: scrollable `nfqws2.toml` viewer, `nftables` preview, and capability diagnostics.
    Config,
    /// Tab 4: before/after speed comparison (daemon stopped vs. daemon running).
    Speed,
}

impl ActiveTab {
    /// Every tab in header order, used to derive index, next and previous consistently.
    const ORDER: [Self; 4] = [Self::Finder, Self::Run, Self::Config, Self::Speed];

    /// Returns the 0-based tab index for `ratatui::widgets::Tabs`.
    pub fn index(self) -> usize {
        Self::ORDER.iter().position(|t| *t == self).unwrap_or(0)
    }

    /// Advances to the next tab cyclically.
    pub fn next(self) -> Self {
        Self::ORDER[(self.index() + 1) % Self::ORDER.len()]
    }

    /// Moves to the previous tab cyclically.
    pub fn prev(self) -> Self {
        Self::ORDER[(self.index() + Self::ORDER.len() - 1) % Self::ORDER.len()]
    }
}
