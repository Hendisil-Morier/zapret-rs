//! Top-level navigation tabs and shared metadata descriptors of the `zapret-rs` TUI.

/// Key codes matched by shared log/pane scrolling helpers.
use crossterm::event::KeyCode;
/// Serialization support for preserving the active tab across seamless `setcap` restarts.
use serde::{Deserialize, Serialize};

/// Platform-appropriate packet engine name displayed in Tab 2 headers, logs, and status banners.
pub(crate) const ENGINE_LABEL: &str = if cfg!(windows) { "WinDivert" } else { "nfqws2" };

/// Shared header/popup descriptor defining one top-level tab in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TabSpec {
    /// Target [`ActiveTab`] variant switched to on hotkey or header click.
    pub tab: ActiveTab,
    /// Leading numeric hotkey prefix rendered in the header (`" 1:"`, etc.).
    pub num_prefix: &'static str,
    /// Compact tab title rendered in the top bar (`" Strategy Finder "`, etc.).
    pub short_label: &'static str,
    /// Ultra-compact tab title used when the terminal is too narrow for full tab labels.
    pub compact_label: &'static str,
    /// Full section title rendered in the `?` keybindings popup.
    pub full_title: &'static str,
}

impl TabSpec {
    /// Total terminal cell width occupied by this tab inside the header `Tabs` widget.
    pub const fn hit_width(self, compact: bool) -> u16 {
        let label = if compact { self.compact_label } else { self.short_label };
        (self.num_prefix.len() + label.len()) as u16
    }
}

/// Top-level navigation tabs in the `zapret-rs` TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveTab {
    /// Tab 1: interactive strategy discovery form, live sweep progress, and results table.
    Finder,
    /// Tab 2: live in-process `nfqws2` engine controller with real-time packet counters.
    Run,
    /// Tab 3: scrollable `nfqws2.toml` viewer, `nftables` preview, and `Auto Hostlist` pane.
    Config,
    /// Tab 4: before/after speed comparison (daemon stopped vs. daemon running).
    Speed,
    /// Tab 5: operational health status for privileges, driver, Lua, `curl`, config, and IPC.
    Status,
}

impl ActiveTab {
    /// Single source of truth for tab order, header widths, and keybind popup titles.
    pub const SPECS: [TabSpec; 5] = [
        TabSpec {
            tab: Self::Finder,
            num_prefix: " 1:",
            short_label: " Strategy Finder ",
            compact_label: "Find ",
            full_title: "1: Strategy Finder",
        },
        TabSpec {
            tab: Self::Run,
            num_prefix: " 2:",
            short_label: if cfg!(windows) { " Run WinDivert " } else { " Run nfqws2 " },
            compact_label: "Run ",
            full_title: if cfg!(windows) { "2: Run WinDivert" } else { "2: Run nfqws2" },
        },
        TabSpec {
            tab: Self::Config,
            num_prefix: " 3:",
            short_label: " Config & Diag ",
            compact_label: "Cfg ",
            full_title: "3: Config & Diagnostics",
        },
        TabSpec {
            tab: Self::Speed,
            num_prefix: " 4:",
            short_label: " Speed Test ",
            compact_label: "Spd ",
            full_title: "4: Speed Test",
        },
        TabSpec {
            tab: Self::Status,
            num_prefix: " 5:",
            short_label: " Status ",
            compact_label: "Stat ",
            full_title: "5: Status",
        },
    ];

    /// Returns `true` when `tabs_box_width` is too narrow to show full tab titles cleanly.
    pub fn use_compact_labels(tabs_box_width: u16) -> bool {
        tabs_box_width < 68
    }

    /// Returns the shared [`TabSpec`] metadata for `self`.
    pub const fn spec(self) -> &'static TabSpec {
        match self {
            Self::Finder => &Self::SPECS[0],
            Self::Run => &Self::SPECS[1],
            Self::Config => &Self::SPECS[2],
            Self::Speed => &Self::SPECS[3],
            Self::Status => &Self::SPECS[4],
        }
    }

    /// Returns the 0-based tab index for `ratatui::widgets::Tabs`.
    pub fn index(self) -> usize {
        Self::SPECS.iter().position(|s| s.tab == self).unwrap_or(0)
    }

    /// Advances to the next tab cyclically.
    pub fn next(self) -> Self {
        Self::SPECS[(self.index() + 1) % Self::SPECS.len()].tab
    }

    /// Moves to the previous tab cyclically.
    pub fn prev(self) -> Self {
        Self::SPECS[(self.index() + Self::SPECS.len() - 1) % Self::SPECS.len()].tab
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
