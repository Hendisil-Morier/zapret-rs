//! Top-level navigation tabs and shared metadata descriptors of the `zapret-rs` TUI.

/// Key codes and full key events matched by shared log/pane scrolling helpers.
use crossterm::event::{KeyCode, KeyEvent};
/// Serialization support for preserving the active tab across seamless `setcap` restarts.
use serde::{Deserialize, Serialize};

/// Configurable directional movement bindings (`[keybinds.nav]`) driving log/pane scroll helpers.
use crate::tui::keybind_schema::NavKeybinds;

/// Platform-appropriate packet engine name displayed in Tab 2 headers, logs, and status banners.
pub(crate) const ENGINE_LABEL: &str = if cfg!(windows) { "WinDivert" } else { "nfqws2" };

/// Shared header/popup descriptor defining one top-level tab in display order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TabSpec
{
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

impl TabSpec
{
    /// Total terminal cell width occupied by this tab inside the header `Tabs` widget.
    pub const fn hit_width(self, compact: bool) -> u16
    {
        let label = if compact { self.compact_label } else { self.short_label };
        (self.num_prefix.len() + label.len()) as u16
    }
}

/// Top-level navigation tabs in the `zapret-rs` TUI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveTab
{
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
    /// Tab 6: interactive Auto Hostlist and Blacklist domain manager.
    Hostlist,
    /// Tab 7: interactive `config.toml` settings, theme preset, and keybinding manager.
    Settings,
}

impl ActiveTab
{
    /// Single source of truth for tab order, header widths, and keybind popup titles.
    pub const SPECS: [TabSpec; 7] = [
        TabSpec {
            tab: Self::Finder,
            num_prefix: " 1:",
            short_label: " Finder ",
            compact_label: "Find ",
            full_title: "1: Strategy Finder",
        },
        TabSpec {
            tab: Self::Run,
            num_prefix: " 2:",
            short_label: " Run ",
            compact_label: "Run ",
            full_title: if cfg!(windows) { "2: Run WinDivert" } else { "2: Run nfqws2" },
        },
        TabSpec {
            tab: Self::Config,
            num_prefix: " 3:",
            short_label: " Config ",
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
        TabSpec {
            tab: Self::Hostlist,
            num_prefix: " 6:",
            short_label: " Hostlist ",
            compact_label: "List ",
            full_title: "6: Auto Hostlist",
        },
        TabSpec {
            tab: Self::Settings,
            num_prefix: " 7:",
            short_label: " Settings ",
            compact_label: "Set ",
            full_title: "7: Settings",
        },
    ];

    /// Returns `true` when `tabs_box_width` is too narrow to show full tab titles cleanly.
    pub fn use_compact_labels(tabs_box_width: u16) -> bool
    {
        tabs_box_width < 90
    }

    /// Fixed width allocated to the right-hand status badge in the top header row.
    pub const fn header_status_width(total_width: u16) -> u16
    {
        if total_width < 100 { 28 } else { 30 }
    }

    /// Returns the shared [`TabSpec`] metadata for `self`.
    pub const fn spec(self) -> &'static TabSpec
    {
        match self
        {
            Self::Finder => &Self::SPECS[0],
            Self::Run => &Self::SPECS[1],
            Self::Config => &Self::SPECS[2],
            Self::Speed => &Self::SPECS[3],
            Self::Status => &Self::SPECS[4],
            Self::Hostlist => &Self::SPECS[5],
            Self::Settings => &Self::SPECS[6],
        }
    }

    /// Returns the 0-based tab index for `ratatui::widgets::Tabs`.
    pub fn index(self) -> usize
    {
        Self::SPECS.iter().position(|s| s.tab == self).unwrap_or(0)
    }

    /// Advances to the next tab cyclically.
    pub fn next(self) -> Self
    {
        Self::SPECS[(self.index() + 1) % Self::SPECS.len()].tab
    }

    /// Moves to the previous tab cyclically.
    pub fn prev(self) -> Self
    {
        Self::SPECS[(self.index() + Self::SPECS.len() - 1) % Self::SPECS.len()].tab
    }
}

/// Adjusts a bottom-anchored log scroll offset (`0` = live tail) using configurable [`NavKeybinds`].
pub fn adjust_log_scroll_key(scroll: &mut u16, total_len: usize, key: KeyEvent, nav: &NavKeybinds) -> bool
{
    let cap = u16::try_from(total_len.saturating_sub(1)).unwrap_or(u16::MAX);
    if nav.up.contains(key)
    {
        *scroll = scroll.saturating_add(1).min(cap);
    }
    else if nav.down.contains(key)
    {
        *scroll = scroll.saturating_sub(1);
    }
    else if nav.page_up.contains(key)
    {
        *scroll = scroll.saturating_add(5).min(cap);
    }
    else if nav.page_down.contains(key)
    {
        *scroll = scroll.saturating_sub(5);
    }
    else if nav.end.contains(key)
    {
        *scroll = 0;
    }
    else
    {
        return false;
    }
    true
}

/// Adjusts a top-anchored preview scroll offset (`0` = top) using configurable [`NavKeybinds`].
pub fn adjust_pane_scroll_key(scroll: &mut u16, key: KeyEvent, nav: &NavKeybinds) -> bool
{
    if nav.up.contains(key)
    {
        *scroll = scroll.saturating_sub(1);
    }
    else if nav.down.contains(key)
    {
        *scroll = scroll.saturating_add(1);
    }
    else if nav.page_up.contains(key)
    {
        *scroll = scroll.saturating_sub(10);
    }
    else if nav.page_down.contains(key)
    {
        *scroll = scroll.saturating_add(10);
    }
    else if nav.home.contains(key)
    {
        *scroll = 0;
    }
    else
    {
        return false;
    }
    true
}

/// Computes the inclusive-start/exclusive-end visible slice keeping `selected` inside `capacity` rows.
pub(crate) fn visible_window(len: usize, selected: usize, capacity: usize) -> (usize, usize)
{
    if len == 0 || capacity == 0
    {
        return (0, 0);
    }
    let clamped = selected.min(len - 1);
    let end = (clamped + 1).max(capacity.min(len)).min(len);
    let start = end.saturating_sub(capacity);
    (start, end)
}

/// Steps a cursor index `selected` by signed `delta`, clamped within `0..len` (`0` when `len == 0`).
pub(crate) fn step_selection(selected: usize, len: usize, delta: isize) -> usize
{
    if len == 0
    {
        return 0;
    }
    selected.saturating_add_signed(delta).min(len - 1)
}

/// Result of applying a single key event to an inline plain-text `String` buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TextInputOutcome
{
    /// `Esc` pressed: buffer was cleared and inline editing should abort.
    Cancelled,
    /// `Enter` pressed: caller should commit or submit the buffer contents.
    Submitted,
    /// `Backspace` or printable character modified the buffer.
    Edited,
    /// Key was not part of inline text editing.
    Ignored,
}

/// Applies `Esc`, `Enter`, `Backspace`, and non-control `Char` edits uniformly to `buf`.
pub(crate) fn handle_inline_text_key(buf: &mut String, key: KeyEvent) -> TextInputOutcome
{
    match key.code
    {
        KeyCode::Esc =>
        {
            buf.clear();
            TextInputOutcome::Cancelled
        }
        KeyCode::Enter => TextInputOutcome::Submitted,
        KeyCode::Backspace =>
        {
            buf.pop();
            TextInputOutcome::Edited
        }
        KeyCode::Char(c) if !c.is_control() =>
        {
            buf.push(c);
            TextInputOutcome::Edited
        }
        _ => TextInputOutcome::Ignored,
    }
}
