//! Global hotkeys shared by every tab: help popup, quit, tab switching, panel focus, and themes.

/// Key codes matched against the global binding table.
use crossterm::event::KeyCode;

/// Mutable application state receiving global hotkey effects.
use crate::tui::state::AppState;
/// Theme persistence helper bound to the `T` key.
use crate::tui::theme_config::save_theme_to_default_path;
/// Navigation enums and the side-effect action returned to the runner.
use crate::tui::types::{ActiveTab, AppAction};

impl AppState {
    /// Handles a key that means the same on every tab; returns `None` when `code` is not global.
    ///
    /// `t` and `T` are ignored while the packet detail popup is open so they cannot change the
    /// theme underneath it, and `?` is ignored there for the same reason.
    pub(crate) fn handle_global_key(&mut self, code: KeyCode) -> Option<AppAction> {
        let detail_open = self.inspector.detail_open;
        match code {
            KeyCode::Char('?') if !detail_open => {
                self.help_open = true;
                self.dismiss_finder_hover();
            }
            KeyCode::Char('q') => return Some(AppAction::Quit),
            KeyCode::Char('g') if !self.has_net_caps => self.open_caps_modal(),
            KeyCode::Char('1') => return Some(self.switch_tab(ActiveTab::Finder)),
            KeyCode::Char('2') => return Some(self.switch_tab(ActiveTab::Run)),
            KeyCode::Char('3') => return Some(self.switch_tab(ActiveTab::Config)),
            KeyCode::Tab => return Some(self.cycle_panel_focus(true)),
            KeyCode::BackTab => return Some(self.cycle_panel_focus(false)),
            KeyCode::Char('t') if !detail_open => {
                self.theme = self.theme.next_preset();
                self.status_banner =
                    format!("Theme: {} (press 'T' to save theme.toml)", self.theme.name);
            }
            KeyCode::Char('T') if !detail_open => {
                self.status_banner = match save_theme_to_default_path(&self.theme) {
                    Ok(path) => {
                        format!("Saved theme '{}' to {}", self.theme.name, path.display())
                    }
                    Err(err) => format!("Save theme failed: {err}"),
                };
            }
            _ => return None,
        }
        Some(AppAction::None)
    }

    /// Switches top-level tab and resets the Tab 1 tooltip dwell timer cleanly.
    fn switch_tab(&mut self, tab: ActiveTab) -> AppAction {
        self.tab = tab;
        self.reset_finder_hover();
        AppAction::None
    }

    /// Cycles focused panel inside the active tab (`Tab` / `Shift+Tab`) and updates tooltip state.
    fn cycle_panel_focus(&mut self, forward: bool) -> AppAction {
        self.focus.cycle(self.tab, forward);
        self.reset_finder_hover();
        AppAction::None
    }
}
