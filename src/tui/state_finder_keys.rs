//! Tab 1 Strategy Finder setup navigation, field toggles, text editing, and key handling.

/// Keyboard key codes and events handled inside the Strategy Finder form and text editor.
use crossterm::event::{KeyCode, KeyEvent};

/// Strategy scan thoroughness cycled by the Strategy Level field.
use crate::tools::ScanLevel;
/// Application state updated by Strategy Finder keyboard actions.
use crate::tui::state::AppState;
/// Navigation, form descriptors, action results, and scroll/selection helpers.
use crate::tui::types::{
    ActiveTab, AppAction, FinderField, FinderFocus, FinderStatus, adjust_log_scroll_key, step_selection,
};

impl AppState
{
    /// Moves Tab 1 Setup form focus up (`forward = false`) or down (`forward = true`) cyclically.
    pub(crate) fn step_finder_setup_focus(&mut self, forward: bool)
    {
        self.finder
            .focus_idx = if forward
        {
            (self
                .finder
                .focus_idx
                + 1)
                % FinderField::ALL.len()
        }
        else if self
            .finder
            .focus_idx
            == 0
        {
            FinderField::ALL.len() - 1
        }
        else
        {
            self.finder
                .focus_idx
                - 1
        };
        self.finder
            .text_scroll = 0;
        self.reset_finder_hover();
    }

    /// Handles vertical/page navigation for whichever Tab 1 panel currently owns focus.
    fn handle_finder_nav(&mut self, key: KeyEvent) -> bool
    {
        let nav = &self
            .keybinds
            .nav;
        match self
            .focus
            .finder
        {
            FinderFocus::Setup =>
            {
                if nav
                    .up
                    .contains(key)
                {
                    self.step_finder_setup_focus(false);
                    true
                }
                else if nav
                    .down
                    .contains(key)
                {
                    self.step_finder_setup_focus(true);
                    true
                }
                else if self
                    .focused_field()
                    .is_text()
                    && (nav
                        .left
                        .contains(key)
                        || nav
                            .right
                            .contains(key)
                        || nav
                            .home
                            .contains(key)
                        || nav
                            .end
                            .contains(key))
                    && !matches!(key.code, KeyCode::Char('h' | 'l'))
                {
                    let cap = self
                        .focused_text_buf_len()
                        .saturating_sub(16);
                    if nav
                        .left
                        .contains(key)
                    {
                        self.finder
                            .text_scroll = self
                            .finder
                            .text_scroll
                            .saturating_sub(1);
                    }
                    else if nav
                        .right
                        .contains(key)
                    {
                        self.finder
                            .text_scroll = (self
                            .finder
                            .text_scroll
                            + 1)
                        .min(cap);
                    }
                    else if nav
                        .home
                        .contains(key)
                    {
                        self.finder
                            .text_scroll = 0;
                    }
                    else if nav
                        .end
                        .contains(key)
                    {
                        self.finder
                            .text_scroll = cap;
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
                self.focus
                    .finder_results_sel = step_selection(
                    self.focus
                        .finder_results_sel,
                    self.finder
                        .targets
                        .len(),
                    delta,
                );
                true
            }
            FinderFocus::Log =>
            {
                let nav = self
                    .keybinds
                    .nav
                    .clone();
                adjust_log_scroll_key(
                    &mut self
                        .focus
                        .finder_log_scroll,
                    self.finder
                        .logs
                        .len(),
                    key,
                    &nav,
                )
            }
        }
    }

    /// Returns character count of the currently focused text field (`0` for non-text fields).
    fn focused_text_buf_len(&self) -> usize
    {
        match self.focused_field()
        {
            FinderField::Domains => self
                .finder
                .domains_input
                .chars()
                .count(),
            FinderField::LuaDir => self
                .finder
                .lua_dir_input
                .chars()
                .count(),
            FinderField::OutputPath => self
                .finder
                .output_path
                .chars()
                .count(),
            _ => 0,
        }
    }

    /// Returns a mutable reference to the active text field buffer, or `None` for non-text fields.
    fn focused_text_buf_mut(&mut self) -> Option<&mut String>
    {
        match self.focused_field()
        {
            FinderField::Domains => Some(
                &mut self
                    .finder
                    .domains_input,
            ),
            FinderField::LuaDir => Some(
                &mut self
                    .finder
                    .lua_dir_input,
            ),
            FinderField::OutputPath => Some(
                &mut self
                    .finder
                    .output_path,
            ),
            _ => None,
        }
    }

    /// Edits the active text field buffer while `editing_text` is `true`.
    pub(crate) fn handle_text_edit_key(&mut self, code: KeyCode) -> AppAction
    {
        if matches!(code, KeyCode::Esc | KeyCode::Enter)
        {
            self.finder
                .editing_text = false;
            self.status_banner = "Field updated.".to_owned();
            self.reset_finder_hover();
            return AppAction::None;
        }
        let pos = self
            .finder
            .text_cursor;
        let Some(buf) = self.focused_text_buf_mut()
        else
        {
            self.finder
                .editing_text = false;
            self.reset_finder_hover();
            return AppAction::None;
        };
        let next_cursor = match code
        {
            KeyCode::Backspace if pos > 0 =>
            {
                let prev = buf[..pos]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                buf.remove(prev);
                Some(prev)
            }
            KeyCode::Delete if pos < buf.len() =>
            {
                buf.remove(pos);
                None
            }
            KeyCode::Left if pos > 0 => Some(
                buf[..pos]
                    .char_indices()
                    .next_back()
                    .map(|(i, _)| i)
                    .unwrap_or(0),
            ),
            KeyCode::Right if pos < buf.len() => Some(
                buf[pos..]
                    .char_indices()
                    .nth(1)
                    .map(|(i, _)| pos + i)
                    .unwrap_or(buf.len()),
            ),
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
            self.finder
                .text_cursor = cursor;
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
        let f = &self
            .keybinds
            .finder;
        if self
            .finder
            .status
            != FinderStatus::Scanning
            && self
                .finder
                .hover
                .open
            && f.dismiss_hover
                .contains(key)
        {
            self.dismiss_finder_hover();
        }
        else if self
            .focus
            .finder
            == FinderFocus::Setup
            && f.activate
                .contains(key)
        {
            self.activate_focused_finder_field();
        }
        else if self
            .finder
            .status
            != FinderStatus::Scanning
            && f.start_scan
                .contains(key)
        {
            self.dismiss_finder_hover();
            return AppAction::StartScan;
        }
        else if self
            .finder
            .status
            == FinderStatus::Scanning
            && f.stop_scan
                .contains(key)
        {
            return AppAction::StopScan;
        }
        else if f
            .save_toml
            .contains(key)
        {
            self.dismiss_finder_hover();
            return AppAction::SaveConfig;
        }
        else if f
            .open_run_tab
            .contains(key)
        {
            if self
                .config
                .active_toml
                .is_empty()
            {
                self.status_banner = "No generated config yet: run a scan or load a file first.".to_owned();
            }
            else
            {
                self.tab = ActiveTab::Run;
                let start_lbl = self
                    .keybinds
                    .run
                    .start_stop
                    .primary_label();
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
        if let Some(len) = self
            .focused_text_buf_mut()
            .map(|buf| buf.len())
        {
            self.finder
                .editing_text = true;
            self.finder
                .text_cursor = len;
            self.dismiss_finder_hover();
            self.status_banner =
                "Editing field: Left/Right move cursor, Home/End jump, Del deletes forward, Enter/Esc done."
                    .to_owned();
            return;
        }
        match self.focused_field()
        {
            FinderField::ProtoHttp =>
            {
                self.finder
                    .proto_http = !self
                    .finder
                    .proto_http
            }
            FinderField::ProtoTls12 =>
            {
                self.finder
                    .proto_tls12 = !self
                    .finder
                    .proto_tls12
            }
            FinderField::ProtoTls13 =>
            {
                self.finder
                    .proto_tls13 = !self
                    .finder
                    .proto_tls13
            }
            FinderField::ProtoHttp3 =>
            {
                self.finder
                    .proto_http3 = !self
                    .finder
                    .proto_http3
            }
            FinderField::IpMode =>
            {
                self.finder
                    .ip_mode = self
                    .finder
                    .ip_mode
                    .next()
            }
            FinderField::Level =>
            {
                self.finder
                    .level = match self
                    .finder
                    .level
                {
                    ScanLevel::Quick => ScanLevel::Standard,
                    ScanLevel::Standard => ScanLevel::Force,
                    ScanLevel::Force => ScanLevel::Quick,
                };
            }
            FinderField::StopOnFirst =>
            {
                self.finder
                    .stop_on_first = !self
                    .finder
                    .stop_on_first
            }
            FinderField::NoNft =>
            {
                self.finder
                    .no_nft = !self
                    .finder
                    .no_nft
            }
            FinderField::DomainScope =>
            {
                self.finder
                    .domain_scope = self
                    .finder
                    .domain_scope
                    .next()
            }
            _ =>
            {}
        }
    }
}
