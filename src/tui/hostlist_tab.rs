//! Tab 6 (`Hostlist`) state, keyboard/mouse navigation, direct deletion, and exclude transfers.

/// Key codes handled on Tab 6 for list selection, filtering, deletion, and moves.
use crossterm::event::KeyCode;
/// Layout partitioning aligned identically between `draw_hostlist_tab` and mouse hit-testing.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Wire request enum used to live-reload modified autohostlists on an attached daemon.
use crate::control::Request;
/// Symlink-safe hostlist/TOML editors shared with Web UI and Tab 3 list operations.
use crate::tools::{expand_tilde, mutate_exclude_domains_toml, mutate_hostlist_file};
/// Centered plain-text prompt modal used only when *adding* a new domain (`a` / `b`).
use crate::tui::prompt_modal::{PromptKind, PromptModal};
/// Mutable top-level TUI state updated by Tab 6 interactions.
use crate::tui::state::AppState;
/// Tab 2 remote daemon session handle notified after disk list updates.
use crate::tui::tab2_session::Tab2Session;
/// Shared Tab 3 TOML/domain state and persistent config commit helper.
use crate::tui::tab_states::ConfigTabState;
/// Shared side-effect action returned to `runner.rs`.
use crate::tui::types::AppAction;
/// Shared TOML update/persist/reload helper avoiding duplicate config writes.
use crate::tui::web_actions::commit_updated_toml;

/// Focused list column on Tab 6 (`Auto Hostlist` vs `Blacklist`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostlistFocus {
    /// Left column listing learned/manual domains in `autohostlist.txt`.
    #[default]
    AutoHostlist,
    /// Right column listing permanently excluded domains (`hostlist_exclude_domains`).
    Blacklist,
}

/// Interactive state for Tab 6 (`Hostlist`): focused column, cursors, and live `/` filter.
#[derive(Debug, Clone, Default)]
pub struct HostlistTabState {
    /// Currently focused column receiving cursor/delete keys (`Tab` / `Left` / `Right`).
    pub focus: HostlistFocus,
    /// Selected row index inside the filtered `Auto Hostlist` list.
    pub auto_sel: usize,
    /// Selected row index inside the filtered `Blacklist` list.
    pub blacklist_sel: usize,
    /// Case-insensitive substring filter applied across both lists (`/`).
    pub filter: String,
    /// `true` while typing into the `/` filter box.
    pub filter_editing: bool,
}

/// Computes the inclusive-start/exclusive-end visible slice keeping `sel` inside `capacity` rows.
pub(crate) fn visible_list_window(len: usize, sel: usize, capacity: usize) -> (usize, usize) {
    if len == 0 || capacity == 0 {
        return (0, 0);
    }
    let clamped = sel.min(len - 1);
    let end = (clamped + 1).max(capacity.min(len)).min(len);
    let start = end.saturating_sub(capacity);
    (start, end)
}

impl HostlistTabState {
    /// Toggles focus between the `Auto Hostlist` and `Blacklist` columns.
    pub fn toggle_focus(&mut self) {
        self.focus = match self.focus {
            HostlistFocus::AutoHostlist => HostlistFocus::Blacklist,
            HostlistFocus::Blacklist => HostlistFocus::AutoHostlist,
        };
    }

    /// Returns filtered Auto Hostlist domain slices matching `self.filter`.
    pub fn filtered_auto<'a>(&self, config: &'a ConfigTabState) -> Vec<&'a str> {
        filter_domain_slice(&config.autohostlist_entries, &self.filter)
    }

    /// Returns filtered Blacklist domain slices matching `self.filter`.
    pub fn filtered_blacklist<'a>(&self, config: &'a ConfigTabState) -> Vec<&'a str> {
        filter_domain_slice(&config.exclude_entries, &self.filter)
    }

    /// Returns the currently highlighted domain in the focused column, if any.
    pub fn selected_domain(&self, config: &ConfigTabState) -> Option<String> {
        match self.focus {
            HostlistFocus::AutoHostlist => {
                let items = self.filtered_auto(config);
                items.get(self.auto_sel).map(|s| (*s).to_owned())
            }
            HostlistFocus::Blacklist => {
                let items = self.filtered_blacklist(config);
                items.get(self.blacklist_sel).map(|s| (*s).to_owned())
            }
        }
    }

    /// Clamps both cursors cleanly within the current filtered list lengths.
    pub fn clamp_selection(&mut self, config: &ConfigTabState) {
        let auto_len = self.filtered_auto(config).len();
        self.auto_sel = if auto_len == 0 { 0 } else { self.auto_sel.min(auto_len - 1) };
        let black_len = self.filtered_blacklist(config).len();
        self.blacklist_sel = if black_len == 0 { 0 } else { self.blacklist_sel.min(black_len - 1) };
    }

    /// Moves the active column's cursor by signed `delta`, clamped at list bounds.
    pub fn move_selection(&mut self, config: &ConfigTabState, delta: isize) {
        let (len, sel) = match self.focus {
            HostlistFocus::AutoHostlist => (self.filtered_auto(config).len(), &mut self.auto_sel),
            HostlistFocus::Blacklist => (self.filtered_blacklist(config).len(), &mut self.blacklist_sel),
        };
        if len == 0 {
            *sel = 0;
            return;
        }
        *sel = (*sel as isize + delta).clamp(0, (len - 1) as isize) as usize;
    }
}

/// Filters `entries` case-insensitively when `query` is non-empty.
fn filter_domain_slice<'a>(entries: &'a [String], query: &str) -> Vec<&'a str> {
    let needle = query.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return entries.iter().map(String::as_str).collect();
    }
    entries
        .iter()
        .filter(|item| item.to_ascii_lowercase().contains(&needle))
        .map(String::as_str)
        .collect()
}

impl AppState {
    /// Handles `/` search input, cursor navigation, add prompts, direct delete, and exclude transfers on Tab 6.
    pub(crate) fn handle_hostlist_key(&mut self, code: KeyCode) -> AppAction {
        if self.hostlist.filter_editing {
            match code {
                KeyCode::Esc => {
                    self.hostlist.filter_editing = false;
                    self.hostlist.filter.clear();
                    self.hostlist.clamp_selection(&self.config);
                }
                KeyCode::Enter => self.hostlist.filter_editing = false,
                KeyCode::Backspace => {
                    self.hostlist.filter.pop();
                    self.hostlist.clamp_selection(&self.config);
                }
                KeyCode::Char(c) if !c.is_control() => {
                    self.hostlist.filter.push(c);
                    self.hostlist.clamp_selection(&self.config);
                }
                _ => {}
            }
            return AppAction::None;
        }

        match code {
            KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l') => {
                self.hostlist.toggle_focus();
            }
            KeyCode::Up | KeyCode::Char('k') => self.hostlist.move_selection(&self.config, -1),
            KeyCode::Down | KeyCode::Char('j') => self.hostlist.move_selection(&self.config, 1),
            KeyCode::PageUp => self.hostlist.move_selection(&self.config, -10),
            KeyCode::PageDown => self.hostlist.move_selection(&self.config, 10),
            KeyCode::Home => self.hostlist.move_selection(&self.config, isize::MIN / 2),
            KeyCode::End => self.hostlist.move_selection(&self.config, isize::MAX / 2),
            KeyCode::Char('/') => self.hostlist.filter_editing = true,
            KeyCode::Esc if !self.hostlist.filter.is_empty() => {
                self.hostlist.filter.clear();
                self.hostlist.clamp_selection(&self.config);
            }
            KeyCode::Char('a') => {
                if self.config.autohostlist_paths.is_empty() {
                    self.status_banner = "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first).".to_owned();
                } else {
                    self.prompt_modal = Some(PromptModal::open(PromptKind::AddAutoHostlist));
                }
            }
            KeyCode::Char('b') => {
                if self.config.parsed_profiles.is_empty() {
                    self.status_banner = "No [[profiles]] in nfqws2.toml yet; scan or load a config first.".to_owned();
                } else {
                    self.prompt_modal = Some(PromptModal::open(PromptKind::BlacklistDomain));
                }
            }
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace => {
                if self.hostlist.selected_domain(&self.config).is_some() {
                    return AppAction::DeleteSelectedDomain;
                }
                self.status_banner = "No domain selected to remove.".to_owned();
            }
            KeyCode::Char('x' | 'm') => {
                if self.hostlist.focus == HostlistFocus::AutoHostlist
                    && self.hostlist.selected_domain(&self.config).is_some()
                {
                    return AppAction::MoveAutoToBlacklist;
                }
            }
            KeyCode::Char('r') => return AppAction::ReloadLists,
            _ => {}
        }
        AppAction::None
    }
}

/// Offline wrapper deleting the highlighted domain in Tab 6 without a daemon session (used by tests).
pub fn delete_selected_hostlist_offline(state: &mut AppState) {
    delete_selected_hostlist_domain(state, &None);
}

/// Offline wrapper moving the highlighted Auto Hostlist domain to Blacklist without a daemon session.
pub fn move_selected_auto_to_blacklist_offline(state: &mut AppState) {
    move_selected_auto_to_blacklist(state, &None);
}

/// Deletes the currently highlighted domain in Tab 6 directly without prompting the user to retype it.
pub(crate) fn delete_selected_hostlist_domain(state: &mut AppState, tab2_session: &Option<Tab2Session>) {
    let Some(domain) = state.hostlist.selected_domain(&state.config) else {
        state.status_banner = "No domain selected to remove.".to_owned();
        return;
    };
    match state.hostlist.focus {
        HostlistFocus::AutoHostlist => {
            if let Err(err) = remove_domain_from_autolists(state, &domain) {
                state.status_banner = err;
                return;
            }
            notify_daemon_lists(state, tab2_session, &format!("Removed {domain} from Auto Hostlist"));
        }
        HostlistFocus::Blacklist => {
            let cfg_path = expand_tilde(&state.finder.output_path);
            match mutate_exclude_domains_toml(&state.config.active_toml, &domain, false, cfg_path.parent())
                .and_then(|updated| {
                    commit_updated_toml(state, tab2_session, updated, &format!("Removed {domain} from Blacklist"))
                }) {
                Ok(()) => {}
                Err(err) => state.status_banner = err,
            }
        }
    }
}

/// Moves the selected Auto Hostlist domain into Blacklist (`hostlist_exclude_domains`) in one action.
pub(crate) fn move_selected_auto_to_blacklist(state: &mut AppState, tab2_session: &Option<Tab2Session>) {
    let Some(domain) = (state.hostlist.focus == HostlistFocus::AutoHostlist)
        .then(|| state.hostlist.selected_domain(&state.config))
        .flatten()
    else {
        return;
    };
    if let Err(err) = remove_domain_from_autolists(state, &domain) {
        state.status_banner = err;
        return;
    }
    let cfg_path = expand_tilde(&state.finder.output_path);
    match mutate_exclude_domains_toml(&state.config.active_toml, &domain, true, cfg_path.parent())
        .and_then(|updated| {
            commit_updated_toml(
                state,
                tab2_session,
                updated,
                &format!("Moved {domain} to Blacklist"),
            )
        }) {
        Ok(()) => {}
        Err(err) => state.status_banner = err,
    }
}

/// Refreshes disk hostlists and sends `ReloadLists` when attached to a live daemon.
pub(crate) fn reload_hostlist_entries(state: &mut AppState, tab2_session: &Option<Tab2Session>) {
    state.refresh_autohostlist();
    notify_daemon_lists(state, tab2_session, "Reloaded Auto Hostlist & Blacklist");
}

/// Removes `domain` from every configured `autohostlist` file and refreshes UI state.
fn remove_domain_from_autolists(state: &mut AppState, domain: &str) -> Result<(), String> {
    let mut removed = false;
    for path in state.config.autohostlist_paths.clone() {
        let prev = state.config.autohostlist_entries.len();
        let after = mutate_hostlist_file(&path, domain, false)?;
        if after.len() < prev {
            removed = true;
        }
    }
    state.refresh_autohostlist();
    if removed {
        Ok(())
    } else {
        Err(format!("{domain} not found in Auto Hostlist"))
    }
}

/// Notifies an attached daemon to reload lists from disk and updates the footer banner.
fn notify_daemon_lists(state: &mut AppState, tab2_session: &Option<Tab2Session>, label: &str) {
    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref()
        && remote.send_command(&Request::ReloadLists).is_ok()
    {
        state.status_banner = format!("{label} & reloaded daemon");
    } else {
        state.status_banner = label.to_owned();
    }
}

/// Handles Tab 6 clicks (switching focused list and selecting rows) and mouse-wheel cursor scrolling.
pub(crate) fn handle_hostlist_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(body);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(rows[1]);

    if cols[0].contains(pos) {
        state.hostlist.focus = HostlistFocus::AutoHostlist;
        if let Some(dir) = scroll_dir {
            state.hostlist.move_selection(&state.config, dir);
        } else if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom() {
            let cap = usize::from(cols[0].height.saturating_sub(2)).max(1);
            let len = state.hostlist.filtered_auto(&state.config).len();
            let (start, end) = visible_list_window(len, state.hostlist.auto_sel, cap);
            let idx = start + usize::from(pos.y - cols[0].y - 1);
            if idx < end {
                state.hostlist.auto_sel = idx;
            }
        }
    } else if cols[1].contains(pos) {
        state.hostlist.focus = HostlistFocus::Blacklist;
        if let Some(dir) = scroll_dir {
            state.hostlist.move_selection(&state.config, dir);
        } else if is_left && pos.y > cols[1].y && pos.y + 1 < cols[1].bottom() {
            let cap = usize::from(cols[1].height.saturating_sub(2)).max(1);
            let len = state.hostlist.filtered_blacklist(&state.config).len();
            let (start, end) = visible_list_window(len, state.hostlist.blacklist_sel, cap);
            let idx = start + usize::from(pos.y - cols[1].y - 1);
            if idx < end {
                state.hostlist.blacklist_sel = idx;
            }
        }
    }
}
