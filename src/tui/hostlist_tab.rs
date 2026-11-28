//! Tab 6 (`Hostlist`) state, keyboard/mouse navigation, direct deletion, and exclude transfers.

/// Key events handled on Tab 6 for list selection, filtering, deletion, and moves.
use crossterm::event::KeyEvent;
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
/// Shared Tab 3 TOML/domain state and persistent config commit helper.
use crate::tui::tab_states::ConfigTabState;
/// Shared side-effect action, inline text editing, cursor stepping, and window slicing helpers.
use crate::tui::types::{
    AppAction, TextInputOutcome, handle_inline_text_key, step_selection, visible_window,
};
/// Shared TOML update/persist helper returning reload commands for `runner.rs`.
use crate::tui::web_actions::commit_updated_toml;

/// Focused list column on Tab 6 (`Auto Hostlist` vs `Blacklist`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HostlistFocus
{
    /// Left column listing learned/manual domains in `autohostlist.txt`.
    #[default]
    AutoHostlist,
    /// Right column listing permanently excluded domains (`hostlist_exclude_domains`).
    Blacklist,
}

/// Interactive state for Tab 6 (`Hostlist`): focused column, cursors, and live `/` filter.
#[derive(Debug, Clone, Default)]
pub struct HostlistTabState
{
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

impl HostlistTabState
{
    /// Toggles focus between the `Auto Hostlist` and `Blacklist` columns.
    pub fn toggle_focus(&mut self)
    {
        self.focus = match self.focus
        {
            HostlistFocus::AutoHostlist => HostlistFocus::Blacklist,
            HostlistFocus::Blacklist => HostlistFocus::AutoHostlist,
        };
    }

    /// Returns filtered Auto Hostlist domain slices matching `self.filter`.
    pub fn filtered_auto<'a>(&self, config: &'a ConfigTabState) -> Vec<&'a str>
    {
        filter_domain_slice(&config.autohostlist_entries, &self.filter)
    }

    /// Returns filtered Blacklist domain slices matching `self.filter`.
    pub fn filtered_blacklist<'a>(&self, config: &'a ConfigTabState) -> Vec<&'a str>
    {
        filter_domain_slice(&config.exclude_entries, &self.filter)
    }

    /// Returns the currently highlighted domain in the focused column, if any.
    pub fn selected_domain(&self, config: &ConfigTabState) -> Option<String>
    {
        match self.focus
        {
            HostlistFocus::AutoHostlist =>
            {
                let items = self.filtered_auto(config);
                items
                    .get(self.auto_sel)
                    .map(|s| (*s).to_owned())
            }
            HostlistFocus::Blacklist =>
            {
                let items = self.filtered_blacklist(config);
                items
                    .get(self.blacklist_sel)
                    .map(|s| (*s).to_owned())
            }
        }
    }

    /// Clamps both cursors cleanly within the current filtered list lengths.
    pub fn clamp_selection(&mut self, config: &ConfigTabState)
    {
        self.auto_sel = step_selection(
            self.auto_sel,
            self.filtered_auto(config)
                .len(),
            0,
        );
        self.blacklist_sel = step_selection(
            self.blacklist_sel,
            self.filtered_blacklist(config)
                .len(),
            0,
        );
    }

    /// Moves the active column's cursor by signed `delta`, clamped at list bounds.
    pub fn move_selection(&mut self, config: &ConfigTabState, delta: isize)
    {
        let (len, sel) = match self.focus
        {
            HostlistFocus::AutoHostlist => (
                self.filtered_auto(config)
                    .len(),
                &mut self.auto_sel,
            ),
            HostlistFocus::Blacklist => (
                self.filtered_blacklist(config)
                    .len(),
                &mut self.blacklist_sel,
            ),
        };
        *sel = step_selection(*sel, len, delta);
    }
}

/// Filters `entries` case-insensitively when `query` is non-empty.
fn filter_domain_slice<'a>(entries: &'a [String], query: &str) -> Vec<&'a str>
{
    let needle = query
        .trim()
        .to_ascii_lowercase();
    if needle.is_empty()
    {
        return entries
            .iter()
            .map(String::as_str)
            .collect();
    }
    entries
        .iter()
        .filter(|item| {
            item.to_ascii_lowercase()
                .contains(&needle)
        })
        .map(String::as_str)
        .collect()
}

impl AppState
{
    /// Applies key presses while the incremental `/` search input is focused on Tab 6.
    fn handle_hostlist_filter_key(&mut self, key: KeyEvent)
    {
        match handle_inline_text_key(
            &mut self
                .hostlist
                .filter,
            key,
        )
        {
            TextInputOutcome::Cancelled =>
            {
                self.hostlist
                    .filter_editing = false;
                self.hostlist
                    .clamp_selection(&self.config);
            }
            TextInputOutcome::Submitted =>
            {
                self.hostlist
                    .filter_editing = false
            }
            TextInputOutcome::Edited => self
                .hostlist
                .clamp_selection(&self.config),
            TextInputOutcome::Ignored =>
            {}
        }
    }

    /// Dispatches domain addition, removal, move, and reload shortcuts on Tab 6.
    fn handle_hostlist_action_key(&mut self, key: KeyEvent) -> AppAction
    {
        let hl = &self
            .keybinds
            .hostlist;
        if hl
            .filter
            .contains(key)
        {
            self.hostlist
                .filter_editing = true;
        }
        else if !self
            .hostlist
            .filter
            .is_empty()
            && hl
                .clear_filter
                .contains(key)
        {
            self.hostlist
                .filter
                .clear();
            self.hostlist
                .clamp_selection(&self.config);
        }
        else if hl
            .add_auto
            .contains(key)
        {
            if self
                .config
                .autohostlist_paths
                .is_empty()
            {
                self.status_banner =
                    "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first).".to_owned();
            }
            else
            {
                self.prompt_modal = Some(PromptModal::open(PromptKind::AddAutoHostlist));
            }
        }
        else if hl
            .add_blacklist
            .contains(key)
        {
            if self
                .config
                .parsed_profiles
                .is_empty()
            {
                self.status_banner =
                    "No [[profiles]] in nfqws2.toml yet; scan or load a config first.".to_owned();
            }
            else
            {
                self.prompt_modal = Some(PromptModal::open(PromptKind::BlacklistDomain));
            }
        }
        else if hl
            .delete
            .contains(key)
        {
            if self
                .hostlist
                .selected_domain(&self.config)
                .is_some()
            {
                return AppAction::DeleteSelectedDomain;
            }
            self.status_banner = "No domain selected to remove.".to_owned();
        }
        else if hl
            .move_entry
            .contains(key)
        {
            if self
                .hostlist
                .selected_domain(&self.config)
                .is_some()
            {
                if self
                    .hostlist
                    .focus
                    == HostlistFocus::Blacklist
                    && self
                        .config
                        .autohostlist_paths
                        .is_empty()
                {
                    self.status_banner =
                        "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first).".to_owned();
                }
                else
                {
                    return AppAction::MoveHostlistEntry;
                }
            }
        }
        else if hl
            .reload
            .contains(key)
        {
            return AppAction::ReloadLists;
        }
        AppAction::None
    }

    /// Handles `/` search input, cursor navigation, add prompts, direct delete, and exclude transfers on Tab 6.
    pub(crate) fn handle_hostlist_key(&mut self, key: KeyEvent) -> AppAction
    {
        if self
            .hostlist
            .filter_editing
        {
            self.handle_hostlist_filter_key(key);
            return AppAction::None;
        }

        let nav = &self
            .keybinds
            .nav;
        if nav
            .left
            .contains(key)
            || nav
                .right
                .contains(key)
        {
            self.hostlist
                .toggle_focus();
        }
        else if let Some(delta) = nav.vertical_delta(key, 10)
        {
            self.hostlist
                .move_selection(&self.config, delta);
        }
        else
        {
            return self.handle_hostlist_action_key(key);
        }
        AppAction::None
    }
}

/// Offline wrapper deleting the highlighted domain in Tab 6 without a daemon session (used by tests).
pub fn delete_selected_hostlist_offline(state: &mut AppState)
{
    let _ = delete_selected_hostlist_domain(state);
}

/// Offline wrapper moving the highlighted Tab 6 entry between Auto Hostlist and Blacklist without a daemon session.
pub fn move_selected_hostlist_offline(state: &mut AppState)
{
    let _ = move_selected_hostlist_entry(state);
}

/// Deletes the currently highlighted domain in Tab 6 and returns an optional daemon reload request.
pub(crate) fn delete_selected_hostlist_domain(state: &mut AppState) -> Option<Request>
{
    let Some(domain) = state
        .hostlist
        .selected_domain(&state.config)
    else
    {
        state.status_banner = "No domain selected to remove.".to_owned();
        return None;
    };
    match state
        .hostlist
        .focus
    {
        HostlistFocus::AutoHostlist =>
        {
            if let Err(err) = mutate_autolist_paths(state, &domain, false)
            {
                state.status_banner = err;
                return None;
            }
            state.status_banner = format!("Removed {domain} from Auto Hostlist");
            Some(Request::ReloadLists)
        }
        HostlistFocus::Blacklist =>
        {
            let cfg_path = expand_tilde(
                &state
                    .finder
                    .output_path,
            );
            match mutate_exclude_domains_toml(
                &state
                    .config
                    .active_toml,
                &domain,
                false,
                cfg_path.parent(),
            )
            .and_then(|updated| {
                commit_updated_toml(state, updated, &format!("Removed {domain} from Blacklist"))
            })
            {
                Ok(req) => Some(req),
                Err(err) =>
                {
                    state.status_banner = err;
                    None
                }
            }
        }
    }
}

/// Moves the selected Tab 6 entry between Auto Hostlist and Blacklist and returns a reload request.
pub(crate) fn move_selected_hostlist_entry(state: &mut AppState) -> Option<Request>
{
    let domain = state
        .hostlist
        .selected_domain(&state.config)?;
    let (add_exclude, label) = match state
        .hostlist
        .focus
    {
        HostlistFocus::AutoHostlist =>
        {
            if let Err(err) = mutate_autolist_paths(state, &domain, false)
            {
                state.status_banner = err;
                return None;
            }
            (true, format!("Moved {domain} to Blacklist"))
        }
        HostlistFocus::Blacklist =>
        {
            if state
                .config
                .autohostlist_paths
                .is_empty()
            {
                state.status_banner =
                    "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first).".to_owned();
                return None;
            }
            if let Err(err) = mutate_autolist_paths(state, &domain, true)
            {
                state.status_banner = err;
                return None;
            }
            (false, format!("Moved {domain} to Auto Hostlist"))
        }
    };
    let cfg_path = expand_tilde(
        &state
            .finder
            .output_path,
    );
    match mutate_exclude_domains_toml(
        &state
            .config
            .active_toml,
        &domain,
        add_exclude,
        cfg_path.parent(),
    )
    .and_then(|updated| commit_updated_toml(state, updated, &label))
    {
        Ok(req) => Some(req),
        Err(err) =>
        {
            state.status_banner = err;
            None
        }
    }
}

/// Refreshes disk hostlists and returns [`Request::ReloadLists`] for forwarding to an attached daemon.
pub(crate) fn reload_hostlist_entries(state: &mut AppState) -> Option<Request>
{
    state.refresh_autohostlist();
    state.status_banner = "Reloaded Auto Hostlist & Blacklist".to_owned();
    Some(Request::ReloadLists)
}

/// Adds or removes `domain` across every configured `autohostlist` file and refreshes UI state.
fn mutate_autolist_paths(state: &mut AppState, domain: &str, add: bool) -> Result<(), String>
{
    if state
        .config
        .autohostlist_paths
        .is_empty()
    {
        return Err("Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first)".to_owned());
    }
    let mut changed = false;
    for path in state
        .config
        .autohostlist_paths
        .clone()
    {
        let prev = state
            .config
            .autohostlist_entries
            .len();
        let after = mutate_hostlist_file(&path, domain, add)?;
        if add || after.len() < prev
        {
            changed = true;
        }
    }
    state.refresh_autohostlist();
    if changed { Ok(()) } else { Err(format!("{domain} not found in Auto Hostlist")) }
}

/// Handles Tab 6 clicks (switching focused list and selecting rows) and mouse-wheel cursor scrolling.
pub(crate) fn handle_hostlist_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
)
{
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(body);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(rows[1]);

    if cols[0].contains(pos)
    {
        state
            .hostlist
            .focus = HostlistFocus::AutoHostlist;
        if let Some(dir) = scroll_dir
        {
            state
                .hostlist
                .move_selection(&state.config, dir);
        }
        else if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom()
        {
            let cap = usize::from(
                cols[0]
                    .height
                    .saturating_sub(2),
            )
            .max(1);
            let len = state
                .hostlist
                .filtered_auto(&state.config)
                .len();
            let (start, end) = visible_window(
                len,
                state
                    .hostlist
                    .auto_sel,
                cap,
            );
            let idx = start + usize::from(pos.y - cols[0].y - 1);
            if idx < end
            {
                state
                    .hostlist
                    .auto_sel = idx;
            }
        }
    }
    else if cols[1].contains(pos)
    {
        state
            .hostlist
            .focus = HostlistFocus::Blacklist;
        if let Some(dir) = scroll_dir
        {
            state
                .hostlist
                .move_selection(&state.config, dir);
        }
        else if is_left && pos.y > cols[1].y && pos.y + 1 < cols[1].bottom()
        {
            let cap = usize::from(
                cols[1]
                    .height
                    .saturating_sub(2),
            )
            .max(1);
            let len = state
                .hostlist
                .filtered_blacklist(&state.config)
                .len();
            let (start, end) = visible_window(
                len,
                state
                    .hostlist
                    .blacklist_sel,
                cap,
            );
            let idx = start + usize::from(pos.y - cols[1].y - 1);
            if idx < end
            {
                state
                    .hostlist
                    .blacklist_sel = idx;
            }
        }
    }
}
