//! Mouse click and scroll wheel hit-testing aligned to the `ratatui` panel layouts.

/// Mouse event primitives from `crossterm`.
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
/// Exact same `Layout` engine used by renderers so click targets stay synchronized with visuals.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Tab 6 interactive Auto Hostlist / Blacklist row click and scroll handler.
use crate::tui::hostlist_tab::handle_hostlist_mouse;
/// Per-tab mouse click and wheel scroll handlers for Tabs 1 through 4.
use crate::tui::mouse_tabs::{
    handle_config_mouse, handle_finder_mouse, handle_run_mouse, handle_speed_mouse,
};
/// Tab 7 interactive Settings (`config.toml`) row click and scroll handler.
use crate::tui::settings_actions::handle_settings_mouse;
/// Application state mutated on click or wheel scroll.
use crate::tui::state::AppState;
/// Navigation and action enums reused by top-level mouse hit-testing.
use crate::tui::types::{ActiveTab, AppAction, step_selection};

/// Maps a left click or wheel scroll event at `(mouse.column, mouse.row)` onto `state`.
///
/// Overlays (`modal`, `help_open`, and packet `detail_open`) are respected so background widgets
/// cannot accidentally activate while a modal is visible.
pub fn handle_mouse_event(state: &mut AppState, mouse: MouseEvent, area: Rect) -> AppAction
{
    if state
        .modal
        .is_some()
        || state
            .prompt_modal
            .is_some()
        || area.width == 0
        || area.height == 0
    {
        return AppAction::None;
    }
    let pos = Position::new(mouse.column, mouse.row);
    let is_left = matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left));
    let scroll_dir = match mouse.kind
    {
        MouseEventKind::ScrollUp => Some(-1isize),
        MouseEventKind::ScrollDown => Some(1isize),
        _ => None,
    };
    if !is_left && scroll_dir.is_none()
    {
        return AppAction::None;
    }

    if state.help_open
    {
        if is_left
        {
            state.help_open = false;
            state.reset_finder_hover();
        }
        return AppAction::None;
    }
    if state.tab == ActiveTab::Run
        && state
            .inspector
            .detail_open
    {
        if is_left
        {
            state
                .inspector
                .detail_open = false;
            state.status_banner = "Closed packet detail.".to_owned();
        }
        return AppAction::None;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    if is_left && chunks[0].contains(pos)
    {
        handle_header_click(state, mouse.column, chunks[0]);
        return AppAction::None;
    }
    if is_left && chunks[2].contains(pos)
    {
        return handle_footer_click(state, mouse.column, chunks[2]);
    }
    if !chunks[1].contains(pos)
    {
        return AppAction::None;
    }
    match state.tab
    {
        ActiveTab::Finder => handle_finder_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Run => return handle_run_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Config => handle_config_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Speed => handle_speed_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Status => handle_status_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Hostlist => handle_hostlist_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Settings => handle_settings_mouse(state, pos, is_left, scroll_dir, chunks[1]),
    }
    AppAction::None
}

/// Selects rows by click or scroll wheel inside Tab 5's Component Status table.
fn handle_status_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
)
{
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(5)])
        .split(body);
    if !rows[0].contains(pos)
        || state
            .status
            .checks
            .is_empty()
    {
        return;
    }
    if let Some(dir) = scroll_dir
    {
        state
            .status
            .selected = step_selection(
            state
                .status
                .selected,
            state
                .status
                .checks
                .len(),
            dir,
        );
    }
    else if is_left && pos.y >= rows[0].y + 2 && pos.y + 1 < rows[0].bottom()
    {
        let idx = usize::from(pos.y - (rows[0].y + 2));
        if idx
            < state
                .status
                .checks
                .len()
        {
            state
                .status
                .selected = idx;
        }
    }
}

/// Switches tabs when clicking inside the top-left `Tabs` bar.
fn handle_header_click(state: &mut AppState, col: u16, header_area: Rect)
{
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),
            Constraint::Length(ActiveTab::header_status_width(header_area.width)),
        ])
        .split(header_area);
    let tabs_box = cols[0];
    if col <= tabs_box.x || col + 1 >= tabs_box.right()
    {
        return;
    }
    let compact = ActiveTab::use_compact_labels(tabs_box.width);
    let mut x = tabs_box.x + 1;
    for spec in &ActiveTab::SPECS
    {
        let width = spec.hit_width(compact);
        if col >= x && col < x + width
        {
            state.tab = spec.tab;
            if spec.tab == ActiveTab::Status
            {
                state.refresh_status_checks();
            }
            else if spec.tab == ActiveTab::Hostlist
            {
                state.refresh_autohostlist();
            }
            state
                .finder
                .editing_text = false;
            state.reset_finder_hover();
            return;
        }
        x = x.saturating_add(width + 1);
    }
}

/// Matches a click within a substring region of `haystack` starting at `base_offset`.
pub(super) fn hit_substring(rel: usize, base: usize, haystack: &str, needle: &str) -> bool
{
    haystack
        .find(needle)
        .is_some_and(|idx| rel >= base + idx && rel < base + idx + needle.len())
}

/// Handles clicks on `[?] Keys` and active Web UI link/copy chips in the footer.
fn handle_footer_click(state: &mut AppState, col: u16, footer_area: Rect) -> AppAction
{
    let rel = usize::from(col.saturating_sub(footer_area.x));
    let g = &state
        .keybinds
        .global;
    let help_chip = format!(
        "[{}] Keys",
        g.help
            .primary_label()
    );
    let help_start = 1usize;
    let help_end = help_start + help_chip.len();
    if (help_start..help_end).contains(&rel)
    {
        state.help_open = true;
        state.dismiss_finder_hover();
        return AppAction::None;
    }
    let banner_start = help_end + 5;
    if state
        .web_status
        .is_some()
        && state
            .status_banner
            .starts_with("Web UI:")
        && rel >= banner_start
    {
        let stop_chip = format!(
            "[{}] Stop",
            g.web_ui
                .primary_label()
        );
        let open_chip = format!(
            "[{}] Open",
            g.open_web_ui
                .primary_label()
        );
        if hit_substring(rel, banner_start, &state.status_banner, &stop_chip)
        {
            return AppAction::StopWebUi;
        }
        if let Some((url, _)) = &state.web_status
            && (hit_substring(rel, banner_start, &state.status_banner, url)
                || hit_substring(rel, banner_start, &state.status_banner, &open_chip))
        {
            return AppAction::OpenWebUi;
        }
        return AppAction::CopyWebPasscode;
    }
    AppAction::None
}

/// Applies `steps` vertical wheel steps to a top-anchored scroll offset.
pub(super) fn scroll_pane_n(scroll: &mut u16, dir: isize, steps: u16)
{
    *scroll = if dir < 0 { scroll.saturating_sub(steps) } else { scroll.saturating_add(steps) };
}

/// Applies `steps` vertical wheel steps to a bottom-anchored log scroll offset (`0` = live tail).
pub(super) fn scroll_log_n(scroll: &mut u16, len: usize, dir: isize, steps: u16)
{
    let cap = u16::try_from(len.saturating_sub(1)).unwrap_or(u16::MAX);
    *scroll = if dir < 0
    {
        scroll
            .saturating_add(steps)
            .min(cap)
    }
    else
    {
        scroll.saturating_sub(steps)
    };
}
