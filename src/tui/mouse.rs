//! Mouse click and scroll wheel hit-testing aligned to the `ratatui` panel layouts.

/// Mouse event primitives from `crossterm`.
use crossterm::event::{KeyCode, MouseButton, MouseEvent, MouseEventKind};
/// Exact same `Layout` engine used by renderers so click targets stay synchronized with visuals.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Shared Tab 2 controller card height matching the renderer for accurate hit-testing.
use crate::tui::render::run_controller_height;
/// Application state mutated on click or wheel scroll.
use crate::tui::state::AppState;
/// Navigation, action, focus, and scroll helpers reused by mouse handlers.
use crate::tui::types::{
    ActiveTab, AppAction, ConfigFocus, FinderField, FinderFocus, RunFocus, adjust_log_scroll,
    adjust_pane_scroll,
};

/// Maps a left click or wheel scroll event at `(mouse.column, mouse.row)` onto `state`.
///
/// Overlays (`modal`, `help_open`, and packet `detail_open`) are respected so background widgets
/// cannot accidentally activate while a modal is visible.
pub fn handle_mouse_event(state: &mut AppState, mouse: MouseEvent, area: Rect) -> AppAction {
    if state.modal.is_some() || state.prompt_modal.is_some() || area.width == 0 || area.height == 0 {
        return AppAction::None;
    }
    let pos = Position::new(mouse.column, mouse.row);
    let is_left = matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left));
    let scroll_dir = match mouse.kind {
        MouseEventKind::ScrollUp => Some(-1isize),
        MouseEventKind::ScrollDown => Some(1isize),
        _ => None,
    };
    if !is_left && scroll_dir.is_none() {
        return AppAction::None;
    }

    if state.help_open {
        if is_left {
            state.help_open = false;
            state.reset_finder_hover();
        }
        return AppAction::None;
    }
    if state.tab == ActiveTab::Run && state.inspector.detail_open {
        if is_left {
            state.inspector.detail_open = false;
            state.status_banner = "Closed packet detail.".to_owned();
        }
        return AppAction::None;
    }

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
        .split(area);

    if is_left && chunks[0].contains(pos) {
        handle_header_click(state, mouse.column, chunks[0]);
        return AppAction::None;
    }
    if is_left && chunks[2].contains(pos) {
        return handle_footer_click(state, mouse.column, chunks[2]);
    }
    if !chunks[1].contains(pos) {
        return AppAction::None;
    }
    match state.tab {
        ActiveTab::Finder => handle_finder_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Run => return handle_run_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Config => handle_config_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Speed => handle_speed_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Status => {
            if let Some(dir) = scroll_dir && !state.status_checks.is_empty() {
                let next = state.status_selected as isize + dir;
                state.status_selected = next.clamp(0, state.status_checks.len() as isize - 1) as usize;
            }
        }
    }
    AppAction::None
}

/// Switches tabs when clicking inside the top-left `Tabs` bar.
fn handle_header_click(state: &mut AppState, col: u16, header_area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Min(40),
            Constraint::Length(if header_area.width < 100 { 30 } else { 36 }),
        ])
        .split(header_area);
    let tabs_box = cols[0];
    if col <= tabs_box.x || col + 1 >= tabs_box.right() {
        return;
    }
    let compact = ActiveTab::use_compact_labels(tabs_box.width);
    let mut x = tabs_box.x + 1;
    for spec in &ActiveTab::SPECS {
        let width = spec.hit_width(compact);
        if col >= x && col < x + width {
            state.tab = spec.tab;
            if spec.tab == ActiveTab::Status {
                state.refresh_status_checks();
            }
            state.editing_text = false;
            state.reset_finder_hover();
            return;
        }
        x = x.saturating_add(width + 3);
    }
}

/// Matches a click within a substring region of `haystack` starting at `base_offset`.
fn hit_substring(rel: usize, base: usize, haystack: &str, needle: &str) -> bool {
    haystack
        .find(needle)
        .is_some_and(|idx| rel >= base + idx && rel < base + idx + needle.len())
}

/// Handles clicks on `[?] Keys`, `[t] <theme>`, and active Web UI link/copy chips in the footer.
fn handle_footer_click(state: &mut AppState, col: u16, footer_area: Rect) -> AppAction {
    let rel = usize::from(col.saturating_sub(footer_area.x));
    if (1..=8).contains(&rel) {
        state.help_open = true;
        state.dismiss_finder_hover();
        return AppAction::None;
    }
    let theme_end = 15 + state.theme.name.len();
    if (11..=theme_end).contains(&rel) {
        state.theme = state.theme.next_preset();
        state.status_banner = format!("Theme: {} (press 'T' to save theme.toml)", state.theme.name);
        return AppAction::None;
    }
    let banner_start = theme_end + 5;
    if state.web_status.is_some()
        && state.status_banner.starts_with("Web UI:")
        && rel >= banner_start
    {
        if hit_substring(rel, banner_start, &state.status_banner, "[W] Stop") {
            return AppAction::StopWebUi;
        }
        if let Some((url, _)) = &state.web_status
            && (hit_substring(rel, banner_start, &state.status_banner, url)
                || hit_substring(rel, banner_start, &state.status_banner, "[o] Open"))
        {
            return AppAction::OpenWebUi;
        }
        return AppAction::CopyWebPasscode;
    }
    AppAction::None
}

/// Maps `ScrollUp`/`ScrollDown` into `n` repeated `Up`/`Down` key equivalents on a scroll offset.
fn scroll_pane_n(scroll: &mut u16, dir: isize, steps: usize) {
    let key = if dir < 0 { KeyCode::Up } else { KeyCode::Down };
    for _ in 0..steps {
        adjust_pane_scroll(scroll, key);
    }
}

/// Maps `ScrollUp`/`ScrollDown` into `n` repeated `Up`/`Down` steps on a bottom-anchored log.
fn scroll_log_n(scroll: &mut u16, len: usize, dir: isize, steps: usize) {
    let key = if dir < 0 { KeyCode::Up } else { KeyCode::Down };
    for _ in 0..steps {
        adjust_log_scroll(scroll, len, key);
    }
}

/// Handles left clicks and wheel scrolling across Tab 1 (`Setup`, `Results`, and `Live Scan Log`).
fn handle_finder_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(body);

    if cols[0].contains(pos) {
        state.focus.finder = FinderFocus::Setup;
        if let Some(dir) = scroll_dir {
            let key = if dir < 0 { KeyCode::Up } else { KeyCode::Down };
            state.editing_text = false;
            state.handle_finder_key(key);
            return;
        }
        if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom() {
            let row = usize::from(pos.y - (cols[0].y + 1));
            if let Some(&field) = FinderField::ALL.get(row) {
                let already_focused = state.focus_idx == row;
                state.focus_idx = row;
                state.text_scroll = 0;
                if field.is_text() {
                    if already_focused {
                        state.handle_finder_key(KeyCode::Enter);
                    } else {
                        state.editing_text = false;
                        state.reset_finder_hover();
                    }
                } else {
                    state.editing_text = false;
                    state.handle_finder_key(KeyCode::Enter);
                }
            }
        }
        return;
    }

    state.editing_text = false;
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Percentage(52), Constraint::Min(5)])
        .split(cols[1]);

    if right[1].contains(pos) {
        state.focus.finder = FinderFocus::Results;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir {
            let last = state.targets.len().saturating_sub(1);
            let sel = &mut state.focus.finder_results_sel;
            *sel = if dir < 0 { sel.saturating_sub(1) } else { (*sel + 1).min(last) };
        } else if is_left && !state.targets.is_empty() && pos.y >= right[1].y + 2 && pos.y + 1 < right[1].bottom() {
            let row = usize::from(pos.y - (right[1].y + 2));
            if row < state.targets.len() {
                state.focus.finder_results_sel = row;
            }
        }
    } else if right[2].contains(pos) {
        state.focus.finder = FinderFocus::Log;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir {
            scroll_log_n(&mut state.focus.finder_log_scroll, state.finder_logs.len(), dir, 3);
        }
    }
}

/// Handles Web UI clicks, packet selection, detail toggle, and log scrolling on Tab 2 (`Run nfqws2`).
fn handle_run_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
) -> AppAction {
    let ctrl_h = run_controller_height(state, body.width);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(ctrl_h),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(5),
        ])
        .split(body);

    if is_left
        && rows[0].contains(pos)
        && pos.y == rows[0].y + 5
        && let Some((url, _)) = &state.web_status
    {
        let rel = usize::from(pos.x.saturating_sub(rows[0].x + 1));
        let url_end = 16 + url.len();
        if rel >= 16 && rel < url_end {
            return AppAction::OpenWebUi;
        }
        if let Some((_, passcode)) = &state.web_status {
            let line = format!("Web UI        : {url}  passcode: {passcode}  [o] Open  [y] Copy  [W] Stop");
            if hit_substring(rel, 0, &line, "[o] Open") {
                return AppAction::OpenWebUi;
            }
            if hit_substring(rel, 0, &line, "[W] Stop") {
                return AppAction::StopWebUi;
            }
        }
        return AppAction::CopyWebPasscode;
    }

    if rows[2].contains(pos) {
        state.focus.run = RunFocus::Inspector;
        let visible_len = state.inspector.visible_packets().len();
        if let Some(dir) = scroll_dir {
            if dir < 0 {
                state.inspector.selected = state.inspector.selected.saturating_sub(3);
            } else if visible_len > 0 {
                state.inspector.selected = (state.inspector.selected + 3).min(visible_len - 1);
            }
            return AppAction::None;
        }
        if is_left && visible_len > 0 && pos.y >= rows[2].y + 2 && pos.y + 1 < rows[2].bottom() {
            let capacity = usize::from(rows[2].height.saturating_sub(3)).max(1);
            let clamped = state.inspector.selected.min(visible_len - 1);
            let start = if clamped >= capacity { clamped + 1 - capacity } else { 0 };
            let target = start + usize::from(pos.y - (rows[2].y + 2));
            if target < visible_len {
                if target == clamped {
                    state.inspector.detail_open = true;
                    state.status_banner = "Viewing packet detail (click or Esc to close).".to_owned();
                } else {
                    state.inspector.selected = target;
                }
            }
        }
    } else if rows[3].contains(pos) {
        state.focus.run = RunFocus::Log;
        if let Some(dir) = scroll_dir {
            scroll_log_n(&mut state.focus.run_log_scroll, state.run_logs.len(), dir, 3);
        }
    }
    AppAction::None
}

/// Focuses and scrolls `nfqws2.toml`, `nftables`, or `Auto Hostlist` panes on Tab 3.
fn handle_config_mouse(
    state: &mut AppState,
    pos: Position,
    _is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(body);
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[1]);

    if cols[0].contains(pos) {
        state.focus.config = ConfigFocus::Toml;
        if let Some(dir) = scroll_dir {
            scroll_pane_n(&mut state.toml_scroll, dir, 3);
        }
    } else if right[0].contains(pos) {
        state.focus.config = ConfigFocus::Nft;
        if let Some(dir) = scroll_dir {
            scroll_pane_n(&mut state.focus.nft_scroll, dir, 3);
        }
    } else if right[1].contains(pos) {
        state.focus.config = ConfigFocus::AutoHostlist;
        if let Some(dir) = scroll_dir {
            scroll_pane_n(&mut state.focus.autolist_scroll, dir, 3);
        }
    }
}

/// Selects rows by click or scroll wheel inside Tab 4's Speed Comparison table.
fn handle_speed_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6)])
        .split(body);
    if !rows[1].contains(pos) || state.speed.rows.is_empty() {
        return;
    }
    if let Some(dir) = scroll_dir {
        state.speed.move_selection(dir);
    } else if is_left && pos.y >= rows[1].y + 2 && pos.y + 1 < rows[1].bottom() {
        let idx = usize::from(pos.y - (rows[1].y + 2));
        if idx < state.speed.rows.len() {
            state.speed.selected = idx;
        }
    }
}
