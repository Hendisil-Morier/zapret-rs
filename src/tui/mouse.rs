//! Mouse click and scroll wheel hit-testing aligned to the `ratatui` panel layouts.

/// Mouse event primitives from `crossterm`.
use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};
/// Exact same `Layout` engine used by renderers so click targets stay synchronized with visuals.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Tab 6 interactive Auto Hostlist / Blacklist row click and scroll handler.
use crate::tui::hostlist_tab::handle_hostlist_mouse;
/// Shared Tab 2 controller card height matching the renderer for accurate hit-testing.
use crate::tui::render::run_controller_height;
/// Tab 7 interactive Settings (`config.toml`) row click and scroll handler.
use crate::tui::settings_actions::handle_settings_mouse;
/// Application state mutated on click or wheel scroll.
use crate::tui::state::AppState;
/// Navigation, action, focus, selection, and window helpers reused by mouse handlers.
use crate::tui::types::{
    ActiveTab, AppAction, ConfigFocus, FinderField, FinderFocus, RunFocus, step_selection, visible_window,
};

/// Maps a left click or wheel scroll event at `(mouse.column, mouse.row)` onto `state`.
///
/// Overlays (`modal`, `help_open`, and packet `detail_open`) are respected so background widgets
/// cannot accidentally activate while a modal is visible.
pub fn handle_mouse_event(state: &mut AppState, mouse: MouseEvent, area: Rect) -> AppAction
{
    if state.modal.is_some() || state.prompt_modal.is_some() || area.width == 0 || area.height == 0
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
    if state.tab == ActiveTab::Run && state.inspector.detail_open
    {
        if is_left
        {
            state.inspector.detail_open = false;
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
        ActiveTab::Status =>
        {
            if let Some(dir) = scroll_dir
            {
                state.status.selected = step_selection(state.status.selected, state.status.checks.len(), dir);
            }
        }
        ActiveTab::Hostlist => handle_hostlist_mouse(state, pos, is_left, scroll_dir, chunks[1]),
        ActiveTab::Settings => handle_settings_mouse(state, pos, is_left, scroll_dir, chunks[1]),
    }
    AppAction::None
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
            state.finder.editing_text = false;
            state.reset_finder_hover();
            return;
        }
        x = x.saturating_add(width + 1);
    }
}

/// Matches a click within a substring region of `haystack` starting at `base_offset`.
fn hit_substring(rel: usize, base: usize, haystack: &str, needle: &str) -> bool
{
    haystack.find(needle).is_some_and(|idx| rel >= base + idx && rel < base + idx + needle.len())
}

/// Handles clicks on `[?] Keys`, `[t] <theme>`, and active Web UI link/copy chips in the footer.
fn handle_footer_click(state: &mut AppState, col: u16, footer_area: Rect) -> AppAction
{
    let rel = usize::from(col.saturating_sub(footer_area.x));
    let g = &state.keybinds.global;
    let help_chip = format!("[{}] Keys", g.help.primary_label());
    let theme_prefix = format!("[{}] ", g.cycle_theme.primary_label());
    let help_start = 1usize;
    let help_end = help_start + help_chip.len();
    if (help_start..help_end).contains(&rel)
    {
        state.help_open = true;
        state.dismiss_finder_hover();
        return AppAction::None;
    }
    let theme_start = help_end + 2;
    let theme_end = theme_start + theme_prefix.len() + state.theme.name.len();
    if (theme_start..theme_end).contains(&rel)
    {
        state.theme = state.theme.next_preset();
        state.settings.dirty = true;
        let settings_tab = g.tab_7.primary_label();
        let save_key = state.keybinds.settings.save.primary_label();
        state.status_banner = format!(
            "Theme preview: {} (Tab {settings_tab} Settings -> '{save_key}' to save)",
            state.theme.name
        );
        return AppAction::None;
    }
    let banner_start = theme_end + 5;
    if state.web_status.is_some() && state.status_banner.starts_with("Web UI:") && rel >= banner_start
    {
        let stop_chip = format!("[{}] Stop", g.web_ui.primary_label());
        let open_chip = format!("[{}] Open", g.open_web_ui.primary_label());
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
fn scroll_pane_n(scroll: &mut u16, dir: isize, steps: u16)
{
    *scroll = if dir < 0 { scroll.saturating_sub(steps) } else { scroll.saturating_add(steps) };
}

/// Applies `steps` vertical wheel steps to a bottom-anchored log scroll offset (`0` = live tail).
fn scroll_log_n(scroll: &mut u16, len: usize, dir: isize, steps: u16)
{
    let cap = u16::try_from(len.saturating_sub(1)).unwrap_or(u16::MAX);
    *scroll = if dir < 0 { scroll.saturating_add(steps).min(cap) } else { scroll.saturating_sub(steps) };
}

/// Handles left clicks and wheel scrolling across Tab 1 (`Setup`, `Results`, and `Live Scan Log`).
fn handle_finder_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
)
{
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(body);

    if cols[0].contains(pos)
    {
        state.focus.finder = FinderFocus::Setup;
        if let Some(dir) = scroll_dir
        {
            state.finder.editing_text = false;
            state.step_finder_setup_focus(dir > 0);
            return;
        }
        if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom()
        {
            let row = usize::from(pos.y - (cols[0].y + 1));
            if let Some(&field) = FinderField::ALL.get(row)
            {
                let already_focused = state.finder.focus_idx == row;
                state.finder.focus_idx = row;
                state.finder.text_scroll = 0;
                if field.is_text()
                {
                    if already_focused
                    {
                        state.activate_focused_finder_field();
                    }
                    else
                    {
                        state.finder.editing_text = false;
                        state.reset_finder_hover();
                    }
                }
                else
                {
                    state.finder.editing_text = false;
                    state.activate_focused_finder_field();
                }
            }
        }
        return;
    }

    state.finder.editing_text = false;
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Percentage(52), Constraint::Min(5)])
        .split(cols[1]);

    if right[1].contains(pos)
    {
        state.focus.finder = FinderFocus::Results;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir
        {
            state.focus.finder_results_sel =
                step_selection(state.focus.finder_results_sel, state.finder.targets.len(), dir);
        }
        else if is_left
            && !state.finder.targets.is_empty()
            && pos.y >= right[1].y + 2
            && pos.y + 1 < right[1].bottom()
        {
            let capacity = usize::from(right[1].height.saturating_sub(3)).max(1);
            let (start, end) =
                visible_window(state.finder.targets.len(), state.focus.finder_results_sel, capacity);
            let row = start + usize::from(pos.y - (right[1].y + 2));
            if row < end
            {
                state.focus.finder_results_sel = row;
            }
        }
    }
    else if right[2].contains(pos)
    {
        state.focus.finder = FinderFocus::Log;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir
        {
            scroll_log_n(&mut state.focus.finder_log_scroll, state.finder.logs.len(), dir, 3);
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
) -> AppAction
{
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
        if rel >= 16 && rel < url_end
        {
            return AppAction::OpenWebUi;
        }
        if let Some((_, passcode)) = &state.web_status
        {
            let g = &state.keybinds.global;
            let open_chip = format!("[{}] Open", g.open_web_ui.primary_label());
            let copy_chip = format!("[{}] Copy", g.copy_web_passcode.primary_label());
            let stop_chip = format!("[{}] Stop", g.web_ui.primary_label());
            let line =
                format!("Web UI        : {url}  passcode: {passcode}  {open_chip}  {copy_chip}  {stop_chip}");
            if hit_substring(rel, 0, &line, &open_chip)
            {
                return AppAction::OpenWebUi;
            }
            if hit_substring(rel, 0, &line, &stop_chip)
            {
                return AppAction::StopWebUi;
            }
        }
        return AppAction::CopyWebPasscode;
    }

    if rows[2].contains(pos)
    {
        state.focus.run = RunFocus::Inspector;
        let visible_len = state.inspector.visible_packets().len();
        if let Some(dir) = scroll_dir
        {
            state.inspector.selected = step_selection(state.inspector.selected, visible_len, dir * 3);
            return AppAction::None;
        }
        if is_left && visible_len > 0 && pos.y >= rows[2].y + 2 && pos.y + 1 < rows[2].bottom()
        {
            let capacity = usize::from(rows[2].height.saturating_sub(3)).max(1);
            let clamped = state.inspector.selected.min(visible_len - 1);
            let (start, end) = visible_window(visible_len, clamped, capacity);
            let target = start + usize::from(pos.y - (rows[2].y + 2));
            if target < end
            {
                if target == clamped
                {
                    state.inspector.detail_open = true;
                    state.status_banner = "Viewing packet detail (click or Esc to close).".to_owned();
                }
                else
                {
                    state.inspector.selected = target;
                }
            }
        }
    }
    else if rows[3].contains(pos)
    {
        state.focus.run = RunFocus::Log;
        if let Some(dir) = scroll_dir
        {
            scroll_log_n(&mut state.focus.run_log_scroll, state.run.logs.len(), dir, 3);
        }
    }
    AppAction::None
}

/// Focuses and scrolls `nfqws2.toml` or `nftables` panes on Tab 3.
fn handle_config_mouse(
    state: &mut AppState,
    pos: Position,
    _is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
)
{
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(body);

    if cols[0].contains(pos)
    {
        state.focus.config = ConfigFocus::Toml;
        if let Some(dir) = scroll_dir
        {
            scroll_pane_n(&mut state.config.toml_scroll, dir, 3);
        }
    }
    else if cols[1].contains(pos)
    {
        state.focus.config = ConfigFocus::Nft;
        if let Some(dir) = scroll_dir
        {
            scroll_pane_n(&mut state.focus.nft_scroll, dir, 3);
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
)
{
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6)])
        .split(body);
    if !rows[1].contains(pos) || state.speed.rows.is_empty()
    {
        return;
    }
    if let Some(dir) = scroll_dir
    {
        state.speed.move_selection(dir);
    }
    else if is_left && pos.y >= rows[1].y + 2 && pos.y + 1 < rows[1].bottom()
    {
        let idx = usize::from(pos.y - (rows[1].y + 2));
        if idx < state.speed.rows.len()
        {
            state.speed.selected = idx;
        }
    }
}
