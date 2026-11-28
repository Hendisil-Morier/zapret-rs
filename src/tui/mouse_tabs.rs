//! Per-tab mouse click and wheel handlers shared with the top-level TUI mouse router.

/// Exact `Layout` geometry and position types aligned with `ratatui` renderers.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Shared hit-testing and wheel-scrolling helpers from the top-level mouse module.
use crate::tui::mouse::{hit_substring, scroll_log_n, scroll_pane_n};
/// Shared Tab 2 controller card height matching the renderer for accurate hit-testing.
use crate::tui::render_run::run_controller_height;
/// Application state mutated on click or wheel scroll.
use crate::tui::state::AppState;
/// Navigation, action, focus, selection, and window helpers reused by mouse handlers.
use crate::tui::types::{
    AppAction, ConfigFocus, FinderField, FinderFocus, RunFocus, step_selection, visible_window,
};

/// Maps a table body click at `pos_y` through `visible_window` to update `*selected`.
fn click_windowed_row(pos_y: u16, rect: Rect, len: usize, selected: &mut usize)
{
    if len == 0 || pos_y < rect.y + 2 || pos_y + 1 >= rect.bottom()
    {
        return;
    }
    let capacity = usize::from(
        rect.height
            .saturating_sub(3),
    )
    .max(1);
    let (start, end) = visible_window(len, *selected, capacity);
    let idx = start + usize::from(pos_y - (rect.y + 2));
    if idx < end
    {
        *selected = idx;
    }
}

/// Handles left clicks and wheel scrolling across Tab 1 (`Setup`, `Results`, and `Live Scan Log`).
pub(super) fn handle_finder_mouse(
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
        state
            .focus
            .finder = FinderFocus::Setup;
        if let Some(dir) = scroll_dir
        {
            state
                .finder
                .editing_text = false;
            state.step_finder_setup_focus(dir > 0);
            return;
        }
        if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom()
        {
            let row = usize::from(pos.y - (cols[0].y + 1));
            if let Some(&field) = FinderField::ALL.get(row)
            {
                let already_focused = state
                    .finder
                    .focus_idx
                    == row;
                state
                    .finder
                    .focus_idx = row;
                state
                    .finder
                    .text_scroll = 0;
                if field.is_text()
                {
                    if already_focused
                    {
                        state.activate_focused_finder_field();
                    }
                    else
                    {
                        state
                            .finder
                            .editing_text = false;
                        state.reset_finder_hover();
                    }
                }
                else
                {
                    state
                        .finder
                        .editing_text = false;
                    state.activate_focused_finder_field();
                }
            }
        }
        return;
    }

    state
        .finder
        .editing_text = false;
    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Percentage(52), Constraint::Min(5)])
        .split(cols[1]);

    if right[1].contains(pos)
    {
        state
            .focus
            .finder = FinderFocus::Results;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir
        {
            state
                .focus
                .finder_results_sel = step_selection(
                state
                    .focus
                    .finder_results_sel,
                state
                    .finder
                    .targets
                    .len(),
                dir,
            );
        }
        else if is_left
        {
            let len = state
                .finder
                .targets
                .len();
            click_windowed_row(
                pos.y,
                right[1],
                len,
                &mut state
                    .focus
                    .finder_results_sel,
            );
        }
    }
    else if right[2].contains(pos)
    {
        state
            .focus
            .finder = FinderFocus::Log;
        state.reset_finder_hover();
        if let Some(dir) = scroll_dir
        {
            scroll_log_n(
                &mut state
                    .focus
                    .finder_log_scroll,
                state
                    .finder
                    .logs
                    .len(),
                dir,
                3,
            );
        }
    }
}

/// Handles Web UI clicks, packet selection, detail toggle, and log scrolling on Tab 2 (`Run nfqws2`).
pub(super) fn handle_run_mouse(
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
        let rel = usize::from(
            pos.x
                .saturating_sub(rows[0].x + 1),
        );
        let url_end = 16 + url.len();
        if rel >= 16 && rel < url_end
        {
            return AppAction::OpenWebUi;
        }
        if let Some((_, passcode)) = &state.web_status
        {
            let g = &state
                .keybinds
                .global;
            let open_chip = format!(
                "[{}] Open",
                g.open_web_ui
                    .primary_label()
            );
            let copy_chip = format!(
                "[{}] Copy",
                g.copy_web_passcode
                    .primary_label()
            );
            let stop_chip = format!(
                "[{}] Stop",
                g.web_ui
                    .primary_label()
            );
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
        state
            .focus
            .run = RunFocus::Inspector;
        let visible_len = state
            .inspector
            .visible_packets()
            .len();
        if let Some(dir) = scroll_dir
        {
            state
                .inspector
                .selected = step_selection(
                state
                    .inspector
                    .selected,
                visible_len,
                dir,
            );
            return AppAction::None;
        }
        if is_left && visible_len > 0 && pos.y >= rows[2].y + 2 && pos.y + 1 < rows[2].bottom()
        {
            let capacity = usize::from(
                rows[2]
                    .height
                    .saturating_sub(3),
            )
            .max(1);
            let clamped = state
                .inspector
                .selected
                .min(visible_len - 1);
            let (start, end) = visible_window(visible_len, clamped, capacity);
            let target = start + usize::from(pos.y - (rows[2].y + 2));
            if target < end
            {
                if target == clamped
                {
                    state
                        .inspector
                        .detail_open = true;
                    state.status_banner = "Viewing packet detail (click or Esc to close).".to_owned();
                }
                else
                {
                    state
                        .inspector
                        .selected = target;
                }
            }
        }
    }
    else if rows[3].contains(pos)
    {
        state
            .focus
            .run = RunFocus::Log;
        if let Some(dir) = scroll_dir
        {
            scroll_log_n(
                &mut state
                    .focus
                    .run_log_scroll,
                state
                    .run
                    .logs
                    .len(),
                dir,
                3,
            );
        }
    }
    AppAction::None
}

/// Focuses and scrolls `nfqws2.toml` or `nftables` panes on Tab 3.
pub(super) fn handle_config_mouse(
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
        state
            .focus
            .config = ConfigFocus::Toml;
        if let Some(dir) = scroll_dir
        {
            scroll_pane_n(
                &mut state
                    .config
                    .toml_scroll,
                dir,
                3,
            );
        }
    }
    else if cols[1].contains(pos)
    {
        state
            .focus
            .config = ConfigFocus::Nft;
        if let Some(dir) = scroll_dir
        {
            scroll_pane_n(
                &mut state
                    .focus
                    .nft_scroll,
                dir,
                3,
            );
        }
    }
}

/// Selects rows by click or scroll wheel inside Tab 4's Speed Comparison table.
pub(super) fn handle_speed_mouse(
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
    if !rows[1].contains(pos)
        || state
            .speed
            .rows
            .is_empty()
    {
        return;
    }
    if let Some(dir) = scroll_dir
    {
        state
            .speed
            .move_selection(dir);
    }
    else if is_left
    {
        let len = state
            .speed
            .rows
            .len();
        click_windowed_row(
            pos.y,
            rows[1],
            len,
            &mut state
                .speed
                .selected,
        );
    }
}
