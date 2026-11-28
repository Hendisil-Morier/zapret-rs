//! Pure `ratatui` widget rendering for Tab 1 (Strategy Finder setup, progress, results, and log).

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Clear, Gauge, Paragraph, Row, Table, Wrap},
};

/// Tab 1 setup-form widget renderer.
use crate::tui::render_finder_form::draw_finder_form;
/// Shared log panel widget helper reused from the Tab 2 renderer.
use crate::tui::render_run::draw_log_list;
/// Application state read while rendering the Strategy Finder view.
use crate::tui::state::AppState;
/// Shared panel border helpers and `[key]` badge styling.
use crate::tui::theme::{panel_block, styled_key_hints_owned};
/// Strategy Finder panel focus state, scan lifecycle status, and window helper.
use crate::tui::types::{FinderFocus, FinderStatus, visible_window};

/// Renders Tab 1: left Setup form and right Progress / Results Table / Live Log stack.
pub(crate) fn draw_finder_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    draw_finder_form(frame, cols[0], state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Percentage(52), Constraint::Min(5)])
        .split(cols[1]);

    let ratio = if state
        .finder
        .progress_total
        > 0
    {
        (state
            .finder
            .progress_done as f64
            / state
                .finder
                .progress_total as f64)
            .clamp(0.0, 1.0)
    }
    else if state
        .finder
        .status
        == FinderStatus::Done
    {
        1.0
    }
    else
    {
        0.0
    };
    let (gauge_color, gauge_border) = match state
        .finder
        .status
    {
        FinderStatus::Error(_) => (t.err, t.err),
        FinderStatus::Done => (t.ok_bright, t.ok),
        FinderStatus::Scanning => (t.accent_bright, t.accent),
        FinderStatus::Idle => (t.accent, t.frame),
    };
    let gauge = Gauge::default()
        .block(panel_block(" Scan Progress ", gauge_border, t.info))
        .gauge_style(
            Style::default()
                .fg(gauge_color)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .ratio(ratio)
        .label(
            state
                .finder
                .progress_label
                .as_str(),
        );
    frame.render_widget(gauge, right[0]);

    draw_results_table(frame, right[1], state);
    draw_log_list(
        frame,
        right[2],
        " Live Scan Log ",
        &state
            .finder
            .logs,
        state
            .focus
            .finder_log_scroll,
        state
            .focus
            .finder
            == FinderFocus::Log,
        t,
    );
    if state
        .focus
        .finder
        == FinderFocus::Setup
        && state
            .finder
            .hover
            .open
        && state
            .modal
            .is_none()
        && !state.help_open
        && !state
            .finder
            .editing_text
    {
        draw_finder_tooltip(frame, area, cols[0], cols[1], state);
    }
}

/// Renders the per-domain results table on Tab 1 with scrollable row selection when focused.
fn draw_results_table(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let focused = state
        .focus
        .finder
        == FinderFocus::Results;
    let header = Row::new(["Domain", "Proto", "Baseline", "Hits", "Best Strategy", "RTT"]).style(
        Style::default()
            .fg(t.warn_bright)
            .bg(t.highlight_bg)
            .add_modifier(Modifier::BOLD),
    );

    let capacity = usize::from(
        area.height
            .saturating_sub(3),
    )
    .max(1);
    let clamped_sel = state
        .focus
        .finder_results_sel
        .min(
            state
                .finder
                .targets
                .len()
                .saturating_sub(1),
        );
    let (start, end) = visible_window(
        state
            .finder
            .targets
            .len(),
        clamped_sel,
        capacity,
    );

    let rows: Vec<Row> = state
        .finder
        .targets
        .iter()
        .enumerate()
        .take(end)
        .skip(start)
        .map(|(idx, res)| {
            let (best, rtt, col) = if res.skipped_unblocked
            {
                ("direct OK".to_owned(), "-".to_owned(), t.ok_bright)
            }
            else if let Some(m) = res
                .matches
                .first()
            {
                (
                    m.strategy
                        .id
                        .clone(),
                    format!("{}ms", m.latency_ms),
                    t.ok_bright,
                )
            }
            else
            {
                ("none".to_owned(), "-".to_owned(), t.err_bright)
            };
            let base_summary = res
                .baseline
                .summary();
            let base_col = if res.skipped_unblocked
            {
                t.ok
            }
            else if base_summary.contains("block")
                || base_summary.contains("reset")
                || base_summary.contains("timeout")
            {
                t.warn_bright
            }
            else
            {
                t.subtle
            };
            let selected = focused && idx == clamped_sel;
            let hits_col = if res
                .matches
                .is_empty()
            {
                if selected { t.subtle } else { t.muted }
            }
            else
            {
                t.ok_bright
            };
            let rtt_col = if rtt == "-" { if selected { t.subtle } else { t.muted } } else { t.warn_bright };
            let row = Row::new([
                Cell::from(
                    res.domain
                        .clone(),
                )
                .style(
                    Style::default()
                        .fg(t.text)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(format!("{}/{}", res.proto, res.ipv)).style(Style::default().fg(t.accent_bright)),
                Cell::from(base_summary).style(Style::default().fg(base_col)),
                Cell::from(
                    res.matches
                        .len()
                        .to_string(),
                )
                .style(
                    Style::default()
                        .fg(hits_col)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(best).style(
                    Style::default()
                        .fg(col)
                        .add_modifier(Modifier::BOLD),
                ),
                Cell::from(rtt).style(Style::default().fg(rtt_col)),
            ]);
            if selected { row.style(Style::default().bg(t.highlight_bg)) } else { row }
        })
        .collect();

    let widths = [
        Constraint::Percentage(22),
        Constraint::Length(11),
        Constraint::Percentage(20),
        Constraint::Length(5),
        Constraint::Percentage(30),
        Constraint::Length(7),
    ];
    let title = format!(
        " Results ({} targets, {} cover profiles) ",
        state
            .finder
            .targets
            .len(),
        state
            .finder
            .cover
            .len()
    );
    let (border, title_col) = if focused { (t.accent_bright, t.accent_bright) } else { (t.frame, t.info) };
    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(&title, border, title_col));
    frame.render_widget(table, area);
}

/// Counts how many wrapped lines `text` occupies when word-wrapped within `width` columns.
fn wrapped_line_count(text: &str, width: usize) -> u16
{
    let max_w = width.max(1);
    let mut lines = 1usize;
    let mut col = 0usize;
    for word in text.split_whitespace()
    {
        let len = word
            .chars()
            .count();
        if col == 0
        {
            col = len;
        }
        else if col + 1 + len <= max_w
        {
            col += 1 + len;
        }
        else
        {
            lines += 1;
            col = len;
        }
    }
    u16::try_from(lines).unwrap_or(u16::MAX)
}

/// Renders a floating explanation popup next to the focused [`FinderField`] after a 1s dwell.
fn draw_finder_tooltip(frame: &mut Frame, bounds: Rect, form_col: Rect, right_col: Rect, state: &AppState)
{
    let t = &state.theme;
    let (title, desc) = state
        .focused_field()
        .description();
    let avail_w = right_col
        .width
        .saturating_sub(2)
        .max(28.min(bounds.width));
    let w = 48u16
        .min(avail_w)
        .max(20.min(bounds.width));
    let body_lines = wrapped_line_count(desc, usize::from(w.saturating_sub(2)));
    let h = (body_lines + 4)
        .min(bounds.height)
        .max(5.min(bounds.height));
    let anchor_y = form_col.y
        + 1
        + state
            .finder
            .focus_idx as u16;
    let x = if right_col.width >= 24
    {
        right_col.x + 1
    }
    else
    {
        bounds.x
            + bounds
                .width
                .saturating_sub(w)
                / 2
    };
    let popup = Rect {
        x: x.min(
            bounds.x
                + bounds
                    .width
                    .saturating_sub(w),
        ),
        y: anchor_y.min(
            bounds.y
                + bounds
                    .height
                    .saturating_sub(h),
        ),
        width: w,
        height: h,
    };
    frame.render_widget(Clear, popup);

    let block = panel_block(format!(" ? {title} "), t.warn_bright, t.warn_bright);
    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);
    frame.render_widget(
        Paragraph::new(Span::styled(desc, Style::default().fg(t.text))).wrap(Wrap { trim: true }),
        sections[0],
    );
    let nav_hint = format!(
        "[{}/{}] next  [{}] hide",
        state
            .keybinds
            .nav
            .up
            .primary_label(),
        state
            .keybinds
            .nav
            .down
            .primary_label(),
        state
            .keybinds
            .finder
            .dismiss_hover
            .primary_label()
    );
    frame.render_widget(Paragraph::new(Line::from(styled_key_hints_owned(&nav_hint, t))), sections[1]);
}
