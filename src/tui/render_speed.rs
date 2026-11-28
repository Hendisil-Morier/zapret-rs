//! Pure `ratatui` widget rendering for Tab 4 (before/after `nfqws2` speed comparison).

/// `ratatui` frame, layout, styling, text, and table widgets.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table, Wrap},
};

/// Timed `curl` sample type rendered in before/after columns.
use crate::tools::SpeedSample;
/// Before/after sample formatting and row delta helpers.
use crate::tui::speed::{
    Change, SpeedPhase, build_targets, compare, describe_sample, effective_speed_domains,
};
/// Mutable application state inspected for Tab 1 domains and Tab 4 results.
use crate::tui::state::AppState;
/// Shared bordered panel builder and `[key]` hint badge helper.
use crate::tui::theme::{panel_block, styled_key_hints_owned};
/// Active configurable color palette.
use crate::tui::theme_config::Theme;

/// Maps an optional [`SpeedSample`] to styled display text and color.
fn sample_cell(sample: &Option<SpeedSample>, t: &Theme) -> (String, Color)
{
    match sample
    {
        None => ("-".to_owned(), t.muted),
        Some(s) if s.outcome.is_success() => (describe_sample(s), t.ok_bright),
        Some(s) => (describe_sample(s), t.err_bright),
    }
}

/// Maps a [`Change`] verdict into styled summary text and color.
fn change_cell(change: Change, t: &Theme) -> (String, Color)
{
    match change
    {
        Change::Pending => ("...".to_owned(), t.muted),
        Change::Fixed => ("FIXED (works with zapret)".to_owned(), t.ok_bright),
        Change::Broke => ("REGRESSION (failed with zapret)".to_owned(), t.err_bright),
        Change::StillBlocked => ("STILL BLOCKED".to_owned(), t.warn_bright),
        Change::Compared(summary) => (summary, t.accent_bright),
    }
}

/// Renders Tab 4: target summary bar and before/after comparison table inside the shared shell.
pub(crate) fn draw_speed_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(6)])
        .split(area);

    let phase = state.speed.phase;
    let badge_col = match phase
    {
        SpeedPhase::Idle => t.frame,
        SpeedPhase::Done => t.ok,
        _ => t.warn,
    };
    let eff_domains = effective_speed_domains(&state.finder.domains_input, &state.config.active_toml);
    let preview_targets = build_targets(&eff_domains);
    let source_hint = if state.finder.domains_input.trim().is_empty() && !eff_domains.trim().is_empty()
    {
        "Targets (from active config + control): "
    }
    else
    {
        "Targets (from Tab 1 + control): "
    };
    let target_list: String =
        preview_targets.iter().map(|tgt| tgt.label.as_str()).collect::<Vec<_>>().join(", ");
    let summary = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Phase: ", Style::default().fg(t.info)),
            Span::styled(phase.label(), Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
            Span::styled("   IP Family: ", Style::default().fg(t.info)),
            Span::styled(state.finder.ip_mode.label(), Style::default().fg(t.warn_bright)),
        ]),
        Line::from(vec![
            Span::styled(source_hint, Style::default().fg(t.subtle)),
            Span::styled(target_list, Style::default().fg(t.text)),
        ]),
    ])
    .wrap(Wrap { trim: true })
    .block(panel_block(" Before / After Speed Check ", badge_col, t.accent_bright));
    frame.render_widget(summary, rows[0]);

    if state.speed.rows.is_empty()
    {
        let empty = Paragraph::new(vec![
            Line::default(),
            Line::from(Span::styled("No speed measurements recorded yet.", Style::default().fg(t.subtle))),
            Line::from(styled_key_hints_owned(
                &format!(
                    "Press [{}] to measure with zapret OFF, restart the daemon, and measure with zapret ON.",
                    state.keybinds.speed.start.primary_label()
                ),
                t,
            )),
        ])
        .wrap(Wrap { trim: true })
        .block(panel_block(" Comparison Table ", t.frame, t.info));
        frame.render_widget(empty, rows[1]);
    }
    else
    {
        let header = Row::new(["Target", "Without zapret", "With zapret", "Delta"])
            .style(Style::default().fg(t.warn_bright).bg(t.highlight_bg).add_modifier(Modifier::BOLD));
        let table_rows: Vec<Row> = state
            .speed
            .rows
            .iter()
            .enumerate()
            .map(|(idx, row)| {
                let selected = idx == state.speed.selected;
                let (before_txt, before_col) = sample_cell(&row.before, t);
                let (after_txt, after_col) = sample_cell(&row.after, t);
                let (delta_txt, delta_col) = change_cell(compare(row), t);
                let row_style = if selected
                {
                    Style::default().bg(t.highlight_bg).add_modifier(Modifier::BOLD)
                }
                else
                {
                    Style::default()
                };
                Row::new([
                    Cell::from(row.label.as_str()).style(Style::default().fg(t.text)),
                    Cell::from(before_txt).style(Style::default().fg(before_col)),
                    Cell::from(after_txt).style(Style::default().fg(after_col)),
                    Cell::from(delta_txt).style(Style::default().fg(delta_col)),
                ])
                .style(row_style)
            })
            .collect();
        let widths = [
            Constraint::Percentage(24),
            Constraint::Percentage(27),
            Constraint::Percentage(27),
            Constraint::Percentage(22),
        ];
        let table = Table::new(table_rows, widths).header(header).block(panel_block(
            " Comparison Table ",
            t.accent_bright,
            t.info,
        ));
        frame.render_widget(table, rows[1]);
    }
}
