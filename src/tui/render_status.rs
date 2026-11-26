//! Pure `ratatui` widget rendering for Tab 5 (`Status`: operational component health checks).

/// `ratatui` frame, layout, styling, text, and table/detail widgets.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Paragraph, Row, Table, Wrap},
};

/// Shared horizontal scrolling window helper reused from Tab 1.
use crate::tui::render_finder::windowed_text;
/// Application state holding cached component checks and selected row index.
use crate::tui::state::AppState;
/// Three-state health enum rendered as colored `[OK]` / `[WARN]` / `[ERR]` badges.
use crate::tui::status_check::ComponentHealth;
/// Shared panel border builder and `[key]` hint styling.
use crate::tui::theme::{panel_block, styled_key_hints};

/// Builds one styled table row for a [`ComponentCheck`] item.
fn build_status_row<'a>(
    item: &'a crate::tui::status_check::ComponentCheck,
    selected: bool,
    hscroll: usize,
    summary_width: usize,
    t: &crate::tui::theme_config::Theme,
) -> Row<'a> {
    let (badge, badge_col) = match item.health {
        ComponentHealth::Ok => ("[OK]", t.ok_bright),
        ComponentHealth::Warn => ("[WARN]", t.warn_bright),
        ComponentHealth::Err => ("[ERR]", t.err_bright),
    };
    let row_style = if selected {
        Style::default().bg(t.highlight_bg).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let summary = windowed_text(item.summary.as_str(), None, hscroll, summary_width);
    Row::new(vec![
        Cell::from(Span::styled(item.name, Style::default().fg(t.accent_bright))),
        Cell::from(Span::styled(badge, Style::default().fg(badge_col).add_modifier(Modifier::BOLD))),
        Cell::from(Span::styled(summary, Style::default().fg(t.text))),
    ])
    .style(row_style)
}

/// Renders Tab 5: operational component table and selected-row remediation/detail panel.
pub fn draw_status_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(6)])
        .split(area);

    let summary_width = rows[0].width.saturating_sub(32) as usize;
    let table_rows: Vec<Row<'_>> = state
        .status_checks
        .iter()
        .enumerate()
        .map(|(idx, item)| {
            let selected = idx == state.status_selected;
            let hscroll = if selected { state.status_hscroll } else { 0 };
            build_status_row(item, selected, hscroll, summary_width, t)
        })
        .collect();

    let header = Row::new(["Component", "Status", "Summary"])
        .style(Style::default().fg(t.info).add_modifier(Modifier::BOLD));
    let table = Table::new(
        table_rows,
        [Constraint::Length(18), Constraint::Length(8), Constraint::Min(24)],
    )
    .header(header)
    .block(panel_block(
        " Operational Component Status ",
        t.accent_bright,
        t.info,
    ));
    frame.render_widget(table, rows[0]);

    let detail_lines = if let Some(sel) = state.status_checks.get(state.status_selected) {
        vec![
            Line::from(vec![
                Span::styled(
                    format!("{}: ", sel.name),
                    Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD),
                ),
                Span::styled(sel.detail.as_str(), Style::default().fg(t.text)),
            ]),
            Line::from(styled_key_hints(
                "[r] Refresh Checks   [Up/Down] Select   [Left/Right] Scroll Summary",
                t,
            )),
        ]
    } else {
        vec![Line::from(styled_key_hints(
            "Press [r] to run operational checks.",
            t,
        ))]
    };
    let detail = Paragraph::new(detail_lines)
        .wrap(Wrap { trim: true })
        .block(panel_block(" Component Details ", t.frame, t.info));
    frame.render_widget(detail, rows[1]);
}
