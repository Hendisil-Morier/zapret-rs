//! Pure `ratatui` widget rendering for Tab 6 (interactive Auto Hostlist and Blacklist manager).

/// `ratatui` frame, layout, styling, text, and list primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph},
};

/// Tab 6 column focus and shared visible-window calculator aligned with mouse clicks.
use crate::tui::hostlist_tab::{HostlistFocus, visible_list_window};
/// Top-level TUI application state read while rendering Tab 6.
use crate::tui::state::AppState;
/// Shared bordered panel builder and keycap badge helper.
use crate::tui::theme::{panel_block, styled_key_hints};

/// Renders Tab 6: top status/filter strip plus selectable Auto Hostlist and Blacklist columns.
pub(crate) fn draw_hostlist_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let auto_items = state.hostlist.filtered_auto(&state.config);
    let black_items = state.hostlist.filtered_blacklist(&state.config);
    let auto_on = !state.config.autohostlist_paths.is_empty();

    let header_line = if state.hostlist.filter_editing {
        Line::from(vec![
            Span::styled(" Filter: ", Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{}_", state.hostlist.filter), Style::default().fg(t.text).add_modifier(Modifier::BOLD)),
            Span::styled("   [Enter] Keep  [Esc] Clear", Style::default().fg(t.muted)),
        ])
    } else if !state.hostlist.filter.is_empty() {
        Line::from(vec![
            Span::styled(
                format!(" Filter: \"{}\"  ", state.hostlist.filter),
                Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD),
            ),
            Span::styled("([/] Edit  [Esc] Clear)  ", Style::default().fg(t.muted)),
            Span::styled(
                format!("Auto: {}  Blacklist: {}", auto_items.len(), black_items.len()),
                Style::default().fg(t.info),
            ),
        ])
    } else {
        let mut spans = styled_key_hints(
            " [Up/Down] Select  [d/Del] Remove Sel  [x] Exclude Sel  [a] Add  [b] Blacklist  [/] Filter  [r] Reload",
            t,
        );
        if auto_on {
            let paths = state
                .config
                .autohostlist_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ");
            spans.push(Span::styled(format!("  | {paths}"), Style::default().fg(t.subtle)));
        }
        Line::from(spans)
    };
    let bar = Paragraph::new(header_line).block(panel_block(
        if auto_on { " Auto Hostlist & Blacklist Manager " } else { " Auto Hostlist (off) & Blacklist Manager " },
        if state.hostlist.filter_editing { t.accent_bright } else { t.frame },
        t.info,
    ));
    frame.render_widget(bar, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(rows[1]);

    draw_domain_column(
        frame,
        cols[0],
        &format!(
            " Auto Hostlist ({}{}) ",
            auto_items.len(),
            if auto_on { "" } else { ", off" }
        ),
        &auto_items,
        state.hostlist.auto_sel,
        state.hostlist.focus == HostlistFocus::AutoHostlist,
        if !auto_on {
            "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist)"
        } else if state.config.autohostlist_entries.is_empty() {
            "No learned domains yet — press 'a' to add or wait for live failures"
        } else {
            "No Auto Hostlist entries match filter"
        },
        t.ok_bright,
        state,
    );

    draw_domain_column(
        frame,
        cols[1],
        &format!(" Blacklist ({}) ", black_items.len()),
        &black_items,
        state.hostlist.blacklist_sel,
        state.hostlist.focus == HostlistFocus::Blacklist,
        if state.config.exclude_entries.is_empty() {
            "No excluded domains — press 'b' to blacklist or 'x' on Auto Hostlist"
        } else {
            "No Blacklist entries match filter"
        },
        t.warn_bright,
        state,
    );
}

/// Renders one selectable, cursor-highlighted domain column inside Tab 6.
#[allow(clippy::too_many_arguments)]
fn draw_domain_column(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    items: &[&str],
    selected: usize,
    focused: bool,
    empty_msg: &str,
    accent: Color,
    state: &AppState,
) {
    let t = &state.theme;
    let border = if focused { t.accent_bright } else { t.frame };
    if items.is_empty() {
        let p = Paragraph::new(Line::from(Span::styled(
            format!("  {empty_msg}"),
            Style::default().fg(t.muted),
        )))
        .block(panel_block(title, border, accent));
        frame.render_widget(p, area);
        return;
    }

    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    let (start, end) = visible_list_window(items.len(), selected, capacity);
    let rows: Vec<ListItem> = (start..end)
        .map(|idx| {
            let domain = items[idx];
            let is_sel = idx == selected;
            let prefix = if is_sel && focused {
                "> "
            } else if is_sel {
                "* "
            } else {
                "  "
            };
            let style = if is_sel && focused {
                Style::default()
                    .fg(Color::Black)
                    .bg(t.accent_bright)
                    .add_modifier(Modifier::BOLD)
            } else if is_sel {
                Style::default().fg(accent).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(t.text)
            };
            ListItem::new(Line::from(Span::styled(format!("{prefix}{domain}"), style)))
        })
        .collect();
    let list = List::new(rows).block(panel_block(title, border, accent));
    frame.render_widget(list, area);
}
