//! Pure `ratatui` widget rendering for Tab 6 (interactive Auto Hostlist and Blacklist manager).

/// `ratatui` frame, layout, styling, text, and list primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
};

/// Tab 6 column focus and shared visible-window calculator aligned with mouse clicks.
use crate::tui::hostlist_tab::{HostlistFocus, visible_list_window};
/// Top-level TUI application state read while rendering Tab 6.
use crate::tui::state::AppState;
/// Shared bordered panel builder for Tab 6 cards.
use crate::tui::theme::panel_block;

/// Display parameters for rendering one selectable domain column inside Tab 6.
struct DomainColumnView<'a>
{
    /// Target sub-area inside the Tab 6 column split.
    area: Rect,
    /// Formatted header title including domain count and source file badge.
    title: &'a str,
    /// Filtered domain items displayed inside the column.
    items: &'a [&'a str],
    /// Currently highlighted item index within `items`.
    selected: usize,
    /// Whether this column holds keyboard focus on Tab 6.
    focused: bool,
    /// Placeholder message shown when `items` is empty.
    empty_msg: &'a str,
    /// Title highlight color matching Auto Hostlist or Blacklist status.
    accent: Color,
}

/// Builds the top search/status strip line for Tab 6 (keybinds live in `[?] Keys`).
fn build_hostlist_header<'a>(state: &AppState, auto_count: usize, black_count: usize) -> Line<'a>
{
    let t = &state.theme;
    if state.hostlist.filter_editing
    {
        return Line::from(vec![
            Span::styled(" Filter: ", Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{}_", state.hostlist.filter),
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   (Enter keeps filter, Esc clears)", Style::default().fg(t.muted)),
        ]);
    }
    if !state.hostlist.filter.is_empty()
    {
        return Line::from(vec![
            Span::styled(
                format!(" Filter: \"{}\"  ", state.hostlist.filter),
                Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("Auto: {auto_count}  Blacklist: {black_count}"),
                Style::default().fg(t.info),
            ),
        ]);
    }
    let focus_label =
        if state.hostlist.focus == HostlistFocus::AutoHostlist { "Auto Hostlist" } else { "Blacklist" };
    Line::from(vec![
        Span::styled(
            format!(" Auto Hostlist: {auto_count}   Blacklist: {black_count}   Focus: {focus_label}"),
            Style::default().fg(t.info),
        ),
        Span::styled("   (Filter: none)", Style::default().fg(t.muted)),
    ])
}

/// Renders Tab 6: top status/filter strip plus selectable Auto Hostlist and Blacklist columns.
pub(crate) fn draw_hostlist_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let auto_items = state.hostlist.filtered_auto(&state.config);
    let black_items = state.hostlist.filtered_blacklist(&state.config);
    let auto_on = !state.config.autohostlist_paths.is_empty();

    let header_line = build_hostlist_header(state, auto_items.len(), black_items.len());
    let bar = Paragraph::new(header_line).block(panel_block(
        if auto_on
        {
            " Auto Hostlist & Blacklist Manager "
        }
        else
        {
            " Auto Hostlist (off) & Blacklist Manager "
        },
        if state.hostlist.filter_editing { t.accent_bright } else { t.frame },
        t.info,
    ));
    frame.render_widget(bar, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(56), Constraint::Percentage(44)])
        .split(rows[1]);

    let auto_title = if auto_on
    {
        let name = state
            .config
            .autohostlist_paths
            .first()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("autohostlist.txt");
        format!(" Auto Hostlist ({}) [{name}] ", auto_items.len())
    }
    else
    {
        format!(" Auto Hostlist ({}, off) ", auto_items.len())
    };
    let auto_empty = if !auto_on
    {
        "Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist)"
    }
    else if state.config.autohostlist_entries.is_empty()
    {
        "No learned domains yet — press 'a' to add or wait for live failures"
    }
    else
    {
        "No Auto Hostlist entries match filter"
    };
    draw_domain_column(
        frame,
        &DomainColumnView {
            area: cols[0],
            title: &auto_title,
            items: &auto_items,
            selected: state.hostlist.auto_sel,
            focused: state.hostlist.focus == HostlistFocus::AutoHostlist,
            empty_msg: auto_empty,
            accent: t.ok_bright,
        },
        state,
    );

    let black_empty = if state.config.exclude_entries.is_empty()
    {
        format!(
            "No excluded domains - press '{}' to blacklist or '{}' on Auto Hostlist",
            state.keybinds.hostlist.add_blacklist.primary_label(),
            state.keybinds.hostlist.move_entry.joined_label()
        )
    }
    else
    {
        "No Blacklist entries match filter".to_owned()
    };
    draw_domain_column(
        frame,
        &DomainColumnView {
            area: cols[1],
            title: &format!(" Blacklist ({}) ", black_items.len()),
            items: &black_items,
            selected: state.hostlist.blacklist_sel,
            focused: state.hostlist.focus == HostlistFocus::Blacklist,
            empty_msg: &black_empty,
            accent: t.warn_bright,
        },
        state,
    );
}

/// Renders one selectable, cursor-highlighted domain column inside Tab 6.
fn draw_domain_column(frame: &mut Frame, view: &DomainColumnView<'_>, state: &AppState)
{
    let t = &state.theme;
    let border = if view.focused { t.accent_bright } else { t.frame };
    if view.items.is_empty()
    {
        let p = Paragraph::new(Line::from(Span::styled(
            format!("  {}", view.empty_msg),
            Style::default().fg(t.muted),
        )))
        .wrap(Wrap { trim: false })
        .block(panel_block(view.title, border, view.accent));
        frame.render_widget(p, view.area);
        return;
    }

    let capacity = usize::from(view.area.height.saturating_sub(2)).max(1);
    let (start, end) = visible_list_window(view.items.len(), view.selected, capacity);
    let rows: Vec<ListItem> = (start..end)
        .map(|idx| {
            let domain = view.items[idx];
            let is_sel = idx == view.selected;
            let prefix = if is_sel && view.focused
            {
                "> "
            }
            else if is_sel
            {
                "* "
            }
            else
            {
                "  "
            };
            let style = if is_sel && view.focused
            {
                Style::default().fg(Color::Black).bg(t.accent_bright).add_modifier(Modifier::BOLD)
            }
            else if is_sel
            {
                Style::default().fg(view.accent).add_modifier(Modifier::BOLD)
            }
            else
            {
                Style::default().fg(t.text)
            };
            ListItem::new(Line::from(Span::styled(format!("{prefix}{domain}"), style)))
        })
        .collect();
    let list = List::new(rows).block(panel_block(view.title, border, view.accent));
    frame.render_widget(list, view.area);
}
