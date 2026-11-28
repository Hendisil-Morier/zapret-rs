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
/// Shared bordered panel builder and keycap badge helper.
use crate::tui::theme::{panel_block, styled_key_hints_owned};

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

    let header_line = if state.hostlist.filter_editing
    {
        Line::from(vec![
            Span::styled(" Filter: ", Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!("{}_", state.hostlist.filter),
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   [Enter] Keep  [Esc] Clear", Style::default().fg(t.muted)),
        ])
    }
    else if !state.hostlist.filter.is_empty()
    {
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
    }
    else
    {
        let hl = &state.keybinds.hostlist;
        let nav = &state.keybinds.nav;
        let move_lbl = hl.move_entry.joined_label();
        let dir_label =
            if state.hostlist.focus == HostlistFocus::AutoHostlist { "->Blacklist" } else { "->Auto" };
        let del_label = if hl.delete.joined_label() == "d/Del/Backspace"
        {
            "d/Del".to_owned()
        }
        else
        {
            hl.delete.joined_label()
        };
        let hint = format!(
            " [{}/{}] Select  [{del_label}] Remove  [{move_lbl}] {dir_label}  [{}] Add  [{}] Blacklist  [{}] Filter  [{}] Reload",
            nav.up.primary_label(),
            nav.down.primary_label(),
            hl.add_auto.primary_label(),
            hl.add_blacklist.primary_label(),
            hl.filter.primary_label(),
            hl.reload.primary_label(),
        );
        Line::from(styled_key_hints_owned(&hint, t))
    };
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
    draw_domain_column(
        frame,
        cols[0],
        &auto_title,
        &auto_items,
        state.hostlist.auto_sel,
        state.hostlist.focus == HostlistFocus::AutoHostlist,
        if !auto_on
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
        },
        t.ok_bright,
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
        cols[1],
        &format!(" Blacklist ({}) ", black_items.len()),
        &black_items,
        state.hostlist.blacklist_sel,
        state.hostlist.focus == HostlistFocus::Blacklist,
        &black_empty,
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
)
{
    let t = &state.theme;
    let border = if focused { t.accent_bright } else { t.frame };
    if items.is_empty()
    {
        let p =
            Paragraph::new(Line::from(Span::styled(format!("  {empty_msg}"), Style::default().fg(t.muted))))
                .wrap(Wrap { trim: false })
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
            let prefix = if is_sel && focused
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
            let style = if is_sel && focused
            {
                Style::default().fg(Color::Black).bg(t.accent_bright).add_modifier(Modifier::BOLD)
            }
            else if is_sel
            {
                Style::default().fg(accent).add_modifier(Modifier::BOLD)
            }
            else
            {
                Style::default().fg(t.text)
            };
            ListItem::new(Line::from(Span::styled(format!("{prefix}{domain}"), style)))
        })
        .collect();
    let list = List::new(rows).block(panel_block(title, border, accent));
    frame.render_widget(list, area);
}
