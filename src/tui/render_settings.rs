//! Pure `ratatui` widget rendering for Tab 7 (`Settings` — `config.toml`, theme, and keybinds).

/// `ratatui` layout, styling, list, table, and paragraph primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, List, ListItem, Paragraph, Row, Table},
};

/// Default keybinding baseline used to highlight customized keymaps cleanly.
use crate::tui::keybind_schema::Keybinds;
/// Selected column, setting row, and ordered keybinding entry descriptors on Tab 7.
use crate::tui::settings_tab::{KEYBIND_ENTRIES, SettingRow, SettingsFocus};
/// Shared TUI state rendered inside Tab 7.
use crate::tui::state::AppState;
/// Shared bordered panel builder for Tab 7 cards.
use crate::tui::theme::panel_block;
/// Shared visible-window slice helper aligned with mouse hit-testing.
use crate::tui::types::visible_window;

/// Renders Tab 7: top settings status strip, left `Options` pane, and right `Keybindings` table.
pub(crate) fn draw_settings_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    let header_line = if state.settings.capturing_rebind
    {
        let target = KEYBIND_ENTRIES.get(state.settings.keybind_sel).map_or("", |s| s.id);
        Line::from(vec![
            Span::styled(" Rebinding ", Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD)),
            Span::styled(target, Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
            Span::styled(": press new key or chord  (Esc cancels)", Style::default().fg(t.text)),
        ])
    }
    else if state.settings.editing_option
    {
        Line::from(vec![
            Span::styled(
                " Editing Path: ",
                Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{}_", state.settings.edit_buf),
                Style::default().fg(t.text).add_modifier(Modifier::BOLD),
            ),
            Span::styled("   (Enter applies, Esc cancels)", Style::default().fg(t.muted)),
        ])
    }
    else
    {
        let focus_label =
            if state.settings.focus == SettingsFocus::Options { "Options" } else { "Keybindings" };
        let defaults = Keybinds::default();
        let custom_count = KEYBIND_ENTRIES
            .iter()
            .filter(|spec| (spec.get)(&state.keybinds) != (spec.get)(&defaults))
            .count();
        Line::from(Span::styled(
            format!(
                " Theme: {}   Custom keybinds: {custom_count}/{}   Focus: {focus_label}",
                state.theme.name,
                KEYBIND_ENTRIES.len(),
            ),
            Style::default().fg(t.info),
        ))
    };

    let status_tag = if state.settings.dirty { "[MODIFIED]" } else { "[SAVED]" };
    let header_title = format!(" Settings Manager ({}) {status_tag} ", state.app_config_path.display());
    let header_border = if state.settings.capturing_rebind || state.settings.editing_option
    {
        t.warn_bright
    }
    else if state.settings.dirty
    {
        t.warn
    }
    else
    {
        t.frame
    };
    let bar = Paragraph::new(header_line).block(panel_block(&header_title, header_border, t.info));
    frame.render_widget(bar, rows[0]);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(rows[1]);

    draw_options_column(frame, cols[0], state);
    draw_keybinds_column(frame, cols[1], state);
}

/// Renders the left `Options` column (`Theme Preset`, paths, and `--no-nft` toggle).
fn draw_options_column(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let focused = state.settings.focus == SettingsFocus::Options;
    let border = if focused { t.accent_bright } else { t.frame };

    let items: Vec<ListItem> = SettingRow::ALL
        .iter()
        .enumerate()
        .map(|(idx, &row)| {
            let selected = idx == state.settings.option_sel;
            let prefix = if selected && focused
            {
                "> "
            }
            else if selected
            {
                "* "
            }
            else
            {
                "  "
            };
            let (label, val) = option_label_and_value(state, row, selected);
            let bg = if selected { t.highlight_bg } else { Color::Reset };
            let val_col = if row == SettingRow::NoNft && state.finder.no_nft
            {
                t.warn_bright
            }
            else if selected
            {
                t.accent_bright
            }
            else
            {
                t.text
            };
            ListItem::new(Line::from(vec![
                Span::styled(prefix, Style::default().fg(t.warn_bright).bg(bg).add_modifier(Modifier::BOLD)),
                Span::styled(format!("{label:<14} "), Style::default().fg(t.info).bg(bg)),
                Span::styled(val, Style::default().fg(val_col).bg(bg)),
            ]))
        })
        .collect();

    let list = List::new(items).block(panel_block(" App Options (config.toml) ", border, t.accent_bright));
    frame.render_widget(list, area);
}

/// Formats display label and current value string for one [`SettingRow`].
fn option_label_and_value(state: &AppState, row: SettingRow, selected: bool) -> (&'static str, String)
{
    if selected && state.settings.editing_option
    {
        let name = match row
        {
            SettingRow::Nfqws2Config => "nfqws2_config",
            SettingRow::LuaDir => "lua_dir",
            SettingRow::ControlSocket => "control_socket",
            _ => "value",
        };
        return (name, format!("{}_", state.settings.edit_buf));
    }
    match row
    {
        SettingRow::ThemePreset => ("theme.preset", state.theme.name.to_owned()),
        SettingRow::Nfqws2Config => ("nfqws2_config", state.finder.output_path.clone()),
        SettingRow::LuaDir =>
        {
            let v = if state.finder.lua_dir_input.is_empty()
            {
                "(auto)".to_owned()
            }
            else
            {
                state.finder.lua_dir_input.clone()
            };
            ("lua_dir", v)
        }
        SettingRow::NoNft =>
        {
            ("no_nft", if state.finder.no_nft { "true (manual)" } else { "false (auto)" }.to_owned())
        }
        SettingRow::ControlSocket => (
            "control_socket",
            state
                .run
                .control_socket_override
                .as_ref()
                .map_or_else(|| "(auto)".to_owned(), |p| p.display().to_string()),
        ),
    }
}

/// Renders the right scrollable `Keybindings` table highlighting customized rows and active capture.
fn draw_keybinds_column(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let focused = state.settings.focus == SettingsFocus::Keybinds;
    let border = if focused { t.accent_bright } else { t.frame };
    let defaults = Keybinds::default();
    let cap = usize::from(area.height.saturating_sub(3)).max(1);
    let (start, end) = visible_window(KEYBIND_ENTRIES.len(), state.settings.keybind_sel, cap);

    let header = Row::new(["Action", "Binding", "State"])
        .style(Style::default().fg(t.warn_bright).bg(t.highlight_bg).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = (start..end)
        .map(|idx| {
            let spec = &KEYBIND_ENTRIES[idx];
            let selected = idx == state.settings.keybind_sel;
            let cur = (spec.get)(&state.keybinds);
            let def = (spec.get)(&defaults);
            let is_custom = cur != def;
            let capturing = selected && state.settings.capturing_rebind;
            let bg = if selected { t.highlight_bg } else { Color::Reset };

            let bind_txt = if capturing { "<press new key...>".to_owned() } else { cur.joined_label() };
            let state_txt = if capturing
            {
                "CAPTURING"
            }
            else if is_custom
            {
                "custom"
            }
            else
            {
                "default"
            };
            let bind_col = if capturing
            {
                t.warn_bright
            }
            else if is_custom
            {
                t.special_bright
            }
            else
            {
                t.text
            };
            let state_col = if capturing || is_custom { t.warn_bright } else { t.muted };
            let marker = if selected && focused
            {
                "> "
            }
            else if selected
            {
                "* "
            }
            else
            {
                "  "
            };
            Row::new([
                Cell::from(format!("{marker}{}", spec.id)).style(Style::default().fg(t.info).bg(bg)),
                Cell::from(bind_txt).style(Style::default().fg(bind_col).bg(bg).add_modifier(Modifier::BOLD)),
                Cell::from(state_txt).style(Style::default().fg(state_col).bg(bg)),
            ])
        })
        .collect();

    let title = format!(" Keybindings ({} total, Enter to rebind) ", KEYBIND_ENTRIES.len());
    let table = Table::new(
        rows,
        [Constraint::Percentage(48), Constraint::Percentage(34), Constraint::Percentage(18)],
    )
    .header(header)
    .block(panel_block(&title, border, t.special_bright));
    frame.render_widget(table, area);
}
