//! Pure `ratatui` setup-form widgets and text-window helpers for Tab 1 (Strategy Finder).

/// `ratatui` frame, layout, styling, text, and list primitives.
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem},
};

/// Application state read while rendering Strategy Finder form fields.
use crate::tui::state::AppState;
/// Shared panel border helper.
use crate::tui::theme::panel_block;
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Strategy Finder form descriptor and panel focus state.
use crate::tui::types::{FinderField, FinderFocus};

/// Returns a display-width-limited window of `text` driven by active edit `cursor` or `scroll`.
///
/// Unfocused fields pass `(None, 0)` so they anchor at start and ignore edits elsewhere.
pub(crate) fn windowed_text(text: &str, cursor: Option<usize>, scroll: usize, max_chars: usize) -> String
{
    let char_count = text
        .chars()
        .count();
    let cursor_char = cursor.map(|pos| {
        text[..pos.min(text.len())]
            .chars()
            .count()
    });
    let (win_start_char, win_end_char) = if char_count <= max_chars || max_chars < 4
    {
        (0, char_count)
    }
    else if let Some(cc) = cursor_char
    {
        let start = cc
            .saturating_sub(max_chars / 2)
            .min(char_count - max_chars);
        (start, (start + max_chars).min(char_count))
    }
    else
    {
        let start = scroll.min(char_count - max_chars);
        (start, (start + max_chars).min(char_count))
    };
    let byte_at = |ci: usize| {
        text.char_indices()
            .nth(ci)
            .map(|(i, _)| i)
            .unwrap_or(text.len())
    };
    let start_byte = byte_at(win_start_char);
    let end_byte = byte_at(win_end_char);
    let body = if let Some(pos) = cursor.map(|p| p.min(text.len()))
        && pos >= start_byte
        && pos <= end_byte
    {
        let rel = pos - start_byte;
        let mark = if pos == text.len() { "_" } else { "|" };
        format!("{}{mark}{}", &text[start_byte..start_byte + rel], &text[start_byte + rel..end_byte])
    }
    else
    {
        text[start_byte..end_byte].to_owned()
    };
    let (left_arrow, right_arrow) = if cfg!(windows) { ("<", ">") } else { ("◀", "▶") };
    match (win_start_char > 0, win_end_char < char_count)
    {
        (true, true) => format!("{left_arrow}{body}{right_arrow}"),
        (true, false) => format!("{left_arrow}{body}"),
        (false, true) => format!("{body}{right_arrow}"),
        (false, false) => body,
    }
}

/// Builds a windowed span for one Tab 1 text field, isolating cursor/scroll to `focused`.
fn text_field_span(
    text: &str,
    state: &AppState,
    focused: bool,
    color: Color,
    max_cols: usize,
) -> Span<'static>
{
    let (cursor, scroll) = if focused
        && state
            .finder
            .editing_text
    {
        (
            Some(
                state
                    .finder
                    .text_cursor,
            ),
            0,
        )
    }
    else if focused
    {
        (
            None,
            state
                .finder
                .text_scroll,
        )
    }
    else
    {
        (None, 0)
    };
    Span::styled(windowed_text(text, cursor, scroll, max_cols), Style::default().fg(color))
}

/// Renders one checkbox `[x]` / `[ ]` value with semantic color styling from `t`.
fn checkbox_span(checked: bool, t: &Theme) -> Span<'static>
{
    if checked
    {
        Span::styled(
            "[x]",
            Style::default()
                .fg(t.ok_bright)
                .add_modifier(Modifier::BOLD),
        )
    }
    else
    {
        Span::styled("[ ]", Style::default().fg(t.muted))
    }
}

/// Renders one formatted row for [`FinderField`] inside the left Setup card.
fn format_form_row(
    state: &AppState,
    field: FinderField,
    focused: bool,
    value_cols: usize,
) -> ListItem<'static>
{
    let t = &state.theme;
    let (label, lbl_col, value_span) = match field
    {
        FinderField::Domains =>
        {
            let span = if state
                .finder
                .domains_input
                .is_empty()
                && !focused
            {
                Span::styled("<press Enter to type domain(s)>", Style::default().fg(t.muted))
            }
            else
            {
                text_field_span(
                    &state
                        .finder
                        .domains_input,
                    state,
                    focused,
                    t.accent_bright,
                    value_cols,
                )
            };
            ("Domains      ", t.accent_bright, span)
        }
        FinderField::ProtoHttp => (
            "HTTP (80)    ",
            t.info,
            checkbox_span(
                state
                    .finder
                    .proto_http,
                t,
            ),
        ),
        FinderField::ProtoTls12 => (
            "TLS 1.2 (443)",
            t.info,
            checkbox_span(
                state
                    .finder
                    .proto_tls12,
                t,
            ),
        ),
        FinderField::ProtoTls13 => (
            "TLS 1.3 (443)",
            t.info,
            checkbox_span(
                state
                    .finder
                    .proto_tls13,
                t,
            ),
        ),
        FinderField::ProtoHttp3 => (
            "HTTP/3 (UDP) ",
            t.info,
            checkbox_span(
                state
                    .finder
                    .proto_http3,
                t,
            ),
        ),
        FinderField::IpMode => (
            "IP Version   ",
            t.special_bright,
            Span::styled(
                state
                    .finder
                    .ip_mode
                    .label(),
                Style::default().fg(t.warn_bright),
            ),
        ),
        FinderField::Level => (
            "Scan Level   ",
            t.special_bright,
            Span::styled(
                state
                    .finder
                    .level
                    .as_str(),
                Style::default().fg(t.special_bright),
            ),
        ),
        FinderField::StopOnFirst => (
            "Stop On First",
            t.warn,
            checkbox_span(
                state
                    .finder
                    .stop_on_first,
                t,
            ),
        ),
        FinderField::NoNft => (
            if cfg!(windows) { "Manual Filter" } else { "Manual nft   " },
            t.warn,
            checkbox_span(
                state
                    .finder
                    .no_nft,
                t,
            ),
        ),
        FinderField::LuaDir => (
            "Lua Dir      ",
            t.ok_bright,
            text_field_span(
                &state
                    .finder
                    .lua_dir_input,
                state,
                focused,
                t.info,
                value_cols,
            ),
        ),
        FinderField::OutputPath => (
            "Config Path  ",
            t.ok_bright,
            text_field_span(
                &state
                    .finder
                    .output_path,
                state,
                focused,
                t.info,
                value_cols,
            ),
        ),
        FinderField::DomainScope => (
            "Domain Scope ",
            t.special_bright,
            Span::styled(
                state
                    .finder
                    .domain_scope
                    .label(),
                Style::default().fg(t.warn_bright),
            ),
        ),
    };

    let prefix = if focused { "> " } else { "  " };
    if focused
        && state
            .finder
            .editing_text
    {
        let edit_style = Style::default()
            .fg(Color::Black)
            .bg(t.warn)
            .add_modifier(Modifier::BOLD);
        return ListItem::new(Line::from(vec![
            Span::styled(format!("{prefix}{label}: "), edit_style),
            Span::styled(
                value_span
                    .content
                    .into_owned(),
                edit_style,
            ),
        ]));
    }
    if focused
    {
        let focus_lbl = Style::default()
            .fg(t.accent_bright)
            .bg(t.highlight_bg)
            .add_modifier(Modifier::BOLD);
        return ListItem::new(Line::from(vec![
            Span::styled(
                prefix,
                Style::default()
                    .fg(t.warn_bright)
                    .bg(t.highlight_bg)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("{label}: "), focus_lbl),
            Span::styled(
                value_span
                    .content
                    .into_owned(),
                focus_lbl,
            ),
        ]));
    }
    ListItem::new(Line::from(vec![
        Span::styled(format!("{prefix}{label}: "), Style::default().fg(lbl_col)),
        value_span,
    ]))
}

/// Renders the interactive Finder configuration form card.
pub(super) fn draw_finder_form(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let setup_focused = state
        .focus
        .finder
        == FinderFocus::Setup;
    let value_cols = usize::from(
        area.width
            .saturating_sub(22),
    )
    .max(16);
    let items: Vec<ListItem<'static>> = FinderField::ALL
        .iter()
        .enumerate()
        .map(|(idx, &field)| {
            format_form_row(
                state,
                field,
                setup_focused
                    && idx
                        == state
                            .finder
                            .focus_idx,
                value_cols,
            )
        })
        .collect();
    let (title, border, title_col) = if state
        .finder
        .editing_text
    {
        (" Strategy Setup [EDITING] ", t.warn, t.warn_bright)
    }
    else if setup_focused
    {
        (" Strategy Setup ", t.accent_bright, t.accent_bright)
    }
    else
    {
        (" Strategy Setup ", t.frame, t.info)
    };
    let list = List::new(items).block(panel_block(title, border, title_col));
    frame.render_widget(list, area);
}
