//! Pure `ratatui` widget rendering for Tab 1 (Strategy Finder setup, progress, results, and log).

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Cell, Clear, Gauge, List, ListItem, Paragraph, Row, Table, Wrap},
};

/// Shared log panel widget helper reused from the top-level renderer.
use crate::tui::render::draw_log_list;
/// Application state read while rendering the Strategy Finder view.
use crate::tui::state::AppState;
/// Shared panel border helpers and `[key]` badge styling.
use crate::tui::theme::{panel_block, styled_key_hints};
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Strategy Finder form descriptor, panel focus state, and scan lifecycle status.
use crate::tui::types::{FinderField, FinderFocus, FinderStatus};

/// Returns a display-width-limited window of `text` driven by active edit `cursor` or `scroll`.
///
/// Unfocused fields pass `(None, 0)` so they anchor at start and ignore edits elsewhere.
pub(crate) fn windowed_text(text: &str, cursor: Option<usize>, scroll: usize, max_chars: usize) -> String {
    let char_count = text.chars().count();
    let cursor_char = cursor.map(|pos| text[..pos.min(text.len())].chars().count());
    let (win_start_char, win_end_char) = if char_count <= max_chars || max_chars < 4 {
        (0, char_count)
    } else if let Some(cc) = cursor_char {
        let start = cc.saturating_sub(max_chars / 2).min(char_count - max_chars);
        (start, (start + max_chars).min(char_count))
    } else {
        let start = scroll.min(char_count - max_chars);
        (start, (start + max_chars).min(char_count))
    };
    let byte_at = |ci: usize| text.char_indices().nth(ci).map(|(i, _)| i).unwrap_or(text.len());
    let start_byte = byte_at(win_start_char);
    let end_byte = byte_at(win_end_char);
    let body = if let Some(pos) = cursor.map(|p| p.min(text.len()))
        && pos >= start_byte
        && pos <= end_byte
    {
        let rel = pos - start_byte;
        let mark = if pos == text.len() { "_" } else { "|" };
        format!("{}{mark}{}", &text[start_byte..start_byte + rel], &text[start_byte + rel..end_byte])
    } else {
        text[start_byte..end_byte].to_owned()
    };
    let (left_arrow, right_arrow) = if cfg!(windows) { ("<", ">") } else { ("◀", "▶") };
    match (win_start_char > 0, win_end_char < char_count) {
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
) -> Span<'static> {
    let (cursor, scroll) = if focused && state.finder.editing_text {
        (Some(state.finder.text_cursor), 0)
    } else if focused {
        (None, state.finder.text_scroll)
    } else {
        (None, 0)
    };
    Span::styled(windowed_text(text, cursor, scroll, max_cols), Style::default().fg(color))
}

/// Renders Tab 1: left Setup form and right Progress / Results Table / Live Log stack.
pub(crate) fn draw_finder_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);

    draw_finder_form(frame, cols[0], state);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Percentage(52),
            Constraint::Min(5),
        ])
        .split(cols[1]);

    let ratio = if state.finder.progress_total > 0 {
        (state.finder.progress_done as f64 / state.finder.progress_total as f64).clamp(0.0, 1.0)
    } else if state.finder.status == FinderStatus::Done {
        1.0
    } else {
        0.0
    };
    let (gauge_color, gauge_border) = match state.finder.status {
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
        .label(state.finder.progress_label.as_str());
    frame.render_widget(gauge, right[0]);

    draw_results_table(frame, right[1], state);
    draw_log_list(
        frame,
        right[2],
        " Live Scan Log ",
        &state.finder.logs,
        state.focus.finder_log_scroll,
        state.focus.finder == FinderFocus::Log,
        t,
    );
    if state.focus.finder == FinderFocus::Setup
        && state.finder.hover.open
        && state.modal.is_none()
        && !state.help_open
        && !state.finder.editing_text
    {
        draw_finder_tooltip(frame, area, cols[0], cols[1], state);
    }
}

/// Renders one checkbox `[x]` / `[ ]` value with semantic color styling from `t`.
fn checkbox_span(checked: bool, t: &Theme) -> Span<'static> {
    if checked {
        Span::styled("[x]", Style::default().fg(t.ok_bright).add_modifier(Modifier::BOLD))
    } else {
        Span::styled("[ ]", Style::default().fg(t.muted))
    }
}

/// Renders one formatted row for [`FinderField`] inside the left Setup card.
fn format_form_row(
    state: &AppState,
    field: FinderField,
    focused: bool,
    value_cols: usize,
) -> ListItem<'static> {
    let t = &state.theme;
    let (label, lbl_col, value_span) = match field {
        FinderField::Domains => {
            let span = if state.finder.domains_input.is_empty() && !focused {
                Span::styled("<press Enter to type domain(s)>", Style::default().fg(t.muted))
            } else {
                text_field_span(&state.finder.domains_input, state, focused, t.accent_bright, value_cols)
            };
            ("Domains      ", t.accent_bright, span)
        }
        FinderField::ProtoHttp => ("HTTP (80)    ", t.info, checkbox_span(state.finder.proto_http, t)),
        FinderField::ProtoTls12 => ("TLS 1.2 (443)", t.info, checkbox_span(state.finder.proto_tls12, t)),
        FinderField::ProtoTls13 => ("TLS 1.3 (443)", t.info, checkbox_span(state.finder.proto_tls13, t)),
        FinderField::ProtoHttp3 => ("HTTP/3 (UDP) ", t.info, checkbox_span(state.finder.proto_http3, t)),
        FinderField::IpMode => ("IP Version   ", t.special_bright, Span::styled(state.finder.ip_mode.label(), Style::default().fg(t.warn_bright))),
        FinderField::Level => ("Scan Level   ", t.special_bright, Span::styled(state.finder.level.as_str(), Style::default().fg(t.special_bright))),
        FinderField::StopOnFirst => ("Stop On First", t.warn, checkbox_span(state.finder.stop_on_first, t)),
        FinderField::NoNft => (
            if cfg!(windows) { "Manual Filter" } else { "Manual nft   " },
            t.warn,
            checkbox_span(state.finder.no_nft, t),
        ),
        FinderField::LuaDir => (
            "Lua Dir      ",
            t.ok_bright,
            text_field_span(&state.finder.lua_dir_input, state, focused, t.info, value_cols),
        ),
        FinderField::OutputPath => (
            "Config Path  ",
            t.ok_bright,
            text_field_span(&state.finder.output_path, state, focused, t.info, value_cols),
        ),
        FinderField::DomainScope => (
            "Domain Scope ",
            t.special_bright,
            Span::styled(state.finder.domain_scope.label(), Style::default().fg(t.warn_bright)),
        ),
    };

    let prefix = if focused { "> " } else { "  " };
    if focused && state.finder.editing_text {
        let edit_style = Style::default().fg(Color::Black).bg(t.warn).add_modifier(Modifier::BOLD);
        return ListItem::new(Line::from(vec![
            Span::styled(format!("{prefix}{label}: "), edit_style),
            Span::styled(value_span.content.into_owned(), edit_style),
        ]));
    }
    if focused {
        let focus_lbl = Style::default().fg(t.accent_bright).bg(t.highlight_bg).add_modifier(Modifier::BOLD);
        return ListItem::new(Line::from(vec![
            Span::styled(prefix, Style::default().fg(t.warn_bright).bg(t.highlight_bg).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{label}: "), focus_lbl),
            Span::styled(value_span.content.into_owned(), focus_lbl),
        ]));
    }
    ListItem::new(Line::from(vec![
        Span::styled(format!("{prefix}{label}: "), Style::default().fg(lbl_col)),
        value_span,
    ]))
}

/// Renders the interactive Finder configuration form card.
fn draw_finder_form(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let setup_focused = state.focus.finder == FinderFocus::Setup;
    let value_cols = usize::from(area.width.saturating_sub(22)).max(16);
    let items: Vec<ListItem<'static>> = FinderField::ALL
        .iter()
        .enumerate()
        .map(|(idx, &field)| {
            format_form_row(state, field, setup_focused && idx == state.finder.focus_idx, value_cols)
        })
        .collect();
    let (title, border, title_col) = if state.finder.editing_text {
        (" Strategy Setup [EDITING] ", t.warn, t.warn_bright)
    } else if setup_focused {
        (" Strategy Setup ", t.accent_bright, t.accent_bright)
    } else {
        (" Strategy Setup ", t.frame, t.info)
    };
    let list = List::new(items).block(panel_block(title, border, title_col));
    frame.render_widget(list, area);
}

/// Renders the per-domain results table on Tab 1 with scrollable row selection when focused.
fn draw_results_table(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let focused = state.focus.finder == FinderFocus::Results;
    let header = Row::new(["Domain", "Proto", "Baseline", "Hits", "Best Strategy", "RTT"])
        .style(Style::default().fg(t.warn_bright).bg(t.highlight_bg).add_modifier(Modifier::BOLD));

    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    let clamped_sel = state.focus.finder_results_sel.min(state.finder.targets.len().saturating_sub(1));
    let start = if clamped_sel >= capacity { clamped_sel + 1 - capacity } else { 0 };

    let rows: Vec<Row> = state
        .finder.targets
        .iter()
        .enumerate()
        .skip(start)
        .take(capacity)
        .map(|(idx, res)| {
            let (best, rtt, col) = if res.skipped_unblocked {
                ("direct OK".to_owned(), "-".to_owned(), t.ok_bright)
            } else if let Some(m) = res.matches.first() {
                (m.strategy.id.clone(), format!("{}ms", m.latency_ms), t.ok_bright)
            } else {
                ("none".to_owned(), "-".to_owned(), t.err_bright)
            };
            let base_summary = res.baseline.summary();
            let base_col = if res.skipped_unblocked {
                t.ok
            } else if base_summary.contains("block") || base_summary.contains("reset") || base_summary.contains("timeout") {
                t.warn_bright
            } else {
                t.subtle
            };
            let selected = focused && idx == clamped_sel;
            let hits_col = if res.matches.is_empty() { if selected { t.subtle } else { t.muted } } else { t.ok_bright };
            let rtt_col = if rtt == "-" { if selected { t.subtle } else { t.muted } } else { t.warn_bright };
            let row = Row::new([
                Cell::from(res.domain.clone()).style(Style::default().fg(t.text).add_modifier(Modifier::BOLD)),
                Cell::from(format!("{}/{}", res.proto, res.ipv)).style(Style::default().fg(t.accent_bright)),
                Cell::from(base_summary).style(Style::default().fg(base_col)),
                Cell::from(res.matches.len().to_string()).style(Style::default().fg(hits_col).add_modifier(Modifier::BOLD)),
                Cell::from(best).style(Style::default().fg(col).add_modifier(Modifier::BOLD)),
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
    let title = format!(" Results ({} targets, {} cover profiles) ", state.finder.targets.len(), state.finder.cover.len());
    let (border, title_col) = if focused { (t.accent_bright, t.accent_bright) } else { (t.frame, t.info) };
    let table = Table::new(rows, widths)
        .header(header)
        .block(panel_block(&title, border, title_col));
    frame.render_widget(table, area);
}

/// Counts how many wrapped lines `text` occupies when word-wrapped within `width` columns.
fn wrapped_line_count(text: &str, width: usize) -> u16 {
    let max_w = width.max(1);
    let mut lines = 1usize;
    let mut col = 0usize;
    for word in text.split_whitespace() {
        let len = word.chars().count();
        if col == 0 {
            col = len;
        } else if col + 1 + len <= max_w {
            col += 1 + len;
        } else {
            lines += 1;
            col = len;
        }
    }
    u16::try_from(lines).unwrap_or(u16::MAX)
}

/// Renders a floating explanation popup next to the focused [`FinderField`] after a 1s dwell.
fn draw_finder_tooltip(
    frame: &mut Frame,
    bounds: Rect,
    form_col: Rect,
    right_col: Rect,
    state: &AppState,
) {
    let t = &state.theme;
    let (title, desc) = state.focused_field().description();
    let avail_w = right_col.width.saturating_sub(2).max(28.min(bounds.width));
    let w = 48u16.min(avail_w).max(20.min(bounds.width));
    let body_lines = wrapped_line_count(desc, usize::from(w.saturating_sub(2)));
    let h = (body_lines + 4).min(bounds.height).max(5.min(bounds.height));
    let anchor_y = form_col.y + 1 + state.finder.focus_idx as u16;
    let x = if right_col.width >= 24 {
        right_col.x + 1
    } else {
        bounds.x + bounds.width.saturating_sub(w) / 2
    };
    let popup = Rect {
        x: x.min(bounds.x + bounds.width.saturating_sub(w)),
        y: anchor_y.min(bounds.y + bounds.height.saturating_sub(h)),
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
    frame.render_widget(
        Paragraph::new(Line::from(styled_key_hints("[Up/Down] next  [Esc] hide", t))),
        sections[1],
    );
}
