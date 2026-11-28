//! Pure `ratatui` widget rendering for Tab 2 (`Run nfqws2`) and shared scrolling log panels.

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Wrap},
};

/// Live packet inspector table renderer embedded on Tab 2.
use crate::tui::inspect_ui::draw_packet_inspector;
/// Application state read while rendering the Run tab controller and logs.
use crate::tui::state::AppState;
/// Shared panel border helpers and log line colorization helpers.
use crate::tui::theme::{log_line_spans, panel_block};
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Tab 2 focus selector and daemon lifecycle status enum.
use crate::tui::types::{RunFocus, RunStatus};

/// Builds styled spans for comma-separated profile names or a muted fallback label.
fn profile_spans(profiles: &[String], empty_hint: &'static str, t: &Theme) -> Vec<Span<'static>>
{
    if profiles.is_empty()
    {
        return vec![Span::styled(empty_hint, Style::default().fg(t.muted))];
    }
    let mut spans = Vec::with_capacity(profiles.len() * 2);
    for (idx, name) in profiles
        .iter()
        .enumerate()
    {
        if idx > 0
        {
            spans.push(Span::styled(", ", Style::default().fg(t.muted)));
        }
        spans.push(Span::styled(
            name.clone(),
            Style::default()
                .fg(t.special_bright)
                .add_modifier(Modifier::BOLD),
        ));
    }
    spans
}

/// Formats the Tab 2 Web UI status row shared between local and remote-attached views.
fn web_ui_controller_line(state: &AppState, key_style: Style) -> Line<'static>
{
    let (t, g) = (
        &state.theme,
        &state
            .keybinds
            .global,
    );
    match &state.web_status
    {
        Some((url, passcode)) =>
        {
            let chips = format!(
                "  [{}] Open  [{}] Copy  [{}] Stop",
                g.open_web_ui
                    .primary_label(),
                g.copy_web_passcode
                    .primary_label(),
                g.web_ui
                    .primary_label()
            );
            Line::from(vec![
                Span::styled("Web UI        : ", key_style),
                Span::styled(
                    url.clone(),
                    Style::default()
                        .fg(t.ok_bright)
                        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
                ),
                Span::styled("  passcode: ", Style::default().fg(t.muted)),
                Span::styled(
                    passcode.clone(),
                    Style::default()
                        .fg(t.warn_bright)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(chips, Style::default().fg(t.info)),
            ])
        }
        None => Line::from(vec![
            Span::styled("Web UI        : ", key_style),
            Span::styled(
                format!(
                    "Off (press '{}' to start LAN / localhost UI)",
                    g.web_ui
                        .primary_label()
                ),
                Style::default().fg(t.muted),
            ),
        ]),
    }
}

/// Formats controller summary lines for Tab 2 based on local vs remote-attached mode.
fn run_controller_lines(state: &AppState) -> Vec<Line<'static>>
{
    let t = &state.theme;
    let key_style = Style::default().fg(t.info);
    let mut lines = if state
        .run
        .status
        == RunStatus::Attached
        && let Some(meta) = &state
            .run
            .remote_meta
    {
        let cfg_span = match meta
            .config_path
            .as_deref()
        {
            Some(p) => Span::styled(p.to_owned(), Style::default().fg(t.accent_bright)),
            None => Span::styled("(daemon defaults / CLI args)", Style::default().fg(t.muted)),
        };
        let mut prof_line = vec![Span::styled(
            format!(
                "Profiles ({})  : ",
                meta.profile_names
                    .len()
            ),
            key_style,
        )];
        prof_line.extend(profile_spans(&meta.profile_names, "none (pass-through)", t));
        vec![
            Line::from(vec![
                Span::styled("Engine Status : ", key_style),
                Span::styled(
                    "ATTACHED ",
                    Style::default()
                        .fg(t.accent_bright)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("(PID {}, qnum {}, ", meta.pid, meta.qnum),
                    Style::default().fg(t.warn_bright),
                ),
                Span::styled(
                    format!(
                        "socket {})",
                        meta.socket_path
                            .display()
                    ),
                    Style::default().fg(t.subtle),
                ),
            ]),
            Line::from(vec![Span::styled("Config Path   : ", key_style), cfg_span]),
            Line::from(prof_line),
            Line::from(vec![
                Span::styled("nftables Mode : ", key_style),
                Span::styled("daemon-managed ", Style::default().fg(t.ok_bright)),
                Span::styled(format!("(fwmark 0x{:08x})", meta.fwmark), Style::default().fg(t.warn_bright)),
            ]),
        ]
    }
    else
    {
        let (st_text, st_color) = match &state
            .run
            .status
        {
            RunStatus::Running => ("RUNNING".to_owned(), t.ok_bright),
            RunStatus::Attached => ("ATTACHED".to_owned(), t.accent_bright),
            RunStatus::Stopped => match &state
                .run
                .detected_socket
            {
                Some(sock) => (
                    format!("STOPPED (daemon socket found at {}; press 'r' to attach)", sock.display()),
                    t.warn_bright,
                ),
                None => ("STOPPED".to_owned(), t.warn_bright),
            },
            RunStatus::Error(e) => (format!("ERROR: {e}"), t.err_bright),
        };
        let mut prof_line = vec![Span::styled(
            format!(
                "Profiles ({})  : ",
                state
                    .config
                    .parsed_profiles
                    .len()
            ),
            key_style,
        )];
        prof_line.extend(profile_spans(
            &state
                .config
                .parsed_profiles,
            "none loaded (run Strategy Finder or press 'l' to load config file)",
            t,
        ));
        let (nft_text, nft_col) = if state
            .finder
            .no_nft
        {
            ("manual (--no-nft)", t.warn_bright)
        }
        else
        {
            ("managed (auto cleanup on stop)", t.ok_bright)
        };
        vec![
            Line::from(vec![
                Span::styled("Engine Status : ", key_style),
                Span::styled(
                    st_text,
                    Style::default()
                        .fg(st_color)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![
                Span::styled("Config Path   : ", key_style),
                Span::styled(
                    state
                        .finder
                        .output_path
                        .clone(),
                    Style::default().fg(t.accent_bright),
                ),
            ]),
            Line::from(prof_line),
            Line::from(vec![
                Span::styled("nftables Mode : ", key_style),
                Span::styled(nft_text, Style::default().fg(nft_col)),
            ]),
        ]
    };
    lines.push(web_ui_controller_line(state, key_style));
    lines
}

/// Computes exact Tab 2 controller card height shared by renderer and mouse hit-testing.
pub(crate) fn run_controller_height(state: &AppState, width: u16) -> u16
{
    let ctrl_lines = run_controller_lines(state);
    let inner_w = usize::from(width.saturating_sub(2)).max(1);
    let ctrl_wrapped: usize = ctrl_lines
        .iter()
        .map(|l| {
            l.width()
                .max(1)
                .div_ceil(inner_w)
        })
        .sum();
    u16::try_from(ctrl_wrapped + 2)
        .unwrap_or(8)
        .clamp(6, 9)
}

/// Renders Tab 2: active config summary, live packet telemetry cards, and daemon log.
pub(super) fn draw_run_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let ctrl_lines = run_controller_lines(state);
    let ctrl_h = run_controller_height(state, area.width);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(ctrl_h),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(5),
        ])
        .split(area);

    let ctrl_border = match state
        .run
        .status
    {
        RunStatus::Running => t.ok,
        RunStatus::Attached => t.accent,
        RunStatus::Error(_) => t.err,
        RunStatus::Stopped => t.frame,
    };
    let ctrl_title = if cfg!(windows) { " Live WinDivert Controller " } else { " Live nfqws2 Controller " };
    let info = Paragraph::new(ctrl_lines)
        .wrap(Wrap { trim: true })
        .block(panel_block(ctrl_title, ctrl_border, t.accent_bright));
    frame.render_widget(info, rows[0]);

    let (total, passed, reasm, modified, desynced) = state.visible_counters();
    let metric_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(rows[1]);
    for (idx, (title, val, val_col, border_col)) in [
        (" Total ", total, t.info, t.frame),
        (" Passed ", passed, t.ok_bright, t.ok),
        (" Reasm ", reasm, t.accent_bright, t.accent),
        (" Modified ", modified, t.warn_bright, t.warn),
        (" Desync ", desynced, t.special_bright, t.special),
    ]
    .into_iter()
    .enumerate()
    {
        let card = Paragraph::new(Line::from(Span::styled(
            format!(" {val}"),
            Style::default()
                .fg(val_col)
                .add_modifier(Modifier::BOLD),
        )))
        .block(panel_block(title, border_col, val_col));
        frame.render_widget(card, metric_cols[idx]);
    }

    draw_packet_inspector(
        frame,
        rows[2],
        &state.inspector,
        state
            .focus
            .run
            == RunFocus::Inspector,
        t,
    );
    draw_log_list(
        frame,
        rows[3],
        " Daemon Log ",
        &state
            .run
            .logs,
        state
            .focus
            .run_log_scroll,
        state
            .focus
            .run
            == RunFocus::Log,
        t,
    );
}

/// Pushes `raw` wrapped to `inner_w` into `out`, preserving log coloring on the first line.
fn push_wrapped_log<'a>(out: &mut Vec<ListItem<'a>>, raw: &'a str, inner_w: usize, t: &Theme)
{
    let char_count = raw
        .chars()
        .count();
    if char_count <= inner_w
    {
        out.push(ListItem::new(log_line_spans(raw, t)));
        return;
    }
    let mut boundaries: Vec<usize> = raw
        .char_indices()
        .map(|(b, _)| b)
        .collect();
    boundaries.push(raw.len());
    for (idx, start_c) in (0..char_count)
        .step_by(inner_w)
        .enumerate()
    {
        let end_c = (start_c + inner_w).min(char_count);
        let slice = &raw[boundaries[start_c]..boundaries[end_c]];
        let line = if idx == 0
        {
            log_line_spans(slice, t)
        }
        else
        {
            Line::from(Span::styled(slice, Style::default().fg(t.subtle)))
        };
        out.push(ListItem::new(line));
    }
}

/// Renders a bounded scrolling log widget with optional history offset (`scroll = 0` follows tail).
pub(crate) fn draw_log_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    logs: &std::collections::VecDeque<String>,
    scroll: u16,
    focused: bool,
    t: &Theme,
)
{
    let capacity = usize::from(
        area.height
            .saturating_sub(2),
    )
    .max(1);
    let inner_w = usize::from(
        area.width
            .saturating_sub(2),
    )
    .max(1);
    let mut wrapped_items: Vec<ListItem> = Vec::new();
    for raw in logs
    {
        push_wrapped_log(&mut wrapped_items, raw, inner_w, t);
    }
    let max_scroll = wrapped_items
        .len()
        .saturating_sub(capacity);
    let clamped = usize::from(scroll).min(max_scroll);
    let end = wrapped_items
        .len()
        .saturating_sub(clamped);
    let start = end.saturating_sub(capacity);
    let items: Vec<ListItem> = wrapped_items
        .drain(start..end)
        .collect();
    let heading = if clamped > 0 { format!("{}(+{clamped}) ", title.trim_end()) } else { title.to_owned() };
    let border = if focused { t.accent_bright } else { t.frame };
    let title_col = if focused { t.accent_bright } else { t.info };
    let list = List::new(items).block(panel_block(heading, border, title_col));
    frame.render_widget(list, area);
}
