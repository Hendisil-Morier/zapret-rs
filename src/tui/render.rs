//! Pure `ratatui` widget layout and rendering for the three-tab `zapret-rs` TUI.

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{List, ListItem, Paragraph, Tabs, Wrap},
};

/// Live packet inspector table and detail overlay renderers.
use crate::tui::inspect_ui::{draw_packet_detail_modal, draw_packet_inspector};
/// Floating capability-grant, `sudo`, stop-confirm, and `?` keybindings overlays.
use crate::tui::{keybinds::draw_keybinds_modal, modal::draw_auth_modal};
/// Tab 3 Config & Diagnostics rendering helper.
use crate::tui::render_config::draw_config_tab;
/// Tab 1 Strategy Finder rendering helper.
use crate::tui::render_finder::draw_finder_tab;
/// Tab 4 Speed Test rendering helper.
use crate::tui::render_speed::draw_speed_tab;
/// Application state rendered into the terminal frame.
use crate::tui::state::AppState;
/// Shared panel border helpers, `[key]` badge styling, log tagging, and syntax highlighters.
use crate::tui::theme::{log_line_spans, panel_block, status_banner_color, styled_key_hints};
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Navigation tabs, panel focus selectors, and live daemon/scan lifecycle statuses.
use crate::tui::types::{ActiveTab, FinderStatus, RunFocus, RunStatus};

/// Renders the entire `zapret-rs` TUI (header tabs, active tab body, and compact status strip).
pub fn draw_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(1),
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], state);
    match state.tab {
        ActiveTab::Finder => draw_finder_tab(frame, chunks[1], state),
        ActiveTab::Run => draw_run_tab(frame, chunks[1], state),
        ActiveTab::Config => draw_config_tab(frame, chunks[1], state),
        ActiveTab::Speed => draw_speed_tab(frame, chunks[1], state),
    }
    draw_footer(frame, chunks[2], state);
    if state.tab == ActiveTab::Run
        && state.inspector.detail_open
        && let Some(rec) = state.inspector.selected_record()
    {
        draw_packet_detail_modal(frame, rec, &state.theme);
    }
    if state.help_open {
        draw_keybinds_modal(frame, state);
    }
    if let Some(modal) = &state.modal {
        draw_auth_modal(frame, modal, &state.theme);
    }
}

/// Renders the top navigation bar with colorful tab titles and privilege/activity badges.
fn draw_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(36)])
        .split(area);
    let tab_titles = ActiveTab::SPECS
        .iter()
        .map(|spec| {
            Line::from(vec![
                Span::styled(spec.num_prefix, Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD)),
                Span::styled(spec.short_label, Style::default().fg(t.info)),
            ])
        })
        .collect::<Vec<_>>();
    let tabs = Tabs::new(tab_titles)
        .block(panel_block(
            format!(" zapret-rs v{} ", env!("CARGO_PKG_VERSION")),
            t.frame,
            t.accent_bright,
        ))
        .select(state.tab.index())
        .highlight_style(Style::default().fg(Color::Black).bg(t.accent_bright).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, cols[0]);

    let (cap_txt, cap_col) = if state.has_net_caps { ("CAPS OK", t.ok_bright) } else { ("NO CAPS", t.warn_bright) };
    let (act_txt, act_col, badge_border) = if state.finder_status == FinderStatus::Scanning {
        ("SCANNING", t.special_bright, t.special)
    } else {
        match state.run_status {
            RunStatus::Running => ("RUNNING", t.ok_bright, t.ok),
            RunStatus::Attached => ("ATTACHED", t.accent_bright, t.accent),
            _ => ("IDLE", t.muted, if state.has_net_caps { t.frame } else { t.warn }),
        }
    };
    let uid_col = if state.uid == 0 { t.err_bright } else { t.text };
    let badge = Paragraph::new(Line::from(vec![
        Span::styled(" UID:", Style::default().fg(t.info)),
        Span::styled(format!("{} ", state.uid), Style::default().fg(uid_col).add_modifier(Modifier::BOLD)),
        Span::styled("| ", Style::default().fg(t.muted)),
        Span::styled(cap_txt, Style::default().fg(cap_col).add_modifier(Modifier::BOLD)),
        Span::styled(" | ", Style::default().fg(t.muted)),
        Span::styled(act_txt, Style::default().fg(act_col).add_modifier(Modifier::BOLD)),
    ]))
    .block(panel_block(" Status ", badge_border, t.info));
    frame.render_widget(badge, cols[1]);
}

/// Builds styled spans for comma-separated profile names or a muted fallback label.
fn profile_spans(profiles: &[String], empty_hint: &'static str, t: &Theme) -> Vec<Span<'static>> {
    if profiles.is_empty() {
        return vec![Span::styled(empty_hint, Style::default().fg(t.muted))];
    }
    let mut spans = Vec::with_capacity(profiles.len() * 2);
    for (idx, name) in profiles.iter().enumerate() {
        if idx > 0 {
            spans.push(Span::styled(", ", Style::default().fg(t.muted)));
        }
        spans.push(Span::styled(name.clone(), Style::default().fg(t.special_bright).add_modifier(Modifier::BOLD)));
    }
    spans
}

/// Formats controller summary lines for Tab 2 based on local vs remote-attached mode.
fn run_controller_lines(state: &AppState) -> Vec<Line<'static>> {
    let t = &state.theme;
    let key_style = Style::default().fg(t.info);
    if state.run_status == RunStatus::Attached
        && let Some(meta) = &state.remote_meta
    {
        let cfg_span = match meta.config_path.as_deref() {
            Some(p) => Span::styled(p.to_owned(), Style::default().fg(t.accent_bright)),
            None => Span::styled("(daemon defaults / CLI args)", Style::default().fg(t.muted)),
        };
        let mut prof_line = vec![Span::styled(
            format!("Profiles ({})  : ", meta.profile_names.len()),
            key_style,
        )];
        prof_line.extend(profile_spans(&meta.profile_names, "none (pass-through)", t));
        return vec![
            Line::from(vec![
                Span::styled("Engine Status : ", key_style),
                Span::styled("ATTACHED ", Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD)),
                Span::styled(format!("(PID {}, qnum {}, ", meta.pid, meta.qnum), Style::default().fg(t.warn_bright)),
                Span::styled(format!("socket {})", meta.socket_path.display()), Style::default().fg(t.subtle)),
            ]),
            Line::from(vec![Span::styled("Config Path   : ", key_style), cfg_span]),
            Line::from(prof_line),
            Line::from(vec![
                Span::styled("nftables Mode : ", key_style),
                Span::styled("daemon-managed ", Style::default().fg(t.ok_bright)),
                Span::styled(format!("(fwmark 0x{:08x})", meta.fwmark), Style::default().fg(t.warn_bright)),
            ]),
        ];
    }

    let (st_text, st_color) = match &state.run_status {
        RunStatus::Running => ("RUNNING".to_owned(), t.ok_bright),
        RunStatus::Attached => ("ATTACHED".to_owned(), t.accent_bright),
        RunStatus::Stopped => match &state.detected_socket {
            Some(sock) => (
                format!("STOPPED (daemon socket found at {}; press 'r' to attach)", sock.display()),
                t.warn_bright,
            ),
            None => ("STOPPED".to_owned(), t.warn_bright),
        },
        RunStatus::Error(e) => (format!("ERROR: {e}"), t.err_bright),
    };
    let mut prof_line = vec![Span::styled(
        format!("Profiles ({})  : ", state.parsed_profiles.len()),
        key_style,
    )];
    prof_line.extend(profile_spans(
        &state.parsed_profiles,
        "none loaded (run Strategy Finder or press 'l' to load config file)",
        t,
    ));
    let (nft_text, nft_col) = if state.no_nft {
        ("manual (--no-nft)", t.warn_bright)
    } else {
        ("managed (auto cleanup on stop)", t.ok_bright)
    };
    vec![
        Line::from(vec![
            Span::styled("Engine Status : ", key_style),
            Span::styled(st_text, Style::default().fg(st_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("Config Path   : ", key_style),
            Span::styled(state.output_path.clone(), Style::default().fg(t.accent_bright)),
        ]),
        Line::from(prof_line),
        Line::from(vec![
            Span::styled("nftables Mode : ", key_style),
            Span::styled(nft_text, Style::default().fg(nft_col)),
        ]),
    ]
}

/// Renders Tab 2: active config summary, live packet telemetry cards, and daemon log.
fn draw_run_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(area);

    let ctrl_border = match state.run_status {
        RunStatus::Running => t.ok,
        RunStatus::Attached => t.accent,
        RunStatus::Error(_) => t.err,
        RunStatus::Stopped => t.frame,
    };
    let info = Paragraph::new(run_controller_lines(state))
        .wrap(Wrap { trim: true })
        .block(panel_block(" Live nfqws2 Controller ", ctrl_border, t.accent_bright));
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
            Style::default().fg(val_col).add_modifier(Modifier::BOLD),
        )))
        .block(panel_block(title, border_col, val_col));
        frame.render_widget(card, metric_cols[idx]);
    }

    draw_packet_inspector(frame, rows[2], &state.inspector, state.focus.run == RunFocus::Inspector, t);
    draw_log_list(
        frame,
        rows[3],
        " Daemon Log ",
        &state.run_logs,
        state.focus.run_log_scroll,
        state.focus.run == RunFocus::Log,
        t,
    );
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
) {
    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    let max_scroll = logs.len().saturating_sub(capacity);
    let clamped = usize::from(scroll).min(max_scroll);
    let end = logs.len().saturating_sub(clamped);
    let start = end.saturating_sub(capacity);
    let items: Vec<ListItem> = logs
        .iter()
        .skip(start)
        .take(end - start)
        .map(|line| ListItem::new(log_line_spans(line, t)))
        .collect();
    let heading = if clamped > 0 {
        format!("{}(+{clamped}) ", title.trim_end())
    } else {
        title.to_owned()
    };
    let border = if focused { t.accent_bright } else { t.frame };
    let title_col = if focused { t.accent_bright } else { t.info };
    let list = List::new(items).block(panel_block(heading, border, title_col));
    frame.render_widget(list, area);
}

/// Renders the compact single-line bottom status strip with `[?] Keys` and active theme name.
fn draw_footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let mut line_spans = styled_key_hints(" [?] Keys  [t] ", t);
    line_spans.push(Span::styled(t.name, Style::default().fg(t.special_bright).add_modifier(Modifier::BOLD)));
    line_spans.push(Span::styled("  |  ", Style::default().fg(t.muted)));
    line_spans.push(Span::styled(
        state.status_banner.as_str(),
        Style::default().fg(status_banner_color(&state.status_banner, t)),
    ));
    frame.render_widget(Paragraph::new(Line::from(line_spans)), area);
}
