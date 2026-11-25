//! Pure `ratatui` widget layout and rendering for the three-tab `zapret-rs` TUI.

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Paragraph, Row, Table, Tabs, Wrap},
};

/// Live packet inspector table and detail overlay renderers.
use crate::tui::inspect_ui::{draw_packet_detail_modal, draw_packet_inspector};
/// Floating capability-grant and `sudo` password modal overlay renderer.
use crate::tui::modal::draw_auth_modal;
/// Application state rendered into the terminal frame.
use crate::tui::state::AppState;
/// Navigation tabs, form field descriptors, and worker statuses.
use crate::tui::types::{ActiveTab, FinderField, FinderStatus, RunStatus};

/// Primary accent color for borders, titles, and active controls.
const ACCENT: Color = Color::Cyan;
/// Success badge color for passing strategies and active daemon status.
const OK_COLOR: Color = Color::Green;
/// Warning color for missing capabilities or stopped/partial states.
const WARN_COLOR: Color = Color::Yellow;
/// Error color for failures.
const ERR_COLOR: Color = Color::Red;
/// Muted gray for secondary labels and borders.
const MUTED: Color = Color::DarkGray;

/// Renders the entire `zapret-rs` TUI (header tabs, active tab body, and bottom keybinding bar).
pub fn draw_app(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_header(frame, chunks[0], state);
    match state.tab {
        ActiveTab::Finder => draw_finder_tab(frame, chunks[1], state),
        ActiveTab::Run => draw_run_tab(frame, chunks[1], state),
        ActiveTab::Config => draw_config_tab(frame, chunks[1], state),
    }
    draw_footer(frame, chunks[2], state);
    if state.tab == ActiveTab::Run && state.inspector.detail_open && let Some(rec) = state.inspector.selected_record() {
        draw_packet_detail_modal(frame, rec);
    }
    if let Some(modal) = &state.modal {
        draw_auth_modal(frame, modal);
    }
}

/// Renders the top navigation bar with tab titles and live privilege/activity badges.
fn draw_header(frame: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(36)])
        .split(area);
    let titles = vec![Line::from(" 1: Strategy Finder "), Line::from(" 2: Run nfqws2 "), Line::from(" 3: Config & Diagnostics ")];
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)).title(Span::styled(
            format!(" zapret-rs v{} ", env!("CARGO_PKG_VERSION")),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        )))
        .select(state.tab.index())
        .highlight_style(Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD));
    frame.render_widget(tabs, cols[0]);

    let (cap_txt, cap_col) = if state.has_net_caps {
        ("CAPS OK", OK_COLOR)
    } else {
        ("NO CAPS", WARN_COLOR)
    };
    let (act_txt, act_col) = if state.finder_status == FinderStatus::Scanning {
        ("SCANNING", ACCENT)
    } else if state.run_status == RunStatus::Running {
        ("RUNNING", OK_COLOR)
    } else {
        ("IDLE", MUTED)
    };
    let badge = Paragraph::new(Line::from(vec![
        Span::styled(format!(" UID:{} ", state.uid), Style::default().fg(Color::White)),
        Span::raw("| "),
        Span::styled(cap_txt, Style::default().fg(cap_col).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled(act_txt, Style::default().fg(act_col).add_modifier(Modifier::BOLD)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)).title(" Status "));
    frame.render_widget(badge, cols[1]);
}

/// Renders Tab 1: left Setup form and right Progress / Results Table / Live Log stack.
fn draw_finder_tab(frame: &mut Frame, area: Rect, state: &AppState) {
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

    let ratio = if state.progress_total > 0 {
        (state.progress_done as f64 / state.progress_total as f64).clamp(0.0, 1.0)
    } else if state.finder_status == FinderStatus::Done {
        1.0
    } else {
        0.0
    };
    let gauge_color = match state.finder_status {
        FinderStatus::Error(_) => ERR_COLOR,
        FinderStatus::Done => OK_COLOR,
        _ => ACCENT,
    };
    let gauge = Gauge::default()
        .block(Block::default().borders(Borders::ALL).title(" Scan Progress "))
        .gauge_style(Style::default().fg(gauge_color))
        .ratio(ratio)
        .label(state.progress_label.as_str());
    frame.render_widget(gauge, right[0]);

    draw_results_table(frame, right[1], state);
    draw_log_list(frame, right[2], " Live Scan Log ", &state.finder_logs);
}

/// Renders one formatted row for [`FinderField`] inside the left Setup card.
fn format_form_row(state: &AppState, field: FinderField, focused: bool) -> ListItem<'static> {
    let cursor = if focused && state.editing_text { "_" } else { "" };
    let chk = |b: bool| if b { "[x]" } else { "[ ]" };
    let (label, value) = match field {
        FinderField::Domains => {
            let v = if state.domains_input.is_empty() && !focused {
                "<press Enter to type domain(s)>".to_owned()
            } else {
                format!("{}{cursor}", state.domains_input)
            };
            ("Domains      ", v)
        }
        FinderField::ProtoHttp => ("HTTP (80)    ", chk(state.proto_http).to_owned()),
        FinderField::ProtoTls12 => ("TLS 1.2 (443)", chk(state.proto_tls12).to_owned()),
        FinderField::ProtoTls13 => ("TLS 1.3 (443)", chk(state.proto_tls13).to_owned()),
        FinderField::ProtoHttp3 => ("HTTP/3 (UDP) ", chk(state.proto_http3).to_owned()),
        FinderField::IpMode => ("IP Version   ", state.ip_mode.label().to_owned()),
        FinderField::Level => ("Scan Level   ", state.level.as_str().to_owned()),
        FinderField::StopOnFirst => ("Stop On First", chk(state.stop_on_first).to_owned()),
        FinderField::NoNft => ("Manual nft   ", chk(state.no_nft).to_owned()),
        FinderField::LuaDir => ("Lua Dir      ", format!("{}{cursor}", state.lua_dir_input)),
        FinderField::OutputPath => ("Config Path  ", format!("{}{cursor}", state.output_path)),
    };

    let prefix = if focused { "> " } else { "  " };
    let style = if focused && state.editing_text {
        Style::default().fg(Color::Black).bg(WARN_COLOR).add_modifier(Modifier::BOLD)
    } else if focused {
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::White)
    };
    ListItem::new(Line::from(vec![
        Span::styled(format!("{prefix}{label}: "), style),
        Span::styled(value, style),
    ]))
}

/// Renders the interactive Finder configuration form card.
fn draw_finder_form(frame: &mut Frame, area: Rect, state: &AppState) {
    let items: Vec<ListItem<'static>> = FinderField::ALL
        .iter()
        .enumerate()
        .map(|(idx, &field)| format_form_row(state, field, idx == state.focus_idx))
        .collect();
    let title = if state.editing_text {
        " Strategy Setup [EDITING] "
    } else {
        " Strategy Setup "
    };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if state.editing_text { WARN_COLOR } else { ACCENT }))
            .title(title),
    );
    frame.render_widget(list, area);
}

/// Renders the per-domain results table on Tab 1.
fn draw_results_table(frame: &mut Frame, area: Rect, state: &AppState) {
    let header = Row::new(["Domain", "Proto", "Baseline", "Hits", "Best Strategy", "RTT"])
        .style(Style::default().fg(ACCENT).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = state
        .targets
        .iter()
        .map(|t| {
            let (best, rtt, col) = if t.skipped_unblocked {
                ("direct OK".to_owned(), "-".to_owned(), OK_COLOR)
            } else if let Some(m) = t.matches.first() {
                (m.strategy.id.clone(), format!("{}ms", m.latency_ms), OK_COLOR)
            } else {
                ("none".to_owned(), "-".to_owned(), ERR_COLOR)
            };
            Row::new([
                Cell::from(t.domain.clone()),
                Cell::from(format!("{}/{}", t.proto, t.ipv)),
                Cell::from(t.baseline.summary()),
                Cell::from(t.matches.len().to_string()),
                Cell::from(best).style(Style::default().fg(col)),
                Cell::from(rtt),
            ])
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
    let title = format!(" Results ({} targets, {} cover profiles) ", state.targets.len(), state.cover.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

/// Renders Tab 2: active config summary, live packet telemetry cards, and daemon log.
fn draw_run_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Length(3), Constraint::Min(6), Constraint::Length(4)])
        .split(area);

    let (st_text, st_color) = match &state.run_status {
        RunStatus::Running => ("RUNNING".to_owned(), OK_COLOR),
        RunStatus::Stopped => ("STOPPED".to_owned(), WARN_COLOR),
        RunStatus::Error(e) => (format!("ERROR: {e}"), ERR_COLOR),
    };
    let profiles_str = if state.parsed_profiles.is_empty() {
        "none loaded (run Strategy Finder or press 'l' to load config file)".to_owned()
    } else {
        state.parsed_profiles.join(", ")
    };
    let info = Paragraph::new(vec![
        Line::from(vec![
            Span::raw("Engine Status : "),
            Span::styled(st_text, Style::default().fg(st_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(format!("Config Path   : {}", state.output_path)),
        Line::from(format!("Profiles ({})  : {}", state.parsed_profiles.len(), profiles_str)),
        Line::from(format!("nftables Mode : {}", if state.no_nft { "manual (--no-nft)" } else { "managed (auto cleanup on stop)" })),
    ])
    .wrap(Wrap { trim: true })
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(ACCENT)).title(" Live nfqws2 Controller "));
    frame.render_widget(info, rows[0]);

    let (total, passed, modified, dropped) = state.counters.snapshot();
    let metric_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(rows[1]);
    for (idx, (title, val, col)) in [
        (" Total Packets ", total, ACCENT),
        (" Passed ", passed, OK_COLOR),
        (" Modified ", modified, WARN_COLOR),
        (" Dropped ", dropped, ERR_COLOR),
    ]
    .into_iter()
    .enumerate()
    {
        let card = Paragraph::new(Line::from(Span::styled(
            format!(" {val}"),
            Style::default().fg(col).add_modifier(Modifier::BOLD),
        )))
        .block(Block::default().borders(Borders::ALL).title(title));
        frame.render_widget(card, metric_cols[idx]);
    }

    draw_packet_inspector(frame, rows[2], &state.inspector.packets, state.inspector.filter, state.inspector.selected, state.inspector.paused);
    draw_log_list(frame, rows[3], " Daemon Log ", &state.run_logs);
}

/// Renders Tab 3: scrollable `nfqws2.toml` preview, `nftables` script, and capability diagnostics.
fn draw_config_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let toml_text = if state.active_toml.is_empty() {
        "# No active nfqws2.toml yet.\n# Run a scan on Tab 1 or press 'l' to load from Config Path."
    } else {
        state.active_toml.as_str()
    };
    let toml_pane = Paragraph::new(toml_text)
        .scroll((state.toml_scroll, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(format!(" nfqws2.toml ({}) ", state.output_path)),
        );
    frame.render_widget(toml_pane, cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[1]);

    let nft_pane = Paragraph::new(state.nft_preview_script())
        .wrap(Wrap { trim: false })
        .block(Block::default().borders(Borders::ALL).title(" Temporary nftables Script "));
    frame.render_widget(nft_pane, right[0]);

    let cap_line = if state.has_net_caps {
        Line::from(Span::styled("Capabilities: CAP_NET_ADMIN + CAP_NET_RAW active", Style::default().fg(OK_COLOR)))
    } else {
        Line::from(Span::styled("Capabilities: MISSING (press 'g' to grant & restart)", Style::default().fg(WARN_COLOR)))
    };
    let diag = Paragraph::new(vec![
        Line::from(format!("Effective UID: {}", state.uid)),
        cap_line,
        Line::from("Or run manually:"),
        Line::from(Span::styled(
            format!("sudo setcap cap_net_admin,cap_net_raw+ep {}", state.exe_path),
            Style::default().fg(ACCENT),
        )),
    ])
    .wrap(Wrap { trim: true })
    .block(Block::default().borders(Borders::ALL).title(" System & Privilege Diagnostics "));
    frame.render_widget(diag, right[1]);
}

/// Renders a bounded scrolling log widget showing the newest entries at the bottom.
fn draw_log_list(frame: &mut Frame, area: Rect, title: &str, logs: &std::collections::VecDeque<String>) {
    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    let skip = logs.len().saturating_sub(capacity);
    let items: Vec<ListItem> = logs
        .iter()
        .skip(skip)
        .map(|line| {
            let color = if line.starts_with("[PASS") {
                OK_COLOR
            } else if line.starts_with("[error") {
                ERR_COLOR
            } else if line.starts_with("[warn") {
                WARN_COLOR
            } else {
                Color::White
            };
            ListItem::new(Line::from(Span::styled(line.as_str(), Style::default().fg(color))))
        })
        .collect();
    let list = List::new(items).block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(list, area);
}

/// Renders the bottom contextual keybinding help and status banner.
fn draw_footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let hints = if state.editing_text {
        "[Type] Edit  [Enter/Esc] Done"
    } else if !state.has_net_caps {
        "[g] Grant Caps & Restart  [1/2/3] Tabs  [Up/Down] Move  [Enter] Edit  [q] Quit"
    } else {
        match state.tab {
            ActiveTab::Finder => "[Up/Down] Move  [Enter/Space] Edit/Toggle  [r] Start Scan  [x] Stop  [s] Save  [a] Run Tab  [q] Quit",
            ActiveTab::Run => "[r] Start/Stop  [f] Filter  [p] Pause  [Up/Down] Select  [d] Detail  [c] Clear  [l] Reload  [q] Quit",
            ActiveTab::Config => "[Up/Down/PgUp/PgDn] Scroll  [s] Save TOML  [l] Reload File  [Tab] Switch Tab  [q] Quit",
        }
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(hints, Style::default().fg(ACCENT)),
        Span::raw("  |  "),
        Span::styled(state.status_banner.as_str(), Style::default().fg(Color::White)),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(MUTED)));
    frame.render_widget(footer, area);
}
