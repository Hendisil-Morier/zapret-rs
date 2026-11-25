//! Pure `ratatui` widget layout and rendering for the three-tab `zapret-rs` TUI.

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Tabs, Wrap},
};

/// Live packet inspector table and detail overlay renderers.
use crate::tui::inspect_ui::{draw_packet_detail_modal, draw_packet_inspector};
/// Floating capability-grant, `sudo` password, and confirmation modal overlay renderer.
use crate::tui::modal::draw_auth_modal;
/// Tab 1 Strategy Finder rendering helper.
use crate::tui::render_finder::draw_finder_tab;
/// Application state rendered into the terminal frame.
use crate::tui::state::AppState;
/// Navigation tabs and live daemon/scan lifecycle statuses.
use crate::tui::types::{ActiveTab, FinderStatus, RunStatus};

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
    if state.tab == ActiveTab::Run
        && state.inspector.detail_open
        && let Some(rec) = state.inspector.selected_record()
    {
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
    let titles = vec![
        Line::from(" 1: Strategy Finder "),
        Line::from(" 2: Run nfqws2 "),
        Line::from(" 3: Config & Diagnostics "),
    ];
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
    } else {
        match state.run_status {
            RunStatus::Running => ("RUNNING", OK_COLOR),
            RunStatus::Attached => ("ATTACHED", ACCENT),
            _ => ("IDLE", MUTED),
        }
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

/// Formats controller summary lines for Tab 2 based on local vs remote-attached mode.
fn run_controller_lines(state: &AppState) -> Vec<Line<'static>> {
    if state.run_status == RunStatus::Attached
        && let Some(meta) = &state.remote_meta
    {
        let profs = if meta.profile_names.is_empty() {
            "none (pass-through)".to_owned()
        } else {
            meta.profile_names.join(", ")
        };
        let cfg_display = meta
            .config_path
            .as_deref()
            .unwrap_or("(daemon defaults / CLI args)");
        return vec![
            Line::from(vec![
                Span::raw("Engine Status : "),
                Span::styled(
                    format!(
                        "ATTACHED (PID {}, qnum {}, socket {})",
                        meta.pid,
                        meta.qnum,
                        meta.socket_path.display()
                    ),
                    Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(format!("Config Path   : {cfg_display}")),
            Line::from(format!("Profiles ({})  : {profs}", meta.profile_names.len())),
            Line::from(format!(
                "nftables Mode : daemon-managed (fwmark 0x{:08x})",
                meta.fwmark
            )),
        ];
    }

    let (st_text, st_color) = match &state.run_status {
        RunStatus::Running => ("RUNNING".to_owned(), OK_COLOR),
        RunStatus::Attached => ("ATTACHED".to_owned(), ACCENT),
        RunStatus::Stopped => match &state.detected_socket {
            Some(sock) => (
                format!("STOPPED (daemon socket found at {}; press 'r' to attach)", sock.display()),
                WARN_COLOR,
            ),
            None => ("STOPPED".to_owned(), WARN_COLOR),
        },
        RunStatus::Error(e) => (format!("ERROR: {e}"), ERR_COLOR),
    };
    let profiles_str = if state.parsed_profiles.is_empty() {
        "none loaded (run Strategy Finder or press 'l' to load config file)".to_owned()
    } else {
        state.parsed_profiles.join(", ")
    };
    vec![
        Line::from(vec![
            Span::raw("Engine Status : "),
            Span::styled(st_text, Style::default().fg(st_color).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(format!("Config Path   : {}", state.output_path)),
        Line::from(format!("Profiles ({})  : {}", state.parsed_profiles.len(), profiles_str)),
        Line::from(format!(
            "nftables Mode : {}",
            if state.no_nft { "manual (--no-nft)" } else { "managed (auto cleanup on stop)" }
        )),
    ]
}

/// Renders Tab 2: active config summary, live packet telemetry cards, and daemon log.
fn draw_run_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(3),
            Constraint::Min(6),
            Constraint::Length(4),
        ])
        .split(area);

    let info = Paragraph::new(run_controller_lines(state))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(ACCENT))
                .title(" Live nfqws2 Controller "),
        );
    frame.render_widget(info, rows[0]);

    let (total, passed, reasm, modified, desynced) = state.counters.snapshot();
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
    for (idx, (title, val, col)) in [
        (" Total ", total, ACCENT),
        (" Passed ", passed, OK_COLOR),
        (" Reasm ", reasm, Color::Cyan),
        (" Modified ", modified, WARN_COLOR),
        (" Desync ", desynced, Color::Magenta),
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

    draw_packet_inspector(frame, rows[2], &state.inspector);
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
    let (toml_title, border_color) = if let Some(err) = &state.toml_error {
        let short = err.lines().next().unwrap_or(err.as_str());
        (format!(" nfqws2.toml ({}) [INVALID: {short}] ", state.output_path), ERR_COLOR)
    } else if !state.active_toml.trim().is_empty() {
        (format!(" nfqws2.toml ({}) [VALID: {} profiles] ", state.output_path, state.parsed_profiles.len()), ACCENT)
    } else {
        (format!(" nfqws2.toml ({}) ", state.output_path), ACCENT)
    };
    let toml_pane = Paragraph::new(toml_text)
        .scroll((state.toml_scroll, 0))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(border_color)).title(toml_title));
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
pub(crate) fn draw_log_list(frame: &mut Frame, area: Rect, title: &str, logs: &std::collections::VecDeque<String>) {
    let capacity = usize::from(area.height.saturating_sub(2)).max(1);
    let skip = logs.len().saturating_sub(capacity);
    let items: Vec<ListItem> = logs
        .iter()
        .skip(skip)
        .map(|line| {
            let color = if line.starts_with("[PASS") || line.starts_with("[attach") {
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
    } else if !state.has_net_caps && state.run_status != RunStatus::Attached {
        "[g] Grant Caps & Restart  [1/2/3] Tabs  [Up/Down] Move  [Enter] Edit  [q] Quit"
    } else {
        match state.tab {
            ActiveTab::Finder => "[Up/Down] Move  [Enter/Space] Edit/Toggle  [r] Start Scan  [x] Stop  [s] Save  [a] Run Tab  [q] Quit",
            ActiveTab::Run if state.run_status == RunStatus::Attached => {
                "[x] Detach  [S] Stop Daemon  [l] Reload Lists  [f] Filter  [p] Pause  [d] Detail  [c] Clear  [q] Quit"
            }
            ActiveTab::Run => "[r] Start/Stop  [f] Filter  [p] Pause  [Up/Down] Select  [d] Detail  [c] Clear  [l] Reload  [q] Quit",
            ActiveTab::Config => "[e/Enter] Edit ($EDITOR)  [Up/Down/PgUp/PgDn] Scroll  [s] Save  [l] Reload  [q] Quit",
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
