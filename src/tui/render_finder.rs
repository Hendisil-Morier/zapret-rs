//! Pure `ratatui` widget rendering for Tab 1 (Strategy Finder setup, progress, results, and log).

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Gauge, List, ListItem, Row, Table},
};

/// Shared log panel widget helper reused from the top-level renderer.
use crate::tui::render::draw_log_list;
/// Application state read while rendering the Strategy Finder view.
use crate::tui::state::AppState;
/// Strategy Finder form descriptor and scan lifecycle status.
use crate::tui::types::{FinderField, FinderStatus};

/// Primary accent color for borders, titles, and active controls.
const ACCENT: Color = Color::Cyan;
/// Success badge color for passing strategies.
const OK_COLOR: Color = Color::Green;
/// Highlight color while typing into an active Finder text box.
const WARN_COLOR: Color = Color::Yellow;
/// Error color for failed strategies or scan errors.
const ERR_COLOR: Color = Color::Red;

/// Renders Tab 1: left Setup form and right Progress / Results Table / Live Log stack.
pub(crate) fn draw_finder_tab(frame: &mut Frame, area: Rect, state: &AppState) {
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
