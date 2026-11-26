//! `ratatui` widgets and hex dump renderer for Tab 2's live Packet Inspector.

/// Hex dump formatting into single-allocation strings.
use std::fmt::Write as _;

/// `ratatui` overlay, layout, styling, and table/paragraph widgets.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Clear, Paragraph, Row, Table, Wrap},
};

/// Shared packet record and outcome verdict rendered in the inspector.
use crate::telemetry::{PacketRecord, PacketVerdict};
/// Live inspector state rendered here.
use crate::tui::inspect::PacketInspectorState;
/// Shared theme panel border and centered modal rect builders.
use crate::tui::theme::{centered_rect, panel_block};
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;

/// Maps a [`PacketVerdict`] to its terminal badge color from `theme`.
const fn verdict_color(verdict: PacketVerdict, theme: &Theme) -> Color {
    match verdict {
        PacketVerdict::Pass => theme.ok_bright,
        PacketVerdict::Reasm => theme.accent_bright,
        PacketVerdict::Modify => theme.warn_bright,
        PacketVerdict::Desync => theme.special_bright,
    }
}

/// Formats `bytes` into classic 16-byte-wide `OFFSET: HEX  |ASCII|` lines.
pub fn format_hex_dump(bytes: &[u8]) -> Vec<String> {
    if bytes.is_empty() {
        return vec!["(empty payload)".to_owned()];
    }
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let mut line = String::with_capacity(76);
            let _ = write!(line, "{:04x}: ", row * 16);
            for i in 0..16 {
                if let Some(&b) = chunk.get(i) {
                    let _ = write!(line, "{b:02x} ");
                } else {
                    line.push_str("   ");
                }
                if i == 7 {
                    line.push(' ');
                }
            }
            line.push_str(" |");
            for &b in chunk {
                line.push(if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' });
            }
            line.push('|');
            line
        })
        .collect()
}

/// Renders the live scrollable Packet Inspector table on Tab 2 using `theme`.
pub fn draw_packet_inspector(
    frame: &mut Frame,
    area: Rect,
    inspector: &PacketInspectorState,
    focused: bool,
    theme: &Theme,
) {
    let visible = inspector.visible_packets();
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    let clamped_sel = inspector.selected.min(visible.len().saturating_sub(1));
    let start = if clamped_sel >= capacity { clamped_sel + 1 - capacity } else { 0 };

    let header = Row::new(["#", "Dir", "Proto", "Flow", "Len", "Verdict", "Info"])
        .style(Style::default().fg(theme.warn_bright).bg(theme.highlight_bg).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = visible
        .iter()
        .enumerate()
        .skip(start)
        .take(capacity)
        .map(|(idx, rec)| {
            let selected = idx == clamped_sel;
            let dim = if selected { theme.subtle } else { theme.muted };
            let dir_col = if rec.direction == "OUT" {
                theme.info
            } else if rec.direction == "IN" {
                theme.ok_bright
            } else {
                theme.subtle
            };
            let proto_col = match rec.proto.as_str() {
                "TCP" => theme.accent_bright,
                "UDP" => theme.special_bright,
                "ICMP" => theme.warn_bright,
                _ => theme.subtle,
            };
            let row_style = if selected {
                Style::default().bg(theme.highlight_bg).fg(theme.text).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            let flow = Line::from(vec![
                Span::styled(rec.src.as_str(), Style::default().fg(theme.text)),
                Span::styled(" -> ", Style::default().fg(dim)),
                Span::styled(rec.dst.as_str(), Style::default().fg(theme.accent_bright)),
            ]);
            let body_col = if selected { theme.text } else { theme.subtle };
            Row::new([
                Cell::from(rec.seq.to_string()).style(Style::default().fg(dim)),
                Cell::from(rec.direction.as_str()).style(Style::default().fg(dir_col).add_modifier(Modifier::BOLD)),
                Cell::from(rec.proto.as_str()).style(Style::default().fg(proto_col)),
                Cell::from(flow),
                Cell::from(format!("{}B", rec.payload_len)).style(Style::default().fg(body_col)),
                Cell::from(rec.verdict.label()).style(Style::default().fg(verdict_color(rec.verdict, theme)).add_modifier(Modifier::BOLD)),
                Cell::from(rec.info.as_str()).style(Style::default().fg(body_col)),
            ])
            .style(row_style)
        })
        .collect();

    let widths = [
        Constraint::Length(5),
        Constraint::Length(4),
        Constraint::Length(5),
        Constraint::Percentage(36),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Percentage(34),
    ];
    let (state_tag, state_col, border_col) = if inspector.paused {
        ("PAUSED", theme.warn_bright, theme.warn)
    } else if focused {
        ("LIVE", theme.ok_bright, theme.accent_bright)
    } else {
        ("LIVE", theme.ok_bright, theme.frame)
    };
    let mut title_spans = vec![
        Span::styled(" Packet Inspector [", Style::default().fg(theme.info).add_modifier(Modifier::BOLD)),
        Span::styled(state_tag, Style::default().fg(state_col).add_modifier(Modifier::BOLD)),
        Span::styled(" | filter: ", Style::default().fg(theme.subtle)),
        Span::styled(inspector.filter.label(), Style::default().fg(theme.special_bright).add_modifier(Modifier::BOLD)),
    ];
    if inspector.filter_editing || !inspector.filter_query.is_empty() {
        let cursor = if inspector.filter_editing { "_" } else { "" };
        title_spans.push(Span::styled(" | /: ", Style::default().fg(theme.subtle)));
        title_spans.push(Span::styled(
            format!("{}{cursor}", inspector.filter_query),
            Style::default().fg(theme.warn_bright).add_modifier(Modifier::BOLD),
        ));
    }
    title_spans.push(Span::styled(" | ", Style::default().fg(theme.subtle)));
    title_spans.push(Span::styled(format!("{} shown", visible.len()), Style::default().fg(theme.accent_bright)));
    title_spans.push(Span::styled("] ", Style::default().fg(theme.info).add_modifier(Modifier::BOLD)));
    let title = Line::from(title_spans);
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(border_col)).title(title));
    frame.render_widget(table, area);
}

/// Formats `bytes` into colorized 16-byte-wide hex + ASCII lines matching [`format_hex_dump`].
fn hex_dump_lines(bytes: &[u8], theme: &Theme) -> Vec<Line<'static>> {
    if bytes.is_empty() {
        return vec![Line::from(Span::styled("(empty payload)", Style::default().fg(theme.muted)))];
    }
    bytes
        .chunks(16)
        .enumerate()
        .map(|(row, chunk)| {
            let mut spans = vec![Span::styled(format!("{:04x}: ", row * 16), Style::default().fg(theme.accent_bright))];
            for i in 0..16 {
                if let Some(&b) = chunk.get(i) {
                    let col = if b == 0 { theme.muted } else { theme.text };
                    spans.push(Span::styled(format!("{b:02x} "), Style::default().fg(col)));
                } else {
                    spans.push(Span::raw("   "));
                }
                if i == 7 {
                    spans.push(Span::raw(" "));
                }
            }
            spans.push(Span::styled(" |", Style::default().fg(theme.muted)));
            for &b in chunk {
                if b.is_ascii_graphic() || b == b' ' {
                    spans.push(Span::styled((b as char).to_string(), Style::default().fg(theme.ok_bright)));
                } else {
                    spans.push(Span::styled(".", Style::default().fg(theme.muted)));
                }
            }
            spans.push(Span::styled("|", Style::default().fg(theme.muted)));
            Line::from(spans)
        })
        .collect()
}

/// Renders a centered floating detail modal showing headers and hex/ASCII dump for `rec`.
pub fn draw_packet_detail_modal(frame: &mut Frame, rec: &PacketRecord, theme: &Theme) {
    let area = frame.area();
    let w = 82u16.min(area.width.saturating_sub(4)).max(40.min(area.width));
    let h = 20u16.min(area.height.saturating_sub(2)).max(12.min(area.height));
    let popup = centered_rect(area, w, h);
    frame.render_widget(Clear, popup);

    let v_col = verdict_color(rec.verdict, theme);
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(v_col).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            format!(" Packet #{} Detail [{}] ", rec.seq, rec.verdict.label()),
            Style::default().fg(v_col).add_modifier(Modifier::BOLD),
        ));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(4), Constraint::Length(1)])
        .split(inner);

    let key_st = Style::default().fg(theme.info).add_modifier(Modifier::BOLD);
    let prof_span = match &rec.profile {
        Some(name) => Span::styled(name.as_str(), Style::default().fg(theme.special_bright).add_modifier(Modifier::BOLD)),
        None if rec.verdict == PacketVerdict::Reasm => Span::styled(
            "none (multi-segment TLS/QUIC reassembled & re-sent raw)",
            Style::default().fg(theme.accent_bright),
        ),
        None => Span::styled("none", Style::default().fg(theme.muted)),
    };
    let mut meta = vec![
        Line::from(vec![
            Span::styled("Flow    : ", key_st),
            Span::styled(format!("{} {} -> {} ", rec.direction, rec.src, rec.dst), Style::default().fg(theme.accent_bright)),
            Span::styled(format!("(iface: {})", rec.iface), Style::default().fg(theme.warn_bright)),
        ]),
        Line::from(vec![
            Span::styled("L3/Mark : ", key_st),
            Span::styled(
                format!("{}  ttl={}  fwmark=0x{:08x}  payload={} bytes", rec.proto, rec.ttl, rec.fwmark, rec.payload_len),
                Style::default().fg(theme.warn_bright),
            ),
        ]),
        Line::from(vec![Span::styled("Profile : ", key_st), prof_span]),
        Line::from(vec![
            Span::styled("Info    : ", key_st),
            Span::styled(rec.info.as_str(), Style::default().fg(theme.text)),
        ]),
    ];
    if let Some(tcp) = &rec.tcp_detail {
        meta.push(Line::from(vec![
            Span::styled("TCP     : ", key_st),
            Span::styled(tcp.as_str(), Style::default().fg(theme.ok_bright)),
        ]));
    }
    frame.render_widget(Paragraph::new(meta).wrap(Wrap { trim: true }), rows[0]);

    let dump = Paragraph::new(hex_dump_lines(&rec.payload_preview, theme))
        .block(panel_block(" Payload Preview (first 128B) ", theme.frame, theme.accent_bright));
    frame.render_widget(dump, rows[1]);

    frame.render_widget(
        Paragraph::new(Span::styled("[Esc / d / Enter] Close", Style::default().fg(theme.warn_bright).add_modifier(Modifier::BOLD))),
        rows[2],
    );
}
