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

/// Decoded packet records and inspector state rendered here.
use crate::tui::inspect::{PacketInspectorState, PacketRecord};

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

/// Renders the live scrollable Packet Inspector table on Tab 2.
pub fn draw_packet_inspector(frame: &mut Frame, area: Rect, inspector: &PacketInspectorState) {
    let visible = inspector.visible_packets();
    let capacity = usize::from(area.height.saturating_sub(3)).max(1);
    let clamped_sel = inspector.selected.min(visible.len().saturating_sub(1));
    let start = if clamped_sel >= capacity { clamped_sel + 1 - capacity } else { 0 };

    let header = Row::new(["#", "Dir", "Proto", "Flow", "Len", "Verdict", "Info"])
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = visible
        .iter()
        .enumerate()
        .skip(start)
        .take(capacity)
        .map(|(idx, rec)| {
            let selected = idx == clamped_sel;
            let row_style = if selected {
                Style::default().bg(Color::DarkGray).fg(Color::White).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            Row::new([
                Cell::from(rec.seq.to_string()),
                Cell::from(rec.direction),
                Cell::from(rec.proto),
                Cell::from(format!("{} -> {}", rec.src, rec.dst)),
                Cell::from(format!("{}B", rec.payload_len)),
                Cell::from(rec.verdict.label()).style(Style::default().fg(rec.verdict.color()).add_modifier(Modifier::BOLD)),
                Cell::from(rec.info.as_str()),
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
    let state_tag = if inspector.paused { "PAUSED" } else { "LIVE" };
    let title = format!(
        " Packet Inspector [{} | filter: {} | {} shown] ",
        state_tag,
        inspector.filter.label(),
        visible.len()
    );
    let table = Table::new(rows, widths)
        .header(header)
        .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

/// Renders a centered floating detail modal showing headers and hex/ASCII dump for `rec`.
pub fn draw_packet_detail_modal(frame: &mut Frame, rec: &PacketRecord) {
    let area = frame.area();
    let w = 82u16.min(area.width.saturating_sub(4)).max(40.min(area.width));
    let h = 20u16.min(area.height.saturating_sub(2)).max(12.min(area.height));
    let popup = Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w,
        height: h,
    };
    frame.render_widget(Clear, popup);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .title(Span::styled(
            format!(" Packet #{} Detail [{}] ", rec.seq, rec.verdict.label()),
            Style::default().fg(rec.verdict.color()).add_modifier(Modifier::BOLD),
        ));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(6), Constraint::Min(4), Constraint::Length(1)])
        .split(inner);

    let prof_line = match &rec.profile {
        Some(name) => format!("Profile : {name}"),
        None if rec.verdict == crate::tui::inspect::PacketVerdict::Reasm => {
            "Profile : none (multi-segment TLS/QUIC reassembled & re-sent raw)".to_owned()
        }
        None => "Profile : none".to_owned(),
    };
    let mut meta = vec![
        Line::from(format!("Flow    : {} {} -> {} (iface: {})", rec.direction, rec.src, rec.dst, rec.iface)),
        Line::from(format!("L3/Mark : {}  ttl={}  fwmark=0x{:08x}  payload={} bytes", rec.proto, rec.ttl, rec.fwmark, rec.payload_len)),
        Line::from(prof_line),
        Line::from(format!("Info    : {}", rec.info)),
    ];
    if let Some(tcp) = &rec.tcp_detail {
        meta.push(Line::from(format!("TCP     : {tcp}")));
    }
    frame.render_widget(Paragraph::new(meta).wrap(Wrap { trim: true }), rows[0]);

    let dump_lines: Vec<Line> = format_hex_dump(&rec.payload_preview).into_iter().map(Line::from).collect();
    let dump = Paragraph::new(dump_lines)
        .block(Block::default().borders(Borders::ALL).title(" Payload Preview (first 128B) "));
    frame.render_widget(dump, rows[1]);

    frame.render_widget(
        Paragraph::new(Span::styled("[Esc / d / Enter] Close", Style::default().fg(Color::Cyan))),
        rows[2],
    );
}
