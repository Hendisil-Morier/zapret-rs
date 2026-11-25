//! Theme-driven panel builders, `[key]` badge styling, log tagging, and TOML/`nftables` highlighters.

/// `ratatui` color, text modifier, and styling primitives.
use ratatui::{
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders},
};

/// Active configurable color palette slots.
use crate::tui::theme_config::Theme;

/// Builds a bordered [`Block`] with colored border lines and a bold colored title.
pub fn panel_block(title: impl Into<String>, border: Color, title_color: Color) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            title.into(),
            Style::default().fg(title_color).add_modifier(Modifier::BOLD),
        ))
}

/// Highlights `[key]` segments in footer and modal hint bars using `theme` colors.
pub fn styled_key_hints<'a>(hints: &'a str, theme: &Theme) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    let mut rest = hints;
    while let Some(open) = rest.find('[') {
        if open > 0 {
            spans.push(Span::styled(&rest[..open], Style::default().fg(theme.subtle)));
        }
        let after_open = &rest[open..];
        if let Some(close) = after_open.find(']') {
            let keycap = &after_open[..=close];
            spans.push(Span::styled(
                keycap,
                Style::default().fg(theme.warn_bright).add_modifier(Modifier::BOLD),
            ));
            rest = &after_open[close + 1..];
        } else {
            spans.push(Span::styled(after_open, Style::default().fg(theme.subtle)));
            rest = "";
            break;
        }
    }
    if !rest.is_empty() {
        spans.push(Span::styled(rest, Style::default().fg(theme.subtle)));
    }
    spans
}

/// Picks a semantic foreground color from `theme` for the bottom status banner message.
pub fn status_banner_color(banner: &str, theme: &Theme) -> Color {
    let lower = banner.to_ascii_lowercase();
    if lower.contains("error") || lower.contains("fail") || lower.contains("lost") || lower.contains("invalid") {
        theme.err_bright
    } else if lower.contains("warn") || lower.contains("stopped") || lower.contains("pause") || lower.contains("missing") {
        theme.warn_bright
    } else if lower.contains("attach")
        || lower.contains("running")
        || lower.contains("saved")
        || lower.contains("reload")
        || lower.contains("pushed")
        || lower.contains("active")
        || lower.contains("complete")
        || lower.contains("theme:")
    {
        theme.ok_bright
    } else {
        theme.text
    }
}

/// Formats one log line with a color-coded `[tag]` badge and readable message text.
pub fn log_line_spans<'a>(line: &'a str, theme: &Theme) -> Line<'a> {
    if line.starts_with('[')
        && let Some(end) = line.find(']')
    {
        let tag = &line[..=end];
        let body = &line[end + 1..];
        let (tag_col, body_col) = if tag.starts_with("[PASS") || tag.starts_with("[attach") {
            (theme.ok_bright, theme.ok)
        } else if tag.starts_with("[FAIL") || tag.starts_with("[error") {
            (theme.err_bright, theme.err)
        } else if tag.starts_with("[warn") {
            (theme.warn_bright, theme.warn)
        } else if tag.starts_with("[reload") || tag.starts_with("[cfg") || tag.starts_with("[stop") {
            (theme.special_bright, theme.text)
        } else {
            (theme.accent_bright, theme.subtle)
        };
        return Line::from(vec![
            Span::styled(tag, Style::default().fg(tag_col).add_modifier(Modifier::BOLD)),
            Span::styled(body, Style::default().fg(body_col)),
        ]);
    }
    Line::from(Span::styled(line, Style::default().fg(theme.text)))
}

/// Syntax-highlights TOML lines for Tab 3's `nfqws2.toml` viewer using `theme`.
pub fn highlight_toml<'a>(text: &'a str, theme: &Theme) -> Vec<Line<'a>> {
    text.lines().map(|l| highlight_toml_line(l, theme)).collect()
}

/// Highlights a single TOML line into colored `ratatui` spans.
fn highlight_toml_line<'a>(line: &'a str, theme: &Theme) -> Line<'a> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return Line::default();
    }
    if trimmed.starts_with('#') {
        return Line::from(Span::styled(line, Style::default().fg(theme.muted)));
    }
    if trimmed.starts_with('[') {
        if let Some(close) = line.rfind(']') {
            let (head, tail) = line.split_at(close + 1);
            return Line::from(vec![
                Span::styled(head, Style::default().fg(theme.special_bright).add_modifier(Modifier::BOLD)),
                Span::styled(tail, Style::default().fg(theme.muted)),
            ]);
        }
        return Line::from(Span::styled(
            line,
            Style::default().fg(theme.special_bright).add_modifier(Modifier::BOLD),
        ));
    }
    if let Some(eq_idx) = line.find('=') {
        let key = &line[..eq_idx];
        let rhs = &line[eq_idx + 1..];
        let mut spans = vec![
            Span::styled(key, Style::default().fg(theme.accent_bright)),
            Span::styled("=", Style::default().fg(theme.muted)),
        ];
        spans.extend(highlight_toml_value(rhs, theme));
        return Line::from(spans);
    }
    Line::from(Span::styled(line, Style::default().fg(theme.subtle)))
}

/// Highlights TOML value tokens (strings, numbers/booleans, punctuation, trailing comments).
fn highlight_toml_value<'a>(rhs: &'a str, theme: &Theme) -> Vec<Span<'a>> {
    let mut spans = Vec::new();
    let bytes = rhs.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let ch = bytes[idx];
        if ch == b'#' {
            spans.push(Span::styled(&rhs[idx..], Style::default().fg(theme.muted)));
            break;
        }
        if ch == b'"' || ch == b'\'' {
            let quote = ch;
            let start = idx;
            idx += 1;
            while idx < bytes.len() {
                if bytes[idx] == b'\\' && quote == b'"' && idx + 1 < bytes.len() {
                    idx += 2;
                    continue;
                }
                if bytes[idx] == quote {
                    idx += 1;
                    break;
                }
                idx += 1;
            }
            spans.push(Span::styled(&rhs[start..idx], Style::default().fg(theme.ok_bright)));
            continue;
        }
        if matches!(ch, b'[' | b']' | b'{' | b'}' | b',') {
            spans.push(Span::styled(&rhs[idx..idx + 1], Style::default().fg(theme.subtle)));
            idx += 1;
            continue;
        }
        if ch.is_ascii_whitespace() {
            let start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            spans.push(Span::raw(&rhs[start..idx]));
            continue;
        }
        let start = idx;
        while idx < bytes.len()
            && !bytes[idx].is_ascii_whitespace()
            && !matches!(bytes[idx], b'#' | b'"' | b'\'' | b'[' | b']' | b'{' | b'}' | b',')
        {
            idx += 1;
        }
        let tok = &rhs[start..idx];
        let col = if matches!(tok, "true" | "false") || tok.starts_with(|c: char| c.is_ascii_digit()) {
            theme.warn_bright
        } else {
            theme.text
        };
        spans.push(Span::styled(tok, Style::default().fg(col)));
    }
    spans
}

/// Syntax-highlights an `nftables` script for Tab 3's preview pane using `theme`.
pub fn highlight_nft<'a>(script: &'a str, theme: &Theme) -> Vec<Line<'a>> {
    script.lines().map(|l| highlight_nft_line(l, theme)).collect()
}

/// Highlights a single `nftables` rule or block header line.
fn highlight_nft_line<'a>(line: &'a str, theme: &Theme) -> Line<'a> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() {
        return Line::default();
    }
    if trimmed.starts_with('#') {
        return Line::from(Span::styled(line, Style::default().fg(theme.muted)));
    }
    let mut spans = Vec::new();
    let bytes = line.as_bytes();
    let mut idx = 0usize;
    while idx < bytes.len() {
        let ch = bytes[idx];
        if ch == b'#' {
            spans.push(Span::styled(&line[idx..], Style::default().fg(theme.muted)));
            break;
        }
        if ch.is_ascii_whitespace() {
            let start = idx;
            while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
                idx += 1;
            }
            spans.push(Span::raw(&line[start..idx]));
            continue;
        }
        if matches!(ch, b'{' | b'}' | b',' | b';') {
            spans.push(Span::styled(&line[idx..idx + 1], Style::default().fg(theme.subtle)));
            idx += 1;
            continue;
        }
        let start = idx;
        while idx < bytes.len()
            && !bytes[idx].is_ascii_whitespace()
            && !matches!(bytes[idx], b'#' | b'{' | b'}' | b',' | b';')
        {
            idx += 1;
        }
        let tok = &line[start..idx];
        spans.push(Span::styled(tok, nft_token_style(tok, theme)));
    }
    Line::from(spans)
}

/// Maps one `nftables` token to its syntax color and weight from `theme`.
fn nft_token_style(tok: &str, theme: &Theme) -> Style {
    if matches!(
        tok,
        "table" | "chain" | "flush" | "delete" | "add" | "type" | "hook" | "priority" | "policy" | "inet" | "ip" | "ip6" | "filter"
    ) {
        Style::default().fg(theme.special_bright).add_modifier(Modifier::BOLD)
    } else if matches!(tok, "accept" | "drop" | "return") {
        Style::default().fg(theme.ok_bright).add_modifier(Modifier::BOLD)
    } else if matches!(
        tok,
        "meta" | "mark" | "tcp" | "udp" | "dport" | "sport" | "ct" | "original" | "packets" | "flags" | "queue" | "to" | "bypass" | "mangle"
    ) {
        Style::default().fg(theme.accent_bright)
    } else if tok.starts_with("0x") || tok.bytes().all(|b| b.is_ascii_digit() || b == b'-') {
        Style::default().fg(theme.warn_bright)
    } else if matches!(tok, "&" | "!=" | "==" | "and" | "or") {
        Style::default().fg(theme.subtle)
    } else {
        Style::default().fg(theme.text)
    }
}
