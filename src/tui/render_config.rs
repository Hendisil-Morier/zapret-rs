//! Pure `ratatui` widget rendering for Tab 3 (TOML preview, `nftables` script, diagnostics).

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Wrap},
};

/// Application state read while rendering the Config view.
use crate::tui::state::AppState;
/// Shared panel border helper and TOML / `nftables` syntax highlighters.
use crate::tui::theme::{highlight_nft, highlight_toml, panel_block};
/// Focused panel selector for the Config tab.
use crate::tui::types::ConfigFocus;

/// Renders Tab 3: scrollable `nfqws2.toml` preview, `nftables` script, and capability diagnostics.
pub(crate) fn draw_config_tab(frame: &mut Frame, area: Rect, state: &AppState) {
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let toml_focused = state.focus.config == ConfigFocus::Toml;
    let (toml_lines, toml_title, border_color, title_color) = if state.active_toml.is_empty() {
        (
            vec![
                Line::from(Span::styled("# No active nfqws2.toml yet.", Style::default().fg(t.muted))),
                Line::from(Span::styled(
                    "# Run a scan on Tab 1 or press 'l' to load from Config Path.",
                    Style::default().fg(t.muted),
                )),
            ],
            format!(" nfqws2.toml ({}) ", state.output_path),
            if toml_focused { t.accent_bright } else { t.frame },
            t.accent_bright,
        )
    } else if let Some(err) = &state.toml_error {
        let short = err.lines().next().unwrap_or(err.as_str());
        (
            highlight_toml(&state.active_toml, t),
            format!(" nfqws2.toml ({}) [INVALID: {short}] ", state.output_path),
            t.err,
            t.err_bright,
        )
    } else {
        (
            highlight_toml(&state.active_toml, t),
            format!(" nfqws2.toml ({}) [VALID: {} profiles] ", state.output_path, state.parsed_profiles.len()),
            if toml_focused { t.accent_bright } else { t.ok },
            t.ok_bright,
        )
    };
    let toml_pane = Paragraph::new(toml_lines)
        .scroll((state.toml_scroll, 0))
        .block(panel_block(&toml_title, border_color, title_color));
    frame.render_widget(toml_pane, cols[0]);

    let right = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(cols[1]);

    let nft_focused = state.focus.config == ConfigFocus::Nft;
    let nft_border = if nft_focused { t.accent_bright } else { t.frame };
    let nft_script = state.nft_preview_script();
    let nft_pane = Paragraph::new(highlight_nft(&nft_script, t))
        .scroll((state.focus.nft_scroll, 0))
        .wrap(Wrap { trim: false })
        .block(panel_block(" Temporary nftables Script ", nft_border, t.accent_bright));
    frame.render_widget(nft_pane, right[0]);

    let (cap_line, diag_border) = if state.has_net_caps {
        (
            Line::from(Span::styled("Capabilities: CAP_NET_ADMIN + CAP_NET_RAW active", Style::default().fg(t.ok_bright))),
            t.ok,
        )
    } else {
        (
            Line::from(Span::styled("Capabilities: MISSING (press 'g' to grant & restart)", Style::default().fg(t.warn_bright))),
            t.warn,
        )
    };
    let diag = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Effective UID: ", Style::default().fg(t.info)),
            Span::styled(state.uid.to_string(), Style::default().fg(t.text).add_modifier(Modifier::BOLD)),
        ]),
        cap_line,
        Line::from(Span::styled("Or run manually:", Style::default().fg(t.subtle))),
        Line::from(Span::styled(
            format!("sudo setcap cap_net_admin,cap_net_raw+ep {}", state.exe_path),
            Style::default().fg(t.special_bright).add_modifier(Modifier::BOLD),
        )),
    ])
    .wrap(Wrap { trim: true })
    .block(panel_block(" System & Privilege Diagnostics ", diag_border, t.info));
    frame.render_widget(diag, right[1]);
}
