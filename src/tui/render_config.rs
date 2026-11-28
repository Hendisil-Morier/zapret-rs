//! Pure `ratatui` widget rendering for Tab 3 (TOML preview, `nftables` script, diagnostics).

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Style,
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
pub(crate) fn draw_config_tab(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
        .split(area);

    let toml_focused = state
        .focus
        .config
        == ConfigFocus::Toml;
    let (toml_lines, toml_title, border_color, title_color) = if state
        .config
        .active_toml
        .is_empty()
    {
        (
            vec![
                Line::from(Span::styled("# No active nfqws2.toml yet.", Style::default().fg(t.muted))),
                Line::from(Span::styled(
                    "# Run a scan on Tab 1 or press 'l' to load from Config Path.",
                    Style::default().fg(t.muted),
                )),
            ],
            format!(
                " nfqws2.toml ({}) ",
                state
                    .finder
                    .output_path
            ),
            if toml_focused { t.accent_bright } else { t.frame },
            t.accent_bright,
        )
    }
    else if let Some(err) = &state
        .config
        .toml_error
    {
        let short = err
            .lines()
            .next()
            .unwrap_or(err.as_str());
        (
            highlight_toml(
                &state
                    .config
                    .active_toml,
                t,
            ),
            format!(
                " nfqws2.toml ({}) [INVALID: {short}] ",
                state
                    .finder
                    .output_path
            ),
            t.err,
            t.err_bright,
        )
    }
    else
    {
        (
            highlight_toml(
                &state
                    .config
                    .active_toml,
                t,
            ),
            format!(
                " nfqws2.toml ({}) [VALID: {} profiles] ",
                state
                    .finder
                    .output_path,
                state
                    .config
                    .parsed_profiles
                    .len()
            ),
            if toml_focused { t.accent_bright } else { t.ok },
            t.ok_bright,
        )
    };
    let toml_pane = Paragraph::new(toml_lines)
        .scroll((
            state
                .config
                .toml_scroll,
            0,
        ))
        .block(panel_block(&toml_title, border_color, title_color));
    frame.render_widget(toml_pane, cols[0]);

    let nft_focused = state
        .focus
        .config
        == ConfigFocus::Nft;
    let nft_border = if nft_focused { t.accent_bright } else { t.frame };
    let (filter_title, nft_script) = state.filter_preview();
    let nft_pane = Paragraph::new(highlight_nft(&nft_script, t))
        .scroll((
            state
                .focus
                .nft_scroll,
            0,
        ))
        .wrap(Wrap { trim: false })
        .block(panel_block(filter_title, nft_border, t.accent_bright));
    frame.render_widget(nft_pane, cols[1]);
}
