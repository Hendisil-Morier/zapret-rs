//! Contextual `?` keybindings popup renderer — shows only bindings for the active tab.

/// `ratatui` overlay (`Clear`), layout, styling, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, Paragraph, Wrap},
};

/// Application state inspected to determine the active tab and daemon lifecycle status.
use crate::tui::state::AppState;
/// Shared keycap styling helper, centered modal rect, and bordered panel builders.
use crate::tui::theme::{centered_rect, panel_block, styled_key_hints};
/// Configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Active tab and daemon lifecycle status used to select the correct binding section.
use crate::tui::types::{ActiveTab, RunStatus};

/// Pushes a styled section heading and one or more hint rows into `lines`.
///
/// `active` controls whether the heading is highlighted as the current tab.
fn push_help_section(
    lines: &mut Vec<Line<'static>>,
    heading: &'static str,
    active: bool,
    rows: &[&'static str],
    t: &Theme,
) {
    let head_col = if active { t.ok_bright } else { t.info };
    let marker = if active { " (current tab)" } else { "" };
    lines.push(Line::from(Span::styled(
        format!("{heading}{marker}"),
        Style::default().fg(head_col).add_modifier(Modifier::BOLD),
    )));
    for row in rows {
        let owned: Vec<Span<'static>> = styled_key_hints(row, t)
            .into_iter()
            .map(|s| Span::styled(s.content.into_owned(), s.style))
            .collect();
        lines.push(Line::from(owned));
    }
    lines.push(Line::default());
}

/// Renders a centered floating `?` keybindings popup showing only the active tab's bindings.
///
/// Global bindings (tab switching, theme, quit) are always shown at the top.
/// The tab-specific section below is determined by `state.tab`, keeping the popup compact.
pub fn draw_keybinds_modal(frame: &mut Frame, state: &AppState) {
    let t = &state.theme;
    let area = frame.area();
    let w = 84u16.min(area.width.saturating_sub(4)).max(44.min(area.width));
    let h = 14u16.min(area.height.saturating_sub(2)).max(8.min(area.height));
    let popup = centered_rect(area, w, h);
    frame.render_widget(Clear, popup);

    let tab_label = state.tab.spec().full_title;
    // `panel_block` takes `&'static str`; leak the formatted title for the lifetime of this frame.
    let title = format!(" Keybindings \u{2014} {tab_label} [?] ");
    let outer = panel_block(Box::leak(title.into_boxed_str()), t.accent_bright, t.warn_bright);
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let mut lines = Vec::new();

    // Global bindings shown regardless of active tab.
    let global_row = if !state.has_net_caps {
        "[1/2/3/4] Views  [Tab/Shift+Tab] Panel  [t] Theme  [T] Save Theme  [g] Caps  [?] Help  [q] Quit"
    } else {
        "[1/2/3/4] Views  [Tab/Shift+Tab] Focus Panel  [t] Theme  [T] Save theme.toml  [?] Help  [q] Quit"
    };
    push_help_section(&mut lines, "Global", false, &[global_row], t);

    // Tab-specific section only.
    match state.tab {
        ActiveTab::Finder => {
            push_help_section(
                &mut lines,
                "Strategy Finder",
                true,
                &[
                    "[Up/Down/j/k] Move/Scroll  [Enter/Space] Edit/Toggle  [r] Start Scan  [x] Stop Scan",
                    "[Left/Right/Home/End] Cursor in field  [Del] Forward delete  [s] Save TOML  [a] Run Tab",
                ],
                t,
            );
        }
        ActiveTab::Run => {
            let run_rows: [&'static str; 2] = if state.run_status == RunStatus::Attached {
                [
                    "[x] Detach  [S] Stop Daemon  [R] Restart  [l] Reload Lists  [f] Verdict  [/] Search  [p] Pause  [d] Detail",
                    "[Up/Down/PgUp/PgDn] Select Packet / Scroll Log  [c] Clear  [Esc/Enter] Close Detail",
                ]
            } else if state.detected_socket.is_some() && state.run_status != RunStatus::Running {
                [
                    "[r] Attach  [R] Restart  [f] Verdict  [/] Search  [p] Pause  [d] Detail  [c] Clear  [l] Reload",
                    "[Up/Down/PgUp/PgDn] Select Packet / Scroll Daemon Log  [Esc/Enter] Close Detail",
                ]
            } else {
                [
                    "[r] Start/Stop  [R] Restart  [f] Verdict  [/] Search  [p] Pause  [d] Detail  [c] Clear  [l] Reload",
                    "[Up/Down/PgUp/PgDn] Select Packet / Scroll Daemon Log  [Esc/Enter] Close Detail",
                ]
            };
            let run_title = if cfg!(windows) { "Run WinDivert" } else { "Run nfqws2" };
            push_help_section(&mut lines, run_title, true, &run_rows, t);
        }
        ActiveTab::Config => {
            let cfg_row = if state.run_status == RunStatus::Attached {
                "[e/Enter] Edit ($EDITOR)  [p] Push Config  [s] Save  [l] Reload  [Up/Down/PgUp/PgDn] Scroll"
            } else {
                "[e/Enter] Edit ($EDITOR)  [s] Save  [l] Reload  [Up/Down/PgUp/PgDn/Home] Scroll TOML/nft/Hostlist"
            };
            push_help_section(&mut lines, "Config & Diagnostics", true, &[cfg_row], t);
        }
        ActiveTab::Speed => {
            push_help_section(
                &mut lines,
                "Speed Test",
                true,
                &["[r] Run Before/After Check  [x/Esc] Cancel  [c] Clear Results  [Up/Down/j/k] Select"],
                t,
            );
        }
        ActiveTab::Status => {
            push_help_section(
                &mut lines,
                "Status",
                true,
                &["[r/Enter] Refresh  [n] DNS Preset  [a] Apply DNS  [d] Debug Report  [Up/Down/Left/Right]"],
                t,
            );
        }
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[0]);
    frame.render_widget(
        Paragraph::new(Line::from(styled_key_hints("[?/Esc/Enter/q] Close", t))),
        chunks[1],
    );
}
