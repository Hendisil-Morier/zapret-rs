//! Pure `ratatui` widget layout and rendering for the three-tab `zapret-rs` TUI.

/// `ratatui` frame, layout, styling, text, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Paragraph, Tabs},
};

/// Live packet detail modal overlay renderer.
use crate::tui::inspect_ui::draw_packet_detail_modal;
/// Tab 3 Config & Diagnostics rendering helper.
use crate::tui::render_config::draw_config_tab;
/// Tab 1 Strategy Finder rendering helper.
use crate::tui::render_finder::draw_finder_tab;
/// Tab 6 interactive Auto Hostlist and Blacklist rendering helper.
use crate::tui::render_hostlist::draw_hostlist_tab;
/// Tab 2 (`Run nfqws2`) rendering helper.
use crate::tui::render_run::draw_run_tab;
/// Tab 7 Settings rendering helper.
use crate::tui::render_settings::draw_settings_tab;
/// Tab 4 Speed Test rendering helper.
use crate::tui::render_speed::draw_speed_tab;
/// Tab 5 Status rendering helper.
use crate::tui::render_status::draw_status_tab;
/// Application state rendered into the terminal frame.
use crate::tui::state::AppState;
/// Shared panel border helpers, `[key]` badge styling, and status banner colors.
use crate::tui::theme::{panel_block, status_banner_color, styled_key_hints_owned};
/// Navigation tabs and live daemon/scan lifecycle statuses.
use crate::tui::types::{ActiveTab, FinderStatus, RunStatus};
/// Floating capability-grant, `sudo`, stop-confirm, domain list prompt, and `?` overlays.
use crate::tui::{keybinds::draw_keybinds_modal, modal::draw_auth_modal, prompt_modal::draw_prompt_modal};

/// Renders the entire `zapret-rs` TUI (header tabs, active tab body, and compact status strip).
pub fn draw_app(frame: &mut Frame, state: &AppState)
{
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(10), Constraint::Length(1)])
        .split(frame.area());

    draw_header(frame, chunks[0], state);
    match state.tab
    {
        ActiveTab::Finder => draw_finder_tab(frame, chunks[1], state),
        ActiveTab::Run => draw_run_tab(frame, chunks[1], state),
        ActiveTab::Config => draw_config_tab(frame, chunks[1], state),
        ActiveTab::Speed => draw_speed_tab(frame, chunks[1], state),
        ActiveTab::Status => draw_status_tab(frame, chunks[1], state),
        ActiveTab::Hostlist => draw_hostlist_tab(frame, chunks[1], state),
        ActiveTab::Settings => draw_settings_tab(frame, chunks[1], state),
    }
    draw_footer(frame, chunks[2], state);
    if state.tab == ActiveTab::Run
        && state
            .inspector
            .detail_open
        && let Some(rec) = state
            .inspector
            .selected_record()
    {
        draw_packet_detail_modal(frame, rec, &state.theme);
    }
    if state.help_open
    {
        draw_keybinds_modal(frame, state);
    }
    if let Some(modal) = &state.modal
    {
        draw_auth_modal(frame, modal, &state.theme);
    }
    if let Some(prompt) = &state.prompt_modal
    {
        draw_prompt_modal(frame, prompt, &state.theme);
    }
}

/// Renders the top navigation bar with colorful tab titles and privilege/activity badges.
fn draw_header(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Length(ActiveTab::header_status_width(area.width))])
        .split(area);
    let compact = ActiveTab::use_compact_labels(cols[0].width);
    let tab_titles = ActiveTab::SPECS
        .iter()
        .map(|spec| {
            let label = if compact { spec.compact_label } else { spec.short_label };
            Line::from(vec![
                Span::styled(
                    spec.num_prefix,
                    Style::default()
                        .fg(t.warn_bright)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(label, Style::default().fg(t.info)),
            ])
        })
        .collect::<Vec<_>>();
    let tabs = Tabs::new(tab_titles)
        .divider("|")
        .block(panel_block(format!(" zapret-rs v{} ", env!("CARGO_PKG_VERSION")), t.frame, t.accent_bright))
        .select(
            state
                .tab
                .index(),
        )
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(t.accent_bright)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, cols[0]);

    let (cap_txt, cap_col) = if state
        .status
        .has_net_caps
    {
        ("CAPS OK", t.ok_bright)
    }
    else
    {
        ("NO CAPS", t.warn_bright)
    };
    let (act_txt, act_col, badge_border) = if state
        .finder
        .status
        == FinderStatus::Scanning
    {
        ("SCANNING", t.special_bright, t.special)
    }
    else
    {
        match state
            .run
            .status
        {
            RunStatus::Running => ("RUNNING", t.ok_bright, t.ok),
            RunStatus::Attached => ("ATTACHED", t.accent_bright, t.accent),
            _ => (
                "IDLE",
                t.muted,
                if state
                    .status
                    .has_net_caps
                {
                    t.frame
                }
                else
                {
                    t.warn
                },
            ),
        }
    };
    let uid_col = if state
        .status
        .uid
        == 0
    {
        t.err_bright
    }
    else
    {
        t.text
    };
    let badge = Paragraph::new(Line::from(vec![
        Span::styled(" UID:", Style::default().fg(t.info)),
        Span::styled(
            format!(
                "{}",
                state
                    .status
                    .uid
            ),
            Style::default()
                .fg(uid_col)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("|", Style::default().fg(t.muted)),
        Span::styled(
            cap_txt,
            Style::default()
                .fg(cap_col)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("|", Style::default().fg(t.muted)),
        Span::styled(
            act_txt,
            Style::default()
                .fg(act_col)
                .add_modifier(Modifier::BOLD),
        ),
    ]))
    .block(panel_block(" Status ", badge_border, t.info));
    frame.render_widget(badge, cols[1]);
}

/// Renders the compact single-line bottom status strip with `[?] Keys` and the live status banner.
fn draw_footer(frame: &mut Frame, area: Rect, state: &AppState)
{
    let t = &state.theme;
    let g = &state
        .keybinds
        .global;
    let footer_keys = format!(
        " [{}] Keys",
        g.help
            .primary_label()
    );
    let mut line_spans = styled_key_hints_owned(&footer_keys, t);
    line_spans.push(Span::styled("  |  ", Style::default().fg(t.muted)));
    line_spans.push(Span::styled(
        state
            .status_banner
            .as_str(),
        Style::default().fg(status_banner_color(&state.status_banner, t)),
    ));
    frame.render_widget(Paragraph::new(Line::from(line_spans)), area);
}
