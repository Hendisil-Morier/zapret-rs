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
use crate::tui::theme::{centered_rect, panel_block, styled_key_hints_owned};
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
    rows: &[String],
    t: &Theme,
)
{
    let head_col = if active { t.ok_bright } else { t.info };
    let marker = if active { " (current tab)" } else { "" };
    lines.push(Line::from(Span::styled(
        format!("{heading}{marker}"),
        Style::default().fg(head_col).add_modifier(Modifier::BOLD),
    )));
    for row in rows
    {
        lines.push(Line::from(styled_key_hints_owned(row, t)));
    }
    lines.push(Line::default());
}

/// Appends the Global keybinding rows to `lines`.
fn push_global_keybinds(lines: &mut Vec<Line<'static>>, state: &AppState)
{
    let t = &state.theme;
    let g = &state.keybinds.global;
    let tab_nav = format!(
        "{}..{}/{}/{}",
        g.tab_1.primary_label(),
        g.tab_7.primary_label(),
        g.prev_tab.primary_label(),
        g.next_tab.primary_label()
    );
    let panel_nav = g.next_panel.combine_labels(&g.prev_panel);
    let global_row = if !state.status.has_net_caps
    {
        format!(
            "[{tab_nav}] Tabs  [{panel_nav}] Panel  [{}] Web UI  [{}] Theme  [{}] Caps  [{}] Help  [{}] Quit",
            g.web_ui.primary_label(),
            g.cycle_theme.primary_label(),
            g.caps_modal.primary_label(),
            g.help.primary_label(),
            g.quit.primary_label(),
        )
    }
    else
    {
        format!(
            "[{tab_nav}] Tabs  [{panel_nav}] Focus Panel  [{}] Web UI  [{}] Theme  [{}] Help  [{}] Quit",
            g.web_ui.primary_label(),
            g.cycle_theme.primary_label(),
            g.help.primary_label(),
            g.quit.primary_label(),
        )
    };
    if state.web_status.is_some()
    {
        let extra = format!(
            "[{}] Open Web UI   [{}] Copy Passcode   [{}] Stop Web UI   (click URL/passcode also works)",
            g.open_web_ui.primary_label(),
            g.copy_web_passcode.primary_label(),
            g.web_ui.primary_label(),
        );
        push_help_section(lines, "Global", false, &[global_row, extra], t);
    }
    else
    {
        push_help_section(lines, "Global", false, &[global_row], t);
    }
}

/// Appends the Tab 2 (Run daemon & Packet Inspector) keybinding rows to `lines`.
fn push_run_tab_keybinds(lines: &mut Vec<Line<'static>>, state: &AppState, page_nav: &str)
{
    let t = &state.theme;
    let r = &state.keybinds.run;
    let insp = &state.keybinds.inspector;
    let row1 = if state.run.status == RunStatus::Attached
    {
        format!(
            "[{}] Detach  [{}] Stop Daemon  [{}] Restart  [{}] Reload Lists  [{}] Verdict  [{}] Search  [{}] Pause  [{}] Detail",
            r.stop_or_detach.primary_label(),
            r.stop_attached.primary_label(),
            r.restart.primary_label(),
            r.reload.primary_label(),
            insp.filter_cycle.primary_label(),
            insp.filter_edit.primary_label(),
            insp.pause.primary_label(),
            insp.detail.primary_label(),
        )
    }
    else if state.run.detected_socket.is_some() && state.run.status != RunStatus::Running
    {
        format!(
            "[{}] Attach  [{}] Restart  [{}] Verdict  [{}] Search  [{}] Pause  [{}] Detail  [{}] Clear  [{}] Reload",
            r.start_stop.primary_label(),
            r.restart.primary_label(),
            insp.filter_cycle.primary_label(),
            insp.filter_edit.primary_label(),
            insp.pause.primary_label(),
            insp.detail.primary_label(),
            r.clear.primary_label(),
            r.reload.primary_label(),
        )
    }
    else
    {
        format!(
            "[{}] Start/Stop  [{}] Restart  [{}] Verdict  [{}] Search  [{}] Pause  [{}] Detail  [{}] Clear  [{}] Reload",
            r.start_stop.primary_label(),
            r.restart.primary_label(),
            insp.filter_cycle.primary_label(),
            insp.filter_edit.primary_label(),
            insp.pause.primary_label(),
            insp.detail.primary_label(),
            r.clear.primary_label(),
            r.reload.primary_label(),
        )
    };
    let row2 = if state.run.status == RunStatus::Attached
    {
        format!(
            "[{page_nav}] Select Packet / Scroll Log  [{}] Clear  [{}] Close Detail",
            r.clear.primary_label(),
            insp.close_detail.joined_label(),
        )
    }
    else
    {
        format!(
            "[{page_nav}] Select Packet / Scroll Daemon Log  [{}] Close Detail",
            insp.close_detail.joined_label(),
        )
    };
    let run_title = if cfg!(windows) { "Run WinDivert" } else { "Run nfqws2" };
    push_help_section(lines, run_title, true, &[row1, row2], t);
}

/// Appends the active tab's keybinding rows for non-Run tabs to `lines`.
fn push_other_tab_keybinds(lines: &mut Vec<Line<'static>>, state: &AppState, v_nav: &str, page_nav: &str)
{
    let t = &state.theme;
    let k = &state.keybinds;
    let g = &k.global;
    let nav = &k.nav;
    match state.tab
    {
        ActiveTab::Finder =>
        {
            let f = &k.finder;
            let row1 = format!(
                "[{v_nav}] Move/Scroll  [{}] Edit/Toggle  [{}] Start Scan  [{}] Stop Scan",
                f.activate.joined_label(),
                f.start_scan.primary_label(),
                f.stop_scan.joined_label(),
            );
            let row2 = format!(
                "[{}/{}/{}/{}] Cursor in field  [Del] Forward delete  [{}] Save TOML  [{}] Run Tab",
                nav.left.primary_label(),
                nav.right.primary_label(),
                nav.home.primary_label(),
                nav.end.primary_label(),
                f.save_toml.primary_label(),
                f.open_run_tab.primary_label(),
            );
            push_help_section(lines, "Strategy Finder", true, &[row1, row2], t);
        }
        ActiveTab::Config =>
        {
            let c = &k.config;
            let row1 = if state.run.status == RunStatus::Attached
            {
                format!(
                    "[{}] Edit ($EDITOR)  [{}] Push Config  [{}] Save  [{}] Reload",
                    c.edit.joined_label(),
                    c.push.primary_label(),
                    c.save.primary_label(),
                    c.reload.primary_label(),
                )
            }
            else
            {
                format!(
                    "[{}] Edit ($EDITOR)  [{}] Save  [{}] Reload",
                    c.edit.joined_label(),
                    c.save.primary_label(),
                    c.reload.primary_label(),
                )
            };
            let target_lbl = if cfg!(windows) { "Filter" } else { "nft" };
            let row2 = format!(
                "[{page_nav}/{}] Scroll TOML / {target_lbl}  [{}] Switch Pane",
                nav.home.primary_label(),
                g.next_panel.primary_label(),
            );
            push_help_section(lines, "Config & Diagnostics", true, &[row1, row2], t);
        }
        ActiveTab::Speed =>
        {
            let s = &k.speed;
            let row = format!(
                "[{}] Run Before/After Check  [{}] Cancel  [{}] Clear Results  [{v_nav}] Select",
                s.start.primary_label(),
                s.cancel.joined_label(),
                s.clear.primary_label(),
            );
            push_help_section(lines, "Speed Test", true, &[row], t);
        }
        ActiveTab::Status =>
        {
            let s = &k.status;
            let row = format!(
                "[{}] Refresh  [{}] DNS Preset  [{}] Apply DNS  [{}] Debug Report  [{}/{}/{}/{}]",
                s.refresh.joined_label(),
                s.next_dns.primary_label(),
                s.apply_dns.primary_label(),
                s.export_debug.primary_label(),
                nav.up.primary_label(),
                nav.down.primary_label(),
                nav.left.primary_label(),
                nav.right.primary_label(),
            );
            push_help_section(lines, "Status", true, &[row], t);
        }
        _ => push_management_tab_keybinds(lines, state, v_nav),
    }
}

/// Appends keybinding help rows for Hostlist and Settings tabs to `lines`.
fn push_management_tab_keybinds(lines: &mut Vec<Line<'static>>, state: &AppState, v_nav: &str)
{
    let t = &state.theme;
    let k = &state.keybinds;
    let g = &k.global;
    let nav = &k.nav;
    match state.tab
    {
        ActiveTab::Hostlist =>
        {
            let hl = &k.hostlist;
            let row1 = format!(
                "[{v_nav}/{}/{}] Select  [{}/{}/{}] Switch List  [{}] Remove Selected",
                nav.page_up.primary_label(),
                nav.page_down.primary_label(),
                g.next_panel.primary_label(),
                nav.left.primary_label(),
                nav.right.primary_label(),
                hl.delete.joined_label(),
            );
            let row2 = format!(
                "[{}] Move Selected (Auto <-> Blacklist)  [{}] Add Auto  [{}] Add Blacklist  [{}] Filter  [{}] Reload",
                hl.move_entry.joined_label(),
                hl.add_auto.primary_label(),
                hl.add_blacklist.primary_label(),
                hl.filter.primary_label(),
                hl.reload.primary_label(),
            );
            push_help_section(lines, "Auto Hostlist & Blacklist", true, &[row1, row2], t);
        }
        ActiveTab::Settings =>
        {
            let st = &k.settings;
            let row1 = format!(
                "[{v_nav}/{}/{}] Navigate  [{}/{}/{}] Column  [{}] Edit/Rebind  [{}] Reset",
                nav.page_up.primary_label(),
                nav.page_down.primary_label(),
                g.next_panel.primary_label(),
                nav.left.primary_label(),
                nav.right.primary_label(),
                st.rebind.primary_label(),
                st.reset.joined_label(),
            );
            let row2 = format!(
                "[{}] Save config.toml  [{}] Reload config.toml  [{}] Open $EDITOR",
                st.save.primary_label(),
                st.reload.primary_label(),
                st.edit.primary_label(),
            );
            push_help_section(lines, "Settings (config.toml)", true, &[row1, row2], t);
        }
        _ =>
        {}
    }
}

/// Renders the centered `[?]` keybindings reference modal over the active tab.
///
/// The tab-specific section below is determined by `state.tab`, keeping the popup compact.
pub fn draw_keybinds_modal(frame: &mut Frame, state: &AppState)
{
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
    push_global_keybinds(&mut lines, state);

    let nav = &state.keybinds.nav;
    let v_nav = nav.up.combine_labels(&nav.down);
    let page_nav = format!(
        "{}/{}/{}/{}",
        nav.up.primary_label(),
        nav.down.primary_label(),
        nav.page_up.primary_label(),
        nav.page_down.primary_label()
    );
    if state.tab == ActiveTab::Run
    {
        push_run_tab_keybinds(&mut lines, state, &page_nav);
    }
    else
    {
        push_other_tab_keybinds(&mut lines, state, &v_nav, &page_nav);
    }

    let g = &state.keybinds.global;
    let close_hint = format!("[{}/Esc/Enter/{}] Close", g.help.primary_label(), g.quit.primary_label());
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), chunks[0]);
    frame.render_widget(Paragraph::new(Line::from(styled_key_hints_owned(&close_hint, t))), chunks[1]);
}
