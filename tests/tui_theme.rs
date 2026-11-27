//! Headless `ratatui` tests for configurable TUI themes, focus tooltips, and panel-focus cycling.

#![cfg(feature = "tui")]

/// Synthetic keyboard events driven through [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless in-memory `ratatui` terminal backend for deterministic UI rendering tests.
use ratatui::{Terminal, backend::TestBackend, style::Color};

/// TUI state, theme helpers, focus enums, and frame renderer under test.
use zapret_rs::tui::{
    ActiveTab, AppState, FinderField, Theme, draw_app, theme,
    types::{ConfigFocus, FINDER_HOVER_DELAY, FinderFocus, RunFocus},
};

/// Creates a plain unmodified [`KeyEvent`] for `code`.
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders `state` into a `TestBackend` buffer of size `(width, height)` and returns the plain text.
fn render_to_string(state: &AppState, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| draw_app(f, state)).expect("draw frame");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Verifies configurable themes, TOML overrides, syntax highlighters, `t` cycling, and buffer colors.
#[test]
fn theme_syntax_highlighters_and_buffer_palette_apply_distinct_colors() {
    let custom = Theme::from_toml_str("preset = \"dracula\"\nframe = \"#123456\"\n").expect("parse theme");
    assert_eq!((custom.name, custom.frame), ("custom", Color::Rgb(0x12, 0x34, 0x56)));
    let hints = theme::styled_key_hints("[r] Start  [q] Quit", &custom);
    assert_eq!((hints[0].style.fg, hints[1].style.fg), (Some(custom.warn_bright), Some(custom.subtle)));
    assert_eq!(hints.iter().map(|s| s.content.as_ref()).collect::<String>(), "[r] Start  [q] Quit");
    let toml_lines = theme::highlight_toml("# comment\n[[profiles]]\nqnum = 200\nname = \"tls\"\n", &custom);
    assert_eq!(toml_lines[0].spans[0].style.fg, Some(custom.muted));
    assert_eq!(toml_lines[1].spans[0].style.fg, Some(custom.special_bright));
    assert_eq!(toml_lines[2].spans[0].style.fg, Some(custom.accent_bright));
    assert_eq!(toml_lines[2].spans.last().and_then(|s| s.style.fg), Some(custom.warn_bright));
    assert_eq!(toml_lines[3].spans.last().and_then(|s| s.style.fg), Some(custom.ok_bright));
    let nft_lines = theme::highlight_nft("table inet zapret {\n  meta mark & 0x4000 != 0 accept\n}", &custom);
    assert_eq!(nft_lines[0].spans[0].style.fg, Some(custom.special_bright));
    assert!(nft_lines[1].spans.iter().any(|s| s.content == "meta" && s.style.fg == Some(custom.accent_bright)));
    assert!(nft_lines[1].spans.iter().any(|s| s.content == "accept" && s.style.fg == Some(custom.ok_bright)));

    let mut state = AppState::new(None, None, false);
    let before_theme = state.theme.name;
    state.handle_key(key(KeyCode::Char('t')));
    assert_ne!(state.theme.name, before_theme, "'t' must cycle built-in presets");
    state.tab = ActiveTab::Run;
    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).expect("create TestBackend terminal");
    terminal.draw(|f| draw_app(f, &state)).expect("draw colorful Run tab");
    let cells = terminal.backend().buffer().content();
    for expected in [state.theme.frame, state.theme.ok, state.theme.special, state.theme.warn, state.theme.accent_bright] {
        assert!(cells.iter().any(|c| c.fg == expected), "expected theme color {expected:?} in Run tab buffer");
    }
}

/// Verifies Tab 1 option tooltips open after a 1-second focus dwell, reset on move, and close on Esc.
#[test]
fn finder_option_tooltip_opens_after_one_second_dwell_and_resets_on_navigation() {
    let mut state = AppState::new(None, None, false);
    let t0 = state.finder.hover.since.expect("initial hover timestamp armed");
    state.poll_finder_hover(t0);
    assert!(!state.finder.hover.open, "tooltip must stay closed immediately");

    state.poll_finder_hover(t0 + FINDER_HOVER_DELAY);
    assert!(state.finder.hover.open, "tooltip must open after 1s dwell");
    let first_popup = render_to_string(&state, 120, 32);
    assert!(first_popup.contains("? Target Domains"));
    assert!(first_popup.contains("[Esc] hide"));

    // Navigating down closes the tooltip immediately and re-arms the 1s timer on the next option.
    state.handle_key(key(KeyCode::Down));
    assert_eq!(state.focused_field(), FinderField::ProtoHttp);
    assert!(!state.finder.hover.open);
    let t1 = state.finder.hover.since.expect("hover re-armed on move");
    state.poll_finder_hover(t1 + FINDER_HOVER_DELAY);
    let second_popup = render_to_string(&state, 120, 32);
    assert!(second_popup.contains("? HTTP (TCP 80)"));

    // Pressing Esc dismisses the tooltip and pauses re-opening until further interaction.
    state.handle_key(key(KeyCode::Esc));
    assert!(!state.finder.hover.open);
    assert!(state.finder.hover.since.is_none());
    state.poll_finder_hover(t1 + FINDER_HOVER_DELAY * 5);
    assert!(!state.finder.hover.open);
}

/// Verifies `Tab`/`BackTab` cycles panel focus within each tab and scrolls logs/results/scripts.
#[test]
fn tab_cycles_panel_focus_within_tabs_and_scrolls_logs_results_and_nft_preview() {
    let mut state = AppState::new(None, None, false);
    for i in 0..20 {
        state.push_finder_log(format!("[info] scan line {i}"));
    }
    assert_eq!(state.focus.finder, FinderFocus::Setup);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.focus.finder, FinderFocus::Results);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.focus.finder, FinderFocus::Log);
    state.handle_key(key(KeyCode::Up));
    assert_eq!(state.focus.finder_log_scroll, 1);
    let scrolled = render_to_string(&state, 120, 32);
    assert!(scrolled.contains("(+1)"));
    state.handle_key(key(KeyCode::BackTab));
    assert_eq!(state.focus.finder, FinderFocus::Results);

    state.handle_key(key(KeyCode::Char('2')));
    state.push_run_log("[info] daemon line 1");
    state.push_run_log("[info] daemon line 2");
    assert_eq!(state.focus.run, RunFocus::Inspector);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.focus.run, RunFocus::Log);
    state.handle_key(key(KeyCode::Up));
    assert_eq!(state.focus.run_log_scroll, 1);

    state.handle_key(key(KeyCode::Char('3')));
    assert_eq!(state.focus.config, ConfigFocus::Toml);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.focus.config, ConfigFocus::Nft);
    state.handle_key(key(KeyCode::Down));
    assert_eq!(state.focus.nft_scroll, 1);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.focus.config, ConfigFocus::Toml);

    state.handle_key(key(KeyCode::Char('6')));
    assert_eq!(state.tab, ActiveTab::Hostlist);
    state.handle_key(key(KeyCode::Tab));
    assert_eq!(state.hostlist.focus, zapret_rs::tui::HostlistFocus::Blacklist);
}
