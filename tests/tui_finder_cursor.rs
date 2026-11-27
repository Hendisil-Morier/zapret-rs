//! Regression tests isolating Tab 1's active edit cursor from unfocused text fields.

/// Keyboard event construction for driving [`AppState::handle_key`].
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless terminal backend for asserting rendered Tab 1 lines.
use ratatui::{Terminal, backend::TestBackend};

/// Top-level TUI state and frame renderer.
use zapret_rs::tui::{AppState, draw_app};

/// Renders `state` into lines so individual form rows can be compared across cursor moves.
fn render_lines(state: &AppState) -> Vec<String> {
    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| draw_app(f, state)).expect("draw");
    let buf = term.backend().buffer();
    (0..32u16)
        .map(|y| (0..120u16).map(|x| buf[(x, y)].symbol()).collect::<String>())
        .collect()
}

/// Finds the line containing `needle` inside `lines`.
fn line_with<'a>(lines: &'a [String], needle: &str) -> &'a str {
    lines
        .iter()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("missing line containing {needle:?}"))
        .as_str()
}

#[test]
fn editing_domains_cursor_does_not_scroll_or_mark_config_path() {
    let mut state = AppState::new(None, None, false);
    state.finder.domains_input = "alpha-first-domain.com,beta-second-domain.com".to_owned();
    state.finder.output_path = "/home/user/.config/zapret-rs/very-long-config-name.toml".to_owned();

    // Start editing `Domains` (focus_idx = 0) and move cursor near the end, then left.
    state.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert!(state.finder.editing_text);

    let before_lines = render_lines(&state);
    let cfg_before = line_with(&before_lines, "Config Path");
    assert!(!cfg_before.contains('◀'), "unfocused Config Path must stay anchored at start: {cfg_before}");
    assert!(line_with(&before_lines, "Domains").contains('_'));

    // Move left 15 chars inside Domains; Config Path must remain byte-for-byte identical.
    for _ in 0..15 {
        state.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
    }
    let after_lines = render_lines(&state);
    let cfg_after = line_with(&after_lines, "Config Path");
    assert_eq!(cfg_before, cfg_after);
    assert!(line_with(&after_lines, "Domains").contains('|'));
}

#[test]
fn arrow_keys_scroll_long_text_row_without_entering_edit_mode() {
    let mut state = AppState::new(None, None, false);
    state.finder.domains_input = "alpha-first-domain.com,beta-second-domain.com,gamma-third.org".to_owned();
    state.finder.output_path = "/home/user/.config/zapret-rs/very-long-config-name.toml".to_owned();

    let initial = render_lines(&state);
    let dom0 = line_with(&initial, "Domains").to_owned();
    let cfg0 = line_with(&initial, "Config Path").to_owned();
    assert!(!state.finder.editing_text);
    assert!(dom0.contains("alpha-first"));

    // Press Right / End in view mode to scroll the text horizontally without editing.
    state.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
    let right1 = render_lines(&state);
    assert!(line_with(&right1, "Domains").contains("◀"));
    assert_eq!(line_with(&right1, "Config Path"), cfg0);

    state.handle_key(KeyEvent::new(KeyCode::End, KeyModifiers::NONE));
    let at_end = render_lines(&state);
    assert!(line_with(&at_end, "Domains").contains("gamma-third.org"));

    state.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    let at_home = render_lines(&state);
    assert!(line_with(&at_home, "Domains").contains("alpha-first"));
}
