//! Integration tests for Tab 5 (`Status`) operational component checks, navigation, and rendering.

#![cfg(feature = "tui")]

/// Keyboard event helpers for switching to Tab 5 and navigating component rows.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless terminal backend verifying Tab 5 layout and rendering without a TTY.
use ratatui::{Terminal, backend::TestBackend};

/// TUI application state, tab enum, and root renderer under test.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, draw_app};

#[test]
fn tab5_status_populates_checks_navigates_and_renders() {
    let mut state = AppState::new(None, None, false);
    assert!(state.status_checks.is_empty());

    assert_eq!(
        state.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE)),
        AppAction::None
    );
    assert_eq!(state.tab, ActiveTab::Status);
    assert_eq!(state.status_checks.len(), 6);
    assert_eq!(state.status_selected, 0);

    let names: Vec<&str> = state.status_checks.iter().map(|c| c.name).collect();
    assert_eq!(
        names,
        [
            "Privileges",
            "Packet Driver",
            "Lua Scripts",
            "Probe (curl)",
            "Config",
            "Daemon & IPC",
        ]
    );

    state.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::NONE));
    assert_eq!(state.status_selected, 1);
    state.handle_key(KeyEvent::new(KeyCode::Home, KeyModifiers::NONE));
    assert_eq!(state.status_selected, 0);
    state.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
    assert_eq!(state.status_checks.len(), 6);

    let backend = TestBackend::new(120, 34);
    let mut term = Terminal::new(backend).expect("create test terminal");
    term.draw(|f| draw_app(f, &state)).expect("render Tab 5");

    let rendered: String = term
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("Operational Component Status"));
    assert!(rendered.contains("Component Details"));
    assert!(rendered.contains("Packet Driver"));
}
