//! TUI Web UI launcher (`W`) keybindings, modal rendering, live HTTP healthz check, and teardown tests.

#![cfg(feature = "tui")]

use std::io::{Read, Write};
use std::net::TcpStream;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use zapret_rs::tui::types::ActiveTab;
use zapret_rs::tui::web_actions::{launch_web_ui, stop_web_ui};
use zapret_rs::tui::{AppAction, AppState, PromptKind, draw_app};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn render_screen(state: &AppState) -> String {
    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("term");
    term.draw(|f| draw_app(f, state)).expect("draw");
    term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
}

#[test]
fn global_w_key_opens_mode_modal_and_selects_lan_or_localhost() {
    let mut state = AppState::new(None, None, false);

    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::LaunchWebUi));

    let modal_screen = render_screen(&state);
    assert!(modal_screen.contains("Launch Web Control UI"));
    assert!(modal_screen.contains("LAN / Phone"));
    assert!(modal_screen.contains("Localhost only"));

    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(state.prompt_modal.is_none());

    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.input.as_str()), Some("lan"));

    assert_eq!(state.handle_key(key(KeyCode::Char('l'))), AppAction::SubmitPrompt);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.input.as_str()), Some("local"));
}

#[test]
fn web_ui_launches_serves_healthz_displays_in_tabs_and_stops_on_second_w() {
    let mut state = AppState::new(None, None, false);
    state.tab = ActiveTab::Run;

    let active = launch_web_ui(&mut state, "127.0.0.1:0".parse().expect("bind addr"))
        .expect("launch_web_ui should succeed on ephemeral loopback port");
    let addr = active.handle.addr();
    let expected_url = format!("http://{addr}");
    assert_eq!(state.web_status.as_ref().map(|(u, _)| u.as_str()), Some(expected_url.as_str()));

    let run_screen = render_screen(&state);
    assert!(run_screen.contains(&expected_url));

    state.tab = ActiveTab::Status;
    state.refresh_status_checks();
    let status_screen = render_screen(&state);
    assert!(status_screen.contains("Web UI"));

    let mut stream = TcpStream::connect(addr).expect("connect to TUI web server");
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .expect("write GET /healthz");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read HTTP response");
    assert!(response.starts_with("HTTP/1.1 200 OK"), "unexpected response: {response}");

    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::StopWebUi);

    let mut web_ui = Some(active);
    stop_web_ui(&mut state, &mut web_ui);
    assert!(web_ui.is_none());
    assert!(state.web_status.is_none());
    assert!(state.status_banner.contains("Stopped Web UI"));
}
