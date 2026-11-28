//! TUI Web UI launcher (`W`) keybindings, modal rendering, live HTTP healthz check, and teardown tests.

#![cfg(feature = "tui")]

use std::io::{Read, Write};
use std::net::TcpStream;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend, layout::Rect};

use zapret_rs::tui::mouse::handle_mouse_event;
use zapret_rs::tui::types::ActiveTab;
use zapret_rs::tui::web_actions::{launch_web_ui, resolve_web_bind, stop_web_ui};
use zapret_rs::tui::{AppAction, AppState, PromptKind, draw_app};

fn key(code: KeyCode) -> KeyEvent
{
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn click(column: u16, row: u16) -> MouseEvent
{
    MouseEvent { kind: MouseEventKind::Down(MouseButton::Left), column, row, modifiers: KeyModifiers::NONE }
}

fn render_screen_size(state: &AppState, width: u16, height: u16) -> String
{
    let backend = TestBackend::new(width, height);
    let mut term = Terminal::new(backend).expect("term");
    term.draw(|f| draw_app(f, state)).expect("draw");
    term.backend().buffer().content().iter().map(|c| c.symbol()).collect()
}

fn render_screen(state: &AppState) -> String
{
    render_screen_size(state, 120, 32)
}

#[test]
fn global_w_key_opens_mode_modal_and_selects_lan_or_localhost()
{
    let mut state = AppState::new(None, None, false);

    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::LaunchWebUi));

    let modal_screen = render_screen(&state);
    assert!(modal_screen.contains("Launch Web Control UI"));
    assert!(modal_screen.contains("LAN / Phone"));
    assert!(modal_screen.contains("Localhost only"));
    assert!(modal_screen.contains("[Esc] Cancel"));

    // Verify zero text clipping even at 80x24 minimum size.
    let compact_screen = render_screen_size(&state, 80, 24);
    assert!(compact_screen.contains("[Esc] Cancel"));

    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    assert!(state.prompt_modal.is_none());

    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.input.as_str()), Some("lan"));
    assert_eq!(resolve_web_bind("lan"), "0.0.0.0:8787");

    assert_eq!(state.handle_key(key(KeyCode::Char('l'))), AppAction::SubmitPrompt);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.input.as_str()), Some("local"));
    assert_eq!(resolve_web_bind("local"), "127.0.0.1:8787");
}

#[test]
fn web_ui_launches_serves_healthz_displays_in_tabs_and_stops_on_second_w()
{
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

    assert_eq!(state.handle_key(key(KeyCode::Char('y'))), AppAction::CopyWebPasscode);
    assert_eq!(state.handle_key(key(KeyCode::Char('o'))), AppAction::OpenWebUi);
    assert_eq!(state.handle_key(key(KeyCode::Char('W'))), AppAction::StopWebUi);

    // Clicking the Tab 2 Web UI URL or Copy/Stop chips dispatches corresponding actions.
    state.tab = ActiveTab::Run;
    let area = Rect::new(0, 0, 120, 32);
    // Row 8 is inside Tab 2 controller card at y=3(header) + 5(Web UI line).
    assert_eq!(handle_mouse_event(&mut state, click(20, 8), area), AppAction::OpenWebUi);
    assert_eq!(handle_mouse_event(&mut state, click(55, 8), area), AppAction::CopyWebPasscode);

    let mut web_ui = Some(active);
    stop_web_ui(&mut state, &mut web_ui);
    assert!(web_ui.is_none());
    assert!(state.web_status.is_none());
    assert!(state.status_banner.contains("Stopped Web UI"));
}
