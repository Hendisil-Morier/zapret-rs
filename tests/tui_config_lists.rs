//! Offline TUI tests for Tab 3 Blacklist (`hostlist_exclude`) and Auto Hostlist domain editing.

use std::fs;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use zapret_rs::tui::types::ActiveTab;
use zapret_rs::tui::web_actions::apply_prompt_offline;
use zapret_rs::tui::{AppAction, AppState, PromptKind, draw_app};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn type_str(state: &mut AppState, text: &str) {
    for ch in text.chars() {
        state.handle_key(key(KeyCode::Char(ch)));
    }
}

#[test]
fn tab3_blacklist_and_conditional_autohostlist_prompts_persist_and_render() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_tui_lists_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("nfqws2.toml");

    // Start with a profile that does NOT set `hostlist_auto` (`ScannedOnly`).
    fs::write(
        &cfg_path,
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"tls13:multisplit\"\nhostlist_domains = [\"example.com\"]\n",
    )
    .expect("write cfg");

    let mut state = AppState::new(Some(cfg_path.clone()), None, false);
    state.tab = ActiveTab::Config;

    // `a` must refuse opening Auto Hostlist modal while `hostlist_auto` is unset.
    assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
    assert!(state.prompt_modal.is_none());
    assert!(state.status_banner.contains("Auto Hostlist is off"));

    // `b` opens Blacklist modal, adds `bank.example.com` to `hostlist_exclude_domains`, and saves TOML.
    assert_eq!(state.handle_key(key(KeyCode::Char('b'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::BlacklistDomain));
    type_str(&mut state, "Bank.Example.com");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    apply_prompt_offline(&mut state);
    assert!(state.prompt_modal.is_none());
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned()]);
    assert!(fs::read_to_string(&cfg_path).expect("read").contains("hostlist_exclude_domains"));

    // Render Tab 3 and confirm Blacklist appears cleanly.
    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("term");
    term.draw(|f| draw_app(f, &state)).expect("draw");
    let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(screen.contains("Blacklist (1)"));
    assert!(screen.contains("bank.example.com"));

    // Enable `hostlist_auto` and verify `a` adds into `autohostlist.txt` and `d` removes from Blacklist.
    state.set_active_toml(
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\nhostlist_exclude_domains = [\"bank.example.com\"]\n".to_owned(),
    );
    assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::AddAutoHostlist));
    type_str(&mut state, "blocked.org");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    apply_prompt_offline(&mut state);
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned()]);

    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::RemoveListDomain));
    type_str(&mut state, "bank.example.com");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    apply_prompt_offline(&mut state);
    assert!(state.config.exclude_entries.is_empty());

    let _ = fs::remove_dir_all(&dir);
}
