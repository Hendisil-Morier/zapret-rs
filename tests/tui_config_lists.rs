//! Offline TUI tests for Tab 6 interactive Auto Hostlist, Blacklist, filtering, and direct row actions.

use std::fs;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use zapret_rs::tui::hostlist_tab::{
    delete_selected_hostlist_offline, move_selected_auto_to_blacklist_offline,
};
use zapret_rs::tui::types::ActiveTab;
use zapret_rs::tui::web_actions::apply_prompt_offline;
use zapret_rs::tui::{AppAction, AppState, HostlistFocus, PromptKind, draw_app};

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn type_str(state: &mut AppState, text: &str) {
    for ch in text.chars() {
        state.handle_key(key(KeyCode::Char(ch)));
    }
}

#[test]
fn tab6_hostlist_interactive_add_filter_direct_delete_and_move_to_blacklist() {
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
    assert_eq!(state.handle_key(key(KeyCode::Char('6'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Hostlist);

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

    // Enable `hostlist_auto` and verify `a` appends `blocked.org` and `track.org`.
    state.set_active_toml(
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\nhostlist_exclude_domains = [\"bank.example.com\"]\n".to_owned(),
    );
    for dom in ["blocked.org", "track.org"] {
        assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
        assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::AddAutoHostlist));
        type_str(&mut state, dom);
        assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
        apply_prompt_offline(&mut state);
    }
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned(), "track.org".to_owned()]);

    // Render Tab 6 and confirm both columns render cleanly with cursor highlight.
    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("term");
    term.draw(|f| draw_app(f, &state)).expect("draw");
    let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(screen.contains("Auto Hostlist (2)") && screen.contains("Blacklist (1)"));
    assert!(screen.contains("blocked.org") && screen.contains("bank.example.com"));

    // Select `track.org` with `Down` and delete it directly via `d` with NO typing prompt.
    assert_eq!(state.handle_key(key(KeyCode::Down)), AppAction::None);
    assert_eq!(state.hostlist.auto_sel, 1);
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::DeleteSelectedDomain);
    assert!(state.prompt_modal.is_none());
    delete_selected_hostlist_offline(&mut state);
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned()]);

    // Move remaining selected `blocked.org` directly into Blacklist with `x`.
    assert_eq!(state.hostlist.auto_sel, 0);
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::MoveAutoToBlacklist);
    move_selected_auto_to_blacklist_offline(&mut state);
    assert!(state.config.autohostlist_entries.is_empty());
    assert_eq!(
        state.config.exclude_entries,
        vec!["bank.example.com".to_owned(), "blocked.org".to_owned()]
    );

    // Filter with `/`, switch to Blacklist with `Right`, and delete filtered match via `Delete`.
    assert_eq!(state.handle_key(key(KeyCode::Char('/'))), AppAction::None);
    assert!(state.hostlist.filter_editing);
    type_str(&mut state, "block");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Right)), AppAction::None);
    assert_eq!(state.hostlist.focus, HostlistFocus::Blacklist);
    assert_eq!(state.handle_key(key(KeyCode::Delete)), AppAction::DeleteSelectedDomain);
    delete_selected_hostlist_offline(&mut state);
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned()]);

    let _ = fs::remove_dir_all(&dir);
}
