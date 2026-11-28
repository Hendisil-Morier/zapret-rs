//! Offline TUI tests for Tab 6 interactive Auto Hostlist, Blacklist, filtering, and direct row actions.

use std::fs;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{Terminal, backend::TestBackend};

use zapret_rs::tui::hostlist_tab::{delete_selected_hostlist_offline, move_selected_hostlist_offline};
use zapret_rs::tui::types::ActiveTab;
use zapret_rs::tui::web_actions::apply_prompt_offline;
use zapret_rs::tui::{AppAction, AppState, HostlistFocus, PromptKind, draw_app};

fn key(code: KeyCode) -> KeyEvent
{
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn type_str(state: &mut AppState, text: &str)
{
    for ch in text.chars()
    {
        state.handle_key(key(KeyCode::Char(ch)));
    }
}

/// Verifies selecting, deleting, and transferring entries between Auto Hostlist and Blacklist.
fn verify_hostlist_selection_and_move(state: &mut AppState)
{
    assert_eq!(state.handle_key(key(KeyCode::Down)), AppAction::None);
    assert_eq!(state.hostlist.auto_sel, 1);
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::DeleteSelectedDomain);
    assert!(state.prompt_modal.is_none());
    delete_selected_hostlist_offline(state);
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned()]);

    assert_eq!(state.hostlist.auto_sel, 0);
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::MoveHostlistEntry);
    move_selected_hostlist_offline(state);
    assert!(state.config.autohostlist_entries.is_empty());
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned(), "blocked.org".to_owned()]);

    assert_eq!(state.handle_key(key(KeyCode::Right)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Down)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('m'))), AppAction::MoveHostlistEntry);
    move_selected_hostlist_offline(state);
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned()]);
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned()]);
    assert_eq!(state.handle_key(key(KeyCode::Left)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::MoveHostlistEntry);
    move_selected_hostlist_offline(state);
    assert!(state.config.autohostlist_entries.is_empty());
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned(), "blocked.org".to_owned()]);
}

/// Verifies `/` search filtering, filtered deletion, and deleting/moving learned bare IP entries.
fn verify_hostlist_filter_and_bare_ips(state: &mut AppState, dir: &std::path::Path)
{
    assert_eq!(state.handle_key(key(KeyCode::Char('/'))), AppAction::None);
    assert!(state.hostlist.filter_editing);
    type_str(state, "block");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Right)), AppAction::None);
    assert_eq!(state.hostlist.focus, HostlistFocus::Blacklist);
    assert_eq!(state.handle_key(key(KeyCode::Delete)), AppAction::DeleteSelectedDomain);
    delete_selected_hostlist_offline(state);
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned()]);

    assert_eq!(state.handle_key(key(KeyCode::Esc)), AppAction::None);
    state.set_active_toml(
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\nhostlist_exclude_domains = [\"bank.example.com\"]\n".to_owned(),
    );
    fs::write(dir.join("autohostlist.txt"), "172.237.72.43\n198.51.100.7\n").expect("seed ips");
    state.refresh_autohostlist();
    assert_eq!(
        state.config.autohostlist_entries,
        vec!["172.237.72.43".to_owned(), "198.51.100.7".to_owned()]
    );
    assert_eq!(state.handle_key(key(KeyCode::Left)), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::DeleteSelectedDomain);
    delete_selected_hostlist_offline(state);
    assert_eq!(state.config.autohostlist_entries, vec!["198.51.100.7".to_owned()]);
    assert_eq!(state.handle_key(key(KeyCode::Char('x'))), AppAction::MoveHostlistEntry);
    move_selected_hostlist_offline(state);
    assert!(state.config.autohostlist_entries.is_empty());
    assert_eq!(state.config.exclude_entries, vec!["198.51.100.7".to_owned(), "bank.example.com".to_owned()]);
}

/// Seeds initial blacklist and autohostlist domains on Tab 6 and renders the two columns.
fn verify_hostlist_modal_seeding_and_render(state: &mut AppState, cfg_path: &std::path::Path)
{
    assert_eq!(state.handle_key(key(KeyCode::Char('b'))), AppAction::None);
    assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::BlacklistDomain));
    type_str(state, "Bank.Example.com");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
    apply_prompt_offline(state);
    assert!(state.prompt_modal.is_none());
    assert_eq!(state.config.exclude_entries, vec!["bank.example.com".to_owned()]);
    assert!(fs::read_to_string(cfg_path).expect("read").contains("hostlist_exclude_domains"));

    state.set_active_toml(
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\nhostlist_exclude_domains = [\"bank.example.com\"]\n".to_owned(),
    );
    for dom in ["blocked.org", "track.org"]
    {
        assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
        assert_eq!(state.prompt_modal.as_ref().map(|m| m.kind), Some(PromptKind::AddAutoHostlist));
        type_str(state, dom);
        assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::SubmitPrompt);
        apply_prompt_offline(state);
    }
    assert_eq!(state.config.autohostlist_entries, vec!["blocked.org".to_owned(), "track.org".to_owned()]);

    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("term");
    term.draw(|f| draw_app(f, state)).expect("draw");
    let screen: String = term.backend().buffer().content().iter().map(|c| c.symbol()).collect();
    assert!(screen.contains("Auto Hostlist (2)") && screen.contains("Blacklist (1)"));
    assert!(screen.contains("blocked.org") && screen.contains("bank.example.com"));
}

#[test]
fn tab6_hostlist_interactive_add_filter_direct_delete_and_move_to_blacklist()
{
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_nanos();
    let dir = std::env::temp_dir().join(format!("zapret_tui_lists_{}_{nanos}", std::process::id()));
    fs::create_dir_all(&dir).expect("mkdir");
    let cfg_path = dir.join("nfqws2.toml");

    fs::write(
        &cfg_path,
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"tls13:multisplit\"\nhostlist_domains = [\"example.com\"]\n",
    )
    .expect("write cfg");

    let mut state = AppState::new(Some(cfg_path.clone()), None, false);
    assert_eq!(state.handle_key(key(KeyCode::Char('6'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Hostlist);

    assert_eq!(state.handle_key(key(KeyCode::Char('a'))), AppAction::None);
    assert!(state.prompt_modal.is_none());
    assert!(state.status_banner.contains("Auto Hostlist is off"));

    verify_hostlist_modal_seeding_and_render(&mut state, &cfg_path);
    verify_hostlist_selection_and_move(&mut state);
    verify_hostlist_filter_and_bare_ips(&mut state, &dir);

    let _ = fs::remove_dir_all(&dir);
}
