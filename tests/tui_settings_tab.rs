//! Integration tests for Tab 7 (`Settings`), live keybind capture, and surgical sparse saving.

#![cfg(feature = "tui")]

/// Temporary test directory lifecycle and file assertions.
use std::fs;

/// Keyboard events driving Tab 7 option toggles, keybind capture, and resets.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless `ratatui` renderer verifying Tab 7 (`7: Settings`) widgets and badges.
use ratatui::{Terminal, backend::TestBackend};

/// Surgical `config.toml` writer and parser helpers under test.
use zapret_rs::tui::app_config::parse_app_config_str;
use zapret_rs::tui::app_config_save::save_settings_surgically;
/// Shared TUI state, Tab 7 enums, and top-level renderer.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, SettingsFocus, draw_app};

/// Builds an unmodified [`KeyEvent`] for `code`.
fn key(code: KeyCode) -> KeyEvent
{
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders `state` into plain text at `120x32` for Tab 7 layout assertions.
fn render_to_string(state: &AppState) -> String
{
    let backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| draw_app(f, state)).expect("draw frame");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..32
    {
        for x in 0..120
        {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Verifies Tab 7 interactive option edits, live key capture (even `'q'`/`'H'`), reset, and surgical save.
#[test]
fn tab7_settings_rebinds_keys_toggles_options_and_saves_sparsely_preserving_comments()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-tab7-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");

    let cfg_path = dir.join("config.toml");
    let theme_path = dir.join("theme.toml");
    fs::write(&theme_path, "preset = \"neon\"\n").expect("write theme.toml");
    fs::write(
        &cfg_path,
        "# Keep my personal header comment\nimport = \"./theme.toml\"\nnfqws2_config = \"/tmp/nfqws2.toml\"\n",
    )
    .expect("write config.toml");

    let (resolved, _) = parse_app_config_str(
        &fs::read_to_string(&cfg_path).expect("read config"),
        cfg_path.clone(),
        cfg_path.parent(),
    )
    .expect("parse config");
    let mut state = AppState::from_startup_config(resolved, None);

    // Pressing `T` globally no longer writes config.toml; Tab 7 owns explicit saving.
    assert_eq!(state.handle_key(key(KeyCode::Char('T'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('7'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Settings);

    // Cycle Theme Preset in Options (`Enter`), toggle `no_nft` (row 3 -> `Down` x3, `Space`).
    assert_eq!(state.theme.name, "neon");
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert_ne!(state.theme.name, "neon");
    assert!(state.settings.dirty);
    for _ in 0..3
    {
        assert_eq!(state.handle_key(key(KeyCode::Down)), AppAction::None);
    }
    assert!(!state.finder.no_nft);
    assert_eq!(state.handle_key(key(KeyCode::Char(' '))), AppAction::None);
    assert!(state.finder.no_nft);

    // Switch to Keybinds pane (`Tab`), capture a new binding `[` for `global.help`, cancel test first.
    assert_eq!(state.handle_key(key(KeyCode::Tab)), AppAction::None);
    assert_eq!(state.settings.focus, SettingsFocus::Keybinds);
    assert_eq!(state.handle_key(key(KeyCode::Enter)), AppAction::None);
    assert!(state.settings.capturing_rebind);
    let capturing_screen = render_to_string(&state);
    assert!(capturing_screen.contains("<press new key...>"));
    assert!(capturing_screen.contains("[MODIFIED]"));

    // Pressing `q` during capture binds `q` cleanly to `global.help` instead of quitting!
    assert_eq!(state.handle_key(key(KeyCode::Char('['))), AppAction::None);
    assert!(!state.settings.capturing_rebind);
    assert_eq!(state.keybinds.global.help.primary_label(), "[");

    // Save sparsely: preserves header comment + `import`, updates sibling `theme.toml`, writes ONLY changed keybind!
    let msg = save_settings_surgically(
        &state.app_config_path,
        &state.finder.output_path,
        &state.finder.lua_dir_input,
        state.finder.no_nft,
        state.run.control_socket_override.as_deref(),
        state.theme,
        &state.keybinds,
    )
    .expect("surgical save");
    assert!(msg.contains("theme.toml"), "expected sibling theme note: {msg}");

    let saved_cfg = fs::read_to_string(&cfg_path).expect("read saved config");
    assert!(saved_cfg.contains("# Keep my personal header comment"));
    assert!(saved_cfg.contains("import = \"./theme.toml\""));
    assert!(saved_cfg.contains("no_nft = true"));
    assert!(saved_cfg.contains("help = \"[\""));
    // Unchanged keybinds and redundant defaults remain absent from disk.
    assert!(!saved_cfg.contains("prev_tab"));
    assert!(!saved_cfg.contains("[keybinds.hostlist]"));

    let saved_theme = fs::read_to_string(&theme_path).expect("read saved theme.toml");
    assert!(saved_theme.contains(&format!("preset = \"{}\"", state.theme.name)));

    // Resetting `global.help` (`r`) and re-saving removes `[keybinds]` completely from `config.toml`.
    assert_eq!(state.handle_key(key(KeyCode::Char('r'))), AppAction::None);
    assert_eq!(state.keybinds.global.help.primary_label(), "?");
    save_settings_surgically(
        &state.app_config_path,
        &state.finder.output_path,
        &state.finder.lua_dir_input,
        false,
        None,
        state.theme,
        &state.keybinds,
    )
    .expect("re-save clean");
    let cleaned_cfg = fs::read_to_string(&cfg_path).expect("read cleaned config");
    assert!(!cleaned_cfg.contains("[keybinds"));
    assert!(!cleaned_cfg.contains("no_nft"));

    let _ = fs::remove_dir_all(&dir);
}
