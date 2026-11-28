//! Integration tests for centralized `config.toml` loading, `nfqws2_config` routing, and remappable keybinds.

#![cfg(feature = "tui")]

/// Temporary test directory management and cleanup.
use std::fs;
/// Path helpers for verifying `--config` auto-detection and relative `nfqws2_config` paths.
use std::path::PathBuf;

/// Keyboard event helpers driving `AppState::handle_key` with remapped chords.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Headless terminal backend verifying dynamic hint labels in footer and `?` help modal.
use ratatui::{Terminal, backend::TestBackend};

/// Centralized app config parser, serializer, and startup resolver under test.
use zapret_rs::tui::app_config::{
    StartupConfigRequest, ensure_default_app_config_file, is_centralized_app_config, parse_app_config_str,
    render_app_config_toml, resolve_startup_app_config,
};
/// Shared TUI state, action enum, keybind types, and headless frame renderer.
use zapret_rs::tui::{ActiveTab, AppAction, AppState, KeyBind, KeyList, draw_app};

/// Builds an unmodified [`KeyEvent`] for `code`.
fn key(code: KeyCode) -> KeyEvent
{
    KeyEvent::new(code, KeyModifiers::NONE)
}

/// Renders `state` into plain text at `(width, height)` for UI hint verification.
fn render_to_string(state: &AppState, width: u16, height: u16) -> String
{
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal.draw(|f| draw_app(f, state)).expect("draw frame");
    let buf = terminal.backend().buffer();
    let mut out = String::new();
    for y in 0..height
    {
        for x in 0..width
        {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

/// Verifies `KeyBind` parsing, modifier chords, `Shift+Tab` / `BackTab` equivalence, and error paths.
#[test]
fn keybind_parser_handles_chords_aliases_and_rejects_invalid_specs()
{
    let ctrl_c = KeyBind::parse("Ctrl+c").expect("Ctrl+c");
    assert!(ctrl_c.matches(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)));
    assert!(!ctrl_c.matches(key(KeyCode::Char('c'))));

    let shift_tab = KeyBind::parse("Shift+Tab").expect("Shift+Tab");
    assert!(shift_tab.matches(key(KeyCode::BackTab)));
    assert!(shift_tab.matches(KeyEvent::new(KeyCode::Tab, KeyModifiers::SHIFT)));
    assert_eq!(shift_tab.format_label(), "Shift+Tab");

    let upper_h = KeyBind::parse("H").expect("H");
    assert!(upper_h.matches(KeyEvent::new(KeyCode::Char('H'), KeyModifiers::SHIFT)));
    assert!(upper_h.matches(key(KeyCode::Char('H'))));
    assert!(!upper_h.matches(key(KeyCode::Char('h'))));

    let plus = KeyBind::parse("Ctrl++").expect("Ctrl++");
    assert!(plus.matches(KeyEvent::new(KeyCode::Char('+'), KeyModifiers::CONTROL)));

    let f5 = KeyBind::parse("F5").expect("F5");
    assert!(f5.matches(key(KeyCode::F(5))));

    assert!(KeyBind::parse("").is_err());
    assert!(KeyBind::parse("Hyper+x").is_err());
    assert!(KeyBind::parse("NoSuchKey").is_err());
}

/// Verifies centralized `config.toml` round-trip serialization, partial overrides, and strict validation.
#[test]
fn centralized_config_toml_round_trips_paths_theme_and_partial_keybinds()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-cfg-rt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let cfg_path = dir.join("config.toml");

    let input = r##"
nfqws2_config = "profiles/custom-nfqws2.toml"
no_nft = true

[theme]
preset = "tokyo"
accent = "#ff00aa"

[keybinds.global]
prev_tab = "["
next_tab = "]"
quit = "Q"

[keybinds.hostlist]
delete = ["X", "Del"]
"##;

    let (resolved, has_theme) =
        parse_app_config_str(input, cfg_path.clone(), cfg_path.parent()).expect("parse config.toml");
    assert!(has_theme);
    assert_eq!(resolved.theme.name, "custom");
    assert_eq!(resolved.nfqws2_config, Some(dir.join("profiles/custom-nfqws2.toml")));
    assert!(resolved.no_nft);
    assert_eq!(resolved.keybinds.global.prev_tab, KeyList::deserialize_test("["));
    assert_eq!(resolved.keybinds.global.next_tab.joined_label(), "]");
    // Unspecified fields retain their defaults.
    assert_eq!(resolved.keybinds.global.help.primary_label(), "?");
    assert_eq!(resolved.keybinds.nav.up.joined_label(), "Up/k");
    assert_eq!(resolved.keybinds.hostlist.delete.joined_label(), "X/Del");

    let serialized = render_app_config_toml(
        Some("profiles/custom-nfqws2.toml"),
        Some("/opt/zapret/lua"),
        true,
        Some(PathBuf::from("/run/zapret.sock").as_path()),
        &resolved.theme,
        &resolved.keybinds,
    )
    .expect("serialize config.toml");
    let (re_parsed, has_theme_2) =
        parse_app_config_str(&serialized, cfg_path.clone(), cfg_path.parent()).expect("re-parse");
    assert!(has_theme_2);
    assert_eq!(re_parsed.keybinds, resolved.keybinds);
    assert_eq!(re_parsed.nfqws2_config, Some(dir.join("profiles/custom-nfqws2.toml")));

    // Typo in keybind field is rejected loudly instead of silently ignored.
    let bad = "[keybinds.global]\nprev_tba = \"[\"\n";
    assert!(parse_app_config_str(bad, cfg_path, None).is_err());

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `--config` auto-detection between `config.toml` and `nfqws2.toml`, plus CLI overrides.
#[test]
fn startup_resolver_distinguishes_app_config_from_nfqws2_and_honors_overrides()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-cfg-res-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");

    let nfq_path = dir.join("my-desync.toml");
    fs::write(&nfq_path, "qnum = 200\nfwmark = 0x40000000\n").expect("write nfqws2.toml");

    let app_cfg_path = dir.join("my-app.toml");
    fs::write(
        &app_cfg_path,
        format!(
            "nfqws2_config = \"{}\"\n[theme]\npreset = \"gruvbox\"\n[keybinds.global]\nnext_tab = \"n\"\n",
            nfq_path.display()
        ),
    )
    .expect("write app config");

    assert!(!is_centralized_app_config(&fs::read_to_string(&nfq_path).expect("read nfq"), &nfq_path));
    assert!(is_centralized_app_config(&fs::read_to_string(&app_cfg_path).expect("read app"), &app_cfg_path));

    let (resolved, warn) = resolve_startup_app_config(StartupConfigRequest {
        cli_config: Some(&app_cfg_path),
        cli_nfqws2_config: None,
        cli_lua_dir: None,
        cli_no_nft: false,
        cli_control_socket: None,
        cli_theme: Some("dracula"),
    });
    assert!(warn.is_none(), "unexpected warning: {warn:?}");
    assert_eq!(resolved.app_config_path, app_cfg_path);
    assert_eq!(resolved.nfqws2_config, Some(nfq_path.clone()));
    // CLI `--theme` overrides `[theme]` inside `config.toml`.
    assert_eq!(resolved.theme.name, "dracula");
    assert_eq!(resolved.keybinds.global.next_tab.primary_label(), "n");

    // Passing `nfqws2.toml` directly to `--config` still treats it as `nfqws2_config`.
    let override_nfq = dir.join("override.toml");
    let (direct, _) = resolve_startup_app_config(StartupConfigRequest {
        cli_config: Some(&nfq_path),
        cli_nfqws2_config: Some(&override_nfq),
        cli_lua_dir: None,
        cli_no_nft: true,
        cli_control_socket: None,
        cli_theme: None,
    });
    assert_eq!(direct.nfqws2_config, Some(override_nfq));
    assert!(direct.no_nft);

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies custom keybinds control runtime dispatch, save to `config.toml`, and update UI hints.
#[test]
fn remapped_keybinds_control_navigation_actions_saving_and_ui_hints()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-kb-rt-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");

    let cfg_path = dir.join("config.toml");
    let nfq_path = dir.join("nfqws2.toml");
    fs::write(
        &nfq_path,
        "qnum = 200\nfwmark = 0x40000000\n\n[[profiles]]\nname = \"auto\"\nhostlist_auto = \"autohostlist.txt\"\n",
    )
    .expect("write nfqws2.toml");
    fs::write(dir.join("autohostlist.txt"), "example.org\n").expect("write autohostlist");

    let cfg_text = format!(
        "nfqws2_config = \"{}\"\n\n[theme]\npreset = \"ansi\"\n\n[keybinds.global]\nhelp = \"F1\"\nprev_tab = \"[\"\nnext_tab = \"]\"\nquit = \"Q\"\nweb_ui = \"U\"\n\n[keybinds.hostlist]\ndelete = \"Z\"\n",
        nfq_path.display()
    );
    let (resolved, _) =
        parse_app_config_str(&cfg_text, cfg_path.clone(), cfg_path.parent()).expect("parse custom config");
    let mut state = AppState::from_startup_config(resolved, None);

    // Old defaults `q` / `H` / `L` / `?` no longer trigger their remapped global actions.
    assert_eq!(state.handle_key(key(KeyCode::Char('q'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('L'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Finder);
    assert_eq!(state.handle_key(key(KeyCode::Char('?'))), AppAction::None);
    assert!(!state.help_open);

    // Remapped `[` / `]` cycle tabs (`Finder -> Settings -> Hostlist`), `F1` toggles help, and `Q` quits.
    assert_eq!(state.handle_key(key(KeyCode::Char('['))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Settings);
    assert_eq!(state.handle_key(key(KeyCode::Char('['))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Hostlist);
    assert_eq!(state.handle_key(key(KeyCode::Char('d'))), AppAction::None);
    assert_eq!(state.handle_key(key(KeyCode::Char('Z'))), AppAction::DeleteSelectedDomain);

    let main_screen = render_to_string(&state, 120, 32);
    assert!(main_screen.contains("[F1] Keys"));
    assert!(main_screen.contains("[Z] Remove"));

    assert_eq!(state.handle_key(key(KeyCode::F(1))), AppAction::None);
    assert!(state.help_open);
    let help_screen = render_to_string(&state, 120, 32);
    assert!(help_screen.contains("[1..7/[/]] Tabs"));
    assert!(help_screen.contains("[Z] Remove Selected"));
    assert_eq!(state.handle_key(key(KeyCode::F(1))), AppAction::None);
    assert!(!state.help_open);

    // Tab 7 (`Settings`) explicitly saves config.toml with sparse overrides only.
    assert_eq!(state.handle_key(key(KeyCode::Char('7'))), AppAction::None);
    assert_eq!(state.tab, ActiveTab::Settings);
    assert_eq!(state.handle_key(key(KeyCode::Char('s'))), AppAction::SaveAppConfig);

    assert_eq!(state.handle_key(key(KeyCode::Char('Q'))), AppAction::Quit);
    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `import` / `imports` merges `theme.toml`, `keybinds.toml`, relative paths, and rejects cycles.
#[test]
fn config_toml_imports_theme_keybinds_nested_paths_and_rejects_cycles()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-cfg-imp-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    let sub = dir.join("sub");
    fs::create_dir_all(&sub).expect("create import dirs");

    let theme_path = dir.join("theme.toml");
    fs::write(&theme_path, "preset = \"tokyo\"\naccent = \"#112233\"\nmuted = \"gray\"\n")
        .expect("write theme.toml");
    let kb_path = dir.join("keybinds.toml");
    fs::write(&kb_path, "[global]\nprev_tab = \"[\"\nnext_tab = \"]\"\n").expect("write keybinds.toml");
    let sub_extra = sub.join("extra.toml");
    fs::write(&sub_extra, "nfqws2_config = \"./local-nfqws2.toml\"\nno_nft = true\n")
        .expect("write sub/extra.toml");

    // Style 1: top-level `import` list merging theme.toml + keybinds.toml + nested config + local override.
    let cfg_path = dir.join("config.toml");
    let root_text = r##"
import = ["./theme.toml", "./keybinds.toml", "./sub/extra.toml"]

[theme]
accent = "#445566"

[keybinds.global]
quit = "Q"
"##;
    assert!(is_centralized_app_config(root_text, &cfg_path));
    let (resolved, has_theme) =
        parse_app_config_str(root_text, cfg_path.clone(), cfg_path.parent()).expect("parse imports");
    assert!(has_theme);
    assert_eq!(resolved.theme.name, "custom");
    assert_eq!(resolved.theme.accent, ratatui::style::Color::Rgb(0x44, 0x55, 0x66));
    assert_eq!(resolved.theme.muted, ratatui::style::Color::Gray);
    assert_eq!(resolved.nfqws2_config, Some(sub.join("./local-nfqws2.toml")));
    assert!(resolved.no_nft);
    assert_eq!(resolved.keybinds.global.prev_tab.primary_label(), "[");
    assert_eq!(resolved.keybinds.global.quit.primary_label(), "Q");

    // Style 2: single-string `[theme] import = "./theme.toml"`.
    let nested_theme = "[theme]\nimport = \"./theme.toml\"\n";
    let (resolved_nested, has_nested_theme) =
        parse_app_config_str(nested_theme, cfg_path.clone(), cfg_path.parent())
            .expect("parse [theme] import");
    assert!(has_nested_theme);
    assert_eq!(resolved_nested.theme.accent, ratatui::style::Color::Rgb(0x11, 0x22, 0x33));

    // Circular imports are rejected clearly.
    let cyc_a = dir.join("cyc_a.toml");
    let cyc_b = dir.join("cyc_b.toml");
    fs::write(&cyc_a, "import = \"./cyc_b.toml\"\n").expect("write cyc_a");
    fs::write(&cyc_b, "import = \"./cyc_a.toml\"\n").expect("write cyc_b");
    let err =
        parse_app_config_str(&fs::read_to_string(&cyc_a).expect("read cyc_a"), cyc_a.clone(), cyc_a.parent())
            .expect_err("circular import must fail");
    assert!(err.contains("circular config import"), "unexpected error: {err}");

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies missing `config.toml` is auto-generated on startup and imports sibling `theme.toml`.
#[test]
fn first_run_auto_generates_config_toml_and_imports_sibling_theme()
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-cfg-init-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create init dir");

    let cfg_path = dir.join("config.toml");
    let theme_path = dir.join("theme.toml");
    fs::write(&theme_path, "preset = \"gruvbox\"\naccent = \"#aabbcc\"\n").expect("write sibling theme.toml");

    let (resolved, _) = resolve_startup_app_config(StartupConfigRequest {
        cli_config: Some(&cfg_path),
        cli_nfqws2_config: None,
        cli_lua_dir: None,
        cli_no_nft: false,
        cli_control_socket: None,
        cli_theme: None,
    });
    assert!(!cfg_path.exists());
    let warn = ensure_default_app_config_file(&resolved, "");
    assert!(warn.is_none(), "unexpected create warning: {warn:?}");
    let created = fs::read_to_string(&cfg_path).expect("auto-generated config.toml");
    assert!(created.contains("import = \"./theme.toml\""));
    // Fresh sparse config.toml omits unchanged default keybinds.
    assert!(!created.contains("[keybinds"));

    let (reloaded, _) = resolve_startup_app_config(StartupConfigRequest {
        cli_config: Some(&cfg_path),
        cli_nfqws2_config: None,
        cli_lua_dir: None,
        cli_no_nft: false,
        cli_control_socket: None,
        cli_theme: None,
    });
    assert_eq!(reloaded.theme.accent, ratatui::style::Color::Rgb(0xaa, 0xbb, 0xcc));

    let _ = fs::remove_dir_all(&dir);
}

/// Extension trait helping tests build expected [`KeyList`] assertions concisely.
trait KeyListExt
{
    /// Parses a single key spec string for assertion checks.
    fn deserialize_test(spec: &str) -> Self;
}

impl KeyListExt for KeyList
{
    fn deserialize_test(spec: &str) -> Self
    {
        Self(vec![KeyBind::parse(spec).expect("valid test key")])
    }
}
