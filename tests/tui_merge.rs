//! Integration tests for Tab 1 domain persistence/seeding and scan-completion merge prompts.

/// Keyboard event helpers for dismissing or submitting the merge modal.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Temporary directory creation for isolated domain history + config fixtures.
use std::fs;
/// Unique temp path helper.
use std::path::PathBuf;

/// Strategy TOML fixture builders and merge helper under test.
use zapret_rs::tools::{
    CoveredProfile, DomainScope, IpFamily, ProbeOutcome, ProbeProtocol, ScanLevel, ScanReport, StrategyMatch,
    TargetScanResult, TomlRenderOptions, build_catalog, merge_nfqws2_toml, render_nfqws2_toml,
};
/// TUI session domain persistence and state machine types under test.
use zapret_rs::tui::session::{
    domains_history_path, save_domains_history, seed_autohostlists_from_domains, seed_domains_on_startup,
};
use zapret_rs::tui::{AppAction, AppState, AuthModal, FinderField, ModalPurpose, ScanUiEvent, draw_app};

/// Creates a unique scratch directory under the OS temp dir.
fn temp_cfg_dir(tag: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-tui-merge-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn startup_seeding_uses_saved_domains_then_falls_back_to_hostlist_domains()
{
    let dir = temp_cfg_dir("seed");
    let cfg_path = dir.join("nfqws2.toml");

    let strat = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4)[0].clone();
    let existing = render_nfqws2_toml(
        &[CoveredProfile {
            strategy: strat,
            domains: vec!["youtube.com".to_owned(), "discord.com".to_owned()],
            avg_latency_ms: 40,
        }],
        &TomlRenderOptions::default(),
    );
    fs::write(&cfg_path, &existing).expect("write fixture toml");

    // Without saved history file, seeding extracts inline hostlist_domains from active_toml.
    let mut state = AppState::new(Some(cfg_path.clone()), None, false);
    state
        .finder
        .domains_input
        .clear();
    seed_domains_on_startup(&mut state);
    assert_eq!(
        state
            .finder
            .domains_input,
        "youtube.com, discord.com"
    );

    // Once user saves a custom domain list, subsequent startups prefer the saved history file.
    state
        .finder
        .domains_input = "store.steampowered.com".to_owned();
    save_domains_history(&state);
    assert!(
        domains_history_path(
            &state
                .finder
                .output_path
        )
        .is_file()
    );

    let mut reloaded = AppState::new(Some(cfg_path), None, false);
    reloaded
        .finder
        .domains_input
        .clear();
    seed_domains_on_startup(&mut reloaded);
    assert_eq!(
        reloaded
            .finder
            .domains_input,
        "store.steampowered.com"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies ConfirmMergeConfig popup rendering, Esc discard, and 'k' keep-existing flow.
fn verify_merge_modal_and_keep_existing(
    state: &mut AppState,
    prev: &str,
    new_only: &str,
    rendered_new: &str,
    existing: &str,
)
{
    let merged = merge_nfqws2_toml(prev, new_only).expect("merge succeeds");
    assert!(merged.contains("old.example") && merged.contains("new.example"));

    state.modal =
        Some(AuthModal::confirm(ModalPurpose::ConfirmMergeConfig, "merge 2 new profile(s)".to_owned()));
    {
        use ratatui::{Terminal, backend::TestBackend};
        use zapret_rs::tui::draw_app;
        let mut term = Terminal::new(TestBackend::new(100, 30)).expect("create test terminal");
        term.draw(|f| draw_app(f, state))
            .expect("render ConfirmMergeConfig modal");
        let rendered: String = term
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|c| c.symbol())
            .collect();
        assert!(rendered.contains("Merge Existing nfqws2.toml Profiles?"));
        assert!(rendered.contains("Action : merge 2 new profile(s)"));
        assert!(rendered.contains("[Enter] Merge Profiles"));
        assert!(!rendered.contains("Enter: merge profiles |"));
        assert!(!rendered.contains("sudo password"));
    }
    assert_eq!(state.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)), AppAction::None);
    assert!(
        state
            .config
            .pending_merge
            .is_none()
    );
    assert_eq!(
        state
            .config
            .active_toml,
        rendered_new
    );

    state
        .config
        .pending_merge = Some((prev.to_owned(), new_only.to_owned()));
    state.modal = Some(AuthModal::confirm(ModalPurpose::ConfirmMergeConfig, "merge".to_owned()));
    assert_eq!(state.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE)), AppAction::None);
    assert!(
        state
            .modal
            .is_none()
    );
    assert!(
        state
            .config
            .pending_merge
            .is_none()
    );
    assert_eq!(
        state
            .config
            .active_toml,
        existing
    );
}

#[test]
fn scan_completion_stashes_pending_merge_and_esc_keeps_new_scan_only()
{
    let tls_strats = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4);
    let http_strats = build_catalog(ProbeProtocol::Http, ScanLevel::Quick, IpFamily::V4);

    let existing = render_nfqws2_toml(
        &[CoveredProfile {
            strategy: http_strats[0].clone(),
            domains: vec!["old.example".to_owned()],
            avg_latency_ms: 25,
        }],
        &TomlRenderOptions::default(),
    );
    let spec_new = tls_strats[0].clone();
    let cover_new = vec![CoveredProfile {
        strategy: spec_new.clone(),
        domains: vec!["new.example".to_owned()],
        avg_latency_ms: 45,
    }];
    let rendered_new = render_nfqws2_toml(&cover_new, &TomlRenderOptions::default());

    let mut state = AppState::new(None, None, false);
    state.set_active_toml(existing.clone());

    state.apply_scan_event(ScanUiEvent::Completed {
        report: ScanReport {
            targets: vec![TargetScanResult {
                domain: "new.example".to_owned(),
                proto: ProbeProtocol::Tls13,
                ipv: IpFamily::V4,
                baseline: ProbeOutcome::Timeout,
                skipped_unblocked: false,
                tested_count: 1,
                matches: vec![StrategyMatch { strategy: spec_new, latency_ms: 45 }],
            }],
            cover: cover_new,
            interrupted: false,
        },
        rendered_toml: rendered_new.clone(),
    });

    // Existing profiles trigger `pending_merge` with (previous, new_scan).
    let (prev, new_only) = state
        .config
        .pending_merge
        .clone()
        .expect("pending_merge populated");
    assert_eq!(prev, existing);
    assert_eq!(new_only, rendered_new);

    verify_merge_modal_and_keep_existing(&mut state, &prev, &new_only, &rendered_new, &existing);
}

#[test]
fn tab1_domain_scope_row_cycles_options_and_renders_in_setup_form()
{
    use ratatui::{Terminal, backend::TestBackend};

    let mut state = AppState::new(None, None, false);
    assert_eq!(
        state
            .finder
            .domain_scope,
        DomainScope::ScannedOnly
    );
    state
        .finder
        .focus_idx = FinderField::ALL.len() - 1;
    assert_eq!(state.focused_field(), FinderField::DomainScope);

    state.handle_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::NONE));
    assert_eq!(
        state
            .finder
            .domain_scope,
        DomainScope::AllDomains
    );
    state.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        state
            .finder
            .domain_scope,
        DomainScope::AutoHostlist
    );

    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| draw_app(f, &state))
        .expect("draw");
    let rendered: String = term
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("Domain Scope") && rendered.contains("Auto Hostlist"));

    state.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
    assert_eq!(
        state
            .finder
            .domain_scope,
        DomainScope::ScannedOnly
    );
}

#[test]
fn tab3_auto_hostlist_panel_loads_and_renders_learned_domains()
{
    use ratatui::{Terminal, backend::TestBackend};
    use zapret_rs::tools::render_nfqws2_toml_scoped;
    use zapret_rs::tui::types::ActiveTab;

    let dir = temp_cfg_dir("autolist-ui");
    let cfg_path = dir.join("nfqws2.toml");
    let autolist_path = dir.join("autohostlist.txt");

    let strat = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4)[0].clone();
    let cfg_toml = render_nfqws2_toml_scoped(
        &[CoveredProfile { strategy: strat, domains: vec!["seed.example".to_owned()], avg_latency_ms: 40 }],
        &TomlRenderOptions::default(),
        DomainScope::AutoHostlist,
    );
    fs::write(&cfg_path, &cfg_toml).expect("write nfqws2.toml");

    let mut state = AppState::new(Some(cfg_path), None, false);
    state
        .finder
        .domains_input = "blocked-one.example, blocked-two.example".to_owned();
    seed_autohostlists_from_domains(&mut state);
    state.tab = ActiveTab::Hostlist;
    assert_eq!(
        state
            .config
            .autohostlist_paths,
        vec![autolist_path]
    );
    assert_eq!(
        state
            .config
            .autohostlist_entries,
        vec!["blocked-one.example".to_owned(), "blocked-two.example".to_owned()]
    );

    let backend = TestBackend::new(120, 32);
    let mut term = Terminal::new(backend).expect("terminal");
    term.draw(|f| draw_app(f, &state))
        .expect("draw");
    let rendered: String = term
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|c| c.symbol())
        .collect();
    assert!(rendered.contains("Auto Hostlist (2)"));
    assert!(rendered.contains("blocked-one.example") && rendered.contains("blocked-two.example"));

    let _ = fs::remove_dir_all(&dir);
}
