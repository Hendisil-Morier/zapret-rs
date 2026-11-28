//! Terminal alternate-screen session RAII wrapper and external `$EDITOR` invocation.

/// Filesystem read after external editor closes to refresh Tab 3 validation state.
use std::fs;
/// Standard stdout stream wrapped by the `ratatui` `CrosstermBackend`.
use std::io::{self, Stdout};
/// Path resolution for the sibling domain history file beside `nfqws2.toml`.
use std::path::PathBuf;

/// `crossterm` terminal raw-mode, alternate-screen, mouse-capture, and bracketed-paste lifecycle commands.
use crossterm::{
    event::{DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
/// `ratatui` terminal abstraction over `crossterm`.
use ratatui::{Terminal, backend::CrosstermBackend};

/// Validated `AppConfig` parser used to extract `hostlist_domains` when seeding Tab 1.
use crate::config::AppConfig;
/// Symlink-safe TOML writer, `~/` expansion, firewall handle, and domain extractor.
use crate::tools::{
    FirewallHandle, expand_tilde, extract_hostlist_domains, normalize_domain, write_config_nofollow,
};
/// Unprivileged `$VISUAL`/`$EDITOR` launcher and starter TOML template generator.
use crate::tui::editor::{build_starter_toml, resolve_editor_command, spawn_unprivileged_editor};
/// Seamless `exec()` environment marker checked during terminal alternate-screen startup.
use crate::tui::session_reexec::SEAMLESS_REEXEC_ENV;
/// Application state read and updated around external editing.
use crate::tui::state::AppState;

/// RAII wrapper keeping `crossterm` raw mode and alternate screen paired with clean teardown.
pub(crate) struct TerminalSession
{
    /// Active `ratatui` terminal bound to stdout.
    pub(crate) terminal: Terminal<CrosstermBackend<Stdout>>,
    /// When `false`, `Drop` keeps the alternate screen active across a seamless `exec()` restart.
    pub(crate) restore_on_drop: bool,
}

impl TerminalSession
{
    /// Enters raw mode, alternate screen buffer, and mouse capture.
    pub(crate) fn enter() -> Result<Self, String>
    {
        #[cfg(windows)]
        {
            /// Windows UTF-8 console code page (`CP_UTF8`).
            const CP_UTF8: u32 = 65_001;
            #[link(name = "kernel32")]
            unsafe extern "system" {
                fn SetConsoleOutputCP(code_page_id: u32) -> i32;
                fn SetConsoleCP(code_page_id: u32) -> i32;
            }
            // SAFETY: Switching console input/output code pages to UTF-8 is process-local and safe.
            unsafe {
                let _ = SetConsoleOutputCP(CP_UTF8);
                let _ = SetConsoleCP(CP_UTF8);
            }
        }
        let seamless = std::env::var_os(SEAMLESS_REEXEC_ENV).is_some();
        enable_raw_mode().map_err(|err| format!("failed to enable terminal raw mode: {err}"))?;
        let mut stdout = io::stdout();
        if !seamless && let Err(err) = execute!(stdout, EnterAlternateScreen)
        {
            let _ = disable_raw_mode();
            return Err(format!("failed to enter alternate screen: {err}"));
        }
        let _ = execute!(stdout, EnableMouseCapture, EnableBracketedPaste);
        let backend = CrosstermBackend::new(stdout);
        let mut terminal =
            Terminal::new(backend).map_err(|err| format!("failed to initialize terminal: {err}"))?;
        // Always wipe the active alternate screen so pre-`exec()` text never ghosts into the fresh `Terminal` buffer.
        let _ = terminal.clear();
        Ok(Self { terminal, restore_on_drop: true })
    }

    /// Temporarily leaves alternate screen, mouse capture, and raw mode while running `action`.
    pub(crate) fn suspend_for<T, F: FnOnce() -> T>(&mut self, action: F) -> T
    {
        let _ = execute!(
            self.terminal
                .backend_mut(),
            DisableBracketedPaste,
            DisableMouseCapture,
            LeaveAlternateScreen
        );
        let _ = disable_raw_mode();
        let result = action();
        let _ = execute!(
            self.terminal
                .backend_mut(),
            EnterAlternateScreen,
            EnableMouseCapture,
            EnableBracketedPaste
        );
        let _ = enable_raw_mode();
        let _ = self
            .terminal
            .clear();
        result
    }
}

impl Drop for TerminalSession
{
    /// Restores cooked terminal mode, disables mouse capture, and leaves alternate screen on exit.
    fn drop(&mut self)
    {
        if self.restore_on_drop
        {
            let _ = execute!(
                self.terminal
                    .backend_mut(),
                DisableBracketedPaste,
                DisableMouseCapture,
                LeaveAlternateScreen
            );
            let _ = disable_raw_mode();
            let _ = self
                .terminal
                .show_cursor();
        }
    }
}

/// Tears down a firewall guard silently unless `sudo` requires a fresh interactive password prompt.
pub(crate) fn drop_fw_tui(session: &mut TerminalSession, guard: Box<dyn FirewallHandle>)
{
    if guard.needs_interactive_drop()
    {
        session.suspend_for(move || drop(guard));
    }
    else
    {
        drop(guard);
    }
}

/// Suspends the TUI to open `state.finder.output_path` in `$VISUAL`/`$EDITOR` with zero caps, then reloads.
pub(crate) fn edit_config_in_editor(state: &mut AppState, session: &mut TerminalSession)
{
    let path = expand_tilde(
        &state
            .finder
            .output_path,
    );
    if !path.exists()
    {
        let seed = if state
            .config
            .active_toml
            .trim()
            .is_empty()
        {
            build_starter_toml(
                crate::intercepter::DEFAULT_QUEUE_NUM,
                state
                    .finder
                    .fwmark,
                &state
                    .finder
                    .lua_dir_input,
            )
        }
        else
        {
            state
                .config
                .active_toml
                .clone()
        };
        if let Err(err) = write_config_nofollow(&path, &seed)
        {
            state.status_banner = format!("Cannot create {}: {err}", path.display());
            return;
        }
    }
    let editor_cmd = resolve_editor_command();
    match session.suspend_for(|| spawn_unprivileged_editor(&editor_cmd, &path))
    {
        Ok(_) => reload_toml_from_disk(state),
        Err(err) => state.status_banner = err,
    }
}

/// Returns the sibling `.zapret-domains` history path beside `state.finder.output_path`.
pub fn domains_history_path(output_path: &str) -> PathBuf
{
    let cfg = expand_tilde(output_path);
    cfg.with_file_name("domains")
}

/// Persists non-empty Tab 1 `domains_input` alongside `nfqws2.toml` cleanly via `O_NOFOLLOW`.
pub fn save_domains_history(state: &AppState)
{
    let trimmed = state
        .finder
        .domains_input
        .trim();
    if trimmed.is_empty()
    {
        return;
    }
    let path = domains_history_path(
        &state
            .finder
            .output_path,
    );
    let _ = write_config_nofollow(&path, trimmed);
}

/// Seeds empty `state.finder.domains_input` from saved domain history or `hostlist_domains` in `active_toml`.
pub fn seed_domains_on_startup(state: &mut AppState)
{
    if !state
        .finder
        .domains_input
        .trim()
        .is_empty()
    {
        return;
    }
    let hist = domains_history_path(
        &state
            .finder
            .output_path,
    );
    if let Ok(saved) = fs::read_to_string(hist)
    {
        let trimmed = saved.trim();
        if !trimmed.is_empty()
        {
            state
                .finder
                .domains_input = trimmed.to_owned();
            return;
        }
    }
    if !state
        .config
        .active_toml
        .trim()
        .is_empty()
        && let Ok(cfg) = AppConfig::from_toml_str(
            &state
                .config
                .active_toml,
            None,
        )
    {
        let domains = extract_hostlist_domains(&cfg);
        if !domains.is_empty()
        {
            state
                .finder
                .domains_input = domains.join(", ");
        }
    }
}

/// Ensures any configured `hostlist_auto` file contains the scanned `domains_input` hostnames.
pub fn seed_autohostlists_from_domains(state: &mut AppState)
{
    if state
        .config
        .autohostlist_paths
        .is_empty()
        || state
            .finder
            .domains_input
            .trim()
            .is_empty()
    {
        return;
    }
    let domains: Vec<String> = state
        .finder
        .domains_input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(normalize_domain)
        .collect();
    if domains.is_empty()
    {
        return;
    }
    for path in &state
        .config
        .autohostlist_paths
    {
        let existing = fs::read_to_string(path).unwrap_or_default();
        let mut out = existing.clone();
        if !out.is_empty() && !out.ends_with('\n')
        {
            out.push('\n');
        }
        let mut changed = false;
        for d in &domains
        {
            let already = existing
                .lines()
                .any(|l| {
                    l.trim()
                        .eq_ignore_ascii_case(d)
                });
            if !already
                && !out
                    .lines()
                    .any(|l| {
                        l.trim()
                            .eq_ignore_ascii_case(d)
                    })
            {
                out.push_str(d);
                out.push('\n');
                changed = true;
            }
        }
        if changed || !path.exists()
        {
            let _ = write_config_nofollow(path, &out);
        }
    }
    state.refresh_autohostlist();
}

/// Saves `state.config.active_toml` cleanly to `state.finder.output_path` without following symlinks.
pub(crate) fn save_toml_to_disk(state: &mut AppState)
{
    if state
        .config
        .active_toml
        .trim()
        .is_empty()
    {
        state.status_banner = "Nothing to save yet.".to_owned();
        return;
    }
    save_domains_history(state);
    state.save_finder_prefs();
    seed_autohostlists_from_domains(state);
    let path = expand_tilde(
        &state
            .finder
            .output_path,
    );
    match write_config_nofollow(
        &path,
        &state
            .config
            .active_toml,
    )
    {
        Ok(()) => state.status_banner = format!("Saved {}", path.display()),
        Err(err) => state.status_banner = format!("Save failed: {err}"),
    }
}

/// Reloads `state.finder.output_path` from disk and refreshes Tab 3 TOML validation diagnostics.
pub(crate) fn reload_toml_from_disk(state: &mut AppState)
{
    let path = expand_tilde(
        &state
            .finder
            .output_path,
    );
    match fs::read_to_string(&path)
    {
        Ok(text) =>
        {
            state.set_active_toml(text);
            seed_domains_on_startup(state);
            state.status_banner = match &state
                .config
                .toml_error
            {
                Some(err) => format!(
                    "Loaded with TOML error: {}",
                    err.lines()
                        .next()
                        .unwrap_or(err)
                ),
                None =>
                {
                    format!(
                        "Loaded {} ({} profiles)",
                        path.display(),
                        state
                            .config
                            .parsed_profiles
                            .len()
                    )
                }
            };
        }
        Err(err) => state.status_banner = format!("Reload failed ({}): {err}", path.display()),
    }
}
