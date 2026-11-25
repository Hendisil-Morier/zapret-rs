//! Terminal alternate-screen session RAII wrapper and external `$EDITOR` invocation.

/// Filesystem read after external editor closes to refresh Tab 3 validation state.
use std::fs;
/// Standard stdout stream wrapped by the `ratatui` `CrosstermBackend`.
use std::io::{self, Stdout};

/// `crossterm` terminal raw-mode and alternate-screen lifecycle commands.
use crossterm::{
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
/// `ratatui` terminal abstraction over `crossterm`.
use ratatui::{Terminal, backend::CrosstermBackend};

/// Symlink-safe TOML writer, `~/` expansion, and `nftables` guard cleanup.
use crate::tools::{FirewallHandle, expand_tilde, write_config_nofollow};
/// Unprivileged `$VISUAL`/`$EDITOR` launcher and starter TOML template generator.
use crate::tui::editor::{build_starter_toml, resolve_editor_command, spawn_unprivileged_editor};
/// Application state read and updated around external editing.
use crate::tui::state::AppState;

/// Environment marker set across seamless post-`setcap` `exec()` restarts to avoid screen flash.
pub(crate) const SEAMLESS_REEXEC_ENV: &str = "ZAPRET_RS_SEAMLESS_REEXEC";

/// RAII wrapper keeping `crossterm` raw mode and alternate screen paired with clean teardown.
pub(crate) struct TerminalSession {
    /// Active `ratatui` terminal bound to stdout.
    pub(crate) terminal: Terminal<CrosstermBackend<Stdout>>,
    /// When `false`, `Drop` keeps the alternate screen active across a seamless `exec()` restart.
    pub(crate) restore_on_drop: bool,
}

impl TerminalSession {
    /// Enters raw mode and the alternate screen buffer.
    pub(crate) fn enter() -> Result<Self, String> {
        let seamless = std::env::var_os(SEAMLESS_REEXEC_ENV).is_some();
        enable_raw_mode().map_err(|err| format!("failed to enable terminal raw mode: {err}"))?;
        let mut stdout = io::stdout();
        if !seamless && let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(format!("failed to enter alternate screen: {err}"));
        }
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)
            .map_err(|err| format!("failed to initialize terminal: {err}"))?;
        if !seamless {
            let _ = terminal.clear();
        }
        Ok(Self { terminal, restore_on_drop: true })
    }

    /// Temporarily leaves alternate screen and raw mode while running an interactive action.
    pub(crate) fn suspend_for<T, F: FnOnce() -> T>(&mut self, action: F) -> T {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let result = action();
        let _ = execute!(self.terminal.backend_mut(), EnterAlternateScreen);
        let _ = enable_raw_mode();
        let _ = self.terminal.clear();
        result
    }
}

impl Drop for TerminalSession {
    /// Restores cooked terminal mode and leaves the alternate screen unless handing off to `exec()`.
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = disable_raw_mode();
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
            let _ = self.terminal.show_cursor();
        }
    }
}

/// Tears down a firewall guard silently unless `sudo` requires a fresh interactive password prompt.
pub(crate) fn drop_fw_tui(session: &mut TerminalSession, guard: Box<dyn FirewallHandle>) {
    if guard.needs_interactive_drop() {
        session.suspend_for(move || drop(guard));
    } else {
        drop(guard);
    }
}

/// Suspends the TUI to open `state.output_path` in `$VISUAL`/`$EDITOR` with zero caps, then reloads.
pub(crate) fn edit_config_in_editor(state: &mut AppState, session: &mut TerminalSession) {
    let path = expand_tilde(&state.output_path);
    if !path.exists() {
        let seed = if state.active_toml.trim().is_empty() {
            build_starter_toml(crate::intercepter::DEFAULT_QUEUE_NUM, state.fwmark, &state.lua_dir_input)
        } else {
            state.active_toml.clone()
        };
        if let Err(err) = write_config_nofollow(&path, &seed) {
            state.status_banner = format!("Cannot create {}: {err}", path.display());
            return;
        }
    }
    let editor_cmd = resolve_editor_command();
    match session.suspend_for(|| spawn_unprivileged_editor(&editor_cmd, &path)) {
        Ok(_) => match fs::read_to_string(&path) {
            Ok(text) => {
                state.set_active_toml(text);
                state.status_banner = match &state.toml_error {
                    Some(err) => format!("Reloaded with TOML error: {}", err.lines().next().unwrap_or(err)),
                    None => format!("Reloaded {} ({} profiles)", path.display(), state.parsed_profiles.len()),
                };
            }
            Err(err) => state.status_banner = format!("Reload failed after edit: {err}"),
        },
        Err(err) => state.status_banner = err,
    }
}
