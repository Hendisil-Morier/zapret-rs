//! Terminal lifecycle, `sudo`-safe suspend/resume, and top-level `ratatui` event loop.

/// Filesystem reading when reloading `nfqws2.toml` from disk.
use std::fs;
/// Standard stdout handle backing the `ratatui` `CrosstermBackend`.
use std::io::{self, Stdout};
/// Unix `exec()` extension for seamlessly restarting the TUI after granting file capabilities.
use std::os::unix::process::CommandExt as _;
/// Path type for optional startup config and Lua directory flags.
use std::path::PathBuf;
/// Subprocess execution for one-key `sudo setcap` capability grant.
use std::process::Command;
/// Event poll tick interval.
use std::time::Duration;

/// `crossterm` event polling and alternate-screen/raw-mode management.
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
/// `ratatui` terminal abstraction over `crossterm`.
use ratatui::{Terminal, backend::CrosstermBackend};

/// Privilege checks and automatic `sudo` UID drop at TUI startup.
use crate::runtime::{CAP_MASK_NET, drop_sudo_root_if_needed, has_effective_caps};
/// Symlink-safe TOML writer and `~/` path expansion.
use crate::tools::{expand_tilde, write_config_nofollow};
/// Pure TUI frame renderer.
use crate::tui::render::draw_app;
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Navigation, action, and worker event enums.
use crate::tui::types::{AppAction, FinderStatus, RunStatus, ScanUiEvent};
/// Background scan and live daemon worker lifecycle helpers.
use crate::tui::workers::{
    ActiveDaemon, ActiveScan, install_default_nft, start_finder_scan, start_live_daemon,
};

/// UI refresh / input poll cadence keeping live gauges and packet counters responsive.
const UI_TICK: Duration = Duration::from_millis(60);

/// Startup options passed into [`run_tui`].
#[derive(Debug, Clone, Default)]
pub struct TuiOptions {
    /// Optional `nfqws2.toml` path pre-loaded into Config/Run tabs.
    pub config: Option<PathBuf>,
    /// Optional explicit directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    pub lua_dir: Option<PathBuf>,
    /// Start with manual `nftables` mode enabled (`--no-nft`).
    pub no_nft: bool,
}

/// RAII wrapper keeping `crossterm` raw mode and alternate screen paired with clean teardown.
struct TerminalSession {
    /// Active `ratatui` terminal bound to stdout.
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TerminalSession {
    /// Enters raw mode and the alternate screen buffer.
    fn enter() -> Result<Self, String> {
        enable_raw_mode().map_err(|err| format!("failed to enable terminal raw mode: {err}"))?;
        let mut stdout = io::stdout();
        if let Err(err) = execute!(stdout, EnterAlternateScreen) {
            let _ = disable_raw_mode();
            return Err(format!("failed to enter alternate screen: {err}"));
        }
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)
            .map_err(|err| format!("failed to initialize terminal: {err}"))?;
        let _ = terminal.clear();
        Ok(Self { terminal })
    }

    /// Temporarily leaves alternate screen + raw mode so external `sudo` prompts render cleanly.
    fn suspend_for<T, F: FnOnce() -> T>(&mut self, action: F) -> T {
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
    /// Restores cooked terminal mode and leaves the alternate screen buffer.
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
        let _ = self.terminal.show_cursor();
    }
}

/// Runs the interactive `ratatui` TUI event loop until the user quits cleanly.
pub fn run_tui(opts: TuiOptions) -> Result<(), String> {
    let _ = drop_sudo_root_if_needed();
    let mut state = AppState::new(opts.config, opts.lua_dir, opts.no_nft);
    state.has_net_caps = has_effective_caps(CAP_MASK_NET).unwrap_or(false);

    let mut session = TerminalSession::enter()?;
    let mut active_scan: Option<ActiveScan> = None;
    let mut active_daemon: Option<ActiveDaemon> = None;
    let mut reexec_after_exit = false;

    loop {
        if let Some(scan) = active_scan.as_mut() {
            let mut finished = false;
            while let Ok(ev) = scan.rx.try_recv() {
                if matches!(ev, ScanUiEvent::Completed { .. } | ScanUiEvent::Failed(_)) {
                    finished = true;
                }
                state.apply_scan_event(ev);
            }
            if finished && let Some(mut done_scan) = active_scan.take() {
                done_scan.shutdown(|g| session.suspend_for(move || drop(g)));
            }
        }

        session
            .terminal
            .draw(|f| draw_app(f, &state))
            .map_err(|err| format!("terminal draw failed: {err}"))?;

        if event::poll(UI_TICK).map_err(|err| format!("event poll failed: {err}"))?
            && let Event::Key(key) = event::read().map_err(|err| format!("event read failed: {err}"))?
            && key.kind == KeyEventKind::Press
        {
            match state.handle_key(key) {
                AppAction::None => {}
                AppAction::Quit => break,
                AppAction::StartScan => {
                    if active_daemon.is_some() {
                        state.status_banner = "Stop live nfqws2 on Tab 2 before scanning.".to_owned();
                    } else if active_scan.is_none() {
                        match start_finder_scan(&mut state, |q, m, tcp, udp| {
                            session.suspend_for(|| install_default_nft(q, m, tcp, udp))
                        }) {
                            Ok(scan) => active_scan = Some(scan),
                            Err(err) => state.apply_scan_event(ScanUiEvent::Failed(err)),
                        }
                    }
                }
                AppAction::StopScan => {
                    if let Some(mut scan) = active_scan.take() {
                        scan.shutdown(|g| session.suspend_for(move || drop(g)));
                        state.finder_status = FinderStatus::Done;
                        state.status_banner = "Scan stopped cleanly.".to_owned();
                    }
                }
                AppAction::SaveConfig => {
                    if state.active_toml.trim().is_empty() {
                        state.status_banner = "Nothing to save yet.".to_owned();
                    } else {
                        let path = expand_tilde(&state.output_path);
                        match write_config_nofollow(&path, &state.active_toml) {
                            Ok(()) => state.status_banner = format!("Saved {}", path.display()),
                            Err(err) => state.status_banner = format!("Save failed: {err}"),
                        }
                    }
                }
                AppAction::ReloadConfig => {
                    let path = expand_tilde(&state.output_path);
                    match fs::read_to_string(&path) {
                        Ok(text) => {
                            state.set_active_toml(text);
                            state.status_banner = format!(
                                "Loaded {} ({} profiles)",
                                path.display(),
                                state.parsed_profiles.len()
                            );
                        }
                        Err(err) => state.status_banner = format!("Reload failed ({}): {err}", path.display()),
                    }
                }
                AppAction::StartDaemon => {
                    if active_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if active_daemon.is_none() {
                        match start_live_daemon(&mut state, |q, m, tcp, udp| {
                            session.suspend_for(|| install_default_nft(q, m, tcp, udp))
                        }) {
                            Ok(daemon) => active_daemon = Some(daemon),
                            Err(err) => {
                                state.run_status = RunStatus::Error(err.clone());
                                state.status_banner = format!("Start failed: {err}");
                                state.push_run_log(format!("[error] {err}"));
                            }
                        }
                    }
                }
                AppAction::StopDaemon => {
                    if let Some(mut daemon) = active_daemon.take() {
                        daemon.shutdown(|g| session.suspend_for(move || drop(g)));
                        state.run_status = RunStatus::Stopped;
                        state.push_run_log("[stop] nfqws2 stopped and temporary nftables cleaned up.");
                        state.status_banner = "nfqws2 stopped cleanly.".to_owned();
                    }
                }
                AppAction::GrantCaps => {
                    let exe = state.exe_path.clone();
                    let status = session.suspend_for(|| {
                        eprintln!("[caps] granting CAP_NET_ADMIN,CAP_NET_RAW to {exe} via sudo setcap");
                        Command::new("sudo")
                            .args(["--", "setcap", "cap_net_admin,cap_net_raw+ep", &exe])
                            .status()
                    });
                    match status {
                        Ok(s) if s.success() => {
                            reexec_after_exit = true;
                            break;
                        }
                        Ok(s) => {
                            state.status_banner = format!("setcap exited with status {s}");
                        }
                        Err(err) => {
                            state.status_banner = format!("failed to run sudo setcap: {err}");
                        }
                    }
                }
            }
        }
    }

    if let Some(mut scan) = active_scan.take() {
        scan.shutdown(|g| session.suspend_for(move || drop(g)));
    }
    if let Some(mut daemon) = active_daemon.take() {
        daemon.shutdown(|g| session.suspend_for(move || drop(g)));
    }
    drop(session);

    if reexec_after_exit {
        let exe = std::env::current_exe()
            .map_err(|err| format!("failed to resolve current executable for restart: {err}"))?;
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let err = Command::new(&exe).args(args).exec();
        return Err(format!("failed to restart {}: {err}", exe.display()));
    }
    Ok(())
}
