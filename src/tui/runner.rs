//! Terminal lifecycle, floating modal auth handling, and top-level `ratatui` event loop.

/// Filesystem reading when reloading `nfqws2.toml` from disk.
use std::fs;
/// Standard stdout handle backing the `ratatui` `CrosstermBackend`.
use std::io::{self, Stdout};
/// Unix `exec()` extension for seamlessly restarting the TUI after granting file capabilities.
use std::os::unix::process::CommandExt as _;
/// Path type for optional startup config and Lua directory flags.
use std::path::PathBuf;
/// Subprocess execution for seamless post-`setcap` self-restart.
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
/// Symlink-safe TOML writer, `~/` expansion, and non-interactive `nftables` helpers.
use crate::tools::{
    FirewallHandle, NftFirewallBackend, STRAT_FINDER_NFT_TABLE, expand_tilde, write_config_nofollow,
};
/// Floating authentication modal state and silent `sudo -S`/`-n` executor.
use crate::tui::modal::{AuthModal, ModalPurpose, run_sudo_silent, zeroize_string};
/// Pure TUI frame renderer.
use crate::tui::render::draw_app;
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Navigation, action, and worker event enums.
use crate::tui::types::{AppAction, FinderStatus, RunStatus, ScanUiEvent};
/// Background scan and live daemon worker lifecycle helpers.
use crate::tui::workers::{ActiveDaemon, ActiveScan, start_finder_scan, start_live_daemon};

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

/// Environment marker set across seamless post-`setcap` `exec()` restarts to prevent screen clear flash.
const SEAMLESS_REEXEC_ENV: &str = "ZAPRET_RS_SEAMLESS_REEXEC";

/// RAII wrapper keeping `crossterm` raw mode and alternate screen paired with clean teardown.
struct TerminalSession {
    /// Active `ratatui` terminal bound to stdout.
    terminal: Terminal<CrosstermBackend<Stdout>>,
    /// When `false`, `Drop` keeps the alternate screen active across a seamless `exec()` restart.
    restore_on_drop: bool,
}

impl TerminalSession {
    /// Enters raw mode and the alternate screen buffer.
    fn enter() -> Result<Self, String> {
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

    /// Temporarily leaves alternate screen + raw mode only if teardown requires a fresh TTY prompt.
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
    /// Restores cooked terminal mode and leaves the alternate screen buffer unless handing off to `exec()`.
    fn drop(&mut self) {
        if self.restore_on_drop {
            let _ = disable_raw_mode();
            let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
            let _ = self.terminal.show_cursor();
        }
    }
}

/// Tears down a firewall guard silently unless `sudo` requires a fresh interactive password prompt.
fn drop_fw_tui(session: &mut TerminalSession, guard: Box<dyn FirewallHandle>) {
    if guard.needs_interactive_drop() {
        session.suspend_for(move || drop(guard));
    } else {
        drop(guard);
    }
}

/// Attempts to start a strategy scan; opens the floating auth modal if caps or `sudo` auth are missing.
fn try_start_scan(state: &mut AppState, active_scan: &mut Option<ActiveScan>) {
    if !state.has_net_caps {
        state.open_caps_modal();
        return;
    }
    let mut need_sudo = false;
    let res = start_finder_scan(state, |q, m, tcp, udp| {
        let r = NftFirewallBackend::default().install_non_interactive(q, m, tcp, udp);
        if let Err(ref e) = r && e.kind() == io::ErrorKind::PermissionDenied {
            need_sudo = true;
        }
        r
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForScan, preview));
        return;
    }
    match res {
        Ok(scan) => *active_scan = Some(scan),
        Err(err) => state.apply_scan_event(ScanUiEvent::Failed(err)),
    }
}

/// Attempts to start live `nfqws2`; opens the floating auth modal if caps or `sudo` auth are missing.
fn try_start_daemon(state: &mut AppState, active_daemon: &mut Option<ActiveDaemon>) {
    if !state.has_net_caps {
        state.open_caps_modal();
        return;
    }
    let mut need_sudo = false;
    let res = start_live_daemon(state, |q, m, tcp, udp| {
        let r = NftFirewallBackend::default().install_non_interactive(q, m, tcp, udp);
        if let Err(ref e) = r && e.kind() == io::ErrorKind::PermissionDenied {
            need_sudo = true;
        }
        r
    });
    if need_sudo {
        let preview = format!("sudo nft -f -  (table inet {STRAT_FINDER_NFT_TABLE})");
        state.modal = Some(AuthModal::open(ModalPurpose::SudoForDaemon, preview));
        return;
    }
    match res {
        Ok(daemon) => *active_daemon = Some(daemon),
        Err(err) => {
            state.run_status = RunStatus::Error(err.clone());
            state.status_banner = format!("Start failed: {err}");
            state.push_run_log(format!("[error] {err}"));
        }
    }
}

/// Executes the confirmed floating modal action (`setcap` or `sudo -v`) without leaving the TUI.
///
/// Returns `true` when `setcap` succeeded and the TUI should re-`exec` cleanly with active caps.
fn submit_auth_modal(
    state: &mut AppState,
    active_scan: &mut Option<ActiveScan>,
    active_daemon: &mut Option<ActiveDaemon>,
) -> bool {
    let Some(modal) = state.modal.as_mut() else {
        return false;
    };
    let purpose = modal.purpose;
    let mut pw_buf = if modal.needs_password { Some(modal.take_password()) } else { None };
    let pw_ref = pw_buf.as_deref();

    let result = match purpose {
        ModalPurpose::GrantCaps => {
            let exe = state.exe_path.clone();
            run_sudo_silent(&["--", "setcap", "cap_net_admin,cap_net_raw+ep", &exe], pw_ref)
        }
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon => run_sudo_silent(&["-v"], pw_ref),
    };
    if let Some(ref mut secret) = pw_buf {
        zeroize_string(secret);
    }

    match result {
        Ok(()) => {
            state.modal = None;
            match purpose {
                ModalPurpose::GrantCaps => {
                    state.has_net_caps = true;
                    state.status_banner = "Capabilities granted.".to_owned();
                    return true;
                }
                ModalPurpose::SudoForScan => try_start_scan(state, active_scan),
                ModalPurpose::SudoForDaemon => try_start_daemon(state, active_daemon),
            }
        }
        Err(msg) => {
            if let Some(modal) = state.modal.as_mut() {
                modal.needs_password = true;
                modal.error = Some(msg);
            }
        }
    }
    false
}

/// Runs the interactive `ratatui` TUI event loop until the user quits cleanly.
pub fn run_tui(opts: TuiOptions) -> Result<(), String> {
    let _ = drop_sudo_root_if_needed();
    let mut state = AppState::new(opts.config, opts.lua_dir, opts.no_nft);
    state.has_net_caps = has_effective_caps(CAP_MASK_NET).unwrap_or(false);
    if !state.has_net_caps {
        state.open_caps_modal();
    }

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
                done_scan.shutdown(|g| drop_fw_tui(&mut session, g));
            }
        }
        if let Some(daemon) = active_daemon.as_mut() {
            // Drain all desynced (`MODIFY`/`DROP`) records first, then recent `PASS` records.
            for _ in 0..256 {
                let Ok(rec) = daemon.desync_rx.try_recv() else { break; };
                state.inspector.push(rec);
            }
            for _ in 0..256 {
                let Ok(rec) = daemon.pkt_rx.try_recv() else { break; };
                state.inspector.push(rec);
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
                        try_start_scan(&mut state, &mut active_scan);
                    }
                }
                AppAction::StopScan => {
                    if let Some(mut scan) = active_scan.take() {
                        scan.shutdown(|g| drop_fw_tui(&mut session, g));
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
                            state.status_banner = format!("Loaded {} ({} profiles)", path.display(), state.parsed_profiles.len());
                        }
                        Err(err) => state.status_banner = format!("Reload failed ({}): {err}", path.display()),
                    }
                }
                AppAction::StartDaemon => {
                    if active_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if active_daemon.is_none() {
                        try_start_daemon(&mut state, &mut active_daemon);
                    }
                }
                AppAction::StopDaemon => {
                    if let Some(mut daemon) = active_daemon.take() {
                        daemon.shutdown(|g| drop_fw_tui(&mut session, g));
                        while let Ok(rec) = daemon.desync_rx.try_recv() {
                            state.inspector.push(rec);
                        }
                        while let Ok(rec) = daemon.pkt_rx.try_recv() {
                            state.inspector.push(rec);
                        }
                        state.run_status = RunStatus::Stopped;
                        state.push_run_log("[stop] nfqws2 stopped and temporary nftables cleaned up.");
                        state.status_banner = "nfqws2 stopped cleanly.".to_owned();
                    }
                }
                AppAction::SubmitModal => {
                    if submit_auth_modal(&mut state, &mut active_scan, &mut active_daemon) {
                        reexec_after_exit = true;
                        break;
                    }
                }
            }
        }
    }

    if let Some(mut scan) = active_scan.take() {
        scan.shutdown(|g| drop_fw_tui(&mut session, g));
    }
    if let Some(mut daemon) = active_daemon.take() {
        daemon.shutdown(|g| drop_fw_tui(&mut session, g));
    }
    if reexec_after_exit {
        // Repaint one clean modal-free frame in place and keep the alternate screen across `exec()`.
        let _ = session.terminal.draw(|f| draw_app(f, &state));
        session.restore_on_drop = false;
        drop(session);

        let exe = std::env::current_exe()
            .map_err(|err| format!("failed to resolve current executable for restart: {err}"))?;
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let err = Command::new(&exe)
            .args(args)
            .env(SEAMLESS_REEXEC_ENV, "1")
            .exec();
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        return Err(format!("failed to restart {}: {err}", exe.display()));
    }
    drop(session);
    Ok(())
}
