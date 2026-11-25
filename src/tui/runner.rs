//! Top-level `ratatui` event loop, startup bootstrap, and clean teardown/re-exec.

/// Standard stdout/I/O error handling for crossterm event polling.
use std::io;
/// Unix `exec()` extension for seamlessly restarting the TUI after granting file capabilities.
use std::os::unix::process::CommandExt as _;
/// Path type for optional startup config, control socket, and Lua directory flags.
use std::path::PathBuf;
/// Subprocess execution for seamless post-`setcap` self-restart.
use std::process::Command;
/// Event poll tick interval.
use std::time::Duration;

/// `crossterm` event polling and keyboard press matching.
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};

/// Wire control request enum sent to an attached daemon socket.
use crate::control::Request;
/// Privilege checks and automatic `sudo` UID drop at TUI startup.
use crate::runtime::{CAP_MASK_NET, drop_sudo_root_if_needed, has_effective_caps};
/// Action executors coordinating workers, `sudo` modals, TOML file I/O, and attach state.
use crate::tui::actions::{
    Tab2Session, cancel_active_scan, execute_remote_stop, poll_active_scan, poll_tab2_session,
    reload_toml_from_disk, save_toml_to_disk, stop_local_daemon, submit_auth_modal,
    try_start_or_attach, try_start_scan,
};
/// Remote daemon socket auto-detection helper.
use crate::tui::remote::detect_control_socket;
/// Pure TUI frame renderer.
use crate::tui::render::draw_app;
/// Terminal RAII session wrapper and external editor launcher.
use crate::tui::session::{
    SEAMLESS_REEXEC_ENV, TerminalSession, drop_fw_tui, edit_config_in_editor,
};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Navigation and action enums.
use crate::tui::types::AppAction;
/// Background strategy scan worker handle.
use crate::tui::workers::ActiveScan;

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
    /// Optional explicit daemon Unix control socket path overriding auto-detection.
    pub control_socket: Option<PathBuf>,
}

/// Executes the interactive `ratatui` TUI event loop until the user quits cleanly.
pub fn run_tui(opts: TuiOptions) -> Result<(), String> {
    let _ = drop_sudo_root_if_needed();
    let mut state = AppState::new(opts.config, opts.lua_dir, opts.no_nft);
    state.control_socket_override = opts.control_socket;
    state.detected_socket = detect_control_socket(state.control_socket_override.as_deref());
    state.has_net_caps = has_effective_caps(CAP_MASK_NET).unwrap_or(false);
    if !state.has_net_caps && state.detected_socket.is_none() {
        state.open_caps_modal();
    }

    let mut session = TerminalSession::enter()?;
    let mut active_scan: Option<ActiveScan> = None;
    let mut tab2_session: Option<Tab2Session> = None;
    let mut reexec_after_exit = false;

    loop {
        poll_active_scan(&mut state, &mut active_scan, &mut session);
        poll_tab2_session(&mut state, &mut tab2_session);

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
                    if matches!(tab2_session, Some(Tab2Session::Local(_))) {
                        state.status_banner = "Stop live nfqws2 on Tab 2 before scanning.".to_owned();
                    } else if active_scan.is_none() {
                        try_start_scan(&mut state, &mut active_scan);
                    }
                }
                AppAction::StopScan => cancel_active_scan(&mut state, &mut active_scan, &mut session),
                AppAction::SaveConfig => save_toml_to_disk(&mut state),
                AppAction::ReloadConfig => reload_toml_from_disk(&mut state),
                AppAction::EditConfig => edit_config_in_editor(&mut state, &mut session),
                AppAction::StartDaemon => {
                    if active_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if tab2_session.is_none() {
                        try_start_or_attach(&mut state, &mut tab2_session);
                    }
                }
                AppAction::StopDaemon => stop_local_daemon(&mut state, &mut tab2_session, &mut session),
                AppAction::DetachDaemon => {
                    if let Some(Tab2Session::Remote(mut remote)) = tab2_session.take() {
                        remote.detach();
                        state.set_detached(
                            "[detach] detached from remote nfqws2 (daemon still running).".to_owned(),
                            "Detached from remote daemon.".to_owned(),
                        );
                    }
                }
                AppAction::ReloadRemoteLists => {
                    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref()
                        && let Err(err) = remote.send_command(&Request::ReloadLists)
                    {
                        state.push_run_log(format!("[error] {err}"));
                        state.status_banner = err;
                    }
                }
                AppAction::StopRemoteDaemon => execute_remote_stop(&mut state, &mut tab2_session),
                AppAction::SubmitModal => {
                    if submit_auth_modal(&mut state, &mut active_scan, &mut tab2_session) {
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
    if let Some(sess) = tab2_session.take() {
        match sess {
            Tab2Session::Local(mut daemon) => daemon.shutdown(|g| drop_fw_tui(&mut session, g)),
            Tab2Session::Remote(mut remote) => remote.detach(),
        }
    }
    if reexec_after_exit {
        let _ = session.terminal.draw(|f| draw_app(f, &state));
        session.restore_on_drop = false;
        drop(session);

        let exe = std::env::current_exe()
            .map_err(|err| format!("failed to resolve current executable for restart: {err}"))?;
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        let err = Command::new(&exe).args(args).env(SEAMLESS_REEXEC_ENV, "1").exec();
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        return Err(format!("failed to restart {}: {err}", exe.display()));
    }
    drop(session);
    Ok(())
}
