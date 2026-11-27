//! Top-level `ratatui` event loop, startup bootstrap, and clean teardown/re-exec.

/// Standard stdout/I/O error handling for crossterm event polling.
use std::io;
/// Unix `exec()` extension for seamlessly restarting the TUI after granting file capabilities.
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
/// Path type for optional startup config, control socket, and Lua directory flags.
use std::path::PathBuf;
/// Subprocess execution for seamless post-`setcap` self-restart.
use std::process::Command;
/// Event poll tick interval and clock reads for Tab 1 focus-dwell help popups.
use std::time::{Duration, Instant};

/// `crossterm` event polling and keyboard press matching.
use crossterm::{
    event::{self, Event, KeyEventKind},
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};
/// Terminal frame geometry passed to mouse hit-testing.
use ratatui::layout::Rect;

/// Wire control request enum sent to an attached daemon socket.
use crate::control::Request;
/// OS-agnostic privilege checks and automatic `sudo` UID drop at TUI startup.
use crate::runtime::{drop_elevated_root_if_needed, has_packet_capture_privileges};
/// Action executors coordinating scan workers, `sudo` modals, and daemon start/attach.
use crate::tui::actions::{
    PendingScanStart, begin_scan_stopping_daemon, cancel_active_scan, poll_active_scan,
    poll_pending_scan, submit_auth_modal, try_start_or_attach,
};
/// Mouse click and scroll wheel handler aligned to `ratatui` panel layouts.
use crate::tui::mouse::handle_mouse_event;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
use crate::tui::tab2_session::{
    Tab2Session, attach_to_socket, execute_remote_stop, poll_tab2_session, push_config_to_daemon,
    stop_local_daemon,
};
/// Stop-then-start daemon restart job and its per-tick driver.
use crate::tui::daemon_cycle::{DaemonCycle, begin_restart, poll_daemon_cycle};
/// Remote daemon socket auto-detection helper.
use crate::tui::remote::detect_control_socket;
/// Pure TUI frame renderer.
use crate::tui::render::draw_app;
/// Embedded Web UI server lifecycle handlers triggered via global `W`.
use crate::tui::web_actions::{ActiveWebUi, stop_web_ui, submit_prompt_modal};
/// Terminal RAII session wrapper, seamless re-exec snapshot, and TOML file I/O helpers.
use crate::tui::session::{
    REEXEC_STATE_ENV, ReexecSnapshot, SEAMLESS_REEXEC_ENV, TerminalSession, drop_fw_tui,
    edit_config_in_editor, reload_toml_from_disk, save_toml_to_disk, seed_domains_on_startup,
};
/// Tab 4 speed comparison job and its per-tick driver.
use crate::tui::speed_runner::{SpeedJob, begin_speed_test, cancel_speed_test, poll_speed_test};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Configurable theme resolver for `--theme` and `~/.config/zapret-rs/theme.toml`.
use crate::tui::theme_config::resolve_theme;
/// Navigation, deferred restart action, and UI action enums.
use crate::tui::types::{ActiveTab, AppAction, PostCapsAction};
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
    /// Optional theme preset name or path to a TOML theme file (`--theme`).
    pub theme: Option<String>,
}

/// Executes the interactive `ratatui` TUI event loop until the user quits cleanly.
pub fn run_tui(opts: TuiOptions) -> Result<(), String> {
    let _ = drop_elevated_root_if_needed();
    let mut state = AppState::new(opts.config, opts.lua_dir, opts.no_nft);
    if let Some(ref theme_spec) = opts.theme {
        let (theme, warn) = resolve_theme(Some(theme_spec));
        state.theme = theme;
        if let Some(msg) = warn {
            state.status_banner = msg;
        }
    }
    let (from_reexec, pending_action) = ReexecSnapshot::restore_from_env(&mut state);
    if !from_reexec {
        seed_domains_on_startup(&mut state);
    }
    state.control_socket_override = opts.control_socket;
    state.detected_socket = detect_control_socket(state.control_socket_override.as_deref());
    state.has_net_caps = has_packet_capture_privileges().unwrap_or(false);
    if !state.has_net_caps && state.detected_socket.is_none() {
        state.open_caps_modal();
    }

    let mut session = TerminalSession::enter()?;
    let mut active_scan: Option<ActiveScan> = None;
    let mut pending_scan: Option<PendingScanStart> = None;
    let mut tab2_session: Option<Tab2Session> = None;
    if let Some(sock) = state.detected_socket.clone()
        && attach_to_socket(&mut state, &mut tab2_session, sock)
        && !from_reexec
    {
        state.tab = ActiveTab::Run;
    }
    if state.has_net_caps {
        match pending_action {
            Some(PostCapsAction::StartScan) => {
                pending_scan = begin_scan_stopping_daemon(
                    &mut state,
                    &mut active_scan,
                    &mut tab2_session,
                    &mut session,
                );
            }
            Some(PostCapsAction::StartDaemon) if tab2_session.is_none() => {
                try_start_or_attach(&mut state, &mut tab2_session);
            }
            _ => {}
        }
    }
    let mut cycle: Option<DaemonCycle> = None;
    let mut speed_job: Option<SpeedJob> = None;
    let mut web_ui: Option<ActiveWebUi> = None;
    let mut probe_tick = 0u8;
    let mut autolist_tick = 0u8;
    let mut reexec_after_exit = false;

    loop {
        poll_active_scan(&mut state, &mut active_scan, &mut session);
        poll_tab2_session(&mut state, &mut tab2_session, &mut probe_tick, active_scan.is_some());
        poll_pending_scan(&mut pending_scan, &mut state, &mut active_scan, &tab2_session);
        if state.tab == crate::tui::ActiveTab::Config {
            autolist_tick = autolist_tick.wrapping_add(1);
            if autolist_tick.is_multiple_of(16) {
                state.refresh_autohostlist();
            }
        }
        poll_daemon_cycle(&mut cycle, &mut state, &mut tab2_session);
        poll_speed_test(&mut speed_job, &mut state, &mut tab2_session);
        state.poll_finder_hover(Instant::now());

        session
            .terminal
            .draw(|f| draw_app(f, &state))
            .map_err(|err| format!("terminal draw failed: {err}"))?;

        if event::poll(UI_TICK).map_err(|err| format!("event poll failed: {err}"))? {
            match event::read().map_err(|err| format!("event read failed: {err}"))? {
                Event::Mouse(mouse) => {
                    if let Ok(sz) = session.terminal.size() {
                        handle_mouse_event(&mut state, mouse, Rect::new(0, 0, sz.width, sz.height));
                    }
                }
                Event::Key(key) if key.kind == KeyEventKind::Press => match state.handle_key(key) {
                AppAction::None => {}
                AppAction::Quit => break,
                AppAction::StartScan => {
                    if cycle.is_some() || speed_job.is_some() {
                        state.status_banner =
                            "Wait for the active daemon cycle or speed test to finish.".to_owned();
                    } else if active_scan.is_none() && pending_scan.is_none() {
                        pending_scan = begin_scan_stopping_daemon(
                            &mut state,
                            &mut active_scan,
                            &mut tab2_session,
                            &mut session,
                        );
                    }
                }
                AppAction::StopScan => {
                    if pending_scan.take().is_some() {
                        state.finder_status = crate::tui::FinderStatus::Done;
                        state.status_banner =
                            "Cancelled strategy scan while stopping nfqws2.".to_owned();
                    } else {
                        cancel_active_scan(&mut state, &mut active_scan, &mut session);
                    }
                }
                AppAction::SaveConfig => save_toml_to_disk(&mut state),
                AppAction::ReloadConfig => reload_toml_from_disk(&mut state),
                AppAction::EditConfig => edit_config_in_editor(&mut state, &mut session),
                AppAction::PushConfigToDaemon => push_config_to_daemon(&mut state, &tab2_session),
                AppAction::StartDaemon => {
                    if active_scan.is_some() || pending_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if tab2_session.is_none() {
                        try_start_or_attach(&mut state, &mut tab2_session);
                    }
                }
                AppAction::StopDaemon => stop_local_daemon(&mut state, &mut tab2_session, &mut session),
                AppAction::DetachDaemon => {
                    if let Some(Tab2Session::Remote(mut remote)) = tab2_session.take() {
                        remote.detach();
                        state.auto_reattach = false;
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
                AppAction::RestartDaemon => {
                    if active_scan.is_some() || pending_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if cycle.is_some() || speed_job.is_some() {
                        state.status_banner = "A daemon cycle is already in progress.".to_owned();
                    } else {
                        cycle = begin_restart(&mut state, &mut tab2_session, &mut session);
                    }
                }
                AppAction::RunSpeedTest => {
                    if active_scan.is_some() || pending_scan.is_some() {
                        state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
                    } else if cycle.is_some() || speed_job.is_some() {
                        state.status_banner = "A speed check or restart is already running.".to_owned();
                    } else {
                        speed_job = begin_speed_test(&mut state, &mut tab2_session, &mut session);
                    }
                }
                AppAction::CancelSpeedTest => cancel_speed_test(&mut speed_job, &mut state),
                AppAction::SubmitModal => {
                    if submit_auth_modal(&mut state, &mut active_scan, &mut tab2_session) {
                        reexec_after_exit = true;
                        break;
                    }
                }
                AppAction::SubmitPrompt => submit_prompt_modal(&mut state, &tab2_session, &mut web_ui),
                AppAction::StopWebUi => stop_web_ui(&mut state, &mut web_ui),
                },
                Event::Key(_) | Event::Resize(_, _) | Event::FocusGained | Event::FocusLost | Event::Paste(_) => {}
            }
        }
    }

    if let Some(mut scan) = active_scan.take() {
        scan.shutdown(|g| drop_fw_tui(&mut session, g));
    }
    stop_web_ui(&mut state, &mut web_ui);
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
        let mut cmd = Command::new(&exe);
        cmd.args(args).env(SEAMLESS_REEXEC_ENV, "1");
        if let Some(encoded) = ReexecSnapshot::capture(&state).encode() {
            cmd.env(REEXEC_STATE_ENV, encoded);
        }
        #[cfg(unix)]
        let err = cmd.exec();
        #[cfg(not(unix))]
        let err = match cmd.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(err) => err,
        };
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        return Err(format!("failed to restart {}: {err}", exe.display()));
    }
    drop(session);
    Ok(())
}
