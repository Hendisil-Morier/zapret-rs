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
    PendingScanStart, begin_scan_stopping_daemon, cancel_active_scan, poll_active_scan, poll_pending_scan,
    submit_auth_modal, try_start_or_attach,
};
/// Centralized `config.toml` resolver for `[theme]`, `[keybinds.*]`, and startup CLI overrides.
use crate::tui::app_config::{
    StartupConfigRequest, ensure_default_app_config_file, resolve_startup_app_config,
};
/// Context-aware clipboard copy and bracketed/`Ctrl+v` paste handlers.
use crate::tui::clipboard_context::{
    apply_paste_to_state, copy_context_selection, paste_clipboard_into_state,
};
/// Stop-then-start daemon restart job and its per-tick driver.
use crate::tui::daemon_cycle::{DaemonCycle, begin_restart, poll_daemon_cycle};
/// Tab 6 Auto Hostlist / Blacklist deletion, exclude transfer, and reload helpers.
use crate::tui::hostlist_tab::{
    delete_selected_hostlist_domain, move_selected_hostlist_entry, reload_hostlist_entries,
};
/// Mouse click and scroll wheel handler aligned to `ratatui` panel layouts.
use crate::tui::mouse::handle_mouse_event;
/// Remote daemon socket auto-detection helper.
use crate::tui::remote::detect_control_socket;
/// Pure TUI frame renderer.
use crate::tui::render::draw_app;
/// Terminal RAII session wrapper and TOML file I/O helpers.
use crate::tui::session::{
    TerminalSession, drop_fw_tui, edit_config_in_editor, reload_toml_from_disk, save_toml_to_disk,
    seed_domains_on_startup,
};
/// Seamless `setcap` restart snapshot serialization and environment marker keys.
use crate::tui::session_reexec::{REEXEC_STATE_ENV, ReexecSnapshot, SEAMLESS_REEXEC_ENV};
/// Tab 7 Settings sparse save, reload, and `$EDITOR` helpers.
use crate::tui::settings_actions::{
    edit_app_config_in_editor, reload_app_config_from_disk, save_app_config_from_settings,
};
/// Tab 4 speed comparison job and its per-tick driver.
use crate::tui::speed_runner::{SpeedJob, begin_speed_test, cancel_speed_test, poll_speed_test};
/// Mutable TUI application state.
use crate::tui::state::AppState;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
use crate::tui::tab2_session::{
    Tab2Session, attach_to_socket, execute_remote_stop, poll_tab2_session, push_config_to_daemon,
    stop_local_daemon,
};
/// Navigation, deferred restart action, and UI action enums.
use crate::tui::types::{ActiveTab, AppAction, PostCapsAction};
/// Embedded Web UI server lifecycle, browser launch, and clipboard copy handlers.
use crate::tui::web_actions::{
    ActiveWebUi, copy_web_passcode, open_web_ui, stop_web_ui, submit_prompt_modal,
};
/// Background strategy scan worker handle.
use crate::tui::workers::ActiveScan;

/// UI refresh / input poll cadence keeping live gauges and packet counters responsive.
const UI_TICK: Duration = Duration::from_millis(60);

/// Startup options passed into [`run_tui`].
#[derive(Debug, Clone, Default)]
pub struct TuiOptions
{
    /// Optional centralized `config.toml` or direct `nfqws2.toml` path (`--config`, auto-detected).
    pub config: Option<PathBuf>,
    /// Optional explicit `nfqws2.toml` path overriding `nfqws2_config` inside `config.toml`.
    pub nfqws2_config: Option<PathBuf>,
    /// Optional explicit directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    pub lua_dir: Option<PathBuf>,
    /// Start with manual `nftables` mode enabled (`--no-nft`).
    pub no_nft: bool,
    /// Optional explicit daemon Unix control socket path overriding auto-detection.
    pub control_socket: Option<PathBuf>,
    /// Optional theme preset name or path to a TOML theme file (`--theme`).
    pub theme: Option<String>,
}

/// Mutable session handles owned by the live TUI event loop across background jobs and modals.
struct TuiSessionHandles
{
    /// Terminal alternate-screen and raw-mode RAII guard.
    session: TerminalSession,
    /// Running Strategy Finder worker handle, if a scan is active.
    active_scan: Option<ActiveScan>,
    /// Deferred scan request waiting for an existing local daemon to exit.
    pending_scan: Option<PendingScanStart>,
    /// Attached local or remote `nfqws2` daemon session on Tab 2.
    tab2_session: Option<Tab2Session>,
    /// In-flight stop/restart daemon cycle state machine.
    cycle: Option<DaemonCycle>,
    /// Background baseline speed check worker handle.
    speed_job: Option<SpeedJob>,
    /// Running embedded web control panel server handle.
    web_ui: Option<ActiveWebUi>,
    /// Frame divider controlling periodic daemon control-socket probes.
    probe_tick: u8,
    /// Frame divider controlling periodic autohostlist refreshes.
    autolist_tick: u8,
    /// Whether exiting the loop should `exec` cleanly after `setcap` succeeded.
    reexec_after_exit: bool,
}

/// Resolves startup configuration, re-exec snapshot state, and initial capability modals.
fn initialize_tui_state(opts: TuiOptions) -> (AppState, bool, Option<PostCapsAction>)
{
    let _ = drop_elevated_root_if_needed();
    let (resolved, warn) = resolve_startup_app_config(StartupConfigRequest {
        cli_config: opts
            .config
            .as_deref(),
        cli_nfqws2_config: opts
            .nfqws2_config
            .as_deref(),
        cli_lua_dir: opts
            .lua_dir
            .as_deref(),
        cli_no_nft: opts.no_nft,
        cli_control_socket: opts
            .control_socket
            .as_deref(),
        cli_theme: opts
            .theme
            .as_deref(),
    });
    let mut state = AppState::from_startup_config(resolved.clone(), warn);
    let (from_reexec, pending_action) = ReexecSnapshot::restore_from_env(&mut state);
    if !from_reexec
    {
        if let Some(create_warn) = ensure_default_app_config_file(
            &resolved,
            &state
                .finder
                .lua_dir_input,
        )
        {
            state.status_banner = create_warn;
        }
        seed_domains_on_startup(&mut state);
    }
    state
        .run
        .detected_socket = detect_control_socket(
        state
            .run
            .control_socket_override
            .as_deref(),
    );
    state
        .status
        .has_net_caps = has_packet_capture_privileges().unwrap_or(false);
    if !state
        .status
        .has_net_caps
        && state
            .run
            .detected_socket
            .is_none()
    {
        state.open_caps_modal();
    }
    (state, from_reexec, pending_action)
}

/// Polls active background workers and periodic tab refreshes once per UI tick.
fn tick_tui_workers(state: &mut AppState, rt: &mut TuiSessionHandles)
{
    poll_active_scan(state, &mut rt.active_scan, &mut rt.session);
    poll_tab2_session(
        state,
        &mut rt.tab2_session,
        &mut rt.probe_tick,
        rt.active_scan
            .is_some(),
    );
    poll_pending_scan(&mut rt.pending_scan, state, &mut rt.active_scan, &rt.tab2_session);
    if state.tab == crate::tui::ActiveTab::Hostlist
    {
        rt.autolist_tick = rt
            .autolist_tick
            .wrapping_add(1);
        if rt
            .autolist_tick
            .is_multiple_of(16)
        {
            state.refresh_autohostlist();
        }
    }
    poll_daemon_cycle(&mut rt.cycle, state, &mut rt.tab2_session);
    poll_speed_test(&mut rt.speed_job, state, &mut rt.tab2_session);
    state.poll_finder_hover(Instant::now());
}

/// Dispatches Tab 2 daemon lifecycle and Tab 4 speed-check [`AppAction`] commands.
fn handle_daemon_or_speed_action(action: AppAction, state: &mut AppState, rt: &mut TuiSessionHandles)
{
    match action
    {
        AppAction::StartDaemon =>
        {
            if rt
                .active_scan
                .is_some()
                || rt
                    .pending_scan
                    .is_some()
            {
                state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
            }
            else if rt
                .tab2_session
                .is_none()
            {
                try_start_or_attach(state, &mut rt.tab2_session);
            }
        }
        AppAction::StopDaemon => stop_local_daemon(state, &mut rt.tab2_session, &mut rt.session),
        AppAction::DetachDaemon =>
        {
            if let Some(Tab2Session::Remote(mut remote)) = rt
                .tab2_session
                .take()
            {
                remote.detach();
                state
                    .run
                    .auto_reattach = false;
                state.set_detached(
                    "[detach] detached from remote nfqws2 (daemon still running).".to_owned(),
                    "Detached from remote daemon.".to_owned(),
                );
            }
        }
        AppAction::ReloadRemoteLists =>
        {
            if let Some(Tab2Session::Remote(remote)) = rt
                .tab2_session
                .as_ref()
                && let Err(err) = remote.send_command(&Request::ReloadLists)
            {
                state.push_run_log(format!("[error] {err}"));
                state.status_banner = err;
            }
        }
        AppAction::StopRemoteDaemon => execute_remote_stop(state, &mut rt.tab2_session),
        AppAction::RestartDaemon =>
        {
            if rt
                .active_scan
                .is_some()
                || rt
                    .pending_scan
                    .is_some()
            {
                state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
            }
            else if rt
                .cycle
                .is_some()
                || rt
                    .speed_job
                    .is_some()
            {
                state.status_banner = "A daemon cycle is already in progress.".to_owned();
            }
            else
            {
                rt.cycle = begin_restart(state, &mut rt.tab2_session, &mut rt.session);
            }
        }
        AppAction::RunSpeedTest =>
        {
            if rt
                .active_scan
                .is_some()
                || rt
                    .pending_scan
                    .is_some()
            {
                state.status_banner = "Stop the active scan on Tab 1 first.".to_owned();
            }
            else if rt
                .cycle
                .is_some()
                || rt
                    .speed_job
                    .is_some()
            {
                state.status_banner = "A speed check or restart is already running.".to_owned();
            }
            else
            {
                rt.speed_job = begin_speed_test(state, &mut rt.tab2_session, &mut rt.session);
            }
        }
        AppAction::CancelSpeedTest => cancel_speed_test(&mut rt.speed_job, state),
        _ =>
        {}
    }
}

/// Forwards an optional config/list reload command to an attached remote daemon and updates status.
fn forward_remote_reload(state: &mut AppState, tab2_session: &Option<Tab2Session>, req: Option<Request>)
{
    let (Some(req), Some(Tab2Session::Remote(remote))) = (req, tab2_session.as_ref())
    else
    {
        return;
    };
    let is_lists = matches!(req, Request::ReloadLists);
    let res = remote.send_command(&req);
    if is_lists
    {
        if res.is_ok()
        {
            state
                .status_banner
                .push_str(" & reloaded daemon");
        }
        return;
    }
    let label = state
        .status_banner
        .rsplit_once(" (saved to ")
        .map_or(
            state
                .status_banner
                .as_str(),
            |(l, _)| l,
        );
    state.status_banner = match res
    {
        Ok(()) => format!("{label} (saved & reloaded daemon)"),
        Err(err) => format!("{label} (saved; daemon reload failed: {err})"),
    };
}

/// Dispatches one keyboard [`AppAction`] against background workers and daemon controls.
///
/// Returns `true` when the main TUI event loop should exit.
fn handle_tui_key_action(action: AppAction, state: &mut AppState, rt: &mut TuiSessionHandles) -> bool
{
    match action
    {
        AppAction::None =>
        {}
        AppAction::Quit => return true,
        AppAction::StartScan =>
        {
            if rt
                .cycle
                .is_some()
                || rt
                    .speed_job
                    .is_some()
            {
                state.status_banner = "Wait for the active daemon cycle or speed test to finish.".to_owned();
            }
            else if rt
                .active_scan
                .is_none()
                && rt
                    .pending_scan
                    .is_none()
            {
                rt.pending_scan = begin_scan_stopping_daemon(
                    state,
                    &mut rt.active_scan,
                    &mut rt.tab2_session,
                    &mut rt.session,
                );
            }
        }
        AppAction::StopScan =>
        {
            if rt
                .pending_scan
                .take()
                .is_some()
            {
                state
                    .finder
                    .status = crate::tui::FinderStatus::Done;
                state.status_banner = "Cancelled strategy scan while stopping nfqws2.".to_owned();
            }
            else
            {
                cancel_active_scan(state, &mut rt.active_scan, &mut rt.session);
            }
        }
        AppAction::SaveConfig => save_toml_to_disk(state),
        AppAction::ReloadConfig => reload_toml_from_disk(state),
        AppAction::EditConfig => edit_config_in_editor(state, &mut rt.session),
        AppAction::PushConfigToDaemon => push_config_to_daemon(state, &rt.tab2_session),
        AppAction::StartDaemon
        | AppAction::StopDaemon
        | AppAction::DetachDaemon
        | AppAction::ReloadRemoteLists
        | AppAction::StopRemoteDaemon
        | AppAction::RestartDaemon
        | AppAction::RunSpeedTest
        | AppAction::CancelSpeedTest => handle_daemon_or_speed_action(action, state, rt),
        AppAction::DeleteSelectedDomain =>
        {
            let req = delete_selected_hostlist_domain(state);
            forward_remote_reload(state, &rt.tab2_session, req);
        }
        AppAction::MoveHostlistEntry =>
        {
            let req = move_selected_hostlist_entry(state);
            forward_remote_reload(state, &rt.tab2_session, req);
        }
        AppAction::ReloadLists =>
        {
            let req = reload_hostlist_entries(state);
            forward_remote_reload(state, &rt.tab2_session, req);
        }
        AppAction::SaveAppConfig => save_app_config_from_settings(state),
        AppAction::ReloadAppConfig => reload_app_config_from_disk(state),
        AppAction::EditAppConfig => edit_app_config_in_editor(state, &mut rt.session),
        AppAction::SubmitModal =>
        {
            if submit_auth_modal(state, &mut rt.active_scan, &mut rt.tab2_session)
            {
                rt.reexec_after_exit = true;
                return true;
            }
        }
        AppAction::SubmitPrompt =>
        {
            let req = submit_prompt_modal(state, &mut rt.web_ui);
            forward_remote_reload(state, &rt.tab2_session, req);
        }
        AppAction::StopWebUi => stop_web_ui(state, &mut rt.web_ui),
        AppAction::CopyWebPasscode => copy_web_passcode(state),
        AppAction::CopyContextText => copy_context_selection(state),
        AppAction::PasteClipboard => paste_clipboard_into_state(state),
        AppAction::OpenWebUi => open_web_ui(state),
    }
    false
}

/// Tears down active scans, embedded web UI, and daemon sessions, then optionally re-execs `zapret-rs`.
fn teardown_tui_session(state: &mut AppState, mut rt: TuiSessionHandles) -> Result<(), String>
{
    if let Some(mut scan) = rt
        .active_scan
        .take()
    {
        scan.shutdown(|g| drop_fw_tui(&mut rt.session, g));
    }
    stop_web_ui(state, &mut rt.web_ui);
    if let Some(sess) = rt
        .tab2_session
        .take()
    {
        match sess
        {
            Tab2Session::Local(mut daemon) => daemon.shutdown(|g| drop_fw_tui(&mut rt.session, g)),
            Tab2Session::Remote(mut remote) => remote.detach(),
        }
    }
    if rt.reexec_after_exit
    {
        let _ = rt
            .session
            .terminal
            .draw(|f| draw_app(f, state));
        rt.session
            .restore_on_drop = false;
        drop(rt.session);

        let exe = std::env::current_exe()
            .map_err(|err| format!("failed to resolve current executable for restart: {err}"))?;
        let args: Vec<_> = std::env::args_os()
            .skip(1)
            .collect();
        let mut cmd = Command::new(&exe);
        cmd.args(args)
            .env(SEAMLESS_REEXEC_ENV, "1");
        if let Some(encoded) = ReexecSnapshot::capture(state).encode()
        {
            cmd.env(REEXEC_STATE_ENV, encoded);
        }
        #[cfg(unix)]
        let err = cmd.exec();
        #[cfg(not(unix))]
        let err = match cmd.status()
        {
            Ok(status) => std::process::exit(
                status
                    .code()
                    .unwrap_or(1),
            ),
            Err(err) => err,
        };
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        return Err(format!("failed to restart {}: {err}", exe.display()));
    }
    if !rt.reexec_after_exit
    {
        state.save_finder_prefs();
    }
    drop(rt.session);
    Ok(())
}

/// Executes the interactive `ratatui` TUI event loop until the user quits cleanly.
pub fn run_tui(opts: TuiOptions) -> Result<(), String>
{
    let (mut state, from_reexec, pending_action) = initialize_tui_state(opts);
    let mut rt = TuiSessionHandles {
        session: TerminalSession::enter()?,
        active_scan: None,
        pending_scan: None,
        tab2_session: None,
        cycle: None,
        speed_job: None,
        web_ui: None,
        probe_tick: 0,
        autolist_tick: 0,
        reexec_after_exit: false,
    };

    if let Some(sock) = state
        .run
        .detected_socket
        .clone()
        && attach_to_socket(&mut state, &mut rt.tab2_session, sock)
        && !from_reexec
    {
        state.tab = ActiveTab::Run;
    }
    if state
        .status
        .has_net_caps
    {
        match pending_action
        {
            Some(PostCapsAction::StartScan) =>
            {
                rt.pending_scan = begin_scan_stopping_daemon(
                    &mut state,
                    &mut rt.active_scan,
                    &mut rt.tab2_session,
                    &mut rt.session,
                );
            }
            Some(PostCapsAction::StartDaemon)
                if rt
                    .tab2_session
                    .is_none() =>
            {
                try_start_or_attach(&mut state, &mut rt.tab2_session);
            }
            _ =>
            {}
        }
    }

    loop
    {
        tick_tui_workers(&mut state, &mut rt);

        rt.session
            .terminal
            .draw(|f| draw_app(f, &state))
            .map_err(|err| format!("terminal draw failed: {err}"))?;

        if event::poll(UI_TICK).map_err(|err| format!("event poll failed: {err}"))?
        {
            match event::read().map_err(|err| format!("event read failed: {err}"))?
            {
                Event::Mouse(mouse) =>
                {
                    if let Ok(sz) = rt
                        .session
                        .terminal
                        .size()
                    {
                        match handle_mouse_event(&mut state, mouse, Rect::new(0, 0, sz.width, sz.height))
                        {
                            AppAction::OpenWebUi => open_web_ui(&mut state),
                            AppAction::CopyWebPasscode => copy_web_passcode(&mut state),
                            AppAction::StopWebUi => stop_web_ui(&mut state, &mut rt.web_ui),
                            _ =>
                            {}
                        }
                    }
                }
                Event::Key(key) if key.kind == KeyEventKind::Press =>
                {
                    let action = state.handle_key(key);
                    if handle_tui_key_action(action, &mut state, &mut rt)
                    {
                        break;
                    }
                }
                Event::Paste(text) =>
                {
                    let _ = apply_paste_to_state(&mut state, &text);
                }
                Event::Key(_) | Event::Resize(_, _) | Event::FocusGained | Event::FocusLost =>
                {}
            }
        }
    }

    teardown_tui_session(&mut state, rt)
}
