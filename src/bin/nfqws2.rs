//! Main `nfqws2` DPI desync daemon binary wiring CLI config, privilege drop, Lua engine, timers, and NFQUEUE.

/// Interior mutability for sharing the pre-initialized [`PacketSender`] with Lua desync callbacks.
use std::cell::RefCell;
/// Readability validation of `--lua-init` script files prior to privilege drop and `--dry-run` exit.
use std::fs::File;
/// Classification of `EACCES`/`EPERM` when skipping raw socket preinit in `--intercept=0` mode.
use std::io::ErrorKind;
/// Path buffer carried inside file I/O diagnostics and control socket setup.
use std::path::{Path, PathBuf};
/// Process exit status code allowing deterministic RAII cleanup before termination.
use std::process::ExitCode;
/// Reference counting for injecting [`RawSender`] into [`DesyncEngine`].
use std::rc::Rc;
/// Shared lock-free telemetry hub for control socket subscribers.
use std::sync::Arc;
/// Poll timeout duration derived from the active timer pool deadline.
use std::time::Duration;

/// CLI parser trait used to interpret `nfqws2` command-line options.
use clap::Parser;
/// Typed error derivation for top-level startup and event-loop failures.
use thiserror::Error;

/// CLI arguments, config resolution, error wrapper, and Lua startup entry variants.
use zapret_rs::config::{AppConfig, CliArgs, ConfigError, LuaInitEntry, resolve_config};
/// Unix control socket server, telemetry hub, and directory helpers.
use zapret_rs::control::{
    ControlServer, ControlServerConfig, ControlServerError, DaemonStatusMeta, TelemetryHub,
    prepare_control_socket_dir, resolve_control_socket_path,
};
/// Core stateful DPI desync engine, list-file validation, and control command/reload helpers.
use zapret_rs::desync::{
    DesyncEngine, collect_profile_names, drain_hub_commands, verify_config_list_files,
};
/// Linux NFQUEUE interception listener and poll error type.
use zapret_rs::intercepter::{IntercepterError, QueueCatcher};
/// LuaJIT runtime initialization and execution error type.
use zapret_rs::lua::LuaEngineError;
/// Packet sender trait, Linux raw socket sender, and socket setup error type.
use zapret_rs::rawsend::{PacketSender, RawSendError, RawSender};
/// Process lifecycle management: PID files, `chdir`, privilege drop, caps, signals, writable dir, and daemonization.
use zapret_rs::runtime::{
    PidFileGuard, ProcessError, apply_chdir, daemonize, drop_privileges_for, install_signal_handlers,
    prepare_writable_dir, quit_flag, resolve_identity, retain_net_capabilities_for,
    take_reload_requested,
};
/// Monotonic boottime clock, scheduled timer pool, and `--intercept=0` execution loop.
use zapret_rs::timer::{TimerPool, boottime_ms, duration_until, run_no_intercept_callbacks};
/// Shared packet counters and L3/L4/L7 packet record builder for control subscribers.
use zapret_rs::telemetry::{PacketCounters, build_packet_record};
/// Built-in strategy finder dispatch and optional auto-managed `nftables` queue helpers.
use zapret_rs::tools::{
    FirewallBackend, FirewallHandle, NftFirewallBackend, collect_config_ports,
    extract_strat_finder_args, run_strat_finder_cli,
};

/// Maximum poll timeout when the control socket is active so commands execute promptly.
const CONTROL_LOOP_TIMEOUT_CAP: Duration = Duration::from_millis(50);

/// Unified error type surfaced cleanly from `main()` with contextual diagnostics.
#[derive(Debug, Error)]
enum DaemonError {
    /// CLI parsing or TOML validation failure.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// Unix domain control socket setup or binding failure.
    #[error("{0}")]
    Control(#[from] ControlServerError),
    /// Failure during `chdir`, UID/user resolution, PID file creation, capability setup, daemonize, or signals.
    #[error("{0}")]
    Process(#[from] ProcessError),
    /// Raw L3 socket pre-initialization failure (`SOCK_RAW` + `IPPROTO_RAW`).
    #[error("{0}")]
    RawSend(#[from] RawSendError),
    /// Embedded LuaJIT initialization, script execution, or missing profile action function.
    #[error("{0}")]
    Lua(#[from] LuaEngineError),
    /// Linux NFQUEUE socket bind, receive, poll, or verdict submission error.
    #[error("{0}")]
    Intercepter(#[from] IntercepterError),
    /// Temporary `nftables` queue rule installation failure when `--nft` is enabled.
    #[error("temporary nftables setup failed: {0}")]
    Nft(#[source] std::io::Error),
    /// Referenced `--lua-init` script file could not be opened under active privileges.
    #[error("cannot open Lua init script '{}': {source}", path.display())]
    ScriptIo {
        /// Filesystem path of the unreadable startup Lua script.
        path: PathBuf,
        /// Underlying OS error returned by `File::open`.
        #[source]
        source: std::io::Error,
    },
    /// Referenced hostlist, ipset, autohostlist, or debug log file failed validation.
    #[error("cannot load list file '{}': {source}", path.display())]
    ListIo {
        /// Filesystem path of the invalid or inaccessible list file.
        path: PathBuf,
        /// Underlying OS or gzip decoding error.
        #[source]
        source: std::io::Error,
    },
}

/// Checks that every `LuaInitEntry::File` script can be opened before `--dry-run` exits or loops begin.
fn verify_lua_init_files(entries: &[LuaInitEntry]) -> Result<(), DaemonError> {
    for entry in entries {
        if let LuaInitEntry::File(path) = entry {
            File::open(path).map_err(|source| DaemonError::ScriptIo {
                path: path.clone(),
                source,
            })?;
        }
    }
    Ok(())
}

/// Validates all hostlists, ipsets, autohostlists, and autohostlist debug log paths (`test_list_files`).
fn verify_list_files(config: &AppConfig) -> Result<(), DaemonError> {
    verify_config_list_files(config).map_err(|(path, source)| DaemonError::ListIo { path, source })
}

/// Processes pending `SIGHUP` reloads and control-socket commands, refreshing `--nft` rules if needed.
fn poll_signals_and_commands(
    engine: &RefCell<DesyncEngine>,
    hub: Option<&TelemetryHub>,
    config: &AppConfig,
    config_dir: Option<&Path>,
    fw_guard: Option<&mut Option<Box<dyn FirewallHandle>>>,
) {
    if take_reload_requested() {
        if config.debug {
            eprintln!("nfqws2: SIGHUP received, reloading lists");
        }
        engine.borrow().reload_lists();
    }
    let Some(active_hub) = hub else {
        return;
    };
    let swapped = drain_hub_commands(
        &mut engine.borrow_mut(),
        active_hub,
        config.qnum,
        config.fwmark,
        config_dir,
        quit_flag(),
        config.debug,
    );
    if swapped && let Some(guard @ Some(_)) = fw_guard {
        refresh_auto_nft_ports(config.qnum, config.fwmark, &engine.borrow(), guard);
    }
}

/// Runs SIGHUP inspection, control commands, Lua GC, and expired timer callbacks.
fn next_loop_timeout(
    engine: &RefCell<DesyncEngine>,
    hub: Option<&TelemetryHub>,
    config: &AppConfig,
    config_dir: Option<&Path>,
    fw_guard: &mut Option<Box<dyn FirewallHandle>>,
) -> Option<Duration> {
    poll_signals_and_commands(engine, hub, config, config_dir, Some(fw_guard));
    let now = boottime_ms();
    let deadline = {
        let eng = engine.borrow();
        eng.runtime().do_gc(now);
        TimerPool::run_expired(eng.runtime().timer_pool(), eng.runtime().lua(), now)
    };
    let wait = duration_until(deadline, boottime_ms());
    if hub.is_some() {
        Some(wait.map_or(CONTROL_LOOP_TIMEOUT_CAP, |d| d.min(CONTROL_LOOP_TIMEOUT_CAP)))
    } else {
        wait
    }
}

/// Refreshes managed `zapret_strat_finder` ports non-interactively after a live `reload_config`.
fn refresh_auto_nft_ports(
    qnum: u16,
    fwmark: u32,
    engine: &DesyncEngine,
    fw_guard: &mut Option<Box<dyn FirewallHandle>>,
) {
    let mut cfg = AppConfig { qnum, fwmark, ..AppConfig::default() };
    cfg.profiles = engine.profiles().iter().map(|p| (**p).clone()).collect();
    let (tcp, udp) = collect_config_ports(&cfg);
    match NftFirewallBackend::default().install_non_interactive(qnum, fwmark, &tcp, &udp) {
        Ok(new_guard) => *fw_guard = Some(new_guard),
        Err(err) => eprintln!("nfqws2: warning: could not refresh --nft rules after reload: {err}"),
    }
}

/// Installs the managed temporary `nftables` queue table when `--nft` (`auto_nft`) is enabled.
fn maybe_install_auto_nft(config: &AppConfig) -> Result<Option<Box<dyn FirewallHandle>>, DaemonError> {
    if !config.auto_nft || !config.intercept {
        return Ok(None);
    }
    let (tcp, udp) = collect_config_ports(config);
    let guard = NftFirewallBackend::default()
        .install(config.qnum, config.fwmark, &tcp, &udp)
        .map_err(DaemonError::Nft)?;
    if config.debug {
        eprintln!(
            "nfqws2: installed auto-cleaned nftables rules on queue {} (fwmark 0x{:08x})",
            config.qnum, config.fwmark
        );
    }
    Ok(Some(guard))
}

/// Starts the Unix control socket server after daemonization and privilege drop when configured.
fn maybe_start_control_server(
    socket_path: Option<&Path>,
    config: &AppConfig,
    engine: &DesyncEngine,
    config_path: Option<&Path>,
) -> Result<(Option<Arc<TelemetryHub>>, Option<ControlServer>), DaemonError> {
    let Some(path) = socket_path else {
        return Ok((None, None));
    };
    let meta = DaemonStatusMeta {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        qnum: config.qnum,
        fwmark: config.fwmark,
        intercept: config.intercept,
        profile_names: collect_profile_names(engine.profiles()),
        config_path: config_path.map(|p| p.display().to_string()),
    };
    let hub = TelemetryHub::new(Arc::new(PacketCounters::default()), meta, config.control_pass_sample);
    let srv_cfg = ControlServerConfig::new(path.to_path_buf(), env!("CARGO_PKG_VERSION"));
    let srv = ControlServer::start(srv_cfg, Arc::clone(&hub))?;
    if config.debug {
        eprintln!("nfqws2: control socket listening at {}", srv.socket_path().display());
    }
    Ok((Some(hub), Some(srv)))
}

/// Executes the `nfqws2` startup pipeline (`chdir`, identity, `preinit`, `droproot`, signals) and event loop.
fn run() -> Result<(), DaemonError> {
    let cli = CliArgs::parse();
    let config = resolve_config(&cli)?;

    if let Some(dir) = &config.chdir {
        apply_chdir(dir)?;
    }

    let identity = resolve_identity(config.user.as_deref(), config.uid.as_deref())?;
    verify_lua_init_files(&config.lua_init)?;
    verify_list_files(&config)?;

    if cli.dry_run {
        if let Some(id) = &identity {
            drop_privileges_for(id, config.intercept, false)?;
            verify_lua_init_files(&config.lua_init)?;
            verify_list_files(&config)?;
        }
        println!("configuration verified");
        return Ok(());
    }

    let control_socket_path =
        resolve_control_socket_path(&config.control_socket, config.intercept);

    if let Some(writable_cfg) = &config.writable {
        let writable_dir = prepare_writable_dir(writable_cfg, identity.as_ref())?;
        if config.debug {
            eprintln!("nfqws2: LUA writable dir: {}", writable_dir.display());
        }
    }

    if let Some(ref sock_path) = control_socket_path {
        let uid = identity.as_ref().map(|id| id.uid);
        let gid = identity.as_ref().and_then(|id| id.gids.first().copied());
        prepare_control_socket_dir(sock_path, uid, gid)?;
    }

    // Create/truncate PID file and open raw sockets prior to dropping root privileges.
    let mut pid_guard = match &config.pidfile {
        Some(path) => Some(PidFileGuard::create(path)?),
        None => None,
    };

    let mut raw_sender = RawSender::new(config.bind_fix4, config.bind_fix6);
    match raw_sender.preinit() {
        Ok(()) => {}
        Err(RawSendError::SocketIo(err))
            if !config.intercept && err.kind() == ErrorKind::PermissionDenied =>
        {
            if config.debug {
                eprintln!(
                    "nfqws2: skipping rawsend preinit without CAP_NET_RAW in --intercept=0 mode"
                );
            }
        }
        Err(err) => return Err(err.into()),
    }

    if let Some(id) = &identity {
        drop_privileges_for(id, config.intercept, config.auto_nft)?;
    } else if config.intercept {
        retain_net_capabilities_for(true, config.auto_nft)?;
    }

    install_signal_handlers()?;

    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(raw_sender));

    let config_dir = cli.config.as_deref().and_then(Path::parent);

    if !config.intercept {
        if config.daemon {
            daemonize()?;
        }
        if let Some(guard) = pid_guard.as_mut() {
            guard.write_current_pid()?;
        }
        let engine = RefCell::new(DesyncEngine::with_sender(&config, sender)?);
        let (hub, control_server) = maybe_start_control_server(
            control_socket_path.as_deref(),
            &config,
            &engine.borrow(),
            cli.config.as_deref(),
        )?;
        run_no_intercept_callbacks(
            quit_flag(),
            || poll_signals_and_commands(&engine, hub.as_deref(), &config, config_dir, None),
            || engine.borrow().runtime().timer_pool().borrow().is_empty(),
            || engine.borrow().runtime().timer_pool().borrow_mut().next_deadline_ms(),
            || {
                let eng = engine.borrow();
                let current_now = boottime_ms();
                eng.runtime().do_gc(current_now);
                TimerPool::run_expired(
                    eng.runtime().timer_pool(),
                    eng.runtime().lua(),
                    current_now,
                )
            },
        );
        if let Some(srv) = control_server {
            srv.shutdown();
        }
        return Ok(());
    }

    let engine = RefCell::new(DesyncEngine::with_sender(&config, sender)?);
    let mut catcher = QueueCatcher::bind(config.to_queue_config())?;
    if config.daemon {
        daemonize()?;
    }
    if let Some(guard) = pid_guard.as_mut() {
        guard.write_current_pid()?;
    }
    let (hub, control_server) = maybe_start_control_server(
        control_socket_path.as_deref(),
        &config,
        &engine.borrow(),
        cli.config.as_deref(),
    )?;
    let mut fw_guard = maybe_install_auto_nft(&config)?;

    let loop_result = catcher.run_until(
        quit_flag(),
        || next_loop_timeout(&engine, hub.as_deref(), &config, config_dir, &mut fw_guard),
        |pkt| {
            if let Some(ref active_hub) = hub {
                let (decision, outcome) = engine.borrow().process_packet_traced(pkt);
                let (seq, verdict) = active_hub.counters().record_outcome(&outcome);
                if active_hub.should_publish(verdict) {
                    active_hub.publish_packet(build_packet_record(seq, pkt, &outcome));
                }
                decision
            } else {
                engine.borrow().process_packet(pkt)
            }
        },
    );
    drop(fw_guard);
    if let Some(srv) = control_server {
        srv.shutdown();
    }
    loop_result?;
    Ok(())
}

/// Entry point dispatches `--strat-finder` or delegates to [`run`], preserving RAII destructors on exit.
fn main() -> ExitCode {
    if let Some(sf_args) = extract_strat_finder_args(std::env::args_os()) {
        return run_strat_finder_cli(sf_args);
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nfqws2 error: {err}");
            ExitCode::FAILURE
        }
    }
}
