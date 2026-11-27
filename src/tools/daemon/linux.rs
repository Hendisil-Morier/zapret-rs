//! Linux `nfqws2` NFQUEUE daemon startup pipeline, control IPC wiring, and event loop.

/// Interior mutability for sharing the pre-initialized [`PacketSender`] with Lua desync callbacks.
use std::cell::RefCell;
/// Readability validation of `--lua-init` script files prior to privilege drop and `--dry-run` exit.
use std::fs::File;
/// Classification of `EACCES`/`EPERM` when skipping raw socket preinit in `--intercept=0` mode.
use std::io::ErrorKind;
/// Path buffer carried inside file I/O diagnostics and control socket setup.
use std::path::{Path, PathBuf};
/// Reference counting for injecting [`RawSender`] into [`DesyncEngine`].
use std::rc::Rc;
/// Shared lock-free telemetry hub for control socket subscribers.
use std::sync::Arc;
/// Poll timeout duration derived from the active timer pool deadline.
use std::time::Duration;

/// Typed error derivation for top-level startup and event-loop failures.
use thiserror::Error;

/// CLI arguments, config resolution, error wrapper, and Lua startup entry variants.
use crate::config::{AppConfig, CliArgs, ConfigError, LuaInitEntry, resolve_config};
/// Unix control socket server, telemetry hub, and directory helpers.
use crate::control::{
    ControlServer, ControlServerConfig, ControlServerError, DaemonStatusMeta, TelemetryHub,
    prepare_control_socket_dir, resolve_control_socket_path,
};
/// Core stateful DPI desync engine, list-file validation, and control command/reload helpers.
use crate::desync::{
    DesyncEngine, collect_profile_names, drain_hub_commands, verify_config_list_files,
};
/// Linux NFQUEUE interception listener and poll error type.
use crate::intercepter::{IntercepterError, QueueCatcher};
/// LuaJIT runtime initialization and execution error type.
use crate::lua::LuaEngineError;
/// Packet sender trait, Linux raw socket sender, and socket setup error type.
use crate::rawsend::{PacketSender, RawSendError, RawSender};
/// Process lifecycle management: PID files, `chdir`, privilege drop, caps, signals, writable dir, and daemonization.
use crate::runtime::{
    PidFileGuard, ProcessError, apply_chdir, daemonize, drop_privileges_for, install_signal_handlers,
    prepare_writable_dir, quit_flag, resolve_identity, retain_net_capabilities_for,
    take_reload_requested,
};
/// Shared packet counters and L3/L4/L7 packet record builder for control subscribers.
use crate::telemetry::{PacketCounters, build_packet_record};
/// Monotonic boottime clock, scheduled timer pool, and `--intercept=0` execution loop.
use crate::timer::{TimerPool, boottime_ms, duration_until, run_no_intercept_callbacks};
/// OS-agnostic firewall handle and range-aware port collection helpers.
use crate::tools::strat::firewall::{FirewallHandle, collect_config_port_ranges};
/// Temporary `nftables` firewall guard backend used by `--nft`.
use crate::tools::strat::nft::NftFirewallBackend;

/// Maximum poll timeout when the control socket is active so commands execute promptly.
const CONTROL_LOOP_TIMEOUT_CAP: Duration = Duration::from_millis(50);

/// Unified error type surfaced cleanly from `nfqws2` startup and event loops.
#[derive(Debug, Error)]
pub(crate) enum DaemonError {
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
    let (tcp, udp) = collect_config_port_ranges(&cfg);
    match NftFirewallBackend::default().install_ranges_non_interactive(qnum, fwmark, &tcp, &udp) {
        Ok(new_guard) => {
            if let Some(old) = fw_guard.as_mut() {
                old.disarm();
            }
            *fw_guard = Some(new_guard);
        }
        Err(err) => eprintln!("nfqws2: warning: could not refresh --nft rules after reload: {err}"),
    }
}

/// Installs the managed temporary `nftables` queue table when `--nft` (`auto_nft`) is enabled.
fn maybe_install_auto_nft(config: &AppConfig) -> Result<Option<Box<dyn FirewallHandle>>, DaemonError> {
    if !config.auto_nft || !config.intercept {
        return Ok(None);
    }
    let (tcp, udp) = collect_config_port_ranges(config);
    let guard = NftFirewallBackend::default()
        .install_ranges(config.qnum, config.fwmark, &tcp, &udp)
        .map_err(DaemonError::Nft)?;
    if config.debug {
        eprintln!(
            "nfqws2: installed auto-cleaned nftables rules on queue {} (fwmark 0x{:08x})",
            config.qnum, config.fwmark
        );
    }
    Ok(Some(guard))
}

/// Daemonizes if requested and writes the active child PID file prior to firewall or IPC setup.
fn prepare_daemon_runtime(
    config: &AppConfig,
    pid_guard: &mut Option<PidFileGuard>,
) -> Result<(), DaemonError> {
    if config.daemon {
        daemonize()?;
    }
    if let Some(guard) = pid_guard.as_mut() {
        guard.write_current_pid()?;
    }
    Ok(())
}

/// Starts the Unix control socket listener and telemetry hub after firewall rules are installed.
fn start_control_session(
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
pub(crate) fn run_daemon_linux(cli: &CliArgs) -> Result<(), DaemonError> {
    let config = resolve_config(cli)?;
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

    let control_socket_path = resolve_control_socket_path(&config.control_socket, config.intercept);
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

    let mut pid_guard = config.pidfile.as_deref().map(PidFileGuard::create).transpose()?;
    let mut raw_sender = RawSender::new(config.bind_fix4, config.bind_fix6);
    match raw_sender.preinit() {
        Ok(()) => {}
        Err(RawSendError::SocketIo(err)) if !config.intercept && err.kind() == ErrorKind::PermissionDenied => {
            if config.debug {
                eprintln!("nfqws2: skipping rawsend preinit without CAP_NET_RAW in --intercept=0 mode");
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
    let engine = RefCell::new(DesyncEngine::with_sender(&config, sender)?);

    if !config.intercept {
        prepare_daemon_runtime(&config, &mut pid_guard)?;
        let (hub, srv) = start_control_session(
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
                let now = boottime_ms();
                eng.runtime().do_gc(now);
                TimerPool::run_expired(eng.runtime().timer_pool(), eng.runtime().lua(), now)
            },
        );
        if let Some(ctrl) = srv {
            ctrl.shutdown();
        }
        return Ok(());
    }

    let mut catcher = QueueCatcher::bind(config.to_queue_config())?;
    prepare_daemon_runtime(&config, &mut pid_guard)?;
    // Install nftables queue rules before opening control.sock so callers never race Packet Probes.
    let mut fw_guard = maybe_install_auto_nft(&config)?;
    let (hub, srv) = start_control_session(
        control_socket_path.as_deref(),
        &config,
        &engine.borrow(),
        cli.config.as_deref(),
    )?;
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
    if let Some(ctrl) = srv {
        ctrl.shutdown();
    }
    loop_result?;
    Ok(())
}
