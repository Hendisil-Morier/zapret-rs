//! Main `nfqws2` DPI desync daemon binary wiring CLI config, privilege drop, Lua engine, timers, and NFQUEUE.

/// Interior mutability for sharing the pre-initialized [`PacketSender`] with Lua desync callbacks.
use std::cell::RefCell;
/// Readability validation of `--lua-init` script files prior to privilege drop and `--dry-run` exit.
use std::fs::File;
/// Classification of `EACCES`/`EPERM` when skipping raw socket preinit in `--intercept=0` mode.
use std::io::ErrorKind;
/// Path buffer carried inside file I/O diagnostics for missing Lua scripts.
use std::path::PathBuf;
/// Process exit status code allowing deterministic RAII cleanup before termination.
use std::process::ExitCode;
/// Reference counting for injecting [`RawSender`] into [`DesyncEngine`].
use std::rc::Rc;
/// Poll timeout duration derived from the active timer pool deadline.
use std::time::Duration;

/// CLI parser trait used to interpret `nfqws2` command-line options.
use clap::Parser;
/// Typed error derivation for top-level startup and event-loop failures.
use thiserror::Error;

/// CLI arguments, config resolution, error wrapper, and Lua startup entry variants.
use zapret_rs::config::{AppConfig, CliArgs, ConfigError, LuaInitEntry, resolve_config};
/// Core stateful DPI desync engine and list-file startup validation helper.
use zapret_rs::desync::{DesyncEngine, verify_config_list_files};
/// Linux NFQUEUE interception listener and poll error type.
use zapret_rs::intercepter::{IntercepterError, QueueCatcher};
/// LuaJIT runtime initialization and execution error type.
use zapret_rs::lua::LuaEngineError;
/// Packet sender trait, Linux raw socket sender, and socket setup error type.
use zapret_rs::rawsend::{PacketSender, RawSendError, RawSender};
/// Process lifecycle management: PID files, `chdir`, privilege drop, caps, signals, writable dir, and daemonization.
use zapret_rs::runtime::{
    PidFileGuard, ProcessError, apply_chdir, daemonize, drop_privileges, install_signal_handlers,
    prepare_writable_dir, quit_flag, resolve_identity, retain_net_capabilities,
    take_reload_requested,
};
/// Monotonic boottime clock, scheduled timer pool, and `--intercept=0` execution loop.
use zapret_rs::timer::{TimerPool, boottime_ms, duration_until, run_no_intercept_with_tick};
/// Built-in strategy finder dispatch invoked when `--strat-finder` is passed on the CLI.
use zapret_rs::tools::{extract_strat_finder_args, run_strat_finder_cli};

/// Unified error type surfaced cleanly from `main()` with contextual diagnostics.
#[derive(Debug, Error)]
enum DaemonError {
    /// CLI parsing or TOML validation failure.
    #[error("{0}")]
    Config(#[from] ConfigError),
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

/// Handles pending `SIGHUP` requests by resetting modification signatures and reloading lists.
fn check_sighup_reload(engine: &DesyncEngine, debug: bool) {
    if take_reload_requested() {
        if debug {
            eprintln!("nfqws2: SIGHUP received, reloading lists");
        }
        engine.reload_lists();
    }
}

/// Runs SIGHUP inspection, periodic Lua GC, and expired timer callbacks, returning the next `poll()` wait.
fn next_loop_timeout(engine: &DesyncEngine, debug: bool) -> Option<Duration> {
    check_sighup_reload(engine, debug);
    let now = boottime_ms();
    engine.runtime().do_gc(now);
    let deadline = TimerPool::run_expired(
        engine.runtime().timer_pool(),
        engine.runtime().lua(),
        now,
    );
    duration_until(deadline, boottime_ms())
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
            drop_privileges(id, config.intercept)?;
            verify_lua_init_files(&config.lua_init)?;
            verify_list_files(&config)?;
        }
        println!("configuration verified");
        return Ok(());
    }

    if let Some(writable_cfg) = &config.writable {
        let writable_dir = prepare_writable_dir(writable_cfg, identity.as_ref())?;
        if config.debug {
            eprintln!("nfqws2: LUA writable dir: {}", writable_dir.display());
        }
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
        drop_privileges(id, config.intercept)?;
    } else if config.intercept {
        retain_net_capabilities(true)?;
    }

    install_signal_handlers()?;

    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(raw_sender));

    if !config.intercept {
        if config.daemon {
            daemonize()?;
        }
        if let Some(guard) = pid_guard.as_mut() {
            guard.write_current_pid()?;
        }
        let engine = DesyncEngine::with_sender(&config, sender)?;
        let debug = config.debug;
        run_no_intercept_with_tick(engine.runtime().timer_pool(), engine.runtime(), quit_flag(), || {
            check_sighup_reload(&engine, debug);
        });
        return Ok(());
    }

    let engine = DesyncEngine::with_sender(&config, sender)?;
    let mut catcher = QueueCatcher::bind(config.to_queue_config())?;
    if config.daemon {
        daemonize()?;
    }
    if let Some(guard) = pid_guard.as_mut() {
        guard.write_current_pid()?;
    }

    let debug = config.debug;
    catcher.run_until(
        quit_flag(),
        || next_loop_timeout(&engine, debug),
        |pkt| engine.process_packet(pkt),
    )?;
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
