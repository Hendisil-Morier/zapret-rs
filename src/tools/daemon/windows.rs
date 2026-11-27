//! Windows WinDivert daemon startup pipeline, control IPC wiring, and event loop.

/// Interior mutability for sharing [`DesyncEngine`] across event-loop callbacks.
use std::cell::RefCell;
/// Path type passed to config resolution and control socket setup.
use std::path::Path;
/// Shared lock-free telemetry hub for control IPC subscribers.
use std::sync::Arc;
/// Local stop signal enabling filter rebinding on `reload_config` without aborting the daemon.
use std::sync::atomic::{AtomicBool, Ordering};
/// Poll timeout duration derived from the active timer pool deadline.
use std::time::Duration;

/// CLI arguments, config resolution, and error wrapper.
use crate::config::{AppConfig, CliArgs, resolve_config};
/// Cross-platform control IPC server, telemetry hub, and directory helpers.
use crate::control::{
    ControlServer, ControlServerConfig, DaemonStatusMeta, TelemetryHub,
    prepare_control_socket_dir, resolve_control_socket_path,
};
/// Core stateful DPI desync engine, profile names, and control command dispatcher.
use crate::desync::{DesyncEngine, collect_profile_names, drain_hub_commands};
/// Windows WinDivert packet intercepter implementing [`PacketIntercepter`].
use crate::intercepter::{PacketIntercepter, WinDivertIntercepter};
/// Console Ctrl-C signal handler and writable directory preparation.
use crate::runtime::{install_signal_handlers, prepare_writable_dir, quit_flag};
/// Shared packet counters and L3/L4/L7 packet record builder for control subscribers.
use crate::telemetry::{PacketCounters, build_packet_record};
/// Monotonic clock, scheduled timer pool, and `--intercept=0` execution loop.
use crate::timer::{TimerPool, boottime_ms, duration_until, run_no_intercept_callbacks};
/// Target port range collector and WinDivert filter-expression builder.
use crate::tools::strat::firewall::{PortRangePair, collect_config_port_ranges};
/// Shared daemon startup and event-loop error enum.
use crate::tools::daemon::error::DaemonError;
/// WinDivert filter string generator matching configured TCP/UDP port ranges.
use crate::tools::strat::windivert::build_windivert_filter_ranges;

/// Maximum timer/command poll slice when control IPC is active.
const CONTROL_LOOP_TIMEOUT_CAP: Duration = Duration::from_millis(50);

/// Optional telemetry hub and control IPC server handles created during Windows startup.
type WindowsControlHandles = (Option<Arc<TelemetryHub>>, Option<ControlServer>);

/// Collects inclusive `(tcp_ranges, udp_ranges)` matching the active `engine` profiles.
fn collect_engine_port_ranges(qnum: u16, fwmark: u32, engine: &DesyncEngine) -> PortRangePair {
    let mut cfg = AppConfig { qnum, fwmark, ..AppConfig::default() };
    cfg.profiles = engine.profiles().iter().map(|p| (**p).clone()).collect();
    collect_config_port_ranges(&cfg)
}

/// Advances Lua GC, timers, and pending control IPC commands between captured packets.
///
/// Sets `round_stop` and returns refreshed `(tcp, udp)` port intervals into `pending_ports` when a
/// live `reload_config` changes the active WinDivert port set.
fn poll_windows_loop(
    engine: &RefCell<DesyncEngine>,
    hub: Option<&TelemetryHub>,
    config: &AppConfig,
    config_dir: Option<&Path>,
    active_ports: &PortRangePair,
    pending_ports: &RefCell<Option<PortRangePair>>,
    round_stop: &AtomicBool,
) -> Option<Duration> {
    if quit_flag().load(Ordering::Acquire) {
        round_stop.store(true, Ordering::Release);
        return None;
    }
    if let Some(active_hub) = hub {
        let mut eng = engine.borrow_mut();
        let swapped = drain_hub_commands(
            &mut eng,
            active_hub,
            config.qnum,
            config.fwmark,
            config_dir,
            quit_flag(),
            config.debug,
        );
        if swapped {
            let new_ports = collect_engine_port_ranges(config.qnum, config.fwmark, &eng);
            if new_ports != *active_ports {
                *pending_ports.borrow_mut() = Some(new_ports);
                round_stop.store(true, Ordering::Release);
                return None;
            }
        }
    }
    let now = boottime_ms();
    {
        let eng = engine.borrow();
        eng.runtime().do_gc(now);
        TimerPool::run_expired(eng.runtime().timer_pool(), eng.runtime().lua(), now);
    }
    let deadline = engine.borrow().runtime().timer_pool().borrow_mut().next_deadline_ms();
    let wait = duration_until(deadline, boottime_ms());
    if hub.is_some() {
        Some(wait.map_or(CONTROL_LOOP_TIMEOUT_CAP, |d| d.min(CONTROL_LOOP_TIMEOUT_CAP)))
    } else {
        wait
    }
}

/// Starts the Windows control IPC server when configured.
fn start_windows_control_server(
    socket_path: Option<&Path>,
    config: &AppConfig,
    engine: &DesyncEngine,
    config_path: Option<&Path>,
) -> Result<WindowsControlHandles, DaemonError> {
    let Some(path) = socket_path else {
        return Ok((None, None));
    };
    prepare_control_socket_dir(path, None, None)?;
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
    Ok((Some(hub), Some(srv)))
}

/// Executes the Windows WinDivert daemon startup pipeline and packet event loop.
pub(crate) fn run_daemon_windows(cli: &CliArgs) -> Result<(), DaemonError> {
    let config = resolve_config(cli)?;
    if let Some(dir) = &config.chdir {
        std::env::set_current_dir(dir)?;
    }
    if config.writable.is_some() {
        let _ = prepare_writable_dir(
            config.writable.as_ref().unwrap_or(&crate::config::WritableDirConfig::Default),
            None,
        )?;
    }
    if cli.dry_run {
        let _ = DesyncEngine::new(&config)?;
        return Ok(());
    }

    install_signal_handlers()?;
    let config_dir = cli.config.as_deref().and_then(Path::parent);
    let socket_path = resolve_control_socket_path(&config.control_socket, config.intercept);
    let engine = RefCell::new(DesyncEngine::new(&config)?);
    let (hub, control_server) = start_windows_control_server(
        socket_path.as_deref(),
        &config,
        &engine.borrow(),
        cli.config.as_deref(),
    )?;

    if !config.intercept {
        run_no_intercept_callbacks(
            quit_flag(),
            || {
                if let Some(active_hub) = hub.as_deref() {
                    let mut eng = engine.borrow_mut();
                    drain_hub_commands(
                        &mut eng,
                        active_hub,
                        config.qnum,
                        config.fwmark,
                        config_dir,
                        quit_flag(),
                        config.debug,
                    );
                }
            },
            || engine.borrow().runtime().timer_pool().borrow().is_empty(),
            || engine.borrow().runtime().timer_pool().borrow_mut().next_deadline_ms(),
            || {
                let eng = engine.borrow();
                let now = boottime_ms();
                eng.runtime().do_gc(now);
                TimerPool::run_expired(eng.runtime().timer_pool(), eng.runtime().lua(), now)
            },
        );
        if let Some(srv) = control_server {
            srv.shutdown();
        }
        return Ok(());
    }

    let mut active_ports = collect_config_port_ranges(&config);
    let mut loop_result = Ok(());
    while !quit_flag().load(Ordering::Acquire) {
        let filter = build_windivert_filter_ranges(&active_ports.0, &active_ports.1);
        let mut catcher = WinDivertIntercepter::bind(&filter)?;
        let round_stop = AtomicBool::new(false);
        let pending_ports = RefCell::new(None);
        loop_result = catcher.run_until(
            &round_stop,
            || {
                poll_windows_loop(
                    &engine,
                    hub.as_deref(),
                    &config,
                    config_dir,
                    &active_ports,
                    &pending_ports,
                    &round_stop,
                )
            },
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
        if loop_result.is_err() {
            break;
        }
        if let Some(next_ports) = pending_ports.into_inner() {
            active_ports = next_ports;
        } else {
            break;
        }
    }
    if let Some(srv) = control_server {
        srv.shutdown();
    }
    loop_result?;
    Ok(())
}
