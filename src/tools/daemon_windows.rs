//! Windows WinDivert daemon startup pipeline, control IPC wiring, and event loop.

/// Interior mutability for sharing [`DesyncEngine`] across event-loop callbacks.
use std::cell::RefCell;
/// Path type passed to config resolution and control socket setup.
use std::path::Path;
/// Shared lock-free telemetry hub for control IPC subscribers.
use std::sync::Arc;
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
/// Target port collector and WinDivert filter-expression builder.
use crate::tools::firewall::collect_config_ports;
/// WinDivert filter string generator matching configured TCP/UDP ports.
use crate::tools::strat_windivert::build_windivert_filter;

/// Maximum timer/command poll slice when control IPC is active.
const CONTROL_LOOP_TIMEOUT_CAP: Duration = Duration::from_millis(50);

/// Advances Lua GC, timers, and pending control IPC commands between captured packets.
fn poll_windows_loop(
    engine: &RefCell<DesyncEngine>,
    hub: Option<&TelemetryHub>,
    config: &AppConfig,
    config_dir: Option<&Path>,
) -> Option<Duration> {
    if let Some(active_hub) = hub {
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
) -> Result<(Option<Arc<TelemetryHub>>, Option<ControlServer>), Box<dyn std::error::Error>> {
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
pub(crate) fn run_daemon_windows(cli: &CliArgs) -> Result<(), Box<dyn std::error::Error>> {
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

    let (tcp_ports, udp_ports) = collect_config_ports(&config);
    let filter = build_windivert_filter(&tcp_ports, &udp_ports);
    let mut catcher = WinDivertIntercepter::bind(&filter)?;
    let loop_result = catcher.run_until(
        quit_flag(),
        || poll_windows_loop(&engine, hub.as_deref(), &config, config_dir),
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
    if let Some(srv) = control_server {
        srv.shutdown();
    }
    loop_result?;
    Ok(())
}
