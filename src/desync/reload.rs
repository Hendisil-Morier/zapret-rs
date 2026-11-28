//! Safe live profile reload helper validating TOML changes before swapping engine state.

/// Optional base directory used to resolve relative hostlist and ipset paths.
use std::path::Path;
/// Shared profile slices exposed by [`DesyncEngine::profiles`].
use std::rc::Rc;
/// Cooperative termination flag triggered cleanly by remote `Stop` commands.
use std::sync::atomic::{AtomicBool, Ordering};

/// TOML parser and validated profile schema (`AppConfig`, `DesyncProfile`).
use crate::config::{AppConfig, DesyncProfile};
/// Daemon IPC command enum and telemetry hub drained in event loops.
use crate::control::{ControlCommand, TelemetryHub};
/// Stateful desync execution engine updated via [`DesyncEngine::replace_profiles`].
use crate::desync::engine::DesyncEngine;

/// Returns display labels for active desync profiles (falling back to `profile#<index>`).
pub fn collect_profile_names(profiles: &[Rc<DesyncProfile>]) -> Vec<String>
{
    profiles
        .iter()
        .map(|p| {
            p.name
                .clone()
                .unwrap_or_else(|| format!("profile#{}", p.index))
        })
        .collect()
}

/// Parses `toml_str`, enforces immutable `qnum`/`fwmark`, and atomically swaps `engine` profiles.
pub fn reload_engine_from_toml(
    engine: &mut DesyncEngine,
    running_qnum: u16,
    running_fwmark: u32,
    base_dir: Option<&Path>,
    toml_str: &str,
) -> Result<Vec<String>, String>
{
    let parsed =
        AppConfig::from_toml_str(toml_str, base_dir).map_err(|err| format!("invalid TOML config: {err}"))?;
    if parsed.qnum != running_qnum
    {
        return Err(format!(
            "cannot change qnum ({running_qnum} -> {}) without restarting nfqws2 daemon",
            parsed.qnum
        ));
    }
    if parsed.fwmark != running_fwmark
    {
        return Err(format!(
            "cannot change fwmark (0x{running_fwmark:08x} -> 0x{:08x}) without restarting nfqws2 daemon",
            parsed.fwmark
        ));
    }
    engine
        .replace_profiles(parsed.profiles)
        .map_err(|err| format!("failed to load reloaded profiles: {err}"))?;
    Ok(collect_profile_names(engine.profiles()))
}

/// Executes all queued [`ControlCommand`] requests on `hub`, returning `true` if profiles changed.
pub fn drain_hub_commands(
    engine: &mut DesyncEngine,
    hub: &TelemetryHub,
    qnum: u16,
    fwmark: u32,
    config_dir: Option<&Path>,
    quit: &AtomicBool,
    debug: bool,
) -> bool
{
    let mut profiles_changed = false;
    while let Some(cmd) = hub.try_recv_command()
    {
        match cmd
        {
            ControlCommand::ReloadLists { reply } =>
            {
                engine.reload_lists();
                if debug
                {
                    eprintln!("nfqws2: control reload_lists completed");
                }
                let _ = reply.send(Ok("reloaded hostlist and ipset files".to_owned()));
            }
            ControlCommand::ReloadConfig { toml, reply } =>
            {
                match reload_engine_from_toml(engine, qnum, fwmark, config_dir, &toml)
                {
                    Ok(names) =>
                    {
                        let count = names.len();
                        hub.set_profile_names(names);
                        profiles_changed = true;
                        if debug
                        {
                            eprintln!("nfqws2: control reload_config swapped {count} profile(s)");
                        }
                        let _ = reply.send(Ok(format!("reloaded {count} profile(s)")));
                    }
                    Err(err) =>
                    {
                        let _ = reply.send(Err(err));
                    }
                }
            }
            ControlCommand::Stop { reply } =>
            {
                quit.store(true, Ordering::Release);
                if debug
                {
                    eprintln!("nfqws2: control stop requested");
                }
                let _ = reply.send(Ok("stopping nfqws2".to_owned()));
            }
        }
    }
    profiles_changed
}
