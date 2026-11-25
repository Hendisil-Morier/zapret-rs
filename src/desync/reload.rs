//! Safe live profile reload helper validating TOML changes before swapping engine state.

/// Optional base directory used to resolve relative hostlist and ipset paths.
use std::path::Path;
/// Shared profile slices exposed by [`DesyncEngine::profiles`].
use std::rc::Rc;

/// TOML parser and validated profile schema (`AppConfig`, `DesyncProfile`).
use crate::config::{AppConfig, DesyncProfile};
/// Stateful desync execution engine updated via [`DesyncEngine::replace_profiles`].
use crate::desync::engine::DesyncEngine;

/// Returns display labels for active desync profiles (falling back to `profile#<index>`).
pub fn collect_profile_names(profiles: &[Rc<DesyncProfile>]) -> Vec<String> {
    profiles
        .iter()
        .map(|p| p.name.clone().unwrap_or_else(|| format!("profile#{}", p.index)))
        .collect()
}

/// Parses `toml_str`, enforces immutable `qnum`/`fwmark`, and atomically swaps `engine` profiles.
pub fn reload_engine_from_toml(
    engine: &mut DesyncEngine,
    running_qnum: u16,
    running_fwmark: u32,
    base_dir: Option<&Path>,
    toml_str: &str,
) -> Result<Vec<String>, String> {
    let parsed = AppConfig::from_toml_str(toml_str, base_dir)
        .map_err(|err| format!("invalid TOML config: {err}"))?;
    if parsed.qnum != running_qnum {
        return Err(format!(
            "cannot change qnum ({running_qnum} -> {}) without restarting nfqws2 daemon",
            parsed.qnum
        ));
    }
    if parsed.fwmark != running_fwmark {
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
