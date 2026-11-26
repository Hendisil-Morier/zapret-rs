//! Plain-text diagnostic bundle exporter for troubleshooting `zapret-rs` across Linux and Windows.

/// String formatting for structured diagnostic sections.
use std::fmt::Write as _;
/// Output path resolution beside `nfqws2.toml`.
use std::path::PathBuf;

/// `~/` path expansion and symlink-safe file writing.
use crate::tools::{expand_tilde, write_config_nofollow};
/// Application state summarized in the exported debug report.
use crate::tui::state::AppState;
/// Component health badges formatted into the report.
use crate::tui::status_check::{ComponentHealth, collect_component_statuses};

/// Maximum trailing lines included from each log buffer in an exported debug report.
const MAX_REPORT_LOG_LINES: usize = 60;

/// Renders a self-contained diagnostic report covering environment, component checks, counters, and logs.
pub fn format_debug_report(state: &AppState) -> String {
    let checks = if state.status_checks.is_empty() {
        collect_component_statuses(state)
    } else {
        state.status_checks.clone()
    };
    let (total, passed, reasm, modified, desynced) = state.visible_counters();

    let mut out = String::new();
    let _ = writeln!(out, "=== zapret-rs Debug Report ===");
    let _ = writeln!(out, "Version     : {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "OS / Arch   : {} / {}", std::env::consts::OS, std::env::consts::ARCH);
    let _ = writeln!(out, "Executable  : {}", state.exe_path);
    let _ = writeln!(out, "UID / Privs : {} / {}", state.uid, if state.has_net_caps { "OK" } else { "MISSING" });
    let _ = writeln!(out, "Config Path : {}", state.output_path);
    let _ = writeln!(out, "Lua Dir     : {}", state.lua_dir_input);
    let _ = writeln!(out, "Run Status  : {:?}", state.run_status);
    let _ = writeln!(
        out,
        "Counters    : total={total} passed={passed} reasm={reasm} modified={modified} desynced={desynced}"
    );
    let _ = writeln!(out);

    let _ = writeln!(out, "=== Operational Component Checks ===");
    for check in &checks {
        let badge = match check.health {
            ComponentHealth::Ok => "OK",
            ComponentHealth::Warn => "WARN",
            ComponentHealth::Err => "ERR",
        };
        let _ = writeln!(out, "[{badge}] {}: {}", check.name, check.summary);
        let _ = writeln!(out, "      {}", check.detail);
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "=== Recent Live Scan Log ===");
    let scan_skip = state.finder_logs.len().saturating_sub(MAX_REPORT_LOG_LINES);
    for line in state.finder_logs.iter().skip(scan_skip) {
        let _ = writeln!(out, "{line}");
    }
    let _ = writeln!(out);

    let _ = writeln!(out, "=== Recent Daemon Log ===");
    let run_skip = state.run_logs.len().saturating_sub(MAX_REPORT_LOG_LINES);
    for line in state.run_logs.iter().skip(run_skip) {
        let _ = writeln!(out, "{line}");
    }
    out
}

/// Resolves the destination path (`zapret-rs-debug.txt`) beside `state.output_path`.
pub fn debug_report_path(output_path: &str) -> PathBuf {
    let cfg = expand_tilde(output_path);
    cfg.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("zapret-rs-debug.txt"), |p| p.join("zapret-rs-debug.txt"))
}

/// Writes [`format_debug_report`] to `zapret-rs-debug.txt` without following symlinks.
pub fn export_debug_report(state: &AppState) -> Result<PathBuf, String> {
    let dest = debug_report_path(&state.output_path);
    let content = format_debug_report(state);
    write_config_nofollow(&dest, &content)
        .map_err(|err| format!("failed to write {}: {err}", dest.display()))?;
    Ok(dest)
}
