//! Plain-text diagnostic bundle exporter for troubleshooting `zapret-rs` across Linux and Windows.

/// String formatting for structured diagnostic sections.
use std::fmt::Write as _;
/// Output path resolution beside `nfqws2.toml`.
use std::path::PathBuf;

/// `~/` path expansion and symlink-safe file writing.
use crate::tools::{expand_tilde, write_config_nofollow};
/// Reused Tab 4 speed sample and before/after delta formatters.
use crate::tui::speed::{Change, compare, describe_sample};
/// Application state summarized in the exported debug report.
use crate::tui::state::AppState;
/// Component health badges formatted into the report.
use crate::tui::status_check::{ComponentCheck, ComponentHealth, collect_component_statuses};
/// Finder scan status enum surfaced in Tab 5 component diagnostics.
use crate::tui::types::FinderStatus;

/// Maximum trailing lines included from each log buffer in an exported debug report.
const MAX_REPORT_LOG_LINES: usize = 60;
/// Maximum lines of `nfqws2.toml` embedded directly in an exported debug report.
const MAX_REPORT_CONFIG_LINES: usize = 120;

/// Formats a single [`crate::tui::speed::SpeedRow`] for both Tab 5 details and exported reports.
fn format_speed_row(row: &crate::tui::speed::SpeedRow) -> String {
    let before = row.before.as_ref().map_or_else(|| "pending".to_owned(), describe_sample);
    let after = row.after.as_ref().map_or_else(|| "pending".to_owned(), describe_sample);
    let result = match compare(row) {
        Change::Pending => "pending".to_owned(),
        Change::Fixed => "FIXED".to_owned(),
        Change::Broke => "BROKE".to_owned(),
        Change::StillBlocked => "STILL BLOCKED".to_owned(),
        Change::Compared(delta) => delta,
    };
    format!("{}: before=[{before}] after=[{after}] result={result}", row.label)
}

/// Formats one [`crate::tools::TargetScanResult`] for both Tab 5 details and exported reports.
fn format_finder_target(t: &crate::tools::TargetScanResult) -> String {
    let best = t.matches.first().map_or_else(
        || if t.skipped_unblocked { "unblocked".to_owned() } else { "none".to_owned() },
        |m| format!("{} ({} ms)", m.strategy.id, m.latency_ms),
    );
    format!(
        "{} ({}/{}): baseline={} tested={} matches={} best={best}",
        t.domain,
        t.proto.as_str(),
        t.ipv.as_str(),
        t.baseline.summary(),
        t.tested_count,
        t.matches.len()
    )
}

/// Builds the live Tab 5 (`Status`) component row summarizing Tab 1 (`Strategy Finder`) state.
pub(crate) fn check_finder_summary(state: &AppState) -> ComponentCheck {
    if state.targets.is_empty() {
        let (health, summary) = match &state.finder_status {
            FinderStatus::Scanning => (
                ComponentHealth::Ok,
                format!("Scanning ({}/{})", state.progress_done, state.progress_total),
            ),
            FinderStatus::Error(err) => (ComponentHealth::Err, format!("Error: {err}")),
            FinderStatus::Idle | FinderStatus::Done => {
                (ComponentHealth::Ok, "Not run in this session".to_owned())
            }
        };
        return ComponentCheck {
            name: "Strategy Scan",
            health,
            summary,
            detail: "Switch to Tab 1 and press 'r' to probe domains and discover working desync strategies."
                .to_owned(),
        };
    }
    let matched = state.targets.iter().filter(|t| !t.matches.is_empty()).count();
    let blocked_none = state
        .targets
        .iter()
        .filter(|t| !t.skipped_unblocked && t.matches.is_empty())
        .count();
    let health = if blocked_none > 0 && matched == 0 {
        ComponentHealth::Warn
    } else {
        ComponentHealth::Ok
    };
    let details: Vec<String> = state.targets.iter().map(format_finder_target).collect();
    ComponentCheck {
        name: "Strategy Scan",
        health,
        summary: format!(
            "{} target(s) | {} matched, {} profile(s)",
            state.targets.len(),
            matched,
            state.cover.len()
        ),
        detail: details.join("; "),
    }
}

/// Builds the live Tab 5 (`Status`) component row summarizing Tab 4 (`Speed Test`) results.
pub(crate) fn check_speed_summary(state: &AppState) -> ComponentCheck {
    let phase = state.speed.phase.label();
    if state.speed.rows.is_empty() {
        return ComponentCheck {
            name: "Speed Test",
            health: ComponentHealth::Ok,
            summary: format!("{phase} (not run yet)"),
            detail: "Switch to Tab 4 and press 'r' to measure before/after latency and throughput."
                .to_owned(),
        };
    }
    let (mut fixed, mut broke, mut blocked, mut compared) = (0usize, 0usize, 0usize, 0usize);
    let mut details = Vec::with_capacity(state.speed.rows.len());
    for row in &state.speed.rows {
        match compare(row) {
            Change::Fixed => fixed += 1,
            Change::Broke => broke += 1,
            Change::StillBlocked => blocked += 1,
            Change::Compared(_) => compared += 1,
            Change::Pending => {}
        }
        details.push(format_speed_row(row));
    }
    let health = if broke > 0 || blocked > 0 {
        ComponentHealth::Warn
    } else {
        ComponentHealth::Ok
    };
    ComponentCheck {
        name: "Speed Test",
        health,
        summary: format!(
            "{phase} | {} row(s): {fixed} fixed, {compared} compared, {blocked} blocked, {broke} broke",
            state.speed.rows.len()
        ),
        detail: details.join("; "),
    }
}

/// Formats Tab 4 (`Speed Test`) results when any comparison has started or finished.
fn append_speed_section(out: &mut String, state: &AppState) {
    let _ = writeln!(out, "=== Speed Test Results ===");
    let _ = writeln!(out, "Phase       : {}", state.speed.phase.label());
    if state.speed.rows.is_empty() {
        let _ = writeln!(out, "(no speed test run yet)");
        let _ = writeln!(out);
        return;
    }
    for row in &state.speed.rows {
        let _ = writeln!(out, "- {}", format_speed_row(row));
    }
    let _ = writeln!(out);
}

/// Formats Tab 1 (`Strategy Finder`) target results and covered profile selections.
fn append_finder_section(out: &mut String, state: &AppState) {
    let _ = writeln!(out, "=== Strategy Finder Results ===");
    let domains = if state.domains_input.trim().is_empty() {
        "(none)"
    } else {
        state.domains_input.trim()
    };
    let _ = writeln!(out, "Status      : {:?}", state.finder_status);
    let _ = writeln!(out, "Targets     : {domains}");
    let _ = writeln!(out, "Mode        : {:?} / {:?}", state.ip_mode, state.level);
    if state.targets.is_empty() && state.cover.is_empty() {
        let _ = writeln!(out, "(no completed strategy results yet)");
        let _ = writeln!(out);
        return;
    }
    for t in &state.targets {
        let _ = writeln!(out, "- {}", format_finder_target(t));
    }
    if !state.cover.is_empty() {
        let _ = writeln!(out, "Covered Profiles:");
        for p in &state.cover {
            let _ = writeln!(
                out,
                "  - {}: domains=[{}] avg={} ms",
                p.strategy.id,
                p.domains.join(", "),
                p.avg_latency_ms
            );
        }
    }
    let _ = writeln!(out);
}

/// Formats the loaded `nfqws2.toml` text (bounded to [`MAX_REPORT_CONFIG_LINES`]).
fn append_config_section(out: &mut String, state: &AppState) {
    let _ = writeln!(out, "=== Active Config (nfqws2.toml) ===");
    if state.active_toml.trim().is_empty() {
        let _ = writeln!(out, "(empty / not loaded)");
        let _ = writeln!(out);
        return;
    }
    if let Some(err) = &state.toml_error {
        let _ = writeln!(out, "Parse Error : {err}");
    }
    let lines: Vec<&str> = state.active_toml.lines().collect();
    for line in lines.iter().take(MAX_REPORT_CONFIG_LINES) {
        let _ = writeln!(out, "{line}");
    }
    if lines.len() > MAX_REPORT_CONFIG_LINES {
        let _ = writeln!(
            out,
            "... ({} more line(s) omitted)",
            lines.len() - MAX_REPORT_CONFIG_LINES
        );
    }
    let _ = writeln!(out);
}

/// Appends the trailing [`MAX_REPORT_LOG_LINES`] entries of a bounded log ring buffer.
fn append_log_tail<'a>(out: &mut String, title: &str, lines: impl ExactSizeIterator<Item = &'a String>) {
    let _ = writeln!(out, "=== {title} ===");
    let skip = lines.len().saturating_sub(MAX_REPORT_LOG_LINES);
    for line in lines.skip(skip) {
        let _ = writeln!(out, "{line}");
    }
}

/// Renders a self-contained diagnostic report covering environment, component checks,
/// speed test measurements, strategy finder outcomes, active config, counters, and logs.
pub fn format_debug_report(state: &AppState) -> String {
    let checks = collect_component_statuses(state);
    let (total, passed, reasm, modified, desynced) = state.visible_counters();

    let mut out = String::new();
    let _ = writeln!(out, "=== zapret-rs Debug Report ===");
    let _ = writeln!(out, "Version     : {}", env!("CARGO_PKG_VERSION"));
    let _ = writeln!(out, "OS / Arch   : {} / {}", std::env::consts::OS, std::env::consts::ARCH);
    let _ = writeln!(out, "Executable  : {}", state.exe_path);
    let _ = writeln!(out, "UID / Privs : {} / {}", state.uid, if state.has_net_caps { "OK" } else { "MISSING" });
    let _ = writeln!(out, "Config Path : {}", state.output_path);
    let _ = writeln!(out, "Lua Dir     : {}", state.lua_dir_input);
    let _ = writeln!(out, "DNS Preset  : {}", state.dns_preset.label());
    let _ = writeln!(out, "Run Status  : {:?}", state.run_status);
    if let Some(meta) = &state.remote_meta {
        let profiles = if meta.profile_names.is_empty() {
            "(none)".to_owned()
        } else {
            meta.profile_names.join(", ")
        };
        let _ = writeln!(
            out,
            "Daemon Info : pid={} ver={} qnum={} intercept={} profiles=[{profiles}]",
            meta.pid, meta.daemon_version, meta.qnum, meta.intercept
        );
    }
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

    append_speed_section(&mut out, state);
    append_finder_section(&mut out, state);
    append_config_section(&mut out, state);
    append_log_tail(&mut out, "Recent Live Scan Log", state.finder_logs.iter());
    let _ = writeln!(out);
    append_log_tail(&mut out, "Recent Daemon Log", state.run_logs.iter());
    if let Some((_, passcode)) = &state.web_status
        && !passcode.is_empty()
        && !passcode.starts_with("none")
    {
        out = out.replace(passcode, "[REDACTED]");
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
