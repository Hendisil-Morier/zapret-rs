//! Web REST handlers for config editing (`nfqws2.toml`), domains, speed tests, and scans.

/// TCP responder stream type passed across API route handlers.
use std::net::TcpStream;
/// Filesystem reads/paths for `nfqws2.toml` and `autohostlist.txt`.
use std::path::{Path, PathBuf};
/// Shared bridge and scan job state handles.
use std::sync::Arc;

/// Validated `nfqws2.toml` parser rejecting malformed profiles prior to disk writes.
use crate::config::AppConfig;
/// Control wire command for live daemon config replacement and list reloads.
use crate::control::Request;
/// Speed test measurement runner and target builders.
use crate::tools::speed_probe::{control_target, domain_target, measure};
/// Domain helpers, symlink-safe config writers, blacklist mutators, and hostlist extractors.
use crate::tools::strat::{
    CurlProbeBackend, DEFAULT_AUTOHOSTLIST_FILE, IpFamily, configured_autohostlist_paths,
    default_output_config_path, extract_exclude_domains, extract_hostlist_domains,
    mutate_exclude_domains_toml, mutate_hostlist_file, parse_clean_domain, read_hostlist_lines,
    write_config_nofollow,
};
/// Runtime web configuration containing explicit `--config` path overrides.
use crate::tools::web::cli::WebConfig;
/// Path confinement checks for Web-submitted TOML configs and hostlist mutations.
use crate::tools::web::config_guard::{is_confined_to_config_dir, validate_web_toml_paths};
/// Bounded HTTP request and JSON/error writers.
use crate::tools::web::http::{HttpMethod, HttpRequest, write_error, write_json};
/// Daemon IPC bridge forwarding `reload_config` / `reload_lists` and SSE updates.
use crate::tools::web::ipc_bridge::WebIpcBridge;
/// Background Strategy Finder scan job coordinator.
use crate::tools::web::scan_job::{ScanStartPayload, WebScanJob};

/// Payload accepted by `POST /api/config`.
#[derive(serde::Deserialize)]
struct SaveConfigPayload
{
    /// Complete `nfqws2.toml` content submitted from the editor.
    toml: String,
    /// When `true` and a daemon is attached, also sends `Request::ReloadConfig`.
    #[serde(default)]
    apply: bool,
}

/// Payload accepted by `POST /api/domains`.
#[derive(serde::Deserialize)]
struct UpdateDomainPayload
{
    /// Domain name to add or remove.
    domain: String,
    /// `"add"` or `"remove"`.
    action: String,
    /// Target list: `"exclude"` (blacklist, never desync) or `"auto"` (autohostlist.txt).
    #[serde(default)]
    list: Option<String>,
}

/// Payload accepted by `POST /api/speed`.
#[derive(serde::Deserialize)]
struct SpeedRequestPayload
{
    /// Target domain list tested alongside optional Cloudflare 25 MB control check.
    #[serde(default)]
    domains: Vec<String>,
    /// Include `speed.cloudflare.com` control target when `true`.
    #[serde(default = "default_true")]
    include_control: bool,
}

const fn default_true() -> bool
{
    true
}

/// Serialized row returned for each measured speed target.
#[derive(serde::Serialize)]
struct SpeedRow
{
    label: String,
    ok: bool,
    summary: String,
    connect_ms: u64,
    ttfb_ms: u64,
    bytes_per_sec: u64,
}

/// Resolves the managed `nfqws2.toml` path from CLI flags or platform defaults.
pub fn resolve_managed_config_path(cfg: &WebConfig) -> PathBuf
{
    cfg.config.clone().unwrap_or_else(default_output_config_path)
}

/// Resolves the sibling `autohostlist.txt` path alongside `config_path`.
pub fn resolve_autohostlist_path(config_path: &Path) -> PathBuf
{
    config_path
        .parent()
        .map_or_else(|| PathBuf::from(DEFAULT_AUTOHOSTLIST_FILE), |p| p.join(DEFAULT_AUTOHOSTLIST_FILE))
}

/// Reads and validates the active `nfqws2.toml` file for `GET /api/config`.
fn read_config_json(path: &Path) -> serde_json::Value
{
    let exists = path.is_file();
    let toml = std::fs::read_to_string(path).unwrap_or_default();
    let (valid, error, profiles) = if toml.trim().is_empty()
    {
        (true, None, 0)
    }
    else
    {
        match AppConfig::from_toml_str(&toml, path.parent())
        {
            Ok(parsed) => (true, None, parsed.profiles.len()),
            Err(err) => (false, Some(err.to_string()), 0),
        }
    };
    serde_json::json!({
        "path": path.display().to_string(),
        "exists": exists,
        "toml": toml,
        "valid": valid,
        "error": error,
        "profiles": profiles,
    })
}

/// Maps a HTTP 400 validation failure with optional label prefix cleanly into Web API tuple format.
fn bad_request(label: &str, err: impl std::fmt::Display) -> (u16, String)
{
    if label.is_empty() { (400, err.to_string()) } else { (400, format!("{label}: {err}")) }
}

/// Maps a HTTP 500 persistence failure cleanly into Web API tuple format.
fn write_failed(path: &Path, err: impl std::fmt::Display) -> (u16, String)
{
    (500, format!("failed to write {}: {err}", path.display()))
}

/// Validates path confinement and syntax, writes symlink-safely, and optionally live-reloads `nfqws2.toml`.
fn save_config_toml(
    path: &Path,
    toml_text: &str,
    apply: bool,
    ipc: &WebIpcBridge,
    cfg: &WebConfig,
) -> Result<serde_json::Value, (u16, String)>
{
    let config_dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    validate_web_toml_paths(toml_text, config_dir, cfg.lua_dir.as_deref())
        .map_err(|err| bad_request("", err))?;
    let parsed = AppConfig::from_toml_str(toml_text, Some(config_dir))
        .map_err(|err| bad_request("invalid config TOML", err))?;
    write_config_nofollow(path, toml_text).map_err(|err| write_failed(path, err))?;

    let applied = if apply
    {
        match ipc.send_command(&Request::ReloadConfig { toml: toml_text.to_owned() })
        {
            Ok(msg) => Some(msg.unwrap_or_else(|| format!("applied {} profile(s)", parsed.profiles.len()))),
            Err(err) => return Err((502, format!("saved to disk, but live reload failed: {err}"))),
        }
    }
    else
    {
        None
    };

    Ok(serde_json::json!({
        "ok": true,
        "path": path.display().to_string(),
        "profiles": parsed.profiles.len(),
        "applied": applied,
    }))
}

/// Reads and filters autohostlist paths strictly confined to `config_path`'s parent directory.
fn confined_autohostlist_paths(cfg: &AppConfig, config_path: &Path) -> Vec<PathBuf>
{
    let config_dir =
        config_path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
    configured_autohostlist_paths(cfg)
        .into_iter()
        .filter(|p| is_confined_to_config_dir(p, config_dir))
        .collect()
}

/// Returns blacklist (`hostlist_exclude`), profile `hostlist_domains`, and conditional `autohostlist.txt` entries.
fn read_domains_json(config_path: &Path) -> serde_json::Value
{
    let toml = std::fs::read_to_string(config_path).unwrap_or_default();
    let parsed = AppConfig::from_toml_str(&toml, config_path.parent()).ok();
    let exclude_domains = parsed.as_ref().map_or_else(Vec::new, extract_exclude_domains);
    let hostlist_domains = parsed.as_ref().map_or_else(Vec::new, extract_hostlist_domains);
    let auto_paths = parsed.as_ref().map_or_else(Vec::new, |c| confined_autohostlist_paths(c, config_path));
    let autohostlist_enabled = !auto_paths.is_empty();
    let autohostlist_path =
        auto_paths.first().cloned().unwrap_or_else(|| resolve_autohostlist_path(config_path));
    let mut autohostlist_domains = Vec::new();
    for p in &auto_paths
    {
        for line in read_hostlist_lines(p)
        {
            if !autohostlist_domains.iter().any(|d: &String| d.eq_ignore_ascii_case(&line))
            {
                autohostlist_domains.push(line);
            }
        }
    }
    serde_json::json!({
        "exclude_domains": exclude_domains,
        "hostlist_domains": hostlist_domains,
        "autohostlist_enabled": autohostlist_enabled,
        "autohostlist_path": autohostlist_path.display().to_string(),
        "autohostlist_domains": autohostlist_domains,
    })
}

/// Adds or removes a domain from either `hostlist_exclude_domains` (`"exclude"`) or `autohostlist.txt` (`"auto"`).
fn mutate_domain_list(
    config_path: &Path,
    payload: &UpdateDomainPayload,
    ipc: &WebIpcBridge,
) -> Result<serde_json::Value, (u16, String)>
{
    let add = match payload.action.as_str()
    {
        "add" => true,
        "remove" => false,
        other => return Err((400, format!("unsupported domain action '{other}'"))),
    };
    let target_list = payload.list.as_deref().unwrap_or("exclude");
    match target_list
    {
        "exclude" =>
        {
            let current = std::fs::read_to_string(config_path)
                .map_err(|err| bad_request(&format!("missing {}", config_path.display()), err))?;
            let updated = mutate_exclude_domains_toml(&current, &payload.domain, add, config_path.parent())
                .map_err(|err| bad_request("", err))?;
            write_config_nofollow(config_path, &updated).map_err(|err| write_failed(config_path, err))?;
            let reloaded = ipc.send_command(&Request::ReloadConfig { toml: updated }).is_ok();
            let domains = AppConfig::from_toml_str(
                &std::fs::read_to_string(config_path).unwrap_or_default(),
                config_path.parent(),
            )
            .ok()
            .map_or_else(Vec::new, |cfg| extract_exclude_domains(&cfg));
            Ok(serde_json::json!({
                "ok": true,
                "list": "exclude",
                "exclude_domains": domains,
                "reloaded": reloaded,
            }))
        }
        "auto" =>
        {
            let current = std::fs::read_to_string(config_path).unwrap_or_default();
            let parsed = AppConfig::from_toml_str(&current, config_path.parent())
                .map_err(|err| bad_request("invalid config", err))?;
            let auto_paths = confined_autohostlist_paths(&parsed, config_path);
            let Some(auto_path) = auto_paths.first()
            else
            {
                return Err((
                    400,
                    "Auto Hostlist is disabled; set Domain Scope to Auto Hostlist first".to_owned(),
                ));
            };
            let domains =
                mutate_hostlist_file(auto_path, &payload.domain, add).map_err(|e| bad_request("", e))?;
            let reloaded = ipc.send_command(&Request::ReloadLists).is_ok();
            Ok(serde_json::json!({
                "ok": true,
                "list": "auto",
                "autohostlist_domains": domains,
                "reloaded": reloaded,
            }))
        }
        other => Err((400, format!("unsupported list '{other}' (expected exclude or auto)"))),
    }
}

/// Measures throughput and handshake timing across requested domains + optional control target.
fn run_speed_probe(payload: &SpeedRequestPayload) -> Vec<SpeedRow>
{
    let backend = CurlProbeBackend::default();
    let mut targets: Vec<_> =
        payload.domains.iter().filter_map(|d| parse_clean_domain(d)).map(|d| domain_target(&d)).collect();
    if payload.include_control
    {
        targets.push(control_target());
    }
    targets
        .into_iter()
        .map(|target| {
            let sample = measure(&backend, &target, IpFamily::V4);
            SpeedRow {
                label: target.label,
                ok: sample.outcome.is_success(),
                summary: sample.outcome.summary(),
                connect_ms: sample.connect_ms,
                ttfb_ms: sample.ttfb_ms,
                bytes_per_sec: sample.bytes_per_sec,
            }
        })
        .collect()
}

/// Handles `POST /api/config` JSON payload decoding, validation, persistence, and response writing.
fn handle_post_config(
    stream: &mut TcpStream,
    req: &HttpRequest,
    config_path: &std::path::Path,
    cfg: &WebConfig,
    ipc: &Arc<WebIpcBridge>,
)
{
    let Ok(payload) = serde_json::from_slice::<SaveConfigPayload>(&req.body)
    else
    {
        let _ = write_error(stream, 400, "Bad Request", "expected JSON object with toml");
        return;
    };
    match save_config_toml(config_path, &payload.toml, payload.apply, ipc, cfg)
    {
        Ok(val) =>
        {
            let _ = write_json(stream, 200, "OK", &[], &val);
        }
        Err((code, msg)) =>
        {
            let reason = match code
            {
                400 => "Bad Request",
                502 => "Bad Gateway",
                _ => "Internal Server Error",
            };
            let _ = write_error(stream, code, reason, &msg);
        }
    }
}

/// Handles `POST /api/domains` JSON payload decoding and hostlist mutation.
fn handle_post_domains(
    stream: &mut TcpStream,
    req: &HttpRequest,
    config_path: &std::path::Path,
    ipc: &Arc<WebIpcBridge>,
)
{
    let Ok(payload) = serde_json::from_slice::<UpdateDomainPayload>(&req.body)
    else
    {
        let _ = write_error(stream, 400, "Bad Request", "expected JSON object with domain and action");
        return;
    };
    match mutate_domain_list(config_path, &payload, ipc)
    {
        Ok(val) =>
        {
            let _ = write_json(stream, 200, "OK", &[], &val);
        }
        Err((code, msg)) =>
        {
            let _ = write_error(
                stream,
                code,
                if code == 400 { "Bad Request" } else { "Internal Server Error" },
                &msg,
            );
        }
    }
}

/// Handles `POST /api/scan/start` JSON payload decoding and background scan job launch.
fn handle_post_scan_start(
    stream: &mut TcpStream,
    req: &HttpRequest,
    cfg: &WebConfig,
    ipc: &Arc<WebIpcBridge>,
    scan_job: &WebScanJob,
)
{
    let Ok(payload) = serde_json::from_slice::<ScanStartPayload>(&req.body)
    else
    {
        let _ = write_error(stream, 400, "Bad Request", "expected JSON object with domains");
        return;
    };
    match scan_job.start(payload, cfg, ipc)
    {
        Ok(snap) =>
        {
            let _ = write_json(stream, 200, "OK", &[], &snap);
        }
        Err((code, msg)) =>
        {
            let reason = match code
            {
                400 => "Bad Request",
                403 => "Forbidden",
                409 => "Conflict",
                _ => "Internal Server Error",
            };
            let _ = write_error(stream, code, reason, &msg);
        }
    }
}

/// Dispatches `/api/config`, `/api/domains`, `/api/speed`, and `/api/scan/*`; returns `false` if unmatched.
pub fn handle_ops_route(
    stream: &mut TcpStream,
    req: &HttpRequest,
    cfg: &WebConfig,
    ipc: &Arc<WebIpcBridge>,
    scan_job: &WebScanJob,
) -> bool
{
    let config_path = resolve_managed_config_path(cfg);
    match (&req.method, req.path.as_str())
    {
        (HttpMethod::Get, "/api/config") =>
        {
            let _ = write_json(stream, 200, "OK", &[], &read_config_json(&config_path));
            true
        }
        (HttpMethod::Post, "/api/config") =>
        {
            handle_post_config(stream, req, &config_path, cfg, ipc);
            true
        }
        (HttpMethod::Get, "/api/domains") =>
        {
            let _ = write_json(stream, 200, "OK", &[], &read_domains_json(&config_path));
            true
        }
        (HttpMethod::Post, "/api/domains") =>
        {
            handle_post_domains(stream, req, &config_path, ipc);
            true
        }
        (HttpMethod::Post, "/api/speed") =>
        {
            let payload: SpeedRequestPayload = serde_json::from_slice(&req.body)
                .unwrap_or(SpeedRequestPayload { domains: Vec::new(), include_control: true });
            let rows = run_speed_probe(&payload);
            let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "rows": rows }));
            true
        }
        (HttpMethod::Get, "/api/scan") =>
        {
            let _ = write_json(stream, 200, "OK", &[], &scan_job.snapshot());
            true
        }
        (HttpMethod::Post, "/api/scan/start") =>
        {
            handle_post_scan_start(stream, req, cfg, ipc, scan_job);
            true
        }
        (HttpMethod::Post, "/api/scan/stop") =>
        {
            let stopped = scan_job.stop();
            let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "stopped": stopped }));
            true
        }
        _ => false,
    }
}
