//! `strat_finder`: native Rust in-process DPI-bypass strategy finder for `zapret-rs`.

/// Filesystem writing for `--write-config` output files.
use std::fs;
/// Standard I/O helpers for interactive TTY prompts and terminal detection.
use std::io::{self, IsTerminal, Write as _};
/// Filesystem path handling for Lua script discovery and output configs.
use std::path::{Path, PathBuf};
/// Process exit status codes.
use std::process::ExitCode;
/// Per-request timeout duration conversion.
use std::time::Duration;

/// CLI flag parsing and auto-generated help output.
use clap::Parser;

/// Application config model, Lua init entries, and hex/decimal fwmark parser.
use zapret_rs::config::{AppConfig, LuaInitEntry, parse_u32_radix};
/// Default desync fwmark constant shared with `nfqws2`.
use zapret_rs::intercepter::DEFAULT_DESYNC_FWMARK;
/// Process signal installation and shared termination flag (`SIGINT`/`SIGTERM`).
use zapret_rs::runtime::{install_signal_handlers, quit_flag};
/// Strategy finder catalog, probe, firewall, worker, orchestrator, and TOML renderer.
use zapret_rs::tools::{
    CoveredProfile, CurlProbeBackend, FirewallBackend, InProcessWorkerHandle, IpFamily,
    NftFirewallBackend, ProbeProtocol, ProgressEvent, ScanConfig, ScanLevel, ScanReport,
    TomlRenderOptions, build_catalog, render_nfqws2_toml, run_scan,
};

/// Default NFQUEUE number for `strat_finder` (distinct from `nfqws2`'s default `200`).
const DEFAULT_STRAT_QNUM: u16 = 210;

/// Command-line interface for the `strat_finder` DPI-bypass strategy finder.
#[derive(Debug, Parser)]
#[command(name = "strat_finder", version = env!("CARGO_PKG_VERSION"), about = "Native in-process DPI-bypass strategy finder for zapret-rs (nfqws2)")]
struct Cli {
    /// Target domain(s) to probe (repeatable or comma-separated; prompts interactively on TTY).
    #[arg(short = 'd', long = "domain", value_delimiter = ',')]
    domains: Vec<String>,
    /// Protocols to sweep (`http`, `tls12`, `tls13`, `http3`).
    #[arg(long = "proto", value_delimiter = ',', default_value = "http,tls12,tls13,http3")]
    protos: Vec<String>,
    /// Scan thoroughness (`quick`, `standard`, or `force`).
    #[arg(long = "level", default_value = "standard")]
    level: String,
    /// Probe over IPv4 (enabled by default when neither `--ipv4` nor `--ipv6` is specified).
    #[arg(short = '4', long = "ipv4")]
    ipv4: bool,
    /// Probe over IPv6.
    #[arg(short = '6', long = "ipv6")]
    ipv6: bool,
    /// Temporary NFQUEUE number used during discovery.
    #[arg(long = "qnum", default_value_t = DEFAULT_STRAT_QNUM)]
    qnum: u16,
    /// Desync firewall mark in hex (`0x40000000`) or decimal for loop suppression.
    #[arg(long = "fwmark", default_value = "0x40000000")]
    fwmark: String,
    /// Per-probe curl timeout in seconds.
    #[arg(long = "timeout", default_value_t = 3)]
    timeout: u64,
    /// Stop sweeping a target as soon as the first working strategy succeeds.
    #[arg(long = "stop-on-first")]
    stop_on_first: bool,
    /// Run strategy sweep even when the direct baseline probe succeeds.
    #[arg(long = "force-blocked")]
    force_blocked: bool,
    /// Write a ready-to-use `nfqws2.toml` for the minimal covering strategies.
    #[arg(short = 'w', long = "write-config")]
    write_config: Option<PathBuf>,
    /// Emit a machine-readable JSON summary to stdout.
    #[arg(long = "json")]
    json: bool,
    /// Directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    #[arg(long = "lua-dir")]
    lua_dir: Option<PathBuf>,
    /// Path or executable name of `curl`.
    #[arg(long = "curl-bin", default_value = "curl")]
    curl_bin: PathBuf,
    /// Path or executable name of `nft`.
    #[arg(long = "nft-bin", default_value = "nft")]
    nft_bin: PathBuf,
    /// List expanded strategy candidates without binding NFQUEUE or touching `nftables`.
    #[arg(long = "list-strategies")]
    list_strategies: bool,
}

/// Normalizes a domain token by stripping any URL scheme, path, port, and surrounding whitespace.
fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = no_scheme.split(['/', '?', '#']).next().unwrap_or("").trim();
    let host = host.split(':').next().unwrap_or("").trim().trim_end_matches('.');
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

/// Resolves target domains from CLI flags, interactive TTY prompt, or piped stdin.
fn resolve_domains(cli_domains: &[String]) -> Result<Vec<String>, String> {
    let mut out: Vec<String> = cli_domains.iter().filter_map(|raw| normalize_domain(raw)).collect();
    if !out.is_empty() {
        return Ok(out);
    }
    let mut input = String::new();
    if io::stdin().is_terminal() {
        eprint!("Enter target domain(s) separated by space or comma: ");
        let _ = io::stderr().flush();
        io::stdin()
            .read_line(&mut input)
            .map_err(|err| format!("failed to read domain prompt: {err}"))?;
    } else {
        let _ = io::Read::read_to_string(&mut io::stdin(), &mut input);
    }
    out.extend(input.split(|c: char| c.is_whitespace() || c == ',').filter_map(normalize_domain));
    if out.is_empty() {
        return Err("no target domains provided (pass --domain <DOMAIN> or enter them interactively)".to_owned());
    }
    Ok(out)
}

/// Resolves `zapret-lib.lua` and `zapret-antidpi.lua` from `--lua-dir` or standard search paths.
fn resolve_lua_scripts(explicit_dir: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    let mut candidates = Vec::new();
    if let Some(dir) = explicit_dir {
        candidates.push(dir.to_path_buf());
    } else {
        candidates.push(PathBuf::from("lua"));
        candidates.push(PathBuf::from("../zapret2/lua"));
        if let Ok(exe) = std::env::current_exe()
            && let Some(parent) = exe.parent()
        {
            candidates.push(parent.join("lua"));
            if let Some(grand) = parent.parent().and_then(Path::parent) {
                candidates.push(grand.join("../zapret2/lua"));
            }
        }
        candidates.push(PathBuf::from("/opt/zapret2/lua"));
        candidates.push(PathBuf::from("/usr/share/zapret2/lua"));
    }

    for dir in &candidates {
        let lib = dir.join("zapret-lib.lua");
        let antidpi = dir.join("zapret-antidpi.lua");
        if lib.is_file() && antidpi.is_file() {
            let lib_abs = fs::canonicalize(&lib).unwrap_or(lib);
            let anti_abs = fs::canonicalize(&antidpi).unwrap_or(antidpi);
            return Ok(vec![lib_abs, anti_abs]);
        }
    }

    Err(format!(
        "could not locate zapret-lib.lua and zapret-antidpi.lua (checked: {}); pass --lua-dir <PATH>",
        candidates
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

/// Escapes a string literal for manual JSON emission without extra crate dependencies.
fn json_quote(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Formats `report` as a self-contained JSON document printed when `--json` is set.
fn format_report_json(report: &ScanReport) -> String {
    let mut out = String::from("{\n");
    out.push_str(&format!("  \"interrupted\": {},\n", report.interrupted));
    out.push_str("  \"targets\": [\n");
    for (ti, t) in report.targets.iter().enumerate() {
        let comma = if ti + 1 < report.targets.len() { "," } else { "" };
        let best = t.matches.first().map_or_else(|| "null".to_owned(), |m| json_quote(&m.strategy.id));
        out.push_str(&format!(
            "    {{\"domain\": {}, \"proto\": {}, \"ipv\": {}, \"baseline\": {}, \"skipped_unblocked\": {}, \"tested\": {}, \"matches\": {}, \"best\": {}}}{comma}\n",
            json_quote(&t.domain),
            json_quote(t.proto.as_str()),
            json_quote(t.ipv.as_str()),
            json_quote(&t.baseline.summary()),
            t.skipped_unblocked,
            t.tested_count,
            t.matches.len(),
            best,
        ));
    }
    out.push_str("  ],\n  \"cover\": [\n");
    for (ci, c) in report.cover.iter().enumerate() {
        let comma = if ci + 1 < report.cover.len() { "," } else { "" };
        let doms: Vec<String> = c.domains.iter().map(|d| json_quote(d)).collect();
        out.push_str(&format!(
            "    {{\"strategy\": {}, \"weight\": {}, \"avg_latency_ms\": {}, \"domains\": [{}]}}{comma}\n",
            json_quote(&c.strategy.id),
            c.strategy.weight,
            c.avg_latency_ms,
            doms.join(", "),
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

/// Prints a concise human-readable summary of `report` to stdout.
fn print_report_summary(report: &ScanReport) {
    println!("\n=== strat_finder summary ===");
    if report.interrupted {
        println!("Note: scan interrupted early; showing partial results.");
    }
    for t in &report.targets {
        if t.skipped_unblocked {
            println!("- {} ({}/{}): reachable directly [{}]", t.domain, t.proto, t.ipv, t.baseline.summary());
        } else if let Some(best) = t.matches.first() {
            println!(
                "- {} ({}/{}): {} working (best: {}, {} ms; tested {})",
                t.domain, t.proto, t.ipv, t.matches.len(), best.strategy.id, best.latency_ms, t.tested_count
            );
        } else {
            println!(
                "- {} ({}/{}): no working strategy found (baseline: {}; tested {})",
                t.domain, t.proto, t.ipv, t.baseline.summary(), t.tested_count
            );
        }
    }
    if !report.cover.is_empty() {
        println!("\nSelected minimal profile set ({}):", report.cover.len());
        for c in &report.cover {
            println!(
                "  * {} (weight {}, avg {} ms) -> {}",
                c.strategy.id, c.strategy.weight, c.avg_latency_ms, c.domains.join(", ")
            );
        }
    }
}

/// Handles `--list-strategies` offline preview and optional sample `--write-config`.
fn run_list_mode(
    cli: &Cli,
    protos: &[ProbeProtocol],
    families: &[IpFamily],
    level: ScanLevel,
    fwmark: u32,
) -> Result<(), String> {
    let mut sample_cover = Vec::new();
    let domains: Vec<String> = cli.domains.iter().filter_map(|d| normalize_domain(d)).collect();
    for &ipv in families {
        for &proto in protos {
            let catalog = build_catalog(proto, level, ipv);
            println!("# {proto}/{ipv} ({level}): {} candidates", catalog.len());
            for spec in &catalog {
                println!("  [w={:02}] {}", spec.weight, spec.id);
            }
            if let Some(first) = catalog.into_iter().next() {
                sample_cover.push(CoveredProfile {
                    strategy: first,
                    domains: domains.clone(),
                    avg_latency_ms: 0,
                });
            }
        }
    }
    if let Some(out_path) = &cli.write_config {
        let lua_init = resolve_lua_scripts(cli.lua_dir.as_deref()).unwrap_or_default();
        let toml = render_nfqws2_toml(
            &sample_cover,
            &TomlRenderOptions { qnum: cli.qnum, fwmark, lua_init },
        );
        fs::write(out_path, toml)
            .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
        eprintln!("Wrote sample nfqws2 config to {}", out_path.display());
    }
    Ok(())
}

/// Runs the CLI application and returns a formatted error message on failure.
fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let level: ScanLevel = cli.level.parse()?;
    let mut protos = Vec::new();
    for raw in &cli.protos {
        let p: ProbeProtocol = raw.parse()?;
        if !protos.contains(&p) {
            protos.push(p);
        }
    }
    if protos.is_empty() {
        return Err("at least one protocol must be specified via --proto".to_owned());
    }
    let families = match (cli.ipv4, cli.ipv6) {
        (false, true) => vec![IpFamily::V6],
        (true, true) => vec![IpFamily::V4, IpFamily::V6],
        _ => vec![IpFamily::V4],
    };
    let fwmark = parse_u32_radix(&cli.fwmark)
        .ok_or_else(|| format!("invalid --fwmark '{}' (expected hex like 0x40000000 or decimal)", cli.fwmark))?;
    let fwmark = if fwmark == 0 { DEFAULT_DESYNC_FWMARK } else { fwmark };

    if cli.list_strategies {
        return run_list_mode(&cli, &protos, &families, level, fwmark);
    }

    let domains = resolve_domains(&cli.domains)?;
    let lua_scripts = resolve_lua_scripts(cli.lua_dir.as_deref())?;
    install_signal_handlers().map_err(|err| format!("failed to install signal handlers: {err}"))?;

    let mut base_cfg = AppConfig {
        qnum: cli.qnum,
        fwmark,
        ..AppConfig::default()
    };
    base_cfg.ipcache.hostname = true;
    base_cfg.lua_init = lua_scripts.iter().cloned().map(LuaInitEntry::File).collect();

    let scan_cfg = ScanConfig {
        domains,
        protos,
        families,
        level,
        timeout: Duration::from_secs(cli.timeout.max(1)),
        stop_on_first: cli.stop_on_first,
        force_blocked: cli.force_blocked,
    };

    // Bind NFQUEUE + Lua worker first, then install temporary nftables rules so Drop order removes
    // nftables rules BEFORE unbinding NFQUEUE.
    let mut worker = InProcessWorkerHandle::spawn(base_cfg, quit_flag())?;
    let (tcp_ports, udp_ports) = scan_cfg.required_ports();
    let nft = NftFirewallBackend::new(cli.nft_bin.clone());
    let _fw_guard = nft
        .install(cli.qnum, fwmark, &tcp_ports, &udp_ports)
        .map_err(|err| format!("failed to install temporary nftables rules (run with sudo/root): {err}"))?;

    let probe = CurlProbeBackend::new(cli.curl_bin.clone());
    let report = run_scan(&scan_cfg, &probe, &mut worker, quit_flag(), |ev| match ev {
        ProgressEvent::Http3Unavailable => {
            eprintln!("[warn] curl does not report HTTP3 support; skipping http3 probes");
        }
        ProgressEvent::Baseline { domain, proto, ipv, outcome } => {
            eprintln!("[baseline] {domain} ({proto}/{ipv}) -> {}", outcome.summary());
        }
        ProgressEvent::Candidate { domain, index, total, strategy, outcome } => {
            if outcome.is_success() {
                eprintln!("[PASS {index}/{total}] {domain} :: {} -> {}", strategy.id, outcome.summary());
            }
        }
    })?;

    if cli.json {
        print!("{}", format_report_json(&report));
    } else {
        print_report_summary(&report);
    }

    if let Some(out_path) = &cli.write_config {
        if report.cover.is_empty() {
            eprintln!("No working strategies found; skipping config write to {}", out_path.display());
        } else {
            let toml = render_nfqws2_toml(
                &report.cover,
                &TomlRenderOptions { qnum: 200, fwmark, lua_init: lua_scripts },
            );
            fs::write(out_path, toml)
                .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
            eprintln!(
                "\nWrote nfqws2 config to {}\nRun with: sudo nfqws2 --config {}",
                out_path.display(),
                out_path.display()
            );
        }
    }
    Ok(())
}

/// Process entry point printing typed errors cleanly to stderr without panicking.
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("strat_finder error: {err}");
            ExitCode::FAILURE
        }
    }
}
