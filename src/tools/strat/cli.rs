//! Shared CLI runner powering both `nfqws2 --strat-finder` and the standalone `strat_finder` binary.

/// OS string argument handling for dispatching `--strat-finder` sub-invocations.
use std::ffi::OsString;
/// Standard I/O terminal detection and stdin reading.
use std::io::{self, IsTerminal};
/// Filesystem path type for Lua scripts, binaries, and output configs.
use std::path::PathBuf;
/// Process exit codes mapped from `clap` and runtime results.
use std::process::ExitCode;
/// Per-probe curl timeout conversion.
use std::time::Duration;

/// `clap` CLI parser and error kind classification for `--help`/`--version`.
use clap::{Parser, error::ErrorKind};

/// Application config model, Lua init entries, and hex/decimal fwmark parser.
use crate::config::{AppConfig, LuaInitEntry, parse_u32_radix};
/// Default desync fwmark constant shared with `nfqws2`.
use crate::intercepter::DEFAULT_DESYNC_FWMARK;
/// Least-privilege capability checks, elevation drop, and signal handling.
use crate::runtime::{
    drop_elevated_root_if_needed, has_packet_capture_privileges, install_signal_handlers,
    quit_flag,
};
/// Strategy catalog types and expansion function.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, build_catalog};
/// Embedded Lua script discovery and fallback extractor.
use crate::tools::lua_bundle::{detect_lua_dir, resolve_lua_scripts};
/// Interactive terminal setup wizard and domain/tilde helpers.
use crate::tools::strat::interactive::{
    InteractiveDefaults, expand_tilde, normalize_domain, prompt_interactive_wizard,
};
/// OS-agnostic firewall backend trait implemented by [`NftFirewallBackend`].
use crate::tools::strat::firewall::FirewallBackend;
/// Temporary `nftables` queue guard backend and ruleset printer.
use crate::tools::strat::nft::{NftFirewallBackend, build_nft_cleanup_cmd};
/// Live `curl` connectivity probe backend (runs children with zero capabilities).
use crate::tools::strat::probe::CurlProbeBackend;
/// In-process NFQUEUE worker thread and scan orchestrator.
use crate::tools::strat::runner::{ProgressEvent, ScanConfig, ScanReport, run_scan};
/// In-process capture worker handle.
use crate::tools::strat::worker::InProcessWorkerHandle;
/// Minimal profile cover and symlink-safe `nfqws2.toml` serializer.
use crate::tools::strat::toml::{
    CoveredProfile, TomlRenderOptions, render_nfqws2_toml, write_config_nofollow,
};

/// Default NFQUEUE number for `strat_finder` (distinct from `nfqws2`'s default `200`).
pub const DEFAULT_STRAT_QNUM: u16 = 210;

/// Command-line options accepted by `strat_finder` and `nfqws2 --strat-finder`.
#[derive(Debug, Parser)]
#[command(name = "strat_finder", version = env!("CARGO_PKG_VERSION"), about = "Native in-process DPI-bypass strategy finder for zapret-rs (nfqws2)")]
pub struct StratFinderCli {
    /// Target domain(s) to probe (repeatable or comma-separated; launches interactive wizard if omitted on a TTY).
    #[arg(short = 'd', long = "domain", value_delimiter = ',')]
    pub domains: Vec<String>,
    /// Launch the interactive setup wizard even when some CLI options are already provided.
    #[arg(short = 'i', long = "interactive")]
    pub interactive: bool,
    /// Protocols to sweep (`http`, `tls12`, `tls13`, `http3`).
    #[arg(long = "proto", value_delimiter = ',', default_value = "http,tls12,tls13,http3")]
    pub protos: Vec<String>,
    /// Scan thoroughness (`quick`, `standard`, or `force`).
    #[arg(long = "level", default_value = "standard")]
    pub level: String,
    /// Probe over IPv4 (enabled by default when neither `--ipv4` nor `--ipv6` is specified).
    #[arg(short = '4', long = "ipv4")]
    pub ipv4: bool,
    /// Probe over IPv6.
    #[arg(short = '6', long = "ipv6")]
    pub ipv6: bool,
    /// Temporary NFQUEUE number used during discovery.
    #[arg(long = "qnum", default_value_t = DEFAULT_STRAT_QNUM)]
    pub qnum: u16,
    /// Desync firewall mark in hex (`0x40000000`) or decimal for loop suppression.
    #[arg(long = "fwmark", default_value = "0x40000000")]
    pub fwmark: String,
    /// Per-probe curl timeout in seconds.
    #[arg(long = "timeout", default_value_t = 3)]
    pub timeout: u64,
    /// Stop sweeping a target as soon as the first working strategy succeeds.
    #[arg(long = "stop-on-first")]
    pub stop_on_first: bool,
    /// Run strategy sweep even when the direct baseline probe succeeds.
    #[arg(long = "force-blocked")]
    pub force_blocked: bool,
    /// Write a ready-to-use `nfqws2.toml` for the minimal covering strategies.
    #[arg(short = 'w', long = "write-config")]
    pub write_config: Option<PathBuf>,
    /// Emit a machine-readable JSON summary to stdout.
    #[arg(long = "json")]
    pub json: bool,
    /// Directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    #[arg(long = "lua-dir")]
    pub lua_dir: Option<PathBuf>,
    /// Path or executable name of `curl`.
    #[arg(long = "curl-bin", default_value = "curl")]
    pub curl_bin: PathBuf,
    /// Path or executable name of `nft`.
    #[arg(long = "nft-bin", default_value = "nft")]
    pub nft_bin: PathBuf,
    /// Skip automatic `nftables` setup/teardown (use when managing NFQUEUE rules manually).
    #[arg(long = "no-nft")]
    pub no_nft: bool,
    /// Print the temporary `nftables` ruleset and cleanup command without binding NFQUEUE.
    #[arg(long = "print-nft")]
    pub print_nft: bool,
    /// List expanded strategy candidates without binding NFQUEUE or touching `nftables`.
    #[arg(long = "list-strategies")]
    pub list_strategies: bool,
}

/// Inspects an `nfqws2` argument vector and, if `--strat-finder` appears before `--`, returns the
/// rewritten argument vector ready to pass into [`run_strat_finder_cli`].
pub fn extract_strat_finder_args<I, T>(args: I) -> Option<Vec<OsString>>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut found = false;
    let mut out = Vec::with_capacity(raw.len());
    let mut past_double_dash = false;

    for (idx, arg) in raw.into_iter().enumerate() {
        if idx == 0 {
            out.push(OsString::from("nfqws2 --strat-finder"));
            continue;
        }
        if !past_double_dash && arg == "--" {
            past_double_dash = true;
            out.push(arg);
            continue;
        }
        if !past_double_dash && !found && arg == "--strat-finder" {
            found = true;
            continue;
        }
        out.push(arg);
    }

    if found { Some(out) } else { None }
}

/// Escapes a string literal for JSON output using `serde_json`.
fn json_quote(raw: &str) -> String {
    serde_json::to_string(raw).unwrap_or_else(|_| "\"\"".to_owned())
}

/// Formats `report` as JSON printed to stdout when `--json` is set.
fn format_report_json(report: &ScanReport) -> String {
    let mut out = format!("{{\n  \"interrupted\": {},\n  \"targets\": [\n", report.interrupted);
    for (i, t) in report.targets.iter().enumerate() {
        let sep = if i + 1 < report.targets.len() { "," } else { "" };
        let best = t.matches.first().map_or_else(|| "null".to_owned(), |m| json_quote(&m.strategy.id));
        out.push_str(&format!(
            "    {{\"domain\": {}, \"proto\": {}, \"ipv\": {}, \"baseline\": {}, \"skipped_unblocked\": {}, \"tested\": {}, \"matches\": {}, \"best\": {}}}{sep}\n",
            json_quote(&t.domain), json_quote(t.proto.as_str()), json_quote(t.ipv.as_str()),
            json_quote(&t.baseline.summary()), t.skipped_unblocked, t.tested_count, t.matches.len(), best,
        ));
    }
    out.push_str("  ],\n  \"cover\": [\n");
    for (i, c) in report.cover.iter().enumerate() {
        let sep = if i + 1 < report.cover.len() { "," } else { "" };
        let doms: Vec<String> = c.domains.iter().map(|d| json_quote(d)).collect();
        out.push_str(&format!(
            "    {{\"strategy\": {}, \"weight\": {}, \"avg_latency_ms\": {}, \"domains\": [{}]}}{sep}\n",
            json_quote(&c.strategy.id), c.strategy.weight, c.avg_latency_ms, doms.join(", "),
        ));
    }
    out.push_str("  ]\n}\n");
    out
}

/// Prints a concise human-readable scan summary to stdout.
fn print_report_summary(report: &ScanReport) {
    println!("\n=== strat_finder summary ===");
    if report.interrupted {
        println!("Note: scan interrupted early; showing partial results.");
    }
    for t in &report.targets {
        if t.skipped_unblocked {
            println!("- {} ({}/{}): reachable directly [{}]", t.domain, t.proto, t.ipv, t.baseline.summary());
        } else if let Some(best) = t.matches.first() {
            println!("- {} ({}/{}): {} working (best: {}, {} ms; tested {})", t.domain, t.proto, t.ipv, t.matches.len(), best.strategy.id, best.latency_ms, t.tested_count);
        } else {
            println!("- {} ({}/{}): no working strategy found (baseline: {}; tested {})", t.domain, t.proto, t.ipv, t.baseline.summary(), t.tested_count);
        }
    }
    if !report.cover.is_empty() {
        println!("\nSelected minimal profile set ({}):", report.cover.len());
        for c in &report.cover {
            println!("  * {} (weight {}, avg {} ms) -> {}", c.strategy.id, c.strategy.weight, c.avg_latency_ms, c.domains.join(", "));
        }
    }
}

/// Handles `--list-strategies` offline preview and optional sample `--write-config`.
fn run_list_mode(
    cli: &StratFinderCli,
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
                sample_cover.push(CoveredProfile { strategy: first, domains: domains.clone(), avg_latency_ms: 0 });
            }
        }
    }
    if let Some(out_path) = &cli.write_config {
        let out_path = expand_tilde(&out_path.to_string_lossy());
        let lua_init = resolve_lua_scripts(cli.lua_dir.as_deref()).unwrap_or_default();
        let toml = render_nfqws2_toml(&sample_cover, &TomlRenderOptions { qnum: cli.qnum, fwmark, lua_init });
        write_config_nofollow(&out_path, &toml).map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
        eprintln!("Wrote sample nfqws2 config to {}", out_path.display());
    }
    Ok(())
}

/// Ensures `CAP_NET_ADMIN|CAP_NET_RAW` are active, dropping `sudo` UID 0 first when present.
fn ensure_least_privilege_net_caps() -> Result<(), String> {
    if let Some((uid, gid)) = drop_elevated_root_if_needed().map_err(|err| format!("privilege drop failed: {err}"))? {
        eprintln!("[sec] dropped root privileges to uid={uid}, gid={gid} (retaining only CAP_NET_ADMIN, CAP_NET_RAW)");
    }
    if !has_packet_capture_privileges().map_err(|err| format!("capability check failed: {err}"))? {
        let exe = std::env::current_exe()
            .ok()
            .map_or_else(|| "./target/release/nfqws2".to_owned(), |p| p.display().to_string());
        return Err(format!(
            "missing CAP_NET_ADMIN / CAP_NET_RAW capabilities.\n\
             Grant only network capabilities once (no sudo needed at runtime):\n  \
             sudo setcap cap_net_admin,cap_net_raw+ep {exe}\n\
             Then re-run without sudo."
        ));
    }
    Ok(())
}

/// Executes a parsed [`StratFinderCli`] session, launching the interactive wizard when appropriate.
pub fn run_strat_finder(cli: StratFinderCli) -> Result<(), String> {
    let mut level: ScanLevel = cli.level.parse()?;
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
    let mut families = match (cli.ipv4, cli.ipv6) {
        (false, true) => vec![IpFamily::V6],
        (true, true) => vec![IpFamily::V4, IpFamily::V6],
        _ => vec![IpFamily::V4],
    };
    let fwmark = parse_u32_radix(&cli.fwmark)
        .ok_or_else(|| format!("invalid --fwmark '{}' (expected hex like 0x40000000 or decimal)", cli.fwmark))?;
    let fwmark = if fwmark == 0 { DEFAULT_DESYNC_FWMARK } else { fwmark };

    if cli.print_nft {
        let dummy = ScanConfig { domains: Vec::new(), protos, families, level, timeout: Duration::from_secs(1), stop_on_first: false, force_blocked: false };
        let (tcp, udp) = dummy.required_ports();
        print!("{}", NftFirewallBackend::build_nft_script(cli.qnum, fwmark, &tcp, &udp));
        println!("# Cleanup: sudo {}", build_nft_cleanup_cmd());
        return Ok(());
    }
    if cli.list_strategies {
        return run_list_mode(&cli, &protos, &families, level, fwmark);
    }

    ensure_least_privilege_net_caps()?;

    let mut domains: Vec<String> = cli.domains.iter().filter_map(|d| normalize_domain(d)).collect();
    let mut stop_on_first = cli.stop_on_first;
    let mut lua_dir = cli.lua_dir.clone().map(|p| expand_tilde(&p.to_string_lossy()));
    let mut write_config = cli.write_config.clone().map(|p| expand_tilde(&p.to_string_lossy()));

    let interactive = cli.interactive || (domains.is_empty() && io::stdin().is_terminal());
    if interactive {
        let defaults = InteractiveDefaults {
            domains, protos, families, level, stop_on_first,
            lua_dir: lua_dir.or_else(|| detect_lua_dir(None)), write_config,
        };
        let stdin = io::stdin();
        let sel = prompt_interactive_wizard(&mut stdin.lock(), &mut io::stderr(), &defaults)?;
        (domains, protos, families, level, stop_on_first, lua_dir, write_config) =
            (sel.domains, sel.protos, sel.families, sel.level, sel.stop_on_first, sel.lua_dir, sel.write_config);
    } else if domains.is_empty() {
        let mut buf = String::new();
        let _ = io::Read::read_to_string(&mut io::stdin(), &mut buf);
        domains.extend(buf.split(|c: char| c.is_whitespace() || c == ',').filter_map(normalize_domain));
        if domains.is_empty() {
            return Err("no target domains provided (pass --domain <DOMAIN> or run interactively)".to_owned());
        }
    }

    let lua_scripts = resolve_lua_scripts(lua_dir.as_deref())?;
    install_signal_handlers().map_err(|err| format!("failed to install signal handlers: {err}"))?;

    let mut base_cfg = AppConfig { qnum: cli.qnum, fwmark, ..AppConfig::default() };
    base_cfg.ipcache.hostname = true;
    base_cfg.lua_init = lua_scripts.iter().cloned().map(LuaInitEntry::File).collect();

    let scan_cfg = ScanConfig {
        domains, protos, families, level, stop_on_first,
        timeout: Duration::from_secs(cli.timeout.max(1)), force_blocked: cli.force_blocked,
    };

    // Spawn NFQUEUE worker before installing nftables rules so Drop tears down nftables first.
    let mut worker = InProcessWorkerHandle::spawn(base_cfg, quit_flag())?;
    let (tcp_ports, udp_ports) = scan_cfg.required_ports();
    let _fw_guard = if cli.no_nft {
        None
    } else {
        Some(
            NftFirewallBackend::new(cli.nft_bin)
                .install(cli.qnum, fwmark, &tcp_ports, &udp_ports)
                .map_err(|err| format!("{err}"))?,
        )
    };

    let probe = CurlProbeBackend::new(cli.curl_bin);
    let report = run_scan(&scan_cfg, &probe, &mut worker, quit_flag(), |ev| match ev {
        ProgressEvent::Http3Unavailable => eprintln!("[warn] curl lacks HTTP3 support; skipping http3"),
        ProgressEvent::Baseline { domain, proto, ipv, outcome } => eprintln!("[baseline] {domain} ({proto}/{ipv}) -> {}", outcome.summary()),
        ProgressEvent::Candidate { domain, index, total, strategy, outcome } if outcome.is_success() => {
            eprintln!("[PASS {index}/{total}] {domain} :: {} -> {}", strategy.id, outcome.summary());
        }
        ProgressEvent::Candidate { .. } => {}
    })?;

    if cli.json { print!("{}", format_report_json(&report)); } else { print_report_summary(&report); }

    if let Some(out_path) = write_config {
        if report.cover.is_empty() {
            eprintln!("No working strategies found; skipping config write to {}", out_path.display());
        } else {
            let toml = render_nfqws2_toml(&report.cover, &TomlRenderOptions { qnum: 200, fwmark, lua_init: lua_scripts });
            write_config_nofollow(&out_path, &toml).map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
            eprintln!("\nWrote nfqws2 config to {}\nRun with: nfqws2 --config {}", out_path.display(), out_path.display());
        }
    }
    Ok(())
}

/// Parses `args` with `clap`, runs [`run_strat_finder`], and maps results to process [`ExitCode`].
pub fn run_strat_finder_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match StratFinderCli::try_parse_from(args) {
        Ok(cli) => match run_strat_finder(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("strat_finder error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            let is_info = matches!(err.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion);
            let _ = err.print();
            if is_info { ExitCode::SUCCESS } else { ExitCode::from(2) }
        }
    }
}
