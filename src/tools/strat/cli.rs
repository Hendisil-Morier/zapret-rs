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
    drop_elevated_root_if_needed, has_packet_capture_privileges, install_signal_handlers, quit_flag,
};
/// Embedded Lua script discovery and fallback extractor.
use crate::tools::lua_bundle::{detect_lua_dir, resolve_lua_scripts};
/// Strategy catalog types and expansion function.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, build_catalog};
/// JSON and stdout scan report formatters.
use crate::tools::strat::cli_report::{format_report_json, print_report_summary};
/// Temporary `nftables` queue guard backend and ruleset printer on Linux.
#[cfg(target_os = "linux")]
use crate::tools::strat::firewall::FirewallBackend;
/// OS-agnostic firewall backend selector and [`FirewallBackend`] trait.
#[cfg(not(target_os = "linux"))]
use crate::tools::strat::firewall::active_firewall_backend;
/// Interactive terminal setup wizard and domain/tilde helpers.
use crate::tools::strat::interactive::{
    InteractiveDefaults, expand_tilde, normalize_domain, prompt_interactive_wizard,
};
/// Temporary `nftables` queue guard backend and ruleset printer on Linux.
#[cfg(target_os = "linux")]
use crate::tools::strat::nft::{NftFirewallBackend, build_nft_cleanup_cmd};
/// Live `curl` connectivity probe backend (runs children with zero capabilities).
use crate::tools::strat::probe::CurlProbeBackend;
/// In-process NFQUEUE worker thread and scan orchestrator.
use crate::tools::strat::runner::{ProgressEvent, ScanConfig, run_scan};
/// Minimal profile cover and symlink-safe `nfqws2.toml` serializer.
use crate::tools::strat::toml::{
    CoveredProfile, TomlRenderOptions, render_nfqws2_toml, write_config_nofollow,
};
/// In-process capture worker handle.
use crate::tools::strat::worker::InProcessWorkerHandle;

/// Default NFQUEUE number for `strat_finder` (distinct from `nfqws2`'s default `200`).
pub const DEFAULT_STRAT_QNUM: u16 = 210;

/// Command-line options accepted by `strat_finder` and `nfqws2 --strat-finder`.
#[derive(Debug, Parser)]
#[command(name = "strat_finder", version = env!("CARGO_PKG_VERSION"), about = "Native in-process DPI-bypass strategy finder for zapret-rs (nfqws2)")]
pub struct StratFinderCli
{
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
    /// Per-probe curl timeout in seconds (fractional values such as `1.5` supported).
    #[arg(long = "timeout", default_value_t = 2.0)]
    pub timeout: f64,
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

    for (idx, arg) in raw.into_iter().enumerate()
    {
        if idx == 0
        {
            out.push(OsString::from("nfqws2 --strat-finder"));
            continue;
        }
        if !past_double_dash && arg == "--"
        {
            past_double_dash = true;
            out.push(arg);
            continue;
        }
        if !past_double_dash && !found && arg == "--strat-finder"
        {
            found = true;
            continue;
        }
        out.push(arg);
    }

    if found { Some(out) } else { None }
}

/// Handles `--list-strategies` offline preview and optional sample `--write-config`.
fn run_list_mode(
    cli: &StratFinderCli,
    protos: &[ProbeProtocol],
    families: &[IpFamily],
    level: ScanLevel,
    fwmark: u32,
) -> Result<(), String>
{
    let mut sample_cover = Vec::new();
    let domains: Vec<String> = cli.domains.iter().filter_map(|d| normalize_domain(d)).collect();
    for &ipv in families
    {
        for &proto in protos
        {
            let catalog = build_catalog(proto, level, ipv);
            println!("# {proto}/{ipv} ({level}): {} candidates", catalog.len());
            for spec in &catalog
            {
                println!("  [w={:02}] {}", spec.weight, spec.id);
            }
            if let Some(first) = catalog.into_iter().next()
            {
                sample_cover.push(CoveredProfile {
                    strategy: first,
                    domains: domains.clone(),
                    avg_latency_ms: 0,
                });
            }
        }
    }
    if let Some(out_path) = &cli.write_config
    {
        let out_path = expand_tilde(&out_path.to_string_lossy());
        let lua_init = resolve_lua_scripts(cli.lua_dir.as_deref()).unwrap_or_default();
        let toml = render_nfqws2_toml(&sample_cover, &TomlRenderOptions { qnum: cli.qnum, fwmark, lua_init });
        write_config_nofollow(&out_path, &toml)
            .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
        eprintln!("Wrote sample nfqws2 config to {}", out_path.display());
    }
    Ok(())
}

/// Ensures packet capture privileges are active (`CAP_NET_ADMIN|CAP_NET_RAW` on Linux, Admin on Windows).
fn ensure_least_privilege_net_caps() -> Result<(), String>
{
    if let Some((uid, gid)) =
        drop_elevated_root_if_needed().map_err(|err| format!("privilege drop failed: {err}"))?
    {
        eprintln!(
            "[sec] dropped root privileges to uid={uid}, gid={gid} (retaining only CAP_NET_ADMIN, CAP_NET_RAW)"
        );
    }
    if !has_packet_capture_privileges().map_err(|err| format!("capability check failed: {err}"))?
    {
        #[cfg(target_os = "linux")]
        {
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
        #[cfg(windows)]
        return Err(
            "missing Administrator privileges.\nRight-click zapret-rs.exe and choose 'Run as administrator'."
                .to_owned(),
        );
        #[cfg(not(any(target_os = "linux", windows)))]
        return Err("packet capture is not supported on this operating system".to_owned());
    }
    Ok(())
}

/// Resolved domain, protocol, family, level, and output options ready for a scan run.
struct ResolvedScanInputs
{
    /// Target domain list to test.
    domains: Vec<String>,
    /// Protocols included in the sweep.
    protos: Vec<ProbeProtocol>,
    /// IP address families included in the sweep.
    families: Vec<IpFamily>,
    /// Search depth level.
    level: ScanLevel,
    /// Whether to stop probing a target once one working strategy succeeds.
    stop_on_first: bool,
    /// Optional explicit directory containing Lua init scripts.
    lua_dir: Option<std::path::PathBuf>,
    /// Optional output TOML path for the covering config.
    write_config: Option<std::path::PathBuf>,
}

/// Prints the preview firewall rules for `--print-nft` and exits.
fn print_nft_preview(
    cli: &StratFinderCli,
    protos: Vec<ProbeProtocol>,
    families: Vec<IpFamily>,
    level: ScanLevel,
    fwmark: u32,
)
{
    let dummy = ScanConfig {
        domains: Vec::new(),
        protos,
        families,
        level,
        timeout: Duration::from_secs(1),
        stop_on_first: false,
        force_blocked: false,
    };
    let (tcp, udp) = dummy.required_ports();
    #[cfg(target_os = "linux")]
    {
        print!("{}", NftFirewallBackend::build_nft_script(cli.qnum, fwmark, &tcp, &udp));
        println!("# Cleanup: sudo {}", build_nft_cleanup_cmd());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let backend = active_firewall_backend();
        println!("{}", backend.preview_filter(cli.qnum, fwmark, &tcp, &udp));
    }
}

/// Gathers domains and scan preferences from CLI arguments, interactive prompts, or piped stdin.
fn resolve_scan_inputs(
    cli: &StratFinderCli,
    protos: Vec<ProbeProtocol>,
    families: Vec<IpFamily>,
    level: ScanLevel,
) -> Result<ResolvedScanInputs, String>
{
    let mut domains: Vec<String> = cli.domains.iter().filter_map(|d| normalize_domain(d)).collect();
    let stop_on_first = cli.stop_on_first;
    let lua_dir = cli.lua_dir.clone().map(|p| expand_tilde(&p.to_string_lossy()));
    let write_config = cli.write_config.clone().map(|p| expand_tilde(&p.to_string_lossy()));

    let interactive = cli.interactive || (domains.is_empty() && io::stdin().is_terminal());
    if interactive
    {
        let defaults = InteractiveDefaults {
            domains,
            protos,
            families,
            level,
            stop_on_first,
            lua_dir: lua_dir.or_else(|| detect_lua_dir(None)),
            write_config,
        };
        let stdin = io::stdin();
        let sel = prompt_interactive_wizard(&mut stdin.lock(), &mut io::stderr(), &defaults)?;
        return Ok(ResolvedScanInputs {
            domains: sel.domains,
            protos: sel.protos,
            families: sel.families,
            level: sel.level,
            stop_on_first: sel.stop_on_first,
            lua_dir: sel.lua_dir,
            write_config: sel.write_config,
        });
    }

    if domains.is_empty()
    {
        let mut buf = String::new();
        let _ = io::Read::read_to_string(&mut io::stdin(), &mut buf);
        domains.extend(buf.split(|c: char| c.is_whitespace() || c == ',').filter_map(normalize_domain));
        if domains.is_empty()
        {
            return Err("no target domains provided (pass --domain <DOMAIN> or run interactively)".to_owned());
        }
    }

    Ok(ResolvedScanInputs { domains, protos, families, level, stop_on_first, lua_dir, write_config })
}

/// Installs the live firewall hook, executes the strategy scan, and outputs the final report.
fn execute_and_report_scan(
    cli: &StratFinderCli,
    inputs: ResolvedScanInputs,
    fwmark: u32,
) -> Result<(), String>
{
    let lua_scripts = resolve_lua_scripts(inputs.lua_dir.as_deref())?;
    install_signal_handlers().map_err(|err| format!("failed to install signal handlers: {err}"))?;

    let mut base_cfg = AppConfig { qnum: cli.qnum, fwmark, ..AppConfig::default() };
    base_cfg.ipcache.hostname = true;
    base_cfg.lua_init = lua_scripts.iter().cloned().map(LuaInitEntry::File).collect();

    if !cli.timeout.is_finite() || cli.timeout <= 0.0
    {
        return Err(format!("invalid --timeout '{}' (expected positive seconds, e.g. 2.0)", cli.timeout));
    }
    let scan_cfg = ScanConfig {
        domains: inputs.domains,
        protos: inputs.protos,
        families: inputs.families,
        level: inputs.level,
        stop_on_first: inputs.stop_on_first,
        timeout: Duration::from_secs_f64(cli.timeout.clamp(0.2, 60.0)),
        force_blocked: cli.force_blocked,
    };

    // Spawn packet worker before installing firewall rules so Drop tears down rules first.
    let mut worker = InProcessWorkerHandle::spawn(base_cfg, quit_flag())?;
    let (tcp_ports, udp_ports) = scan_cfg.required_ports();
    let _fw_guard = if cli.no_nft
    {
        None
    }
    else
    {
        #[cfg(target_os = "linux")]
        {
            Some(
                NftFirewallBackend::new(cli.nft_bin.clone())
                    .install(cli.qnum, fwmark, &tcp_ports, &udp_ports)
                    .map_err(|err| format!("{err}"))?,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            Some(
                active_firewall_backend()
                    .install(cli.qnum, fwmark, &tcp_ports, &udp_ports)
                    .map_err(|err| format!("{err}"))?,
            )
        }
    };

    let probe = CurlProbeBackend::new(cli.curl_bin.clone());
    let report = run_scan(&scan_cfg, &probe, &mut worker, quit_flag(), |ev| match ev
    {
        ProgressEvent::Http3Unavailable => eprintln!("[warn] curl lacks HTTP3 support; skipping http3"),
        ProgressEvent::Baseline { domain, proto, ipv, outcome } =>
        {
            eprintln!("[baseline] {domain} ({proto}/{ipv}) -> {}", outcome.summary())
        }
        ProgressEvent::Candidate { domain, index, total, strategy, outcome } if outcome.is_success() =>
        {
            eprintln!("[PASS {index}/{total}] {domain} :: {} -> {}", strategy.id, outcome.summary());
        }
        ProgressEvent::Candidate { .. } =>
        {}
    })?;

    if cli.json
    {
        print!("{}", format_report_json(&report));
    }
    else
    {
        print_report_summary(&report);
    }

    if let Some(out_path) = inputs.write_config
    {
        if report.cover.is_empty()
        {
            eprintln!("No working strategies found; skipping config write to {}", out_path.display());
        }
        else
        {
            let toml = render_nfqws2_toml(
                &report.cover,
                &TomlRenderOptions { qnum: 200, fwmark, lua_init: lua_scripts },
            );
            write_config_nofollow(&out_path, &toml)
                .map_err(|err| format!("failed to write {}: {err}", out_path.display()))?;
            eprintln!(
                "\nWrote nfqws2 config to {}\nRun with: nfqws2 --config {}",
                out_path.display(),
                out_path.display()
            );
        }
    }
    Ok(())
}

/// Executes a parsed [`StratFinderCli`] session, launching the interactive wizard when appropriate.
pub fn run_strat_finder(cli: StratFinderCli) -> Result<(), String>
{
    let level: ScanLevel = cli.level.parse()?;
    let mut protos = Vec::new();
    for raw in &cli.protos
    {
        let p: ProbeProtocol = raw.parse()?;
        if !protos.contains(&p)
        {
            protos.push(p);
        }
    }
    if protos.is_empty()
    {
        return Err("at least one protocol must be specified via --proto".to_owned());
    }
    let families = match (cli.ipv4, cli.ipv6)
    {
        (false, true) => vec![IpFamily::V6],
        (true, true) => vec![IpFamily::V4, IpFamily::V6],
        _ => vec![IpFamily::V4],
    };
    let fwmark = parse_u32_radix(&cli.fwmark).ok_or_else(|| {
        format!("invalid --fwmark '{}' (expected hex like 0x40000000 or decimal)", cli.fwmark)
    })?;
    let fwmark = if fwmark == 0 { DEFAULT_DESYNC_FWMARK } else { fwmark };

    if cli.print_nft
    {
        print_nft_preview(&cli, protos, families, level, fwmark);
        return Ok(());
    }
    if cli.list_strategies
    {
        return run_list_mode(&cli, &protos, &families, level, fwmark);
    }

    ensure_least_privilege_net_caps()?;
    let inputs = resolve_scan_inputs(&cli, protos, families, level)?;
    execute_and_report_scan(&cli, inputs, fwmark)
}

/// Parses `args` with `clap`, runs [`run_strat_finder`], and maps results to process [`ExitCode`].
pub fn run_strat_finder_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match StratFinderCli::try_parse_from(args)
    {
        Ok(cli) => match run_strat_finder(cli)
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) =>
            {
                eprintln!("strat_finder error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) =>
        {
            let is_info = matches!(err.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion);
            let _ = err.print();
            if is_info { ExitCode::SUCCESS } else { ExitCode::from(2) }
        }
    }
}
