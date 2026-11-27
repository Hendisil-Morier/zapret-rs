//! BusyBox-style multicall applet routing via `argv[0]` basename or subcommand token.

/// Argument string conversion when inspecting `argv[0]` and subcommand names.
use std::ffi::{OsStr, OsString};
/// Path basename extraction across Unix and Windows executable names.
use std::path::Path;
/// Exit status returned from whichever applet handled the invocation.
use std::process::ExitCode;

/// Shared `nfqws2` daemon runner (`daemon` / `nfqws2`).
use crate::tools::daemon::cli::run_nfqws2_cli;
/// OS DNS/DoH preset management CLI runner (`dns`).
use crate::tools::dns::run_dns_cli;
/// Self-installer and uninstaller CLI runners (`install` / `uninstall`).
use crate::tools::installer::{run_install_cli, run_uninstall_cli};
/// Shared `ip2net` subnet aggregator runner.
use crate::tools::ip2net_cli::run_ip2net_cli;
/// Shared `mdig` multi-threaded DNS resolver runner.
use crate::tools::mdig::cli::run_mdig_cli;
/// Shared `strat_finder` CLI runner (`scan` / `strat_finder`).
use crate::tools::strat::cli::run_strat_finder_cli;
/// Embedded web dashboard CLI runner (`web`).
use crate::tools::web::cli::run_web_cli;

/// Resolved multicall applet together with the canonical binary name for `argv[0]` forwarding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MulticallApplet {
    /// Interactive `ratatui` TUI (default `zapret-rs` invocation).
    Tui,
    /// `nfqws2` NFQUEUE packet interception daemon (`daemon` or `nfqws2`).
    Daemon,
    /// CLI strategy finder (`scan`, `strat-finder`, or `strat_finder`).
    Scan,
    /// Streaming IPv4/IPv6 CIDR aggregator (`ip2net`).
    Ip2Net,
    /// Multi-threaded DNS resolver and raw query helper (`mdig`).
    Mdig,
    /// Self-installer deploying binary, Lua scripts, capabilities, and optional systemd unit.
    Install,
    /// Uninstaller removing installed binaries, symlinks, and Lua scripts.
    Uninstall,
    /// OS DNS/DoH preset status and configuration manager (`dns`).
    Dns,
    /// Embedded HTTP/SSE mobile & desktop web dashboard (`web`).
    Web,
}

/// Normalizes an executable stem by taking its filename, stripping `.exe`, and lowercasing.
fn normalize_applet_token(raw: &OsStr) -> String {
    let lossy = raw.to_string_lossy();
    let name = Path::new(lossy.as_ref())
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or(lossy.as_ref());
    let stem = name.strip_suffix(".exe").unwrap_or(name);
    stem.to_ascii_lowercase()
}

/// Maps `argv[0]` basename alone to an applet when invoked through a named symlink/copy.
pub fn resolve_argv0_applet(arg0: &OsStr) -> Option<MulticallApplet> {
    match normalize_applet_token(arg0).as_str() {
        "nfqws2" => Some(MulticallApplet::Daemon),
        "strat_finder" | "strat-finder" => Some(MulticallApplet::Scan),
        "ip2net" => Some(MulticallApplet::Ip2Net),
        "mdig" => Some(MulticallApplet::Mdig),
        _ => None,
    }
}

/// Resolves an explicit first subcommand token (`daemon`, `scan`, `ip2net`, `mdig`, `install`, `uninstall`).
pub fn resolve_subcommand_applet(arg1: &OsStr) -> Option<MulticallApplet> {
    match arg1.to_string_lossy().as_ref() {
        "daemon" | "nfqws2" => Some(MulticallApplet::Daemon),
        "scan" | "strat-finder" | "strat_finder" => Some(MulticallApplet::Scan),
        "ip2net" => Some(MulticallApplet::Ip2Net),
        "mdig" => Some(MulticallApplet::Mdig),
        "install" => Some(MulticallApplet::Install),
        "uninstall" => Some(MulticallApplet::Uninstall),
        "dns" => Some(MulticallApplet::Dns),
        "web" => Some(MulticallApplet::Web),
        _ => None,
    }
}

/// Resolves the target applet and normalized argument vector (replacing shifted `argv[0]`).
pub fn resolve_multicall<I, T>(args: I) -> (MulticallApplet, Vec<OsString>)
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let raw: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if let Some(arg0) = raw.first()
        && let Some(applet) = resolve_argv0_applet(arg0)
    {
        return (applet, raw);
    }
    if let Some(arg1) = raw.get(1)
        && let Some(applet) = resolve_subcommand_applet(arg1)
    {
        let canonical = match applet {
            MulticallApplet::Tui => "zapret-rs",
            MulticallApplet::Daemon => "nfqws2",
            MulticallApplet::Scan => "strat_finder",
            MulticallApplet::Ip2Net => "ip2net",
            MulticallApplet::Mdig => "mdig",
            MulticallApplet::Install => "zapret-rs install",
            MulticallApplet::Uninstall => "zapret-rs uninstall",
            MulticallApplet::Dns => "zapret-rs dns",
            MulticallApplet::Web => "zapret-rs web",
        };
        let mut forwarded = Vec::with_capacity(raw.len());
        forwarded.push(OsString::from(canonical));
        forwarded.extend(raw.into_iter().skip(2));
        return (applet, forwarded);
    }
    (MulticallApplet::Tui, raw)
}

/// Dispatches non-TUI applets (`Daemon`, `Scan`, `Ip2Net`, `Mdig`, `Install`, `Uninstall`), returning `Some(exit_code)`.
///
/// Returns `None` when [`MulticallApplet::Tui`] should handle the invocation.
pub fn dispatch_headless_applet<I, T>(args: I) -> Option<ExitCode>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let (applet, forwarded) = resolve_multicall(args);
    match applet {
        MulticallApplet::Tui => None,
        MulticallApplet::Daemon => Some(run_nfqws2_cli(forwarded)),
        MulticallApplet::Scan => Some(run_strat_finder_cli(forwarded)),
        MulticallApplet::Ip2Net => Some(run_ip2net_cli(forwarded)),
        MulticallApplet::Mdig => Some(run_mdig_cli(forwarded)),
        MulticallApplet::Install => Some(run_install_cli(forwarded)),
        MulticallApplet::Uninstall => Some(run_uninstall_cli(forwarded)),
        MulticallApplet::Dns => Some(run_dns_cli(forwarded)),
        MulticallApplet::Web => Some(run_web_cli(forwarded)),
    }
}
