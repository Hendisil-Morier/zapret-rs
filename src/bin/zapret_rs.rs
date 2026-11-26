//! `zapret-rs`: unified multicall binary wrapping TUI, `nfqws2` daemon, `strat_finder`, `ip2net`, and `mdig`.

/// Path options accepted on the CLI for pre-loading configs and Lua scripts.
use std::path::PathBuf;
/// Process exit status code returned on clean exit or terminal failure.
use std::process::ExitCode;

/// Minimal CLI flag parsing (`--config`, `--lua-dir`, `--no-nft`, `--version`).
use clap::Parser;

/// Headless multicall router for `argv[0]` symlinks and subcommands (`daemon`, `scan`, `ip2net`, `mdig`).
use zapret_rs::tools::dispatch_headless_applet;
/// TUI entry point and options struct when compiled with the default `tui` feature.
#[cfg(feature = "tui")]
use zapret_rs::tui::{TuiOptions, run_tui};

/// Help footer listing multicall subcommands available through the unified `zapret-rs` binary.
const SUBCOMMAND_HELP: &str = "\
Subcommands:
  daemon (nfqws2)  Run the NFQUEUE DPI desync daemon
  scan             Run the CLI strategy finder (strat_finder)
  ip2net           Group IPs into covering CIDR subnets
  mdig             Multi-threaded DNS lookup tool";

/// Command-line options for the `zapret-rs` interactive TUI and multicall entry point.
#[derive(Debug, Parser)]
#[command(
    name = "zapret-rs",
    version = env!("CARGO_PKG_VERSION"),
    about = "Unified zapret-rs binary: interactive TUI, nfqws2 daemon, strat_finder, ip2net, and mdig",
    after_help = SUBCOMMAND_HELP
)]
struct ZapretTuiCli {
    /// Optional `nfqws2.toml` path to pre-load into the Config and Run tabs.
    #[arg(short = 'c', long = "config")]
    config: Option<PathBuf>,
    /// Optional directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    #[arg(long = "lua-dir")]
    lua_dir: Option<PathBuf>,
    /// Start with manual `nftables` mode enabled (skip automatic `nft` calls).
    #[arg(long = "no-nft")]
    no_nft: bool,
    /// Optional daemon Unix control socket path override for attach mode.
    #[arg(long = "control-socket")]
    control_socket: Option<PathBuf>,
    /// Theme preset (`neon`, `tokyo`, `dracula`, `gruvbox`, `ansi`) or path to a `theme.toml` file.
    #[arg(long = "theme")]
    theme: Option<String>,
}

/// Dispatches multicall applets first, then parses TUI flags and opens the interactive interface.
fn main() -> ExitCode {
    if let Some(code) = dispatch_headless_applet(std::env::args_os()) {
        return code;
    }
    let cli = ZapretTuiCli::parse();
    #[cfg(feature = "tui")]
    {
        let opts = TuiOptions {
            config: cli.config,
            lua_dir: cli.lua_dir,
            no_nft: cli.no_nft,
            control_socket: cli.control_socket,
            theme: cli.theme,
        };
        match run_tui(opts) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("zapret-rs TUI error: {err}");
                ExitCode::FAILURE
            }
        }
    }
    #[cfg(not(feature = "tui"))]
    {
        let _ = cli;
        eprintln!(
            "zapret-rs: built without 'tui' feature; run a headless subcommand (daemon, scan, ip2net, mdig)"
        );
        ExitCode::FAILURE
    }
}
