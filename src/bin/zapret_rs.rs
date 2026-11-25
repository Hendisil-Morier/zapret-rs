//! `zapret-rs`: unified `ratatui` TUI wrapping strategy discovery, config management, and live `nfqws2`.

/// Path options accepted on the CLI for pre-loading configs and Lua scripts.
use std::path::PathBuf;
/// Process exit status code returned on clean exit or terminal failure.
use std::process::ExitCode;

/// Minimal CLI flag parsing (`--config`, `--lua-dir`, `--no-nft`, `--version`).
use clap::Parser;

/// TUI entry point and options struct from the library crate.
use zapret_rs::tui::{TuiOptions, run_tui};

/// Command-line options for the `zapret-rs` interactive TUI.
#[derive(Debug, Parser)]
#[command(
    name = "zapret-rs",
    version = env!("CARGO_PKG_VERSION"),
    about = "Interactive TUI wrapping zapret-rs strategy finder, config preview, and live nfqws2"
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
}

/// Parses optional startup flags and launches the interactive `ratatui` TUI.
fn main() -> ExitCode {
    let cli = ZapretTuiCli::parse();
    let opts = TuiOptions {
        config: cli.config,
        lua_dir: cli.lua_dir,
        no_nft: cli.no_nft,
    };
    match run_tui(opts) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("zapret-rs TUI error: {err}");
            ExitCode::FAILURE
        }
    }
}
