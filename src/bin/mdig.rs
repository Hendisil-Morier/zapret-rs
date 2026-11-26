//! Standalone `mdig` binary delegating directly to [`zapret_rs::tools::run_mdig_cli`].

/// Process exit status code matching `zapret2/mdig/mdig.c`.
use std::process::ExitCode;

/// Shared `mdig` DNS resolver CLI entry point.
use zapret_rs::tools::run_mdig_cli;

/// Delegates process arguments to the shared `mdig` runner.
fn main() -> ExitCode {
    run_mdig_cli(std::env::args_os())
}
