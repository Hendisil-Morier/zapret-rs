//! Standalone `nfqws2` binary delegating directly to [`zapret_rs::tools::run_nfqws2_cli`].

/// Process exit status code returned cleanly after RAII destructors run.
use std::process::ExitCode;

/// Shared `nfqws2` daemon and `--strat-finder` CLI entry point.
use zapret_rs::tools::run_nfqws2_cli;

/// Delegates process arguments to the shared `nfqws2` runner.
fn main() -> ExitCode {
    run_nfqws2_cli(std::env::args_os())
}
