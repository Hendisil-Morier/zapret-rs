//! Standalone `strat_finder` binary delegating directly to [`zapret_rs::tools::run_strat_finder_cli`].

/// Process exit code returned by the shared strategy finder CLI runner.
use std::process::ExitCode;

/// Shared strategy finder CLI implementation also invoked via `nfqws2 --strat-finder`.
use zapret_rs::tools::run_strat_finder_cli;

/// Delegates process arguments to the shared `strat_finder` CLI entry point.
fn main() -> ExitCode {
    run_strat_finder_cli(std::env::args_os())
}
