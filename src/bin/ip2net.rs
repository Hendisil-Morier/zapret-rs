//! Standalone `ip2net` binary delegating directly to [`zapret_rs::tools::run_ip2net_cli`].

/// Process exit status code returned on invalid arguments or completion.
use std::process::ExitCode;

/// Shared `ip2net` subnet aggregator CLI entry point.
use zapret_rs::tools::run_ip2net_cli;

/// Delegates process arguments to the shared `ip2net` runner.
fn main() -> ExitCode {
    run_ip2net_cli(std::env::args_os())
}
