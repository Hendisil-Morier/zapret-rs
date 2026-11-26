//! Shared `nfqws2` daemon CLI entrypoint powering both standalone `nfqws2` and `zapret-rs daemon`.

/// Argument list forwarding supporting `argv[0]` multicall and `--strat-finder` dispatch.
use std::ffi::OsString;
/// Process exit status code allowing deterministic RAII cleanup before termination.
use std::process::ExitCode;

/// CLI parser trait used to interpret `nfqws2` command-line options from explicit argv iterators.
use clap::Parser;

/// CLI flag definitions parsed before dispatching Linux runtime execution.
use crate::config::CliArgs;
/// Linux daemon runtime startup and event loop runner.
#[cfg(target_os = "linux")]
use crate::tools::daemon_runtime::run_daemon_linux;
/// Windows WinDivert daemon runtime startup and event loop runner.
#[cfg(windows)]
use crate::tools::daemon_windows::run_daemon_windows;
/// Shared strategy finder CLI dispatch (`--strat-finder`).
use crate::tools::strat_cli::{extract_strat_finder_args, run_strat_finder_cli};

/// Executes the `nfqws2` daemon or `--strat-finder` CLI from an arbitrary argument list.
pub fn run_nfqws2_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let argv: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if let Some(sf_args) = extract_strat_finder_args(argv.iter().cloned()) {
        return run_strat_finder_cli(sf_args);
    }
    let cli = match CliArgs::try_parse_from(argv) {
        Ok(cli) => cli,
        Err(err) => {
            let is_err = err.use_stderr();
            let _ = err.print();
            return if is_err { ExitCode::from(2) } else { ExitCode::SUCCESS };
        }
    };
    #[cfg(target_os = "linux")]
    match run_daemon_linux(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nfqws2 error: {err}");
            ExitCode::FAILURE
        }
    }
    #[cfg(windows)]
    match run_daemon_windows(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("nfqws2 error: {err}");
            ExitCode::FAILURE
        }
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = cli;
        eprintln!("nfqws2 error: packet interception is not yet implemented on this OS");
        ExitCode::FAILURE
    }
}
