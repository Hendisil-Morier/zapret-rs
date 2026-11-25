//! `ip2net` CLI binary reading IPv4/IPv6 addresses from stdin and grouping them into CIDRs.

/// Standard buffered I/O wrappers and `BrokenPipe` handling for downstream UNIX pipelines.
use std::io::{self, BufWriter, ErrorKind, Write};
/// Process exit status code returning `1` on invalid CLI arguments.
use std::process::ExitCode;

/// `clap` parser trait and positional/flag attributes matching `zapret2/ip2net` flags.
use clap::Parser;

/// `ip2net` parameter parser, IPv4/IPv6 grouping engine, and typed error enum.
use zapret_rs::tools::{Ip2NetConfig, Ip2NetError, Ip2NetFamily, run_ip2net};

/// Command-line flags accepted by the `ip2net` companion utility.
#[derive(Debug, Parser)]
#[command(
    name = "ip2net",
    version,
    about = "Group IPv4 or IPv6 addresses from stdin into covering CIDR subnets"
)]
struct Ip2NetCli {
    /// Select IPv4 list processing mode (default).
    #[arg(short = '4', long = "4", overrides_with_all = ["ipv4", "ipv6"])]
    ipv4: bool,
    /// Select IPv6 list processing mode.
    #[arg(short = '6', long = "6", overrides_with_all = ["ipv4", "ipv6"])]
    ipv6: bool,
    /// Prefix length bounds `min[-max]` searched for covering CIDRs (e.g. `22-30`, `56-64`).
    #[arg(long = "prefix-length", value_name = "MIN[-MAX]")]
    prefix_length: Option<String>,
    /// IPv4 minimum subnet fill ratio `mul/div` (default `3/4`).
    #[arg(long = "v4-threshold", value_name = "MUL/DIV")]
    v4_threshold: Option<String>,
    /// IPv6 minimum distinct address count per subnet (default `5`).
    #[arg(long = "v6-threshold", value_name = "N")]
    v6_threshold: Option<String>,
}

/// Parses CLI flags, runs streaming subnet collapsing on stdin/stdout, and maps pipeline exit codes.
fn run() -> ExitCode {
    let cli = match Ip2NetCli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let is_err = err.use_stderr();
            let _ = err.print();
            return if is_err {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    let family = if cli.ipv6 && !cli.ipv4 {
        Ip2NetFamily::Ipv6
    } else {
        Ip2NetFamily::Ipv4
    };
    let cfg = match Ip2NetConfig::from_options(
        family,
        cli.prefix_length.as_deref(),
        cli.v4_threshold.as_deref(),
        cli.v6_threshold.as_deref(),
    ) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = BufWriter::new(stdout.lock());

    match run_ip2net(&cfg, &mut reader, &mut writer).and_then(|()| Ok(writer.flush()?)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Ip2NetError::Io(ref err)) if err.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("ip2net: {err}");
            ExitCode::from(1)
        }
    }
}

/// Entry point returning `0` on success or `1` on invalid CLI flags or I/O errors.
fn main() -> ExitCode {
    run()
}
