//! `mdig` CLI binary providing multi-threaded DNS resolution and raw DNS packet helpers.

/// Optional resolved/failed domain log file creation (`--log-resolved`, `--log-failed`).
use std::fs::File;
/// Buffered stdin/stdout/file I/O and `BrokenPipe` detection for shell pipeline composition.
use std::io::{self, BufReader, BufWriter, ErrorKind, Write};
/// Filesystem paths accepted by `--log-resolved` and `--log-failed`.
use std::path::{Path, PathBuf};
/// Process exit codes matching `zapret2/mdig/mdig.c` (`0`, `1`, `5`, `10`, `11`, `12`).
use std::process::ExitCode;

/// `clap` parser trait and flag attributes compatible with `zapret2/mdig`.
use clap::Parser;

/// `mdig` DNS packet helpers, resolver pool, configuration parser, and typed errors.
use zapret_rs::tools::{
    LibcResolver, MdigConfig, MdigDnsError, MdigOutputs, build_dns_query,
    read_and_parse_dns_reply, run_mdig_resolver,
};

/// Command-line flags accepted by the `mdig` companion utility.
#[derive(Debug, Parser)]
#[command(
    name = "mdig",
    version,
    about = "Multi-threaded DNS resolver and raw DNS query/reply helper"
)]
struct MdigCli {
    /// Address family (`4`, `6`, or `46`).
    #[arg(long = "family", value_name = "4|6|46")]
    family: Option<String>,
    /// Concurrent DNS worker threads (`1..=100`).
    #[arg(long = "threads", value_name = "N")]
    threads: Option<String>,
    /// Maximum attempts on `EAI_AGAIN` (`1..=1000`).
    #[arg(long = "eagain", value_name = "N")]
    eagain: Option<String>,
    /// Delay in milliseconds between `EAI_AGAIN` attempts (`0..=100000`).
    #[arg(long = "eagain-delay", value_name = "MS")]
    eagain_delay: Option<String>,
    /// Print thread progress and failure codes to stderr.
    #[arg(long = "verbose")]
    verbose: bool,
    /// Print resolution statistics to stderr every `N` domains (`<= 0` disables stats).
    #[arg(long = "stats", value_name = "N", allow_negative_numbers = true)]
    stats: Option<String>,
    /// Log successfully handled domains and pass-through IPs to file.
    #[arg(long = "log-resolved", value_name = "FILE")]
    log_resolved: Option<PathBuf>,
    /// Log failed or invalid lines to file.
    #[arg(long = "log-failed", value_name = "FILE")]
    log_failed: Option<PathBuf>,
    /// Emit raw binary RFC 1035 DNS query for `DOMAIN` to stdout.
    #[arg(long = "dns-make-query", value_name = "DOMAIN")]
    dns_make_query: Option<String>,
    /// Parse a binary RFC 1035 DNS reply read from stdin into stdout IP lines.
    #[arg(long = "dns-parse-query")]
    dns_parse_query: bool,
}

/// Opens an optional log file as a buffered writer, printing the `mdig.c` diagnostic on error.
fn open_optional_log(path: Option<&Path>) -> Result<Option<BufWriter<File>>, ExitCode> {
    let Some(path) = path else {
        return Ok(None);
    };
    match File::create(path) {
        Ok(file) => Ok(Some(BufWriter::new(file))),
        Err(_) => {
            eprintln!("failed to create {}", path.display());
            Err(ExitCode::from(5))
        }
    }
}

/// Handles `--dns-parse-query` mode, returning exit code `0`, `10`, or `11`.
fn handle_dns_parse_query() -> ExitCode {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut reader = stdin.lock();
    let mut writer = BufWriter::new(stdout.lock());
    let outcome = read_and_parse_dns_reply(&mut reader, &mut writer)
        .and_then(|()| writer.flush().map_err(MdigDnsError::WriteFailed));
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(MdigDnsError::WriteFailed(ref err)) if err.kind() == ErrorKind::BrokenPipe => {
            ExitCode::SUCCESS
        }
        Err(MdigDnsError::ReadFailed) => {
            eprintln!("{}", MdigDnsError::ReadFailed);
            ExitCode::from(10)
        }
        Err(MdigDnsError::WriteFailed(err)) => {
            eprintln!("{err}");
            ExitCode::from(10)
        }
        Err(MdigDnsError::ParseFailed) => {
            eprintln!("{}", MdigDnsError::ParseFailed);
            ExitCode::from(11)
        }
        Err(MdigDnsError::InvalidQuery) => ExitCode::from(1),
    }
}

/// Handles `--dns-make-query=DOMAIN` mode, returning exit code `0`, `1`, or `10`.
fn handle_dns_make_query(domain: &str, cfg: &MdigConfig) -> ExitCode {
    let Some(packet) = build_dns_query(domain, cfg.family) else {
        eprintln!("{}", MdigDnsError::InvalidQuery);
        return ExitCode::from(1);
    };
    let stdout = io::stdout();
    let mut out = stdout.lock();
    match out.write_all(&packet).and_then(|()| out.flush()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) if err.kind() == ErrorKind::BrokenPipe => ExitCode::SUCCESS,
        Err(_) => {
            eprintln!("could not write DNS query blob to stdout");
            ExitCode::from(10)
        }
    }
}

/// Parses CLI options and executes DNS blob helper modes or the multi-threaded resolver loop.
fn run() -> ExitCode {
    let cli = match MdigCli::try_parse() {
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

    if cli.dns_parse_query {
        return handle_dns_parse_query();
    }

    let cfg = match MdigConfig::from_options(
        cli.family.as_deref(),
        cli.threads.as_deref(),
        cli.eagain.as_deref(),
        cli.eagain_delay.as_deref(),
        cli.verbose,
        cli.stats.as_deref(),
    ) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };

    if let Some(domain) = cli.dns_make_query.as_deref() {
        return handle_dns_make_query(domain, &cfg);
    }

    let mut log_resolved = match open_optional_log(cli.log_resolved.as_deref()) {
        Ok(writer) => writer,
        Err(code) => return code,
    };
    let mut log_failed = match open_optional_log(cli.log_failed.as_deref()) {
        Ok(writer) => writer,
        Err(code) => return code,
    };

    let mut reader = BufReader::new(io::stdin());
    let mut out = BufWriter::new(io::stdout());
    let mut err = io::stderr();
    let outputs = MdigOutputs {
        stdout: &mut out,
        stderr: &mut err,
        log_resolved: log_resolved.as_mut().map(|w| w as &mut (dyn Write + Send)),
        log_failed: log_failed.as_mut().map(|w| w as &mut (dyn Write + Send)),
    };

    let started = run_mdig_resolver(&cfg, &LibcResolver, &mut reader, outputs);
    if started == 0 {
        ExitCode::from(12)
    } else {
        ExitCode::SUCCESS
    }
}

/// Entry point returning `mdig` POSIX status codes cleanly after RAII buffer flushes.
fn main() -> ExitCode {
    run()
}
