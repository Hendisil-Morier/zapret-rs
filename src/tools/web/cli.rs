//! CLI options and runner for `zapret-rs web` dashboard invocations.

/// OS string argument conversion passed from the multicall dispatcher.
use std::ffi::OsString;
/// Socket bind address validation.
use std::net::SocketAddr;
/// Config, Lua directory, and control socket overrides.
use std::path::PathBuf;
/// Exit codes returned to the shell from CLI execution.
use std::process::ExitCode;
/// Atomic shutdown polling interval while waiting for `SIGINT`/`SIGTERM`.
use std::sync::atomic::Ordering;
/// Shutdown sleep loop and thread primitives.
use std::thread;
/// Main wait loop cadence.
use std::time::Duration;

/// CLI parser and informational exit handling (`--help`/`--version`).
use clap::{Parser, error::ErrorKind as ClapErrorKind};

/// Cooperative shutdown signal flag shared with `SIGINT`/`SIGTERM` handlers.
use crate::runtime::{install_signal_handlers, quit_flag};
/// Session auth validator guarding non-loopback bindings.
use crate::tools::web::auth::WebAuth;
/// HTTP/SSE listener launcher wrapped by [`run_web`].
use crate::tools::web::server::start_web_server;

/// Default loopback listen address preventing accidental unauthenticated WAN exposure.
pub const DEFAULT_WEB_BIND: &str = "127.0.0.1:8787";

/// Command-line flags for `zapret-rs web`.
#[derive(Debug, Parser)]
#[command(name = "zapret-rs web", version = env!("CARGO_PKG_VERSION"), about = "Mobile & desktop web control dashboard for zapret-rs")]
pub struct WebCli
{
    /// Listen address as IP:PORT (use loopback, LAN IP, or Tailscale IP; e.g. 127.0.0.1:8787).
    #[arg(long = "bind", default_value = DEFAULT_WEB_BIND)]
    pub bind: String,
    /// Shared passcode/bearer token required to unlock the web UI (or read ZAPRET_WEB_TOKEN).
    #[arg(long = "token")]
    pub token: Option<String>,
    /// Disable authentication (permitted strictly on loopback addresses such as 127.0.0.1).
    #[arg(long = "no-auth")]
    pub no_auth: bool,
    /// Optional daemon Unix control socket path override.
    #[arg(long = "control-socket")]
    pub control_socket: Option<PathBuf>,
    /// Optional `nfqws2.toml` path managed through the Config panel.
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    /// Optional Lua scripts directory passed when running scans or validating TOML.
    #[arg(long = "lua-dir")]
    pub lua_dir: Option<PathBuf>,
}

/// Validated runtime configuration for [`start_web_server`].
#[derive(Debug, Clone)]
pub struct WebConfig
{
    /// Resolved socket address to bind.
    pub bind: SocketAddr,
    /// Authentication policy guarding protected routes.
    pub auth: WebAuth,
    /// Optional control socket path override.
    pub control_socket: Option<PathBuf>,
    /// Optional `nfqws2.toml` path override.
    pub config: Option<PathBuf>,
    /// Optional Lua directory override.
    pub lua_dir: Option<PathBuf>,
}

/// Executes a parsed [`WebCli`] invocation until interrupted by `SIGINT`/`SIGTERM`.
pub fn run_web(cli: WebCli) -> Result<(), String>
{
    let bind: SocketAddr =
        cli.bind.parse().map_err(|err| format!("invalid --bind address '{}': {err}", cli.bind))?;
    let env_token = std::env::var("ZAPRET_WEB_TOKEN").ok().filter(|s| !s.trim().is_empty());
    let (auth, generated) = WebAuth::new(bind, cli.token.or(env_token), cli.no_auth)?;

    let cfg = WebConfig {
        bind,
        auth,
        control_socket: cli.control_socket,
        config: cli.config,
        lua_dir: cli.lua_dir,
    };

    install_signal_handlers().map_err(|err| format!("failed to install signal handlers: {err}"))?;
    let mut handle = start_web_server(cfg)?;
    eprintln!("zapret-rs web listening on http://{}", handle.addr());
    if let Some(tok) = generated
    {
        eprintln!("Pairing passcode: {tok}");
    }
    else if handle.addr().ip().is_loopback() && cli.no_auth
    {
        eprintln!("Authentication disabled on loopback (--no-auth).");
    }

    let quit = quit_flag();
    while !quit.load(Ordering::Acquire)
    {
        thread::sleep(Duration::from_millis(100));
    }
    handle.shutdown();
    Ok(())
}

/// Parses `args` with `clap`, launches [`run_web`], and returns the shell [`ExitCode`].
pub fn run_web_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match WebCli::try_parse_from(args)
    {
        Ok(cli) => match run_web(cli)
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) =>
            {
                eprintln!("zapret-rs web error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) =>
        {
            let is_info = matches!(err.kind(), ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion);
            let _ = err.print();
            if is_info { ExitCode::SUCCESS } else { ExitCode::from(2) }
        }
    }
}
