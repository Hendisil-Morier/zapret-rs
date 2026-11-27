//! CLI entrypoint, configuration resolution, and bounded HTTP listener for `zapret-rs web`.

/// OS string argument conversion passed from the multicall dispatcher.
use std::ffi::OsString;
/// Non-blocking accept errors and I/O helpers.
use std::io::ErrorKind;
/// HTTP TCP listener, bound endpoint address, and request sockets.
use std::net::{SocketAddr, TcpListener, TcpStream};
/// Config, Lua directory, and control socket overrides.
use std::path::PathBuf;
/// Exit codes returned to the shell from CLI execution.
use std::process::ExitCode;
/// Shared configuration and thread-safe worker accounting.
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
/// Accept thread join handle and request worker spawning.
use std::thread::{self, JoinHandle};
/// Socket read/write timeouts protecting against slowloris stalls.
use std::time::Duration;

/// CLI parser and informational exit handling (`--help`/`--version`).
use clap::{Parser, error::ErrorKind as ClapErrorKind};
/// Deserialize login payloads (`{ "token": "..." }`).
use serde::Deserialize;

/// Cooperative shutdown signal flag shared with `SIGINT`/`SIGTERM` handlers.
use crate::runtime::{install_signal_handlers, quit_flag};
/// Session auth validator, CSRF guard, and UNIX epoch helper.
use crate::tools::web::auth::{WebAuth, unix_now_secs};
/// Bounded HTTP request reader and JSON/error responders.
use crate::tools::web::http::{HttpMethod, HttpRequest, read_http_request, write_error, write_json};

/// Default loopback listen address preventing accidental unauthenticated WAN exposure.
pub const DEFAULT_WEB_BIND: &str = "127.0.0.1:8787";
/// Maximum concurrent short-lived HTTP request threads accepted simultaneously.
const MAX_HTTP_WORKERS: usize = 16;
/// Accept poll sleep duration when the non-blocking listener is idle.
const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(25);
/// Socket timeout bounding malformed/stalled client HTTP requests.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Command-line flags for `zapret-rs web`.
#[derive(Debug, Parser)]
#[command(name = "zapret-rs web", version = env!("CARGO_PKG_VERSION"), about = "Mobile & desktop web control dashboard for zapret-rs")]
pub struct WebCli {
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
pub struct WebConfig {
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

/// Running web dashboard HTTP server stopped automatically on [`Drop`].
pub struct WebServerHandle {
    /// Actual bound local socket address (useful when binding `:0` in tests).
    addr: SocketAddr,
    /// Shared shutdown signal observed by the accept loop.
    stop: Arc<AtomicBool>,
    /// Accept thread joined cleanly on [`Self::shutdown`] or [`Drop`].
    join: Option<JoinHandle<()>>,
}

impl WebServerHandle {
    /// Returns the actual bound listening [`SocketAddr`].
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Signals the accept loop to stop and joins its background thread.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for WebServerHandle {
    /// Ensures the listener thread exits cleanly when the handle is dropped.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// JSON body accepted by `POST /api/login`.
#[derive(Deserialize)]
struct LoginPayload {
    /// Pairing token / passcode entered by the user.
    token: String,
}

/// Decrements active HTTP worker count on scope exit even after early returns.
struct WorkerSlotGuard<'a>(&'a AtomicUsize);

impl Drop for WorkerSlotGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Dispatches one parsed HTTP request against auth, health, and API routes.
fn handle_request(stream: &mut TcpStream, req: &HttpRequest, cfg: &WebConfig) {
    let now = unix_now_secs();
    match (&req.method, req.path.as_str()) {
        (HttpMethod::Get, "/healthz") => {
            let _ = write_json(
                stream,
                200,
                "OK",
                &[],
                &serde_json::json!({ "ok": true, "auth_required": cfg.auth.is_required() }),
            );
        }
        (HttpMethod::Get, "/api/auth/check") => {
            let authed = cfg.auth.is_authorized(req, now);
            let _ = write_json(
                stream,
                if authed { 200 } else { 401 },
                if authed { "OK" } else { "Unauthorized" },
                &[],
                &serde_json::json!({ "authenticated": authed, "auth_required": cfg.auth.is_required() }),
            );
        }
        (HttpMethod::Post, "/api/login") => {
            if !WebAuth::passes_csrf_guard(req) {
                let _ = write_error(stream, 403, "Forbidden", "missing JSON or X-Zapret-Action header");
                return;
            }
            let Ok(payload) = serde_json::from_slice::<LoginPayload>(&req.body) else {
                let _ = write_error(stream, 400, "Bad Request", "expected JSON object with token");
                return;
            };
            if !cfg.auth.verify_token(&payload.token) {
                let _ = write_error(stream, 401, "Unauthorized", "invalid passcode");
                return;
            }
            if let Some(cookie) = cfg.auth.issue_session_cookie(now) {
                let header = WebAuth::format_set_cookie(&cookie, 12 * 3600);
                let _ = write_json(
                    stream,
                    200,
                    "OK",
                    &[("Set-Cookie", &header)],
                    &serde_json::json!({ "authenticated": true }),
                );
            } else {
                let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "authenticated": true }));
            }
        }
        (HttpMethod::Post, "/api/logout") => {
            if !WebAuth::passes_csrf_guard(req) {
                let _ = write_error(stream, 403, "Forbidden", "missing JSON or X-Zapret-Action header");
                return;
            }
            let cleared = WebAuth::format_set_cookie("", 0);
            let _ = write_json(
                stream,
                200,
                "OK",
                &[("Set-Cookie", &cleared)],
                &serde_json::json!({ "authenticated": false }),
            );
        }
        _ => {
            if !cfg.auth.is_authorized(req, now) {
                let _ = write_error(stream, 401, "Unauthorized", "authentication required");
                return;
            }
            if req.method == HttpMethod::Post && !WebAuth::passes_csrf_guard(req) {
                let _ = write_error(stream, 403, "Forbidden", "missing JSON or X-Zapret-Action header");
                return;
            }
            let _ = write_error(stream, 404, "Not Found", "endpoint not found");
        }
    }
}

/// Processes one accepted TCP socket connection within read/write timeouts.
fn serve_connection(mut stream: TcpStream, cfg: &WebConfig, active_workers: &AtomicUsize) {
    let _slot = WorkerSlotGuard(active_workers);
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
    let mut reader = match stream.try_clone() {
        Ok(cloned) => cloned,
        Err(_) => return,
    };
    match read_http_request(&mut reader) {
        Ok(Some(req)) => handle_request(&mut stream, &req, cfg),
        Ok(None) => {}
        Err(err) => {
            let (status, reason, msg) = err.http_status();
            let _ = write_error(&mut stream, status, reason, &msg);
        }
    }
}

/// Starts the embedded HTTP/1.1 dashboard listener in a background accept thread.
pub fn start_web_server(cfg: WebConfig) -> Result<WebServerHandle, String> {
    let listener = TcpListener::bind(cfg.bind)
        .map_err(|err| format!("failed to bind web server on {}: {err}", cfg.bind))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to configure non-blocking listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect local bind address: {err}"))?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_bg = Arc::clone(&stop);
    let active_workers = Arc::new(AtomicUsize::new(0));
    let cfg_arc = Arc::new(cfg);

    let join = thread::Builder::new()
        .name("zapret-web-http".to_owned())
        .spawn(move || {
            while !stop_bg.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let prev = active_workers.fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_HTTP_WORKERS {
                            active_workers.fetch_sub(1, Ordering::AcqRel);
                            let _ = write_error(&mut stream, 503, "Service Unavailable", "server busy");
                            continue;
                        }
                        let cfg_req = Arc::clone(&cfg_arc);
                        let workers_req = Arc::clone(&active_workers);
                        if thread::Builder::new()
                            .name("zapret-web-req".to_owned())
                            .spawn(move || serve_connection(stream, &cfg_req, &workers_req))
                            .is_err()
                        {
                            active_workers.fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(ACCEPT_IDLE_SLEEP);
                    }
                    Err(_) => thread::sleep(ACCEPT_IDLE_SLEEP),
                }
            }
        })
        .map_err(|err| format!("failed to spawn web server thread: {err}"))?;

    Ok(WebServerHandle { addr, stop, join: Some(join) })
}

/// Executes a parsed [`WebCli`] invocation until interrupted by `SIGINT`/`SIGTERM`.
pub fn run_web(cli: WebCli) -> Result<(), String> {
    let bind: SocketAddr = cli
        .bind
        .parse()
        .map_err(|err| format!("invalid --bind address '{}': {err}", cli.bind))?;
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
    if let Some(tok) = generated {
        eprintln!("Pairing passcode: {tok}");
    } else if handle.addr().ip().is_loopback() && cli.no_auth {
        eprintln!("Authentication disabled on loopback (--no-auth).");
    }

    let quit = quit_flag();
    while !quit.load(Ordering::Acquire) {
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
    match WebCli::try_parse_from(args) {
        Ok(cli) => match run_web(cli) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("zapret-rs web error: {err}");
                ExitCode::FAILURE
            }
        },
        Err(err) => {
            let is_info = matches!(err.kind(), ClapErrorKind::DisplayHelp | ClapErrorKind::DisplayVersion);
            let _ = err.print();
            if is_info { ExitCode::SUCCESS } else { ExitCode::from(2) }
        }
    }
}
