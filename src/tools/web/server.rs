//! HTTP/1.1 router, SSE streamer, and bounded TCP listener for `zapret-rs web`.

/// Connection error matching for non-blocking accept loops.
use std::io::ErrorKind;
/// Bound HTTP TCP listener and accepted sockets.
use std::net::{SocketAddr, TcpListener, TcpStream};
/// Shared bridge, server config, and worker counter handles.
use std::sync::Arc;
/// Cooperative shutdown flag shared between accept loop and SSE readers.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
/// Listener accept thread handle joined cleanly on drop.
use std::thread::{self, JoinHandle};
/// Socket read/write timeouts and idle accept sleep duration.
use std::time::Duration;

/// JSON body parsing for login requests.
use serde::Deserialize;

/// Wire control commands forwarded to the daemon socket on API actions.
use crate::control::Request;
/// Session authentication validator, Host/Origin DNS-rebinding guard, and login rate limiter.
use crate::tools::web::auth::{LoginRateLimiter, WebAuth, unix_now_secs};
/// Resolved web runtime configuration passed from [`crate::tools::web::cli`].
use crate::tools::web::cli::WebConfig;
/// Bounded HTTP request parser and JSON/error/asset responders.
use crate::tools::web::http::{
    HttpMethod, HttpRequest, read_http_request, write_error, write_json, write_response,
};
/// Background daemon control IPC bridge and SSE fanout hub.
use crate::tools::web::ipc_bridge::WebIpcBridge;
/// Config, domain list, speed check, and scan API route handlers.
use crate::tools::web::ops::handle_ops_route;
/// Background Strategy Finder scan job coordinator.
use crate::tools::web::scan_job::WebScanJob;
/// Real-time Server-Sent Events stream handler.
use crate::tools::web::sse::stream_sse_loop;

/// Embedded mobile-first single-page dashboard HTML served at `/`.
const INDEX_HTML: &str = include_str!("assets/index.html");
/// Embedded daylight-first and dark-mode hardware faceplate stylesheet served at `/app.css`.
const APP_CSS: &str = include_str!("assets/app.css");
/// Embedded SSE + fetch client script served at `/app.js`.
const APP_JS: &str = include_str!("assets/app.js");

/// Maximum concurrent short-lived HTTP request threads accepted simultaneously.
const MAX_HTTP_WORKERS: usize = 16;
/// Accept poll pause when the non-blocking listener has no queued TCP connections.
const ACCEPT_IDLE_SLEEP: Duration = Duration::from_millis(25);
/// Socket timeout bounding malformed/stalled client HTTP requests.
const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// Running web dashboard HTTP server and IPC bridge stopped automatically on [`Drop`].
pub struct WebServerHandle
{
    /// Actual bound local socket address (useful when binding `:0` in tests).
    addr: SocketAddr,
    /// Background daemon control socket bridge shared with routes and SSE streams.
    ipc: Arc<WebIpcBridge>,
    /// Background Strategy Finder scan coordinator stopped on shutdown.
    scan_job: Arc<WebScanJob>,
    /// Shared shutdown signal observed by accept and SSE loops.
    stop: Arc<AtomicBool>,
    /// Accept thread joined cleanly on [`Self::shutdown`] or [`Drop`].
    join: Option<JoinHandle<()>>,
}

impl WebServerHandle
{
    /// Returns the actual bound listening [`SocketAddr`].
    pub const fn addr(&self) -> SocketAddr
    {
        self.addr
    }

    /// Signals the accept loop and IPC bridge to stop and joins background threads.
    pub fn shutdown(&mut self)
    {
        self.stop
            .store(true, Ordering::Release);
        self.scan_job
            .stop();
        self.ipc
            .shutdown();
        if let Some(handle) = self
            .join
            .take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for WebServerHandle
{
    /// Ensures accept and IPC threads exit cleanly when the handle drops.
    fn drop(&mut self)
    {
        self.shutdown();
    }
}

/// JSON body accepted by `POST /api/login`.
#[derive(Deserialize)]
struct LoginPayload
{
    /// Pairing token / passcode entered by the user.
    token: String,
}

/// Shared runtime dependencies passed to HTTP connection worker threads.
struct WebServerState
{
    /// Static web configuration (`--bind`, `--config`, `--lua-dir`, `WebAuth`).
    cfg: WebConfig,
    /// Background daemon control socket bridge.
    ipc: Arc<WebIpcBridge>,
    /// Background Strategy Finder scan coordinator.
    scan_job: Arc<WebScanJob>,
    /// Sliding-window failed `/api/login` rate limiter.
    limiter: LoginRateLimiter,
    /// Shared shutdown signal observed by accept and SSE loops.
    stop: Arc<AtomicBool>,
    /// Active short-request worker thread count.
    active_workers: AtomicUsize,
}

/// Decrements active HTTP worker count on scope exit even across early returns.
struct WorkerSlotGuard<'a>(Option<&'a AtomicUsize>);

impl Drop for WorkerSlotGuard<'_>
{
    fn drop(&mut self)
    {
        if let Some(counter) = self.0
        {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Handles `POST /api/login` credential verification, rate limiting, and `Set-Cookie` minting.
fn handle_login(
    stream: &mut TcpStream,
    req: &HttpRequest,
    cfg: &WebConfig,
    limiter: &LoginRateLimiter,
    now: u64,
)
{
    if !WebAuth::passes_csrf_guard(req)
    {
        let _ = write_error(stream, 403, "Forbidden", "missing JSON or X-Zapret-Action header");
        return;
    }
    if limiter
        .check_allowed(now)
        .is_err()
    {
        let _ = write_error(stream, 429, "Too Many Requests", "too many failed attempts; retry later");
        return;
    }
    let Ok(payload) = serde_json::from_slice::<LoginPayload>(&req.body)
    else
    {
        let _ = write_error(stream, 400, "Bad Request", "expected JSON object with token");
        return;
    };
    if !cfg
        .auth
        .verify_token(&payload.token)
    {
        limiter.record_failure(now);
        let _ = write_error(stream, 401, "Unauthorized", "invalid passcode");
        return;
    }
    limiter.record_success();
    if let Some(cookie) = cfg
        .auth
        .issue_session_cookie(now)
    {
        let header = WebAuth::format_set_cookie(&cookie, 12 * 3600);
        let _ = write_json(
            stream,
            200,
            "OK",
            &[("Set-Cookie", &header)],
            &serde_json::json!({ "authenticated": true }),
        );
    }
    else
    {
        let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "authenticated": true }));
    }
}

/// Dispatches authenticated daemon actions (`reload-lists`, `stop`).
fn handle_daemon_action(stream: &mut TcpStream, req: &HttpRequest, ipc: &WebIpcBridge)
{
    let cmd = match req
        .path
        .as_str()
    {
        "/api/daemon/reload-lists" => Request::ReloadLists,
        "/api/daemon/stop" => Request::Stop,
        _ =>
        {
            let _ = write_error(stream, 404, "Not Found", "endpoint not found");
            return;
        }
    };
    match ipc.send_command(&cmd)
    {
        Ok(detail) =>
        {
            let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "ok": true, "message": detail }));
        }
        Err(err) =>
        {
            let status = if err.contains("not connected")
            {
                (503, "Service Unavailable")
            }
            else
            {
                (502, "Bad Gateway")
            };
            let _ = write_error(stream, status.0, status.1, &err);
        }
    }
}

/// Enforces authentication and CSRF checks and dispatches protected HTTP routes.
fn handle_protected_route(
    stream: &mut TcpStream,
    req: &HttpRequest,
    st: &WebServerState,
    slot: &mut WorkerSlotGuard<'_>,
    now: u64,
)
{
    if !st
        .cfg
        .auth
        .is_authorized(req, now)
    {
        let _ = write_error(stream, 401, "Unauthorized", "authentication required");
        return;
    }
    if req.method == HttpMethod::Post && !WebAuth::passes_csrf_guard(req)
    {
        let _ = write_error(stream, 403, "Forbidden", "missing JSON or X-Zapret-Action header");
        return;
    }
    match (
        &req.method,
        req.path
            .as_str(),
    )
    {
        (HttpMethod::Get, "/api/status") =>
        {
            let snap = st
                .ipc
                .snapshot();
            let _ = write_json(stream, 200, "OK", &[], &snap);
        }
        (HttpMethod::Get, "/api/events") =>
        {
            // Release short-request worker slot before entering long-lived SSE loop.
            if let Some(c) = slot
                .0
                .take()
            {
                c.fetch_sub(1, Ordering::AcqRel);
            }
            stream_sse_loop(stream, &st.ipc, &st.stop);
        }
        (HttpMethod::Post, p) if p.starts_with("/api/daemon/") =>
        {
            handle_daemon_action(stream, req, &st.ipc);
        }
        _ =>
        {
            if !handle_ops_route(stream, req, &st.cfg, &st.ipc, &st.scan_job)
            {
                let _ = write_error(stream, 404, "Not Found", "endpoint not found");
            }
        }
    }
}

/// Dispatches one parsed HTTP request against auth, SSE, and API endpoints.
fn handle_request(
    stream: &mut TcpStream,
    req: &HttpRequest,
    st: &WebServerState,
    slot: &mut WorkerSlotGuard<'_>,
)
{
    if !WebAuth::passes_host_and_origin_guard(
        req,
        st.cfg
            .bind,
    )
    {
        let _ = write_error(stream, 403, "Forbidden", "invalid Host or cross-origin request");
        return;
    }
    let now = unix_now_secs();
    match (
        &req.method,
        req.path
            .as_str(),
    )
    {
        (HttpMethod::Get, "/" | "/index.html") =>
        {
            let _ = write_response(stream, 200, "OK", "text/html; charset=utf-8", &[], INDEX_HTML.as_bytes());
        }
        (HttpMethod::Get, "/app.css") =>
        {
            let _ = write_response(stream, 200, "OK", "text/css; charset=utf-8", &[], APP_CSS.as_bytes());
        }
        (HttpMethod::Get, "/app.js") =>
        {
            let _ = write_response(
                stream,
                200,
                "OK",
                "application/javascript; charset=utf-8",
                &[],
                APP_JS.as_bytes(),
            );
        }
        (HttpMethod::Get, "/healthz") =>
        {
            let _ = write_json(
                stream,
                200,
                "OK",
                &[],
                &serde_json::json!({ "ok": true, "auth_required": st.cfg.auth.is_required() }),
            );
        }
        (HttpMethod::Get, "/api/auth/check") =>
        {
            let authed = st
                .cfg
                .auth
                .is_authorized(req, now);
            let _ = write_json(
                stream,
                if authed { 200 } else { 401 },
                if authed { "OK" } else { "Unauthorized" },
                &[],
                &serde_json::json!({ "authenticated": authed, "auth_required": st.cfg.auth.is_required() }),
            );
        }
        (HttpMethod::Post, "/api/login") => handle_login(stream, req, &st.cfg, &st.limiter, now),
        (HttpMethod::Post, "/api/logout") =>
        {
            if !WebAuth::passes_csrf_guard(req)
            {
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
        _ => handle_protected_route(stream, req, st, slot, now),
    }
}

/// Processes one accepted TCP socket connection within read/write timeouts.
fn serve_connection(mut stream: TcpStream, st: &WebServerState)
{
    let mut slot = WorkerSlotGuard(Some(&st.active_workers));
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
    let Ok(mut reader) = stream.try_clone()
    else
    {
        return;
    };
    match read_http_request(&mut reader)
    {
        Ok(Some(req)) => handle_request(&mut stream, &req, st, &mut slot),
        Ok(None) =>
        {}
        Err(err) =>
        {
            let (status, reason, msg) = err.http_status();
            let _ = write_error(&mut stream, status, reason, &msg);
        }
    }
}

/// Starts the embedded HTTP/1.1 dashboard listener and daemon IPC bridge.
pub fn start_web_server(cfg: WebConfig) -> Result<WebServerHandle, String>
{
    let listener = TcpListener::bind(cfg.bind)
        .map_err(|err| format!("failed to bind web server on {}: {err}", cfg.bind))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to configure non-blocking listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect local bind address: {err}"))?;

    let ipc = Arc::new(WebIpcBridge::spawn(
        cfg.control_socket
            .clone(),
    ));
    let scan_job = Arc::new(WebScanJob::default());
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(WebServerState {
        cfg,
        ipc: Arc::clone(&ipc),
        scan_job: Arc::clone(&scan_job),
        limiter: LoginRateLimiter::default(),
        stop: Arc::clone(&stop),
        active_workers: AtomicUsize::new(0),
    });
    let shared_bg = Arc::clone(&shared);

    let join = thread::Builder::new()
        .name("zapret-web-http".to_owned())
        .spawn(move || {
            while !shared_bg
                .stop
                .load(Ordering::Acquire)
            {
                match listener.accept()
                {
                    Ok((mut stream, _)) =>
                    {
                        let prev = shared_bg
                            .active_workers
                            .fetch_add(1, Ordering::AcqRel);
                        if prev >= MAX_HTTP_WORKERS
                        {
                            shared_bg
                                .active_workers
                                .fetch_sub(1, Ordering::AcqRel);
                            let _ = write_error(&mut stream, 503, "Service Unavailable", "server busy");
                            continue;
                        }
                        let st_req = Arc::clone(&shared_bg);
                        if thread::Builder::new()
                            .name("zapret-web-req".to_owned())
                            .spawn(move || serve_connection(stream, &st_req))
                            .is_err()
                        {
                            shared_bg
                                .active_workers
                                .fetch_sub(1, Ordering::AcqRel);
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::WouldBlock =>
                    {
                        thread::sleep(ACCEPT_IDLE_SLEEP);
                    }
                    Err(_) => thread::sleep(ACCEPT_IDLE_SLEEP),
                }
            }
        })
        .map_err(|err| format!("failed to spawn web server thread: {err}"))?;

    Ok(WebServerHandle { addr, ipc, scan_job, stop, join: Some(join) })
}
