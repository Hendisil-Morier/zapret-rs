//! HTTP/1.1 router, SSE streamer, and bounded TCP listener for `zapret-rs web`.

/// Connection error matching and flushing SSE event frames cleanly.
use std::io::{ErrorKind, Write};
/// Bound HTTP TCP listener and accepted sockets.
use std::net::{SocketAddr, TcpListener, TcpStream};
/// Cooperative shutdown flag shared between accept loop and SSE readers.
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
/// Receiver delivering broadcast SSE events from [`WebIpcBridge`].
use std::sync::mpsc::{Receiver, RecvTimeoutError};
/// Shared bridge, server config, and worker counter handles.
use std::sync::Arc;
/// Listener accept thread handle joined cleanly on drop.
use std::thread::{self, JoinHandle};
/// Socket read/write timeouts and SSE keepalive intervals.
use std::time::Duration;

/// JSON body parsing for login requests.
use serde::Deserialize;

/// Wire control commands forwarded to the daemon socket on API actions.
use crate::control::Request;
/// Session authentication validator, CSRF guard, and UNIX epoch helper.
use crate::tools::web::auth::{WebAuth, unix_now_secs};
/// Resolved web runtime configuration passed from [`crate::tools::web::cli`].
use crate::tools::web::cli::WebConfig;
/// Bounded HTTP request parser and JSON/error/asset responders.
use crate::tools::web::http::{
    HttpMethod, HttpRequest, read_http_request, write_error, write_json, write_response,
};
/// Background daemon control IPC bridge and SSE fanout hub.
use crate::tools::web::ipc_bridge::WebIpcBridge;

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
/// SSE keepalive comment cadence preventing idle mobile/Tailscale connection drops.
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Running web dashboard HTTP server and IPC bridge stopped automatically on [`Drop`].
pub struct WebServerHandle {
    /// Actual bound local socket address (useful when binding `:0` in tests).
    addr: SocketAddr,
    /// Background daemon control socket bridge shared with routes and SSE streams.
    ipc: Arc<WebIpcBridge>,
    /// Shared shutdown signal observed by accept and SSE loops.
    stop: Arc<AtomicBool>,
    /// Accept thread joined cleanly on [`Self::shutdown`] or [`Drop`].
    join: Option<JoinHandle<()>>,
}

impl WebServerHandle {
    /// Returns the actual bound listening [`SocketAddr`].
    pub const fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Signals the accept loop and IPC bridge to stop and joins background threads.
    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
        if let Some(ipc) = Arc::get_mut(&mut self.ipc) {
            ipc.shutdown();
        }
    }
}

impl Drop for WebServerHandle {
    /// Ensures accept and IPC threads exit cleanly when the handle drops.
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

/// Decrements active HTTP worker count on scope exit even across early returns.
struct WorkerSlotGuard<'a>(Option<&'a AtomicUsize>);

impl Drop for WorkerSlotGuard<'_> {
    fn drop(&mut self) {
        if let Some(counter) = self.0 {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

/// Streams HTTP `text/event-stream` status/counters/packet updates until client disconnect or stop.
fn stream_sse_loop(
    stream: &mut TcpStream,
    ipc: &WebIpcBridge,
    stop: &AtomicBool,
) {
    let Some((initial, rx)) = ipc.subscribe_sse() else {
        let _ = write_error(stream, 503, "Service Unavailable", "too many live telemetry tabs open");
        return;
    };
    let head = "HTTP/1.1 200 OK\r\n\
                Content-Type: text/event-stream; charset=utf-8\r\n\
                Cache-Control: no-cache\r\n\
                X-Content-Type-Options: nosniff\r\n\
                Connection: keep-alive\r\n\r\n";
    if stream.write_all(head.as_bytes()).is_err() {
        return;
    }
    if let Ok(json) = serde_json::to_string(&initial) {
        let first = format!("event: status\ndata: {json}\n\n");
        if stream.write_all(first.as_bytes()).is_err() {
            return;
        }
    }
    let _ = stream.flush();
    drain_sse_frames(stream, rx, stop);
}

/// Reads SSE frames from `rx`, emitting keepalives on idle timeouts until EOF or `stop`.
fn drain_sse_frames(stream: &mut TcpStream, rx: Receiver<String>, stop: &AtomicBool) {
    while !stop.load(Ordering::Acquire) {
        match rx.recv_timeout(SSE_KEEPALIVE_INTERVAL) {
            Ok(frame) => {
                if frame.is_empty() {
                    continue;
                }
                if stream.write_all(frame.as_bytes()).is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                if stream.write_all(b": keepalive\n\n").is_err() || stream.flush().is_err() {
                    break;
                }
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Handles `POST /api/login` credential verification and `Set-Cookie` minting.
fn handle_login(stream: &mut TcpStream, req: &HttpRequest, cfg: &WebConfig, now: u64) {
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

/// Dispatches authenticated daemon actions (`reload-lists`, `stop`).
fn handle_daemon_action(stream: &mut TcpStream, req: &HttpRequest, ipc: &WebIpcBridge) {
    let cmd = match req.path.as_str() {
        "/api/daemon/reload-lists" => Request::ReloadLists,
        "/api/daemon/stop" => Request::Stop,
        _ => {
            let _ = write_error(stream, 404, "Not Found", "endpoint not found");
            return;
        }
    };
    match ipc.send_command(&cmd) {
        Ok(detail) => {
            let _ = write_json(stream, 200, "OK", &[], &serde_json::json!({ "ok": true, "message": detail }));
        }
        Err(err) => {
            let status = if err.contains("not connected") { (503, "Service Unavailable") } else { (502, "Bad Gateway") };
            let _ = write_error(stream, status.0, status.1, &err);
        }
    }
}

/// Dispatches one parsed HTTP request against auth, SSE, and API endpoints.
fn handle_request(
    stream: &mut TcpStream,
    req: &HttpRequest,
    cfg: &WebConfig,
    ipc: &WebIpcBridge,
    stop: &AtomicBool,
    slot: &mut WorkerSlotGuard<'_>,
) {
    let now = unix_now_secs();
    match (&req.method, req.path.as_str()) {
        (HttpMethod::Get, "/" | "/index.html") => {
            let _ = write_response(stream, 200, "OK", "text/html; charset=utf-8", &[], INDEX_HTML.as_bytes());
        }
        (HttpMethod::Get, "/app.css") => {
            let _ = write_response(stream, 200, "OK", "text/css; charset=utf-8", &[], APP_CSS.as_bytes());
        }
        (HttpMethod::Get, "/app.js") => {
            let _ = write_response(
                stream,
                200,
                "OK",
                "application/javascript; charset=utf-8",
                &[],
                APP_JS.as_bytes(),
            );
        }
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
        (HttpMethod::Post, "/api/login") => handle_login(stream, req, cfg, now),
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
            match (&req.method, req.path.as_str()) {
                (HttpMethod::Get, "/api/status") => {
                    let snap = ipc.snapshot();
                    let _ = write_json(stream, 200, "OK", &[], &snap);
                }
                (HttpMethod::Get, "/api/events") => {
                    // Release short-request worker slot before entering long-lived SSE loop.
                    if let Some(c) = slot.0.take() {
                        c.fetch_sub(1, Ordering::AcqRel);
                    }
                    stream_sse_loop(stream, ipc, stop);
                }
                (HttpMethod::Post, p) if p.starts_with("/api/daemon/") => {
                    handle_daemon_action(stream, req, ipc);
                }
                _ => {
                    let _ = write_error(stream, 404, "Not Found", "endpoint not found");
                }
            }
        }
    }
}

/// Processes one accepted TCP socket connection within read/write timeouts.
fn serve_connection(
    mut stream: TcpStream,
    cfg: &WebConfig,
    ipc: &WebIpcBridge,
    stop: &AtomicBool,
    active_workers: &AtomicUsize,
) {
    let mut slot = WorkerSlotGuard(Some(active_workers));
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT));
    let mut reader = match stream.try_clone() {
        Ok(cloned) => cloned,
        Err(_) => return,
    };
    match read_http_request(&mut reader) {
        Ok(Some(req)) => handle_request(&mut stream, &req, cfg, ipc, stop, &mut slot),
        Ok(None) => {}
        Err(err) => {
            let (status, reason, msg) = err.http_status();
            let _ = write_error(&mut stream, status, reason, &msg);
        }
    }
}

/// Starts the embedded HTTP/1.1 dashboard listener and daemon IPC bridge.
pub fn start_web_server(cfg: WebConfig) -> Result<WebServerHandle, String> {
    let listener = TcpListener::bind(cfg.bind)
        .map_err(|err| format!("failed to bind web server on {}: {err}", cfg.bind))?;
    listener
        .set_nonblocking(true)
        .map_err(|err| format!("failed to configure non-blocking listener: {err}"))?;
    let addr = listener
        .local_addr()
        .map_err(|err| format!("failed to inspect local bind address: {err}"))?;

    let ipc = Arc::new(WebIpcBridge::spawn(cfg.control_socket.clone()));
    let ipc_accept = Arc::clone(&ipc);
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
                        let ipc_req = Arc::clone(&ipc_accept);
                        let stop_req = Arc::clone(&stop_bg);
                        let workers_req = Arc::clone(&active_workers);
                        if thread::Builder::new()
                            .name("zapret-web-req".to_owned())
                            .spawn(move || serve_connection(stream, &cfg_req, &ipc_req, &stop_req, &workers_req))
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

    Ok(WebServerHandle { addr, ipc, stop, join: Some(join) })
}
