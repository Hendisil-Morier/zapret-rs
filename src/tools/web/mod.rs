//! Embedded HTTP/1.1 + SSE web dashboard bridge for mobile and desktop remote control.

/// Pairing-token verification, HMAC-SHA256 session cookies, and CSRF request guards.
pub mod auth;
/// CLI options and shutdown loop for `zapret-rs web`.
pub mod cli;
/// Path confinement validator preventing Web UI config uploads from escaping config dir.
pub mod config_guard;
/// Bounded HTTP/1.1 request parser and JSON/asset response writers.
pub mod http;
/// Background `ControlStream` subscriber bridging daemon status and packets to SSE.
pub mod ipc_bridge;
/// REST handlers for `nfqws2.toml` config, autohostlist domains, and speed tests.
pub mod ops;
/// Background Strategy Finder scan job coordinator streaming progress over SSE.
pub mod scan_job;
/// HTTP/1.1 router, worker pool, and bounded TCP listener.
pub mod server;
/// Server-Sent Events (`text/event-stream`) live telemetry streamer.
pub mod sse;

/// Public API re-exports for web authentication and cookie validation.
pub use auth::{SESSION_COOKIE_NAME, WebAuth, unix_now_secs};
/// Public API re-exports for `zapret-rs web` CLI and server configuration.
pub use cli::{DEFAULT_WEB_BIND, WebCli, WebConfig, run_web_cli};
/// Public API re-exports for HTTP request/response types and bounded reader errors.
pub use http::{
    HttpMethod, HttpReadError, HttpRequest, MAX_BODY_BYTES, MAX_HEADER_BYTES, read_http_request,
    write_error, write_json, write_response,
};
/// Public API re-exports for daemon IPC bridge state and status DTOs.
pub use ipc_bridge::{MAX_SSE_CLIENTS, WebIpcBridge, WebStatusSnapshot};
/// Public API re-exports for HTTP/SSE server lifecycle handle.
pub use server::{WebServerHandle, start_web_server};
