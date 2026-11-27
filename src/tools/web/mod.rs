//! Embedded HTTP/1.1 + SSE web dashboard bridge for mobile and desktop remote control.

/// Pairing-token verification, HMAC-SHA256 session cookies, and CSRF request guards.
pub mod auth;
/// CLI options and shutdown loop for `zapret-rs web`.
pub mod cli;
/// Bounded HTTP/1.1 request parser and JSON/asset response writers.
pub mod http;
/// Background `ControlStream` subscriber bridging daemon status and packets to SSE.
pub mod ipc_bridge;
/// HTTP/1.1 router, SSE streamer, and bounded TCP listener.
pub mod server;

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
