//! Embedded HTTP/1.1 + SSE web dashboard bridge for mobile and desktop remote control.

/// Pairing-token verification, HMAC-SHA256 session cookies, and CSRF request guards.
pub mod auth;
/// CLI options, router dispatch, and bounded listener loop for `zapret-rs web`.
pub mod cli;
/// Bounded HTTP/1.1 request parser and JSON/asset response writers.
pub mod http;

/// Public API re-exports for web authentication and cookie validation.
pub use auth::{SESSION_COOKIE_NAME, WebAuth, unix_now_secs};
/// Public API re-exports for `zapret-rs web` configuration, server handle, and CLI runner.
pub use cli::{DEFAULT_WEB_BIND, WebCli, WebConfig, WebServerHandle, run_web_cli, start_web_server};
/// Public API re-exports for HTTP request/response types and bounded reader errors.
pub use http::{
    HttpMethod, HttpReadError, HttpRequest, MAX_BODY_BYTES, MAX_HEADER_BYTES, read_http_request,
    write_error, write_json, write_response,
};
