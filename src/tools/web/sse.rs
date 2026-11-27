//! Server-Sent Events (`text/event-stream`) streaming handler for live Web UI updates.

/// Stream writes and flushing for real-time SSE frames and keepalives.
use std::io::Write;
/// Accepted client TCP socket stream.
use std::net::TcpStream;
/// Shutdown signal observed by the SSE frame pump.
use std::sync::atomic::{AtomicBool, Ordering};
/// Broadcast channel receiver carrying formatted SSE events.
use std::sync::mpsc::{Receiver, RecvTimeoutError};
/// Keepalive idle ping interval preventing mobile/Tailscale proxy disconnects.
use std::time::Duration;

/// Bounded HTTP error helper when subscriber limits are reached.
use crate::tools::web::http::write_error;
/// Daemon IPC bridge producing initial status snapshots and SSE event streams.
use crate::tools::web::ipc_bridge::WebIpcBridge;

/// SSE keepalive comment cadence preventing idle mobile/Tailscale connection drops.
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// Streams HTTP `text/event-stream` status/counters/packet updates until client disconnect or stop.
pub(crate) fn stream_sse_loop(
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
                X-Frame-Options: DENY\r\n\
                Content-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n\
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
