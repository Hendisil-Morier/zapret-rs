//! Control socket protocol types, bounded JSON codec, telemetry hub, and local Unix IPC server.

/// Per-client control socket reader, writer, handshake gate, and command dispatcher.
pub mod client_session;
/// Bounded newline-delimited JSON line reader, writer, and typed framing errors.
pub mod codec;
/// Lock-free telemetry hub and non-blocking command bridge for subscribed IPC clients.
pub mod hub;
/// `SO_PEERCRED` peer identity extraction and UID authorization predicates.
pub mod peer;
/// Request, response, status snapshot, and version handshake wire messages.
pub mod protocol;
/// Multi-client Unix domain control socket server with safe binding and slow-client isolation.
pub mod server;
/// Symlink-safe, umask-0177 socket binder, stale-socket prober, and poll helpers.
pub mod socket;

/// Re-exported framing constants, typed codec error, and stream read/write helpers.
pub use codec::{
    CodecError, MAX_CONTROL_LINE_BYTES, decode_line, encode_line, read_bounded_line,
    read_message, write_message,
};
/// Re-exported daemon status metadata, command requests, and telemetry hub.
pub use hub::{ControlCommand, DaemonStatusMeta, TelemetryHub};
/// Re-exported peer credential helpers and default same-UID authorization check.
pub use peer::{PeerCredentials, PeerUidCheck, current_euid, peer_credentials, same_uid};
/// Re-exported control wire protocol constants, messages, and version validator.
pub use protocol::{
    CONTROL_PROTOCOL_VERSION, ControlErrorCode, CountersSnapshot, DEFAULT_PASS_SAMPLE_RATE,
    DaemonStatus, Request, Response, validate_protocol_version,
};
/// Re-exported Unix control socket server and configuration.
pub use server::{ControlServer, ControlServerConfig};
/// Re-exported socket binding error types.
pub use socket::ControlServerError;
