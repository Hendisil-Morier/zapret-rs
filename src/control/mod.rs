//! Control socket protocol types and bounded newline-delimited JSON framing codec.

/// Bounded newline-delimited JSON line reader, writer, and typed framing errors.
pub mod codec;
/// Request, response, status snapshot, and version handshake wire messages.
pub mod protocol;

/// Re-exported framing constants, typed codec error, and stream read/write helpers.
pub use codec::{
    CodecError, MAX_CONTROL_LINE_BYTES, decode_line, encode_line, read_bounded_line,
    read_message, write_message,
};
/// Re-exported control wire protocol constants, messages, and version validator.
pub use protocol::{
    CONTROL_PROTOCOL_VERSION, ControlErrorCode, CountersSnapshot, DEFAULT_PASS_SAMPLE_RATE,
    DaemonStatus, Request, Response, validate_protocol_version,
};
