//! Typed errors produced during packet dissection, validation, checksum calculation, and reconstruction.

/// Errors returned by packet parsing, checksum verification, and packet reconstruction routines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PacketError {
    /// Input buffer ended before the expected header or payload length.
    #[error("Packet ended unexpectedly")]
    Truncated,

    /// IP version nibble was not recognized for the requested parser.
    #[error("Unsupported IP version: {0}")]
    UnsupportedVersion(u8),

    /// Transport protocol number was not supported by the targeted parser.
    #[error("Unsupported protocol number: {0}")]
    UnsupportedProtocol(u8),

    /// Header length field decoded to fewer bytes than the protocol minimum.
    #[error("Invalid header length: {0} bytes")]
    InvalidHeaderLen(usize),

    /// IPv4 or TCP options exceeded the 40-byte wire limit.
    #[error("Header options exceed maximum 40 bytes: {0} bytes")]
    OptionsTooLong(usize),

    /// An IPv6 extension header failed length, alignment, or boundary checks.
    #[error("Invalid IPv6 extension header")]
    InvalidExtHeader,

    /// Payload exceeded the 65535-byte or 65536-byte packet limit.
    #[error("Payload exceeds maximum allowed size: {0} bytes")]
    PayloadTooLarge(usize),

    /// IPv4 or IPv6 fragmentation metadata pointed outside the reconstructed buffer.
    #[error("Invalid fragment offset or length")]
    InvalidFragment,

    /// Packet reconstruction was invoked without either an IPv4 or IPv6 header.
    #[error("Missing IPv4 or IPv6 network header")]
    MissingNetworkHeader,

    /// Header buffer passed to checksum calculation failed validation.
    #[error("Invalid header passed for checksum calculation")]
    InvalidChecksumHeader,
}
