//! Error types returned by raw socket initialization, interface binding, and packet injection.

/// Typed error enum for raw socket setup and transmission failures.
#[derive(Debug, thiserror::Error)]
pub enum RawSendError
{
    /// Underlying OS socket, `setsockopt`, or `sendto` system call failed.
    #[error("Raw socket I/O failed: {0}")]
    SocketIo(#[from] std::io::Error),

    /// Outgoing interface name contained an interior NUL byte and could not be passed to `SO_BINDTODEVICE`.
    #[error("Invalid outgoing interface name: {0}")]
    InvalidInterfaceName(String),

    /// Destination address family was neither IPv4 nor IPv6.
    #[error("Unsupported destination address family")]
    UnsupportedAddressFamily,
}
