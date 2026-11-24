//! Typed error variants for Linux NFQUEUE setup, polling, and packet dispatch.

/// I/O and netlink error wrapper for [`crate::intercepter`] operations.
#[derive(Debug, thiserror::Error)]
pub enum IntercepterError {
    /// Underlying Linux socket, netlink, or `poll` I/O failure.
    #[error("Linux NFQUEUE operation failed: {0}")]
    Io(#[from] std::io::Error),
    /// Netlink socket closed or entered an error state during `poll`.
    #[error("NFQUEUE netlink socket closed or errored (revents=0x{0:x})")]
    PollError(i16),
}
