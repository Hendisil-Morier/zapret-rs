//! Typed error variants for packet interception setup, polling, and packet dispatch.

/// I/O and driver error wrapper for [`crate::intercepter`] operations.
#[derive(Debug, thiserror::Error)]
pub enum IntercepterError
{
    /// Underlying OS packet-interception I/O failure (NFQUEUE on Linux, WinDivert on Windows).
    #[cfg_attr(target_os = "linux", error("Linux NFQUEUE operation failed: {0}"))]
    #[cfg_attr(windows, error("WinDivert packet interception failed: {0}"))]
    #[cfg_attr(not(any(target_os = "linux", windows)), error("Packet interception operation failed: {0}"))]
    Io(#[from] std::io::Error),
    /// Netlink socket closed or entered an error state during `poll`.
    #[error("NFQUEUE netlink socket closed or errored (revents=0x{0:x})")]
    PollError(i16),
}
