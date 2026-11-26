//! Linux NFQUEUE packet interception, interface resolution, and verdict dispatch modules.

/// Error variants for NFQUEUE setup and polling.
pub mod error;
/// Persistent `SIOCGIFNAME` socket helper for interface name resolution.
#[cfg(target_os = "linux")]
pub mod ifname;
/// Non-blocking `poll()` NFQUEUE listener and verdict dispatch helpers.
#[cfg(target_os = "linux")]
pub mod nfqueue;
/// Default constants, queue config, packet metadata, and verdict decision types.
pub mod types;

/// Re-exported NFQUEUE error enum.
pub use error::IntercepterError;
/// Re-exported `SIOCGIFNAME` interface resolver.
#[cfg(target_os = "linux")]
pub use ifname::IfNameResolver;
/// Re-exported queue catcher and pure packet dispatch helpers.
#[cfg(target_os = "linux")]
pub use nfqueue::{QueueCatcher, apply_decision, dispatch_packet, poll_timeout_ms};
/// Re-exported NFQUEUE configuration defaults, [`PacketIntercepter`] trait, and packet/verdict types.
pub use types::{
    DEFAULT_DESYNC_FWMARK, DEFAULT_QUEUE_MAXLEN, DEFAULT_QUEUE_NUM, DEFAULT_QUEUE_RCVBUF,
    Decision, PacketIntercepter, QueueConfig, QueuedPacket,
};
