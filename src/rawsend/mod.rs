//! Raw socket packet injection and kernel network topology inspection modules.

/// Raw socket error definitions.
pub mod error;
/// Kernel source-IP lookup and network interface enumeration.
pub mod netinfo;
/// Linux `SOCK_RAW` sender implementation and abstract [`PacketSender`] trait.
pub mod sender;

/// Re-exported raw socket error type.
pub use error::RawSendError;
/// Re-exported network topology types and functions.
pub use netinfo::{InterfaceAddr, InterfaceInfo, get_ifaddrs, get_source_ip};
/// Re-exported packet sender trait and Linux raw socket implementation.
pub use sender::{PacketSender, RawSender};
