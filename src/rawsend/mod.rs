//! Raw socket packet injection and kernel network topology inspection modules.

/// Raw socket error definitions.
pub mod error;
/// Kernel source-IP lookup and network interface enumeration.
#[cfg(target_os = "linux")]
pub mod netinfo;
/// Linux `SOCK_RAW` sender implementation.
#[cfg(target_os = "linux")]
pub mod sender;
/// OS-agnostic [`PacketSender`] trait.
pub mod types;
/// Windows WinDivert `SEND_ONLY` raw packet injector.
#[cfg(windows)]
pub mod windivert;

/// Re-exported raw socket error type.
pub use error::RawSendError;
/// Re-exported network topology types and functions.
#[cfg(target_os = "linux")]
pub use netinfo::{InterfaceAddr, InterfaceInfo, get_ifaddrs, get_source_ip};
/// Re-exported Linux raw socket implementation.
#[cfg(target_os = "linux")]
pub use sender::RawSender;
/// Re-exported OS-agnostic packet sender trait.
pub use types::PacketSender;
/// Re-exported Windows WinDivert raw packet injector.
#[cfg(windows)]
pub use windivert::WinDivertSender;
