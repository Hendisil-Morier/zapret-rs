//! Unified top-level library error type bridging core `zapret-rs` subsystem error enums.

/// Unified `thiserror` derive macro implemented across `zapret-rs` domain error enums.
use thiserror::Error;

/// Configuration loading, CLI validation, and TOML parsing error enum.
use crate::config::ConfigError;
/// Control IPC line framing error enum.
use crate::control::CodecError;
/// Control socket directory, binding, and transport error enum.
use crate::control::ControlServerError;
/// Pure-Rust cryptographic primitive error enum.
use crate::crypto::CryptoError;
/// Kernel packet interception error enum (`QueueCatcher` / `WinDivertIntercepter`).
use crate::intercepter::IntercepterError;
/// Embedded LuaJIT initialization, execution, and script verification error enum.
use crate::lua::LuaEngineError;
/// Wire packet dissection and reconstruction error enum.
use crate::packet::PacketError;
/// Raw packet socket and `WinDivertSender` error enum.
use crate::rawsend::RawSendError;
/// Privilege drop, capability retention, PID file, and directory ownership error enum.
use crate::runtime::ProcessError;

/// Crate-wide error type converting transparently from every core subsystem error enum via `?`.
#[derive(Debug, Error)]
pub enum ZapretError {
    /// Configuration file, CLI option, or profile validation error.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// Control IPC socket setup, binding, or listener failure.
    #[error("{0}")]
    Control(#[from] ControlServerError),
    /// Control IPC JSON/line codec failure.
    #[error("{0}")]
    Codec(#[from] CodecError),
    /// Cryptographic algorithm, key length, or IV error.
    #[error("{0}")]
    Crypto(#[from] CryptoError),
    /// Kernel packet queue interception error.
    #[error("{0}")]
    Intercepter(#[from] IntercepterError),
    /// LuaJIT script load or runtime callback error.
    #[error("{0}")]
    Lua(#[from] LuaEngineError),
    /// Packet wire dissection or reconstruction error.
    #[error("{0}")]
    Packet(#[from] PacketError),
    /// Process lifecycle, capability, PID, or writable directory error.
    #[error("{0}")]
    Process(#[from] ProcessError),
    /// Raw L3 injection error.
    #[error("{0}")]
    RawSend(#[from] RawSendError),
    /// Generic operating-system I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
