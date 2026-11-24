//! Error types returned during LuaJIT initialization, hardening, binding registration, and script execution.

/// Typed packet dissection and reconstruction errors.
use crate::packet::error::PacketError;
/// Typed raw socket injection errors.
use crate::rawsend::error::RawSendError;

/// Unified error enum surfaced by the `zapret-rs` LuaJIT runtime.
#[derive(Debug, thiserror::Error)]
pub enum LuaEngineError {
    /// Embedded LuaJIT error raised during script loading or execution.
    #[error("Lua engine error: {0}")]
    Lua(#[from] mlua::Error),

    /// Filesystem I/O failure when loading Lua scripts or blob files.
    #[error("Lua script I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// Packet dissection, checksum, or reconstruction failure bridged to Lua.
    #[error("Packet operation failed: {0}")]
    Packet(#[from] PacketError),

    /// Raw socket transmission failure triggered from Lua `rawsend`.
    #[error("Raw send failed: {0}")]
    RawSend(#[from] RawSendError),

    /// Configured Lua desync function does not exist in `_G` as a callable function.
    #[error("desync function '{0}' does not exist")]
    MissingFunction(String),
}
