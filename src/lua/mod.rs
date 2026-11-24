//! LuaJIT runtime, security hardening, and `zapret2`-compatible C-API bindings.

/// Bitwise logic, shift, and field-slice primitives.
pub mod bitwise;
/// Endian integer packing, byte mutation, random-blob, and hex primitives.
pub mod bytes;
/// Global constant registration and security hardening.
pub mod constants;
/// Desync execution context userdata and `zapret2` C-API callbacks.
pub mod desync_api;
/// Serializers building `zapret2`-compatible Lua `desync`, `arg`, `range`, and `payload` tables.
pub mod desync_encode;
/// Lua runtime error definitions.
pub mod error;
/// Argument validation and strict/coercing value extractors.
pub mod helpers;
/// Lua `dissect`, `reconstruct_dissect`, checksum fixup, and `ntop`/`pton` bindings.
pub mod packet_api;
/// Decoding Lua tables into Rust `PacketDissect` structures and reconstruct options.
pub mod packet_decode;
/// Encoding Rust `PacketDissect` structures and wire IP addresses into Lua tables.
pub mod packet_encode;
/// Lua `rawsend` and `rawsend_dissect` kernel packet-injection bindings.
pub mod rawsend_api;
/// Top-level [`LuaRuntime`] lifecycle and script execution.
pub mod runtime;
/// Logging, OS metadata, clock, and network topology Lua bindings.
pub mod system;

/// Re-exported Lua runtime configuration.
pub use constants::LuaConfig;
/// Re-exported Lua error type.
pub use error::LuaEngineError;
/// Re-exported LuaJIT runtime orchestrator.
pub use runtime::LuaRuntime;
