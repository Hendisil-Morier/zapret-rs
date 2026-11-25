//! LuaJIT runtime, security hardening, and `zapret2`-compatible Rust host bindings.

/// Bitwise logic, shift, and field-slice primitives.
pub mod bitwise;
/// Endian integer packing, byte mutation, random-blob, and hex primitives.
pub mod bytes;
/// Global constant registration and security hardening.
pub mod constants;
/// Cryptographic primitives exposed to Lua (`hash`, `aes`, `aes_gcm`, `aes_ctr`, `hkdf`).
pub mod crypto_api;
/// Serializers building `zapret2`-compatible Lua `desync.track` and position tables.
pub mod ctrack_encode;
/// Desync execution context userdata and `zapret2` Rust host execution callbacks.
pub mod desync_api;
/// Serializers building `zapret2`-compatible Lua `desync`, `arg`, `range`, and `payload` tables.
pub mod desync_encode;
/// Lua runtime error definitions.
pub mod error;
/// POSIX `stat` and broken-down calendar time (`localtime`, `gmtime`, `timelocal`, `timegm`) Lua bindings.
pub mod fs_time_api;
/// Streaming zlib/gzip/raw-deflate compression and decompression bindings (`gunzip_*`, `gzip_*`).
pub mod gzip_api;
/// Pure-Rust streaming RFC 1951/1950/1952 compression engine over `flate2`.
pub mod gzip_deflate;
/// Pure-Rust streaming RFC 1951/1950/1952 decompression engine over `flate2`.
pub mod gzip_inflate;
/// Argument validation and strict/coercing value extractors.
pub mod helpers;
/// Lua `dissect`, `reconstruct_dissect`, checksum fixup, and `ntop`/`pton` bindings.
pub mod packet_api;
/// Decoding Lua tables into Rust `PacketDissect` structures and reconstruct options.
pub mod packet_decode;
/// Encoding Rust `PacketDissect` structures and wire IP addresses into Lua tables.
pub mod packet_encode;
/// Lua protocol split marker resolvers (`resolve_pos`, `resolve_range`) and `tls_mod` bindings.
pub mod protocol_api;
/// Lua `rawsend` and `rawsend_dissect` kernel packet-injection bindings.
pub mod rawsend_api;
/// Top-level [`LuaRuntime`] lifecycle and script execution.
pub mod runtime;
/// Logging, OS metadata, clock, and network topology Lua bindings.
pub mod system;
/// Scheduled timer pool and host bindings (`timer_set`, `timer_del`, `timer_info`, `timer_enum`).
pub mod timer_api;

/// Re-exported Lua runtime configuration.
pub use constants::LuaConfig;
/// Re-exported Lua error type.
pub use error::LuaEngineError;
/// Re-exported LuaJIT runtime orchestrator.
pub use runtime::LuaRuntime;
