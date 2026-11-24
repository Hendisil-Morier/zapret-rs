//! Core library modules for `zapret-rs` packet interception, dissection, injection, and Lua scripting.

/// Profile filters, built-in blobs, TOML configuration schema, and CLI overrides.
pub mod config;
/// Bidirectional TCP/UDP connection tracking table and continuous stream reassembly.
pub mod conntrack;
/// Core DPI desync profile routing and Lua action execution engine.
pub mod desync;
/// Linux NFQUEUE packet interception and verdict loop.
pub mod intercepter;
/// Embedded `zapret2`-compatible LuaJIT runtime and script bindings.
pub mod lua;
/// Wire packet dissection, checksums, constants, and reconstruction engine.
pub mod packet;
/// L7 protocol classifiers, QUIC Initial decryption, TLS modification, and position markers.
pub mod protocol;
/// Linux raw socket packet injection and kernel network topology helpers.
pub mod rawsend;
/// Daemon process lifecycle, privilege drop, Linux capability retention, and signal handlers.
pub mod runtime;
/// Monotonic boottime clock, scheduled timer pool, and non-intercepting timer loop.
pub mod timer;
