//! Core library modules for `zapret-rs` packet interception, dissection, injection, and Lua scripting.

/// Profile filters, built-in blobs, TOML configuration schema, and CLI overrides.
pub mod config;
/// Core DPI desync profile routing and Lua action execution engine.
pub mod desync;
/// Linux NFQUEUE packet interception and verdict loop.
pub mod intercepter;
/// Embedded `zapret2`-compatible LuaJIT runtime and script bindings.
pub mod lua;
/// Wire packet dissection, checksums, constants, and reconstruction engine.
pub mod packet;
/// Linux raw socket packet injection and kernel network topology helpers.
pub mod rawsend;
