//! Core library modules for `zapret-rs` packet interception, dissection, injection, and Lua scripting.

/// Linux NFQUEUE packet interception and verdict loop.
pub mod intercepter;
/// Embedded `zapret2`-compatible LuaJIT runtime and script bindings.
pub mod lua;
/// Wire packet dissection, checksums, constants, and reconstruction engine.
pub mod packet;
/// Linux raw socket packet injection and kernel network topology helpers.
pub mod rawsend;
