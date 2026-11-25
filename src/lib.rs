//! Core library modules for `zapret-rs` packet interception, dissection, injection, and Lua scripting.

/// Profile filters, built-in blobs, TOML configuration schema, and CLI overrides.
pub mod config;
/// Bidirectional TCP/UDP connection tracking table and continuous stream reassembly.
pub mod conntrack;
/// Daemon control socket protocol, bounded line codec, and local Unix IPC server.
pub mod control;
/// Pure-Rust SHA-2, HKDF, AES-128/192/256, and AES-GCM cryptographic primitives.
pub mod crypto;
/// Core DPI desync profile routing and Lua action execution engine.
pub mod desync;
/// Linux NFQUEUE packet interception and verdict loop.
pub mod intercepter;
/// Hostlists, autohostlist failure detection, disjoint CIDR IPsets, and TTL IPCache.
pub mod lists;
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
/// Shared telemetry counters and serializable decoded packet records.
pub mod telemetry;
/// Monotonic boottime clock, scheduled timer pool, and non-intercepting timer loop.
pub mod timer;
/// Companion CLI utilities (`ip2net`, `mdig`, and `strat_finder`).
pub mod tools;
/// Interactive `ratatui` TUI wrapping strategy discovery, config preview, and live `nfqws2`.
#[cfg(feature = "tui")]
pub mod tui;
