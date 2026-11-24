//! Core library modules for `zapret-rs` packet interception and wire parsing.

/// Linux NFQUEUE packet interception and verdict loop.
pub mod intercepter;
/// Wire packet dissection, checksums, constants, and reconstruction engine.
pub mod packet;
