//! Error definitions surfaced by `zapret-rs` pure-Rust cryptographic primitives.

/// Derive macro generating `std::error::Error` and `Display` implementations.
use thiserror::Error;

/// Typed errors returned by pure-Rust SHA-2, HKDF, AES, and AES-GCM operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CryptoError {
    /// Requested hash algorithm name is not supported (`"sha224"` or `"sha256"` only).
    #[error("unsupported hash type {0}")]
    UnsupportedHash(String),
    /// Supplied AES key length is not 16, 24, or 32 bytes.
    #[error("invalid AES key length {0}; expected 16, 24, or 32")]
    InvalidKeyLength(usize),
    /// Supplied IV/nonce length is invalid (for example, zero-length GCM IV).
    #[error("invalid IV length {0}")]
    InvalidIvLength(usize),
    /// Requested HKDF output keying material length is zero or exceeds `255 * hash_len`.
    #[error("invalid HKDF output length {0}")]
    InvalidOkmLength(usize),
}
