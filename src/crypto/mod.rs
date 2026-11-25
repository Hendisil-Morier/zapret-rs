//! Pure-Rust SHA-2, HKDF, AES-128/192/256, and AES-GCM primitives.

/// Pure-Rust FIPS-197 AES-128/192/256 single-block cipher and AES-CTR stream mode.
pub mod aes;
/// Pure-Rust NIST SP 800-38D AES-GCM authenticated encryption supporting arbitrary IV lengths.
pub mod aes_gcm;
/// Typed errors returned by cryptographic primitives.
pub mod error;
/// Pure-Rust FIPS 180-4 SHA-224/SHA-256, RFC 2104 HMAC, and RFC 5869 HKDF primitives.
pub mod sha2;

/// Re-exported AES-128/192/256 cipher, counter increment helper, and CTR stream cipher.
pub use aes::{AesKey, aes_ctr_crypt, ctr_add};
/// Re-exported AES-GCM authenticated cipher returning `(output, tag16)`.
pub use aes_gcm::aes_gcm_crypt;
/// Re-exported cryptographic error enum.
pub use error::CryptoError;
/// Re-exported SHA-2 algorithm selector and hash/HMAC/HKDF functions.
pub use sha2::{HashAlg, hkdf_sha2, hmac_sha2, sha2_hash};
