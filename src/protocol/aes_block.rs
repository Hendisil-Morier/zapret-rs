//! AES-256 single-block ECB cipher and 128-bit counter addition delegated to [`crate::crypto::aes`].

/// Shared FIPS-197 AES key schedule supporting 128/192/256-bit keys.
use crate::crypto::aes::AesKey;

/// Re-exported 128-bit big-endian unsigned AES-CTR counter increment (`ctr_add`).
pub use crate::crypto::aes::ctr_add;

/// Encrypts a single 16-byte plaintext block with AES-256 in ECB mode (FIPS-197).
pub fn aes256_encrypt_block(key: &[u8; 32], block: &[u8; 16]) -> [u8; 16]
{
    AesKey::new_256(key).encrypt_block(block)
}
