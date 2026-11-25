//! Pure-Rust NIST SP 800-38D AES-GCM supporting arbitrary non-empty IVs and full decrypt tags.

/// AES-128/192/256 block cipher schedule used for counter blocks, GHASH `H`, and tag mask.
use crate::crypto::aes::AesKey;
/// Typed error returned when AES key length or IV length is invalid.
use crate::crypto::error::CryptoError;

/// GHASH reduction constant `R = 0xe1 || 0^120` in big-endian `u128` representation.
const GHASH_R: u128 = 0xe100_0000_0000_0000_0000_0000_0000_0000;

/// Multiplies `v` by field element `alpha` (`v >> 1` with `GHASH_R` reduction on LSB = 1).
const fn gf128_mul_alpha(mut v: u128) -> u128 {
    let lsb = v & 1;
    v >>= 1;
    if lsb != 0 {
        v ^= GHASH_R;
    }
    v
}

/// Precomputed 4-bit reduction table mapping shifted-out `(z & 0xf)` to top-16-bit `GHASH_R` masks.
const fn build_last4_reduction() -> [u16; 16] {
    let mut table = [0u16; 16];
    let mut idx = 0usize;
    while idx < 16 {
        let mut v = idx as u128;
        let mut step = 0;
        while step < 4 {
            v = gf128_mul_alpha(v);
            step += 1;
        }
        table[idx] = (v >> 112) as u16;
        idx += 1;
    }
    table
}

/// Compile-time 4-bit Shoup GHASH reduction table (`2^4 = 16` entries).
const LAST4_RED: [u16; 16] = build_last4_reduction();

/// Precomputed 4-bit Shoup multiplication table (`M[0..16]`) for a single GHASH subkey `H`.
struct GhashTable([u128; 16]);

impl GhashTable {
    /// Builds Shoup's 4-bit `GF(2^128)` table (`M[nibble] = nibble * H`) from raw 16-byte key `h`.
    fn new(h: [u8; 16]) -> Self {
        let mut table = [0u128; 16];
        table[8] = u128::from_be_bytes(h);
        let mut bit = 4usize;
        while bit > 0 {
            table[bit] = gf128_mul_alpha(table[bit * 2]);
            bit /= 2;
        }
        let mut hi = 2usize;
        while hi < 16 {
            let base = table[hi];
            let mut lo = 1usize;
            while lo < hi {
                table[hi + lo] = base ^ table[lo];
                lo += 1;
            }
            hi *= 2;
        }
        Self(table)
    }

    /// Multiplies `x` by `H` in `GF(2^128)` using 32 nibble steps (LSB nibble up to MSB nibble).
    fn mul(&self, x: [u8; 16]) -> [u8; 16] {
        let mut z = 0u128;
        for &byte in x.iter().rev() {
            let rem_lo = (z as usize) & 0x0f;
            z = (z >> 4) ^ (u128::from(LAST4_RED[rem_lo]) << 112) ^ self.0[(byte & 0x0f) as usize];
            let rem_hi = (z as usize) & 0x0f;
            z = (z >> 4) ^ (u128::from(LAST4_RED[rem_hi]) << 112) ^ self.0[(byte >> 4) as usize];
        }
        z.to_be_bytes()
    }
}

/// Absorbs `data` (zero-padded to a 16-byte multiple) into the running `GHASH` state.
fn ghash_update(state: &mut [u8; 16], table: &GhashTable, data: &[u8]) {
    for chunk in data.chunks(16) {
        for (slot, &byte) in state.iter_mut().zip(chunk.iter()) {
            *slot ^= byte;
        }
        *state = table.mul(*state);
    }
}

/// Increments the low 32-bit big-endian counter word of a 16-byte GCM counter block (`inc_32`).
fn inc32(ctr: &mut [u8; 16]) {
    let next = u32::from_be_bytes([ctr[12], ctr[13], ctr[14], ctr[15]]).wrapping_add(1);
    ctr[12..16].copy_from_slice(&next.to_be_bytes());
}

/// Computes the initial counter block `J0` for a non-empty IV of any length.
fn compute_j0(table: &GhashTable, iv: &[u8]) -> [u8; 16] {
    let mut j0 = [0u8; 16];
    if iv.len() == 12 {
        j0[..12].copy_from_slice(iv);
        j0[15] = 1;
        return j0;
    }

    ghash_update(&mut j0, table, iv);
    let mut len_block = [0u8; 16];
    let bit_len = (iv.len() as u64).wrapping_mul(8);
    len_block[8..16].copy_from_slice(&bit_len.to_be_bytes());
    ghash_update(&mut j0, table, &len_block);
    j0
}

/// Performs AES-GCM encryption (`encrypt = true`) or decryption (`encrypt = false`).
///
/// Matches `zapret2`'s `aes_gcm_crypt`: accepts 16/24/32-byte keys and any non-empty IV length,
/// and always returns both transformed bytes and the computed 16-byte authentication tag even
/// when decrypting unauthenticated data.
pub fn aes_gcm_crypt(
    encrypt: bool,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
    aad: &[u8],
) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
    let aes = AesKey::new(key)?;
    if iv.is_empty() {
        return Err(CryptoError::InvalidIvLength(0));
    }

    let h = aes.encrypt_block(&[0u8; 16]);
    let ghash = GhashTable::new(h);
    let j0 = compute_j0(&ghash, iv);
    let base_ectr = aes.encrypt_block(&j0);

    let mut ghash_state = [0u8; 16];
    ghash_update(&mut ghash_state, &ghash, aad);

    let mut ctr = j0;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16) {
        inc32(&mut ctr);
        let ectr = aes.encrypt_block(&ctr);
        for (idx, &in_byte) in chunk.iter().enumerate() {
            let out_byte = in_byte ^ ectr[idx];
            out.push(out_byte);
            let ct_byte = if encrypt { out_byte } else { in_byte };
            ghash_state[idx] ^= ct_byte;
        }
        ghash_state = ghash.mul(ghash_state);
    }

    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&(aad.len() as u64).wrapping_mul(8).to_be_bytes());
    len_block[8..16].copy_from_slice(&(input.len() as u64).wrapping_mul(8).to_be_bytes());
    ghash_update(&mut ghash_state, &ghash, &len_block);

    let mut tag = base_ectr;
    for (slot, &gh) in tag.iter_mut().zip(ghash_state.iter()) {
        *slot ^= gh;
    }
    Ok((out, tag))
}
