//! Pure-Rust FIPS-197 AES-128/192/256 single-block cipher and AES-CTR stream mode.

/// Typed error returned when an invalid AES key length is provided.
use crate::crypto::error::CryptoError;

/// Forward AES substitution box (`SubBytes`) defined in FIPS 180/197 Section 5.1.1.
#[rustfmt::skip]
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Derives the FIPS-197 inverse substitution box (`InvSubBytes`) directly from [`SBOX`].
const fn build_inv_sbox() -> [u8; 256]
{
    let mut inv = [0u8; 256];
    let mut i = 0;
    while i < 256
    {
        inv[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    inv
}

/// Inverse AES substitution box (`InvSubBytes`) computed at compile time.
const INV_SBOX: [u8; 256] = build_inv_sbox();

/// AES round constants (`Rcon[i/Nk - 1]`) covering up to 10 key-schedule cycles (AES-128).
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// Applies a 256-entry lookup table element-wise to a 4-byte word (`SubWord`).
const fn sub_word(word: [u8; 4]) -> [u8; 4]
{
    [SBOX[word[0] as usize], SBOX[word[1] as usize], SBOX[word[2] as usize], SBOX[word[3] as usize]]
}

/// Cyclically left-rotates a 4-byte word by one byte (`RotWord`).
const fn rot_word(word: [u8; 4]) -> [u8; 4]
{
    [word[1], word[2], word[3], word[0]]
}

/// Expands a 16-, 24-, or 32-byte AES key into up to 60 4-byte round-key words.
fn expand_key(key: &[u8], nk: usize, rounds: usize) -> [[u8; 4]; 60]
{
    let mut w = [[0u8; 4]; 60];
    let total_words = 4 * (rounds + 1);
    for (dst, &word) in w[..nk].iter_mut().zip(key.as_chunks::<4>().0)
    {
        *dst = word;
    }
    for i in nk..total_words
    {
        let mut temp = w[i - 1];
        if i % nk == 0
        {
            temp = sub_word(rot_word(temp));
            temp[0] ^= RCON[i / nk - 1];
        }
        else if nk == 8 && i % nk == 4
        {
            // FIPS-197 Section 5.2 specifies an extra SubWord every 4th word inside AES-256.
            temp = sub_word(temp);
        }
        let prev = w[i - nk];
        w[i] = [prev[0] ^ temp[0], prev[1] ^ temp[1], prev[2] ^ temp[2], prev[3] ^ temp[3]];
    }
    w
}

/// XORs 4 round-key words (`16` bytes) into the column-major AES state (`AddRoundKey`).
fn add_round_key(state: &mut [u8; 16], round_key: &[[u8; 4]])
{
    for (col, word) in round_key.iter().enumerate()
    {
        let base = col * 4;
        state[base] ^= word[0];
        state[base + 1] ^= word[1];
        state[base + 2] ^= word[2];
        state[base + 3] ^= word[3];
    }
}

/// Substitutes all 16 state bytes through a 256-entry S-box (`SubBytes` / `InvSubBytes`).
fn apply_sbox(state: &mut [u8; 16], table: &[u8; 256])
{
    for b in state.iter_mut()
    {
        *b = table[usize::from(*b)];
    }
}

/// Cyclically left-shifts rows `1..=3` in the column-major 4x4 state (`ShiftRows`).
fn shift_rows(s: &mut [u8; 16])
{
    let r1 = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = r1;

    s.swap(2, 10);
    s.swap(6, 14);

    let r3 = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = r3;
}

/// Cyclically right-shifts rows `1..=3` in the column-major 4x4 state (`InvShiftRows`).
fn inv_shift_rows(s: &mut [u8; 16])
{
    let r1 = s[13];
    s[13] = s[9];
    s[9] = s[5];
    s[5] = s[1];
    s[1] = r1;

    s.swap(2, 10);
    s.swap(6, 14);

    let r3 = s[3];
    s[3] = s[7];
    s[7] = s[11];
    s[11] = s[15];
    s[15] = r3;
}

/// Multiplies a byte by `x` (`0x02`) modulo `x^8 + x^4 + x^3 + x + 1` in `GF(2^8)`.
const fn xtime(b: u8) -> u8
{
    (b << 1) ^ (((b >> 7) & 1) * 0x1b)
}

/// Mixes each 4-byte column over `GF(2^8)` (`MixColumns`).
fn mix_columns(s: &mut [u8; 16])
{
    for col in 0..4
    {
        let base = col * 4;
        let [a0, a1, a2, a3] = [s[base], s[base + 1], s[base + 2], s[base + 3]];
        let t = a0 ^ a1 ^ a2 ^ a3;
        s[base] = a0 ^ t ^ xtime(a0 ^ a1);
        s[base + 1] = a1 ^ t ^ xtime(a1 ^ a2);
        s[base + 2] = a2 ^ t ^ xtime(a2 ^ a3);
        s[base + 3] = a3 ^ t ^ xtime(a3 ^ a0);
    }
}

/// Applies the inverse `GF(2^8)` column mix matrix `{0e, 0b, 0d, 09}` (`InvMixColumns`).
fn inv_mix_columns(s: &mut [u8; 16])
{
    for col in 0..4
    {
        let base = col * 4;
        let [a0, a1, a2, a3] = [s[base], s[base + 1], s[base + 2], s[base + 3]];
        let [u, v] = [xtime(xtime(a0 ^ a2)), xtime(xtime(a1 ^ a3))];
        let [b0, b1, b2, b3] = [a0 ^ u, a1 ^ v, a2 ^ u, a3 ^ v];
        let t = b0 ^ b1 ^ b2 ^ b3;
        s[base] = b0 ^ t ^ xtime(b0 ^ b1);
        s[base + 1] = b1 ^ t ^ xtime(b1 ^ b2);
        s[base + 2] = b2 ^ t ^ xtime(b2 ^ b3);
        s[base + 3] = b3 ^ t ^ xtime(b3 ^ b0);
    }
}

/// Expanded FIPS-197 AES key schedule supporting AES-128, AES-192, and AES-256.
#[derive(Debug, Clone)]
pub struct AesKey
{
    /// Expanded 4-byte key schedule words (`4 * (rounds + 1)` active words).
    round_keys: [[u8; 4]; 60],
    /// Round count (`10` for AES-128, `12` for AES-192, `14` for AES-256).
    rounds: usize,
}

impl AesKey
{
    /// Expands a 16-, 24-, or 32-byte key into an [`AesKey`] schedule.
    pub fn new(key: &[u8]) -> Result<Self, CryptoError>
    {
        let (nk, rounds) = match key.len()
        {
            16 => (4, 10),
            24 => (6, 12),
            32 => (8, 14),
            other => return Err(CryptoError::InvalidKeyLength(other)),
        };
        Ok(Self { round_keys: expand_key(key, nk, rounds), rounds })
    }

    /// Infallibly expands a 32-byte key into an AES-256 schedule (`14` rounds).
    pub fn new_256(key: &[u8; 32]) -> Self
    {
        Self { round_keys: expand_key(key, 8, 14), rounds: 14 }
    }

    /// Encrypts a single 16-byte plaintext block in ECB mode (FIPS-197 `Cipher`).
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16]
    {
        let mut state = *block;
        add_round_key(&mut state, &self.round_keys[0..4]);
        for round in 1..self.rounds
        {
            apply_sbox(&mut state, &SBOX);
            shift_rows(&mut state);
            mix_columns(&mut state);
            let start = round * 4;
            add_round_key(&mut state, &self.round_keys[start..start + 4]);
        }
        apply_sbox(&mut state, &SBOX);
        shift_rows(&mut state);
        let final_start = self.rounds * 4;
        add_round_key(&mut state, &self.round_keys[final_start..final_start + 4]);
        state
    }

    /// Decrypts a single 16-byte ciphertext block in ECB mode (FIPS-197 `InvCipher`).
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16]
    {
        let mut state = *block;
        let final_start = self.rounds * 4;
        add_round_key(&mut state, &self.round_keys[final_start..final_start + 4]);
        for round in (1..self.rounds).rev()
        {
            inv_shift_rows(&mut state);
            apply_sbox(&mut state, &INV_SBOX);
            let start = round * 4;
            add_round_key(&mut state, &self.round_keys[start..start + 4]);
            inv_mix_columns(&mut state);
        }
        inv_shift_rows(&mut state);
        apply_sbox(&mut state, &INV_SBOX);
        add_round_key(&mut state, &self.round_keys[0..4]);
        state
    }
}

/// Adds `add` to a 16-byte big-endian unsigned AES-CTR counter block (`ctr_add` in `aes-ctr.c`).
pub fn ctr_add(iv: &mut [u8; 16], add: u64)
{
    let val = u128::from_be_bytes(*iv).wrapping_add(u128::from(add));
    *iv = val.to_be_bytes();
}

/// Encrypts or decrypts `input` with AES-CTR using a 16-, 24-, or 32-byte `key` and 16-byte `iv`.
pub fn aes_ctr_crypt(key: &[u8], iv: &[u8; 16], input: &[u8]) -> Result<Vec<u8>, CryptoError>
{
    let aes = AesKey::new(key)?;
    let mut ctr = *iv;
    let mut out = Vec::with_capacity(input.len());
    for chunk in input.chunks(16)
    {
        let keystream = aes.encrypt_block(&ctr);
        ctr_add(&mut ctr, 1);
        for (&byte, &ks) in chunk.iter().zip(keystream.iter())
        {
            out.push(byte ^ ks);
        }
    }
    Ok(out)
}
