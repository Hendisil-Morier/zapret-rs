//! Pure-Rust FIPS 180-4 SHA-224/SHA-256, RFC 2104 HMAC, and RFC 5869 HKDF primitives.

/// Typed error reported for unsupported hash names or out-of-range HKDF output lengths.
use crate::crypto::error::CryptoError;

/// Initial hash words (`H0`) for SHA-224 per FIPS 180-4 Section 5.3.2.
const SHA224_H0: [u32; 8] =
    [0xc105_9ed8, 0x367c_d507, 0x3070_dd17, 0xf70e_5939, 0xffc0_0b31, 0x6858_1511, 0x64f9_8fa7, 0xbefa_4fa4];

/// Initial hash words (`H0`) for SHA-256 per FIPS 180-4 Section 5.3.3.
const SHA256_H0: [u32; 8] =
    [0x6a09_e667, 0xbb67_ae85, 0x3c6e_f372, 0xa54f_f53a, 0x510e_527f, 0x9b05_688c, 0x1f83_d9ab, 0x5be0_cd19];

/// Sixty-four SHA-224/SHA-256 round constants `K_0..K_63` per FIPS 180-4 Section 4.2.2.
#[rustfmt::skip]
const SHA256_K: [u32; 64] = [
    0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5, 0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5,
    0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3, 0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174,
    0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc, 0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da,
    0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7, 0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967,
    0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13, 0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85,
    0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3, 0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070,
    0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5, 0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3,
    0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208, 0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2,
];

/// HMAC input/output block length in bytes shared by SHA-224 and SHA-256.
const SHA2_BLOCK_LEN: usize = 64;

/// Supported SHA-2 hash variants exposed by `zapret2`'s `hash()` and `hkdf()` APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg
{
    /// FIPS 180-4 SHA-224 (`28`-byte digest).
    Sha224,
    /// FIPS 180-4 SHA-256 (`32`-byte digest).
    Sha256,
}

impl HashAlg
{
    /// Parses a `zapret2` hash algorithm identifier (`"sha256"` or `"sha224"`).
    pub fn from_name(name: &str) -> Result<Self, CryptoError>
    {
        match name
        {
            "sha256" => Ok(Self::Sha256),
            "sha224" => Ok(Self::Sha224),
            _ => Err(CryptoError::UnsupportedHash(name.to_owned())),
        }
    }

    /// Returns the output digest length in bytes (`28` for SHA-224, `32` for SHA-256).
    pub const fn digest_len(self) -> usize
    {
        match self
        {
            Self::Sha224 => 28,
            Self::Sha256 => 32,
        }
    }
}

/// Evaluates FIPS 180-4 upper-case Sigma0 `(ROTR^2 ^ ROTR^13 ^ ROTR^22)`.
const fn big_sigma0(x: u32) -> u32
{
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Evaluates FIPS 180-4 upper-case Sigma1 `(ROTR^6 ^ ROTR^11 ^ ROTR^25)`.
const fn big_sigma1(x: u32) -> u32
{
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Evaluates FIPS 180-4 lower-case sigma0 `(ROTR^7 ^ ROTR^18 ^ SHR^3)`.
const fn small_sigma0(x: u32) -> u32
{
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// Evaluates FIPS 180-4 lower-case sigma1 `(ROTR^17 ^ ROTR^19 ^ SHR^10)`.
const fn small_sigma1(x: u32) -> u32
{
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Evaluates FIPS 180-4 choice function `Ch(x, y, z)`.
const fn ch(x: u32, y: u32, z: u32) -> u32
{
    (x & y) ^ (!x & z)
}

/// Evaluates FIPS 180-4 majority function `Maj(x, y, z)`.
const fn maj(x: u32, y: u32, z: u32) -> u32
{
    (x & y) ^ (x & z) ^ (y & z)
}

/// Incremental SHA-224 / SHA-256 digest builder.
struct Sha2Hasher
{
    /// Hash algorithm determining IV constants and output truncation length.
    alg: HashAlg,
    /// Running 256-bit internal hash state words.
    state: [u32; 8],
    /// Pending partial 64-byte message block.
    buf: [u8; SHA2_BLOCK_LEN],
    /// Number of valid bytes currently buffered in `buf`.
    buf_len: usize,
    /// Total message byte count absorbed so far.
    total_len: u64,
}

impl Sha2Hasher
{
    /// Creates a new incremental SHA-2 hasher initialized to `H0`.
    const fn new(alg: HashAlg) -> Self
    {
        let state = match alg
        {
            HashAlg::Sha224 => SHA224_H0,
            HashAlg::Sha256 => SHA256_H0,
        };
        Self { alg, state, buf: [0u8; SHA2_BLOCK_LEN], buf_len: 0, total_len: 0 }
    }

    /// Compresses a single 64-byte big-endian message block into `self.state`.
    fn compress_block(&mut self, block: &[u8; SHA2_BLOCK_LEN])
    {
        let mut w = [0u32; 64];
        for (dst, &word) in w[..16].iter_mut().zip(block.as_chunks::<4>().0)
        {
            *dst = u32::from_be_bytes(word);
        }
        for i in 16..64
        {
            w[i] = small_sigma1(w[i - 2])
                .wrapping_add(w[i - 7])
                .wrapping_add(small_sigma0(w[i - 15]))
                .wrapping_add(w[i - 16]);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64
        {
            let t1 = h
                .wrapping_add(big_sigma1(e))
                .wrapping_add(ch(e, f, g))
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        let delta = [a, b, c, d, e, f, g, h];
        for (slot, add) in self.state.iter_mut().zip(delta)
        {
            *slot = slot.wrapping_add(add);
        }
    }

    /// Feeds arbitrary bytes into the running digest state.
    fn update(&mut self, mut data: &[u8])
    {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0
        {
            let take = (SHA2_BLOCK_LEN - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == SHA2_BLOCK_LEN
            {
                let block = self.buf;
                self.compress_block(&block);
                self.buf_len = 0;
            }
        }

        while data.len() >= SHA2_BLOCK_LEN
        {
            let mut block = [0u8; SHA2_BLOCK_LEN];
            block.copy_from_slice(&data[..SHA2_BLOCK_LEN]);
            self.compress_block(&block);
            data = &data[SHA2_BLOCK_LEN..];
        }

        if !data.is_empty()
        {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    /// Applies Merkle-Damgard padding, compresses the final block, and returns the raw digest.
    fn finalize(mut self) -> Vec<u8>
    {
        let bit_len = self.total_len.wrapping_mul(8);
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if self.buf_len > 56
        {
            self.buf[self.buf_len..].fill(0);
            let block = self.buf;
            self.compress_block(&block);
            self.buf.fill(0);
        }
        else
        {
            self.buf[self.buf_len..56].fill(0);
        }

        self.buf[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let final_block = self.buf;
        self.compress_block(&final_block);

        let words = match self.alg
        {
            HashAlg::Sha224 => 7,
            HashAlg::Sha256 => 8,
        };
        let mut out = Vec::with_capacity(words * 4);
        for word in self.state.iter().take(words)
        {
            out.extend_from_slice(&word.to_be_bytes());
        }
        out
    }
}

/// Computes the FIPS 180-4 digest (`28` bytes for SHA-224, `32` bytes for SHA-256) of `data`.
pub fn sha2_hash(alg: HashAlg, data: &[u8]) -> Vec<u8>
{
    let mut hasher = Sha2Hasher::new(alg);
    hasher.update(data);
    hasher.finalize()
}

/// Computes RFC 2104 HMAC-SHA2 over concatenated message `parts`, avoiding extra intermediate buffers.
fn hmac_sha2_parts(alg: HashAlg, key: &[u8], parts: &[&[u8]]) -> Vec<u8>
{
    let mut key_block = [0u8; SHA2_BLOCK_LEN];
    if key.len() > SHA2_BLOCK_LEN
    {
        let hashed = sha2_hash(alg, key);
        key_block[..hashed.len()].copy_from_slice(&hashed);
    }
    else
    {
        key_block[..key.len()].copy_from_slice(key);
    }

    let ipad = key_block.map(|b| b ^ 0x36);
    let opad = key_block.map(|b| b ^ 0x5c);

    let mut inner = Sha2Hasher::new(alg);
    inner.update(&ipad);
    for part in parts
    {
        inner.update(part);
    }
    let inner_digest = inner.finalize();

    let mut outer = Sha2Hasher::new(alg);
    outer.update(&opad);
    outer.update(&inner_digest);
    outer.finalize()
}

/// Computes RFC 2104 HMAC using SHA-224 or SHA-256.
pub fn hmac_sha2(alg: HashAlg, key: &[u8], data: &[u8]) -> Vec<u8>
{
    hmac_sha2_parts(alg, key, &[data])
}

/// Computes RFC 5869 `HKDF-Extract` (`HMAC-Hash(salt, ikm)`), using an all-zero salt when `None`.
pub fn hkdf_sha2_extract(alg: HashAlg, salt: Option<&[u8]>, ikm: &[u8]) -> Vec<u8>
{
    let hash_len = alg.digest_len();
    let zero_salt = [0u8; 32];
    let effective_salt = salt.unwrap_or(&zero_salt[..hash_len]);
    hmac_sha2(alg, effective_salt, ikm)
}

/// Computes RFC 5869 `HKDF-Expand` over pseudorandom key `prk` and context `info`.
///
/// Rejects `okm_len == 0` and `okm_len > 255 * hash_len` prior to allocating output storage.
pub fn hkdf_sha2_expand(alg: HashAlg, prk: &[u8], info: &[u8], okm_len: usize)
-> Result<Vec<u8>, CryptoError>
{
    let hash_len = alg.digest_len();
    if okm_len == 0 || okm_len > 255 * hash_len
    {
        return Err(CryptoError::InvalidOkmLength(okm_len));
    }

    let blocks = okm_len.div_ceil(hash_len);
    let mut okm = Vec::with_capacity(okm_len);
    let mut prev: Vec<u8> = Vec::new();
    for idx in 1..=blocks
    {
        let counter = [idx as u8];
        let t = hmac_sha2_parts(alg, prk, &[&prev, info, &counter]);
        let take = (okm_len - okm.len()).min(hash_len);
        okm.extend_from_slice(&t[..take]);
        prev = t;
    }
    Ok(okm)
}

/// Derives `okm_len` keying material bytes via RFC 5869 HKDF matching `zapret2/nfq2/crypto/hkdf.c`.
///
/// Rejects `okm_len == 0` and `okm_len > 255 * hash_len` prior to allocating output storage.
pub fn hkdf_sha2(
    alg: HashAlg,
    salt: Option<&[u8]>,
    ikm: &[u8],
    info: &[u8],
    okm_len: usize,
) -> Result<Vec<u8>, CryptoError>
{
    let hash_len = alg.digest_len();
    if okm_len == 0 || okm_len > 255 * hash_len
    {
        return Err(CryptoError::InvalidOkmLength(okm_len));
    }
    let prk = hkdf_sha2_extract(alg, salt, ikm);
    hkdf_sha2_expand(alg, &prk, info, okm_len)
}
