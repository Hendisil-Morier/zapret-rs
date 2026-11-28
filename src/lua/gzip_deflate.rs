//! Pure-Rust streaming RFC 1951/1950/1952 compressor supporting raw deflate, zlib, and gzip framing.

/// Pure-Rust `flate2` compressor, compression level, CRC-32, flush modes, and stream statuses.
use flate2::{Compress, Compression, Crc, FlushCompress, Status};

/// First RFC 1952 gzip magic byte (`0x1F`).
pub(crate) const GZIP_ID1: u8 = 0x1F;
/// Second RFC 1952 gzip magic byte (`0x8B`).
pub(crate) const GZIP_ID2: u8 = 0x8B;
/// RFC 1952 gzip compression method (`8` = deflate).
pub(crate) const GZIP_CM_DEFLATE: u8 = 8;
/// Minimum spare capacity guaranteed in output buffers before invoking `flate2`.
pub(crate) const MIN_OUTPUT_SPARE: usize = 4096;
/// Growth increment allocated while draining compressed output blocks.
const DEFLATE_GROWTH: usize = 8192;

/// Supported zlib `windowBits` framing modes accepted by `gzip_init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeflateMode
{
    /// Raw RFC 1951 deflate stream without container headers (`windowBits` in `-15..=-8`).
    Raw,
    /// RFC 1950 zlib stream (`windowBits` in `8..=15`).
    Zlib,
    /// RFC 1952 gzip stream (`windowBits` in `24..=31`, default `31`).
    Gzip,
}

impl DeflateMode
{
    /// Maps a zlib `deflateInit2` `windowBits` parameter to a [`DeflateMode`].
    pub const fn from_window_bits(window_bits: i64) -> Option<Self>
    {
        match window_bits
        {
            -15..=-8 => Some(Self::Raw),
            8..=15 => Some(Self::Zlib),
            24..=31 => Some(Self::Gzip),
            _ => None,
        }
    }
}

/// Validates zlib `level` (`-1` or `0..=9`) and `memlevel` (`1..=9`), returning `Compression`.
pub fn parse_deflate_level(level: i64, memlevel: i64) -> Option<Compression>
{
    if !(1..=9).contains(&memlevel)
    {
        return None;
    }
    match level
    {
        -1 => Some(Compression::default()),
        0..=9 => Some(Compression::new(level as u32)),
        _ => None,
    }
}

/// Streaming compressor matching `zapret2`'s `gzip_init` and `gzip_deflate`.
pub struct DeflateStream
{
    /// Active output framing (raw deflate, zlib, or gzip).
    mode: DeflateMode,
    /// Underlying `flate2` compressor handle.
    comp: Compress,
    /// Running CRC-32 and input length (`ISIZE`) used for RFC 1952 trailers.
    crc: Crc,
    /// Tracks whether the 10-byte RFC 1952 header has already been emitted.
    header_emitted: bool,
    /// RFC 1952 `XFL` flag (`2` max compression, `4` fastest, `0` default).
    xfl: u8,
    /// Tracks whether `FlushCompress::Finish` has already completed this stream.
    finished: bool,
}

impl DeflateStream
{
    /// Creates a new [`DeflateStream`] for `mode` and compression `level`.
    pub fn new(mode: DeflateMode, level: Compression) -> Self
    {
        let zlib_header = matches!(mode, DeflateMode::Zlib);
        let xfl = if level.level() >= 9
        {
            2
        }
        else if level.level() <= 1
        {
            4
        }
        else
        {
            0
        };
        Self {
            mode,
            comp: Compress::new(level, zlib_header),
            crc: Crc::new(),
            header_emitted: false,
            xfl,
            finished: false,
        }
    }

    /// Compresses `input` (or finalizes when `input` is empty), returning `(compressed_bytes, eof)`.
    pub fn deflate(&mut self, input: &[u8], capacity_hint: usize) -> Option<(Vec<u8>, bool)>
    {
        if self.finished
        {
            return None;
        }
        let mut out = Vec::with_capacity(capacity_hint.max(64));
        if matches!(self.mode, DeflateMode::Gzip) && !self.header_emitted
        {
            out.extend_from_slice(&[GZIP_ID1, GZIP_ID2, GZIP_CM_DEFLATE, 0, 0, 0, 0, 0, self.xfl, 3]);
            self.header_emitted = true;
        }

        if input.is_empty()
        {
            return self.finish(out);
        }

        if matches!(self.mode, DeflateMode::Gzip)
        {
            self.crc.update(input);
        }
        let mut rem = input;
        loop
        {
            if out.capacity() - out.len() < MIN_OUTPUT_SPARE
            {
                out.reserve(DEFLATE_GROWTH);
            }
            let spare_before = out.capacity() - out.len();
            let before_in = self.comp.total_in();
            let before_out = self.comp.total_out();
            let status = self.comp.compress_vec(rem, &mut out, FlushCompress::None);
            let consumed = (self.comp.total_in() - before_in) as usize;
            let produced = (self.comp.total_out() - before_out) as usize;
            rem = &rem[consumed..];
            match status
            {
                Ok(Status::Ok) if rem.is_empty() && produced < spare_before => break,
                Ok(Status::BufError) if rem.is_empty() => break,
                Ok(Status::Ok) | Ok(Status::BufError) =>
                {
                    if consumed == 0 && produced == 0 && !rem.is_empty()
                    {
                        return None;
                    }
                }
                Ok(Status::StreamEnd) => break,
                Err(_) => return None,
            }
        }
        Some((out, false))
    }

    /// Flushes remaining compressed bits and emits any RFC 1952 trailer (`FlushCompress::Finish`).
    fn finish(&mut self, mut out: Vec<u8>) -> Option<(Vec<u8>, bool)>
    {
        let mut stalls = 0usize;
        loop
        {
            if out.capacity() - out.len() < MIN_OUTPUT_SPARE
            {
                out.reserve(DEFLATE_GROWTH);
            }
            let before_out = self.comp.total_out();
            let status = self.comp.compress_vec(&[], &mut out, FlushCompress::Finish);
            let produced = (self.comp.total_out() - before_out) as usize;
            match status
            {
                Ok(Status::StreamEnd) => break,
                Ok(Status::Ok) | Ok(Status::BufError) =>
                {
                    if produced == 0
                    {
                        stalls += 1;
                        if stalls > 4
                        {
                            return None;
                        }
                    }
                    else
                    {
                        stalls = 0;
                    }
                }
                Err(_) => return None,
            }
        }
        if matches!(self.mode, DeflateMode::Gzip)
        {
            out.extend_from_slice(&self.crc.sum().to_le_bytes());
            out.extend_from_slice(&self.crc.amount().to_le_bytes());
        }
        self.finished = true;
        Some((out, true))
    }
}
