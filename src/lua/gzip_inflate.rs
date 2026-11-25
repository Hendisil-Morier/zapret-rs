//! Pure-Rust streaming RFC 1951/1950/1952 decompressor with auto-detect and byte-granular gzip framing.

/// Pure-Rust `flate2` decompressor, CRC-32, flush modes, and stream status.
use flate2::{Crc, Decompress, FlushDecompress, Status};

/// Shared RFC 1952 magic constants and output spare capacity floor.
use crate::lua::gzip_deflate::{GZIP_CM_DEFLATE, GZIP_ID1, GZIP_ID2, MIN_OUTPUT_SPARE};

/// Growth increment allocated during streaming decompression loops.
const INFLATE_GROWTH: usize = 16384;
/// RFC 1952 header flag bit indicating optional `FHCRC` CRC-16 field (`0x02`).
const F_HCRC: u8 = 0x02;
/// RFC 1952 header flag bit indicating optional `FEXTRA` field (`0x04`).
const F_EXTRA: u8 = 0x04;
/// RFC 1952 header flag bit indicating NUL-terminated `FNAME` field (`0x08`).
const F_NAME: u8 = 0x08;
/// RFC 1952 header flag bit indicating NUL-terminated `FCOMMENT` field (`0x10`).
const F_COMMENT: u8 = 0x10;
/// Reserved RFC 1952 header flag bits (`0xE0`) that must remain zero.
const F_RESERVED: u8 = 0xE0;

/// Supported zlib `windowBits` framing modes accepted by `gunzip_init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InflateMode {
    /// Raw RFC 1951 deflate stream (`windowBits` in `-15..=-8`).
    Raw,
    /// RFC 1950 zlib stream (`windowBits` `0` or in `8..=15`).
    Zlib,
    /// RFC 1952 gzip stream (`windowBits` in `24..=31`).
    Gzip,
    /// Automatic zlib vs gzip header sniffing (`windowBits` `32` or in `40..=47`, default `47`).
    AutoDetect,
}

impl InflateMode {
    /// Maps a zlib `inflateInit2` `windowBits` parameter to an [`InflateMode`].
    pub const fn from_window_bits(window_bits: i64) -> Option<Self> {
        match window_bits {
            -15..=-8 => Some(Self::Raw),
            0 | 8..=15 => Some(Self::Zlib),
            24..=31 => Some(Self::Gzip),
            32 | 40..=47 => Some(Self::AutoDetect),
            _ => None,
        }
    }
}

/// Drains `rem` through `dec` into `out`, optionally updating an RFC 1952 payload `crc`.
fn pump_decompress(
    dec: &mut Decompress,
    rem: &mut &[u8],
    out: &mut Vec<u8>,
    mut crc: Option<&mut Crc>,
) -> Option<bool> {
    loop {
        if out.capacity() - out.len() < MIN_OUTPUT_SPARE {
            out.reserve(INFLATE_GROWTH);
        }
        let prev_len = out.len();
        let spare_before = out.capacity() - out.len();
        let before_in = dec.total_in();
        let before_out = dec.total_out();
        let status = dec.decompress_vec(rem, out, FlushDecompress::None);
        let consumed = (dec.total_in() - before_in) as usize;
        let produced = (dec.total_out() - before_out) as usize;
        *rem = &rem[consumed..];

        if produced > 0
            && let Some(c) = crc.as_deref_mut()
        {
            c.update(&out[prev_len..]);
        }

        match status {
            Ok(Status::StreamEnd) => return Some(true),
            Ok(Status::Ok) => {
                if (rem.is_empty() && produced < spare_before) || (consumed == 0 && produced == 0) {
                    return Some(false);
                }
            }
            Ok(Status::BufError) => {
                if rem.is_empty() {
                    return Some(false);
                }
                if consumed == 0 && produced == 0 {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

/// Byte-granular RFC 1952 gzip header, body, and trailer parsing state.
enum GzipPhase {
    /// Fixed 10-byte RFC 1952 header (`ID1..=OS`).
    Fixed {
        /// Partially read 10-byte header buffer.
        buf: [u8; 10],
        /// Valid byte count currently buffered.
        len: usize,
    },
    /// 2-byte little-endian `XLEN` field when `FEXTRA` is set.
    ExtraLen {
        /// Header `FLG` byte.
        flg: u8,
        /// Partially read 2-byte `XLEN` buffer.
        buf: [u8; 2],
        /// Valid byte count currently buffered.
        len: usize,
    },
    /// Skipping `rem` bytes of `FEXTRA` subfield data.
    ExtraData {
        /// Header `FLG` byte.
        flg: u8,
        /// Remaining `FEXTRA` payload bytes.
        rem: usize,
    },
    /// Consuming NUL-terminated `FNAME` string.
    Fname {
        /// Header `FLG` byte.
        flg: u8,
    },
    /// Consuming NUL-terminated `FCOMMENT` string.
    Fcomment {
        /// Header `FLG` byte.
        flg: u8,
    },
    /// Reading 2-byte `FHCRC` header checksum.
    HeaderCrc {
        /// Partially read 2-byte CRC-16 buffer.
        buf: [u8; 2],
        /// Valid byte count currently buffered.
        len: usize,
    },
    /// Inflating raw RFC 1951 deflate payload.
    Body,
    /// Reading 8-byte RFC 1952 `CRC32` + `ISIZE` trailer.
    Trailer {
        /// Partially read 8-byte trailer buffer.
        buf: [u8; 8],
        /// Valid byte count currently buffered.
        len: usize,
    },
    /// Completed and verified gzip member.
    Done,
}

/// Advances to the next enabled RFC 1952 header stage using monotonic `stage_done` (`0..=4`).
const fn next_phase_after(flg: u8, stage_done: u8) -> GzipPhase {
    if stage_done < 1 && (flg & F_EXTRA) != 0 {
        return GzipPhase::ExtraLen { flg, buf: [0; 2], len: 0 };
    }
    if stage_done < 2 && (flg & F_NAME) != 0 {
        return GzipPhase::Fname { flg };
    }
    if stage_done < 3 && (flg & F_COMMENT) != 0 {
        return GzipPhase::Fcomment { flg };
    }
    if stage_done < 4 && (flg & F_HCRC) != 0 {
        return GzipPhase::HeaderCrc { buf: [0; 2], len: 0 };
    }
    GzipPhase::Body
}

/// Streaming RFC 1952 gzip decompressor tolerating splits inside any header or trailer field.
struct GzipInflater {
    /// Current framing state.
    phase: GzipPhase,
    /// Running CRC-32 over header bytes prior to `FHCRC`.
    header_crc: Crc,
    /// Raw RFC 1951 deflate state.
    body: Decompress,
    /// Running CRC-32 and byte length (`ISIZE`) of decompressed payload bytes.
    body_crc: Crc,
}

impl GzipInflater {
    /// Creates a new gzip inflater positioned at byte 0 of the 10-byte header.
    fn new() -> Self {
        Self {
            phase: GzipPhase::Fixed { buf: [0; 10], len: 0 },
            header_crc: Crc::new(),
            body: Decompress::new(false),
            body_crc: Crc::new(),
        }
    }

    /// Updates `header_crc` when optional header checksum `FHCRC` validation is active.
    fn update_hcrc(&mut self, flg: u8, bytes: &[u8]) {
        if (flg & F_HCRC) != 0 {
            self.header_crc.update(bytes);
        }
    }

    /// Consumes a single header byte during `Fixed`..=`HeaderCrc` stages.
    fn feed_header_byte(&mut self, byte: u8) -> Option<()> {
        match &mut self.phase {
            GzipPhase::Fixed { buf, len } => {
                buf[*len] = byte;
                *len += 1;
                if *len == 10 {
                    let flg = buf[3];
                    if buf[0] != GZIP_ID1
                        || buf[1] != GZIP_ID2
                        || buf[2] != GZIP_CM_DEFLATE
                        || (flg & F_RESERVED) != 0
                    {
                        return None;
                    }
                    let header = *buf;
                    self.update_hcrc(flg, &header);
                    self.phase = next_phase_after(flg, 0);
                }
            }
            GzipPhase::ExtraLen { flg, buf, len } => {
                let saved_flg = *flg;
                buf[*len] = byte;
                *len += 1;
                let completed = if *len == 2 {
                    Some(u16::from_le_bytes(*buf))
                } else {
                    None
                };
                self.update_hcrc(saved_flg, &[byte]);
                if let Some(xlen) = completed {
                    let rem = usize::from(xlen);
                    self.phase = if rem == 0 {
                        next_phase_after(saved_flg, 1)
                    } else {
                        GzipPhase::ExtraData { flg: saved_flg, rem }
                    };
                }
            }
            GzipPhase::ExtraData { flg, rem } => {
                let saved_flg = *flg;
                *rem -= 1;
                let finished = *rem == 0;
                self.update_hcrc(saved_flg, &[byte]);
                if finished {
                    self.phase = next_phase_after(saved_flg, 1);
                }
            }
            GzipPhase::Fname { flg } => {
                let saved_flg = *flg;
                self.update_hcrc(saved_flg, &[byte]);
                if byte == 0 {
                    self.phase = next_phase_after(saved_flg, 2);
                }
            }
            GzipPhase::Fcomment { flg } => {
                let saved_flg = *flg;
                self.update_hcrc(saved_flg, &[byte]);
                if byte == 0 {
                    self.phase = next_phase_after(saved_flg, 3);
                }
            }
            GzipPhase::HeaderCrc { buf, len } => {
                buf[*len] = byte;
                *len += 1;
                if *len == 2 {
                    if u16::from_le_bytes(*buf) != (self.header_crc.sum() as u16) {
                        return None;
                    }
                    self.phase = GzipPhase::Body;
                }
            }
            GzipPhase::Body | GzipPhase::Trailer { .. } | GzipPhase::Done => {}
        }
        Some(())
    }

    /// Consumes compressed input, appending decompressed output to `out` and returning EOF status.
    fn feed(&mut self, mut rem: &[u8], out: &mut Vec<u8>) -> Option<bool> {
        loop {
            match &mut self.phase {
                GzipPhase::Body => {
                    if pump_decompress(&mut self.body, &mut rem, out, Some(&mut self.body_crc))? {
                        self.phase = GzipPhase::Trailer { buf: [0; 8], len: 0 };
                        continue;
                    }
                    return Some(false);
                }
                GzipPhase::Trailer { buf, len } => {
                    let take = (8 - *len).min(rem.len());
                    buf[*len..*len + take].copy_from_slice(&rem[..take]);
                    *len += take;
                    if *len < 8 {
                        return Some(false);
                    }
                    let crc_exp = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    let size_exp = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
                    if crc_exp != self.body_crc.sum() || size_exp != self.body_crc.amount() {
                        return None;
                    }
                    self.phase = GzipPhase::Done;
                    return Some(true);
                }
                GzipPhase::Done => return Some(true),
                _ => {
                    if rem.is_empty() {
                        return Some(false);
                    }
                    self.feed_header_byte(rem[0])?;
                    rem = &rem[1..];
                }
            }
        }
    }
}

/// Active decompression stream variant supporting raw deflate, zlib, gzip, and auto-detect.
enum InflateKind {
    /// Raw RFC 1951 deflate stream (`zlib_header = false`).
    Raw(Decompress),
    /// RFC 1950 zlib stream (`zlib_header = true`).
    Zlib(Decompress),
    /// RFC 1952 gzip stream with streaming header and trailer verification.
    Gzip(Box<GzipInflater>),
    /// Buffering at most 1 byte until 2 magic bytes distinguish gzip from zlib.
    AutoPending(Option<u8>),
}

/// Streaming decompressor supporting raw deflate, zlib, gzip, and header auto-detection.
pub struct InflateStream {
    /// Encapsulated decompression state machine.
    kind: InflateKind,
}

impl InflateStream {
    /// Creates an [`InflateStream`] configured for `mode`.
    pub fn new(mode: InflateMode) -> Self {
        let kind = match mode {
            InflateMode::Raw => InflateKind::Raw(Decompress::new(false)),
            InflateMode::Zlib => InflateKind::Zlib(Decompress::new(true)),
            InflateMode::Gzip => InflateKind::Gzip(Box::new(GzipInflater::new())),
            InflateMode::AutoDetect => InflateKind::AutoPending(None),
        };
        Self { kind }
    }

    /// Consumes compressed `input` bytes and returns `Some((decompressed_bytes, eof))`, or `None` on stream error.
    pub fn inflate(&mut self, input: &[u8], capacity_hint: usize) -> Option<(Vec<u8>, bool)> {
        let mut out = Vec::with_capacity(capacity_hint);
        if let InflateKind::AutoPending(first_opt) = &mut self.kind {
            if input.is_empty() {
                return Some((out, false));
            }
            let prev = first_opt.take();
            let second = match prev {
                Some(_) => input[0],
                None if input.len() >= 2 => input[1],
                None => {
                    *first_opt = Some(input[0]);
                    return Some((out, false));
                }
            };
            let first = prev.unwrap_or(input[0]);
            self.kind = if [first, second] == [GZIP_ID1, GZIP_ID2] {
                InflateKind::Gzip(Box::new(GzipInflater::new()))
            } else {
                InflateKind::Zlib(Decompress::new(true))
            };
            if prev.is_some() && self.inflate_inner(&[first], &mut out)? {
                return Some((out, true));
            }
        }

        let eof = self.inflate_inner(input, &mut out)?;
        Some((out, eof))
    }

    /// Dispatches `rem` into the already-resolved inner decompressor.
    fn inflate_inner(&mut self, mut rem: &[u8], out: &mut Vec<u8>) -> Option<bool> {
        match &mut self.kind {
            InflateKind::Raw(dec) | InflateKind::Zlib(dec) => {
                pump_decompress(dec, &mut rem, out, None)
            }
            InflateKind::Gzip(gz) => gz.feed(rem, out),
            InflateKind::AutoPending(_) => None,
        }
    }
}
