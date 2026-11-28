//! Bounded newline-delimited JSON codec for control socket messages.

/// Buffered incremental line reading and atomic line writing over stream transports.
use std::io::{BufRead, Write};

/// Serde traits for encoding outgoing and decoding incoming JSON frames.
use serde::{Serialize, de::DeserializeOwned};

/// Hard maximum byte length permitted for one newline-delimited control frame (64 KiB).
pub const MAX_CONTROL_LINE_BYTES: usize = 64 * 1024;

/// Typed errors produced by control frame encoding, reading, or version validation.
#[derive(Debug, thiserror::Error)]
pub enum CodecError
{
    /// Incoming or outgoing frame exceeded [`MAX_CONTROL_LINE_BYTES`].
    #[error("control frame exceeds maximum length of {max} bytes")]
    LineTooLong
    {
        /// Maximum byte limit that was exceeded.
        max: usize,
    },
    /// JSON serialization or deserialization failed.
    #[error("malformed control JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Underlying socket or stream I/O failed.
    #[error("control stream I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Negotiated protocol version does not match the supported version.
    #[error("unsupported control protocol version {got} (expected {expected})")]
    UnsupportedVersion
    {
        /// Protocol version supported by this build.
        expected: u32,
        /// Protocol version offered by the remote peer.
        got: u32,
    },
}

/// Serializes `msg` into a single newline-terminated JSON byte buffer within [`MAX_CONTROL_LINE_BYTES`].
pub fn encode_line<T: Serialize>(msg: &T) -> Result<Vec<u8>, CodecError>
{
    let mut buf = serde_json::to_vec(msg)?;
    if buf.len() >= MAX_CONTROL_LINE_BYTES
    {
        return Err(CodecError::LineTooLong { max: MAX_CONTROL_LINE_BYTES });
    }
    buf.push(b'\n');
    Ok(buf)
}

/// Encodes `msg` as a bounded JSON line and flushes it into `writer`.
pub fn write_message<W: Write, T: Serialize>(writer: &mut W, msg: &T) -> Result<(), CodecError>
{
    let line = encode_line(msg)?;
    writer.write_all(&line)?;
    writer.flush()?;
    Ok(())
}

/// Decodes one trimmed JSON line (bounded by [`MAX_CONTROL_LINE_BYTES`]) into `T`.
pub fn decode_line<T: DeserializeOwned>(line: &str) -> Result<T, CodecError>
{
    if line.len() > MAX_CONTROL_LINE_BYTES
    {
        return Err(CodecError::LineTooLong { max: MAX_CONTROL_LINE_BYTES });
    }
    Ok(serde_json::from_str(line.trim_end_matches(['\r', '\n']))?)
}

/// Reads a single newline-terminated UTF-8 line from `reader` without exceeding `max_bytes`.
pub fn read_bounded_line<R: BufRead>(reader: &mut R, max_bytes: usize) -> Result<Option<String>, CodecError>
{
    LineReader::with_max_bytes(reader, max_bytes).read_line()
}

/// Reads and deserializes the next bounded JSON line from `reader`, returning `None` on EOF.
pub fn read_message<R: BufRead, T: DeserializeOwned>(reader: &mut R) -> Result<Option<T>, CodecError>
{
    LineReader::new(reader).read_message()
}

/// Stateful newline-delimited frame reader retaining partial bytes across `TimedOut`/`WouldBlock` polls.
pub struct LineReader<R>
{
    /// Underlying buffered stream reader.
    reader: R,
    /// Persistent accumulation buffer holding incomplete frames across poll timeouts.
    buf: Vec<u8>,
    /// Maximum allowed byte length per frame (including line terminator).
    max_bytes: usize,
}

impl<R: BufRead> LineReader<R>
{
    /// Wraps `reader` with the default [`MAX_CONTROL_LINE_BYTES`] frame limit.
    pub fn new(reader: R) -> Self
    {
        Self::with_max_bytes(reader, MAX_CONTROL_LINE_BYTES)
    }

    /// Wraps `reader` with an explicit maximum frame limit `max_bytes`.
    pub fn with_max_bytes(reader: R, max_bytes: usize) -> Self
    {
        Self { reader, buf: Vec::new(), max_bytes }
    }

    /// Returns a shared reference to the underlying buffered reader.
    pub fn get_ref(&self) -> &R
    {
        &self.reader
    }

    /// Returns a mutable reference to the underlying buffered reader.
    pub fn get_mut(&mut self) -> &mut R
    {
        &mut self.reader
    }

    /// Reads one complete newline-terminated UTF-8 line, preserving partial bytes on timeouts.
    pub fn read_line(&mut self) -> Result<Option<String>, CodecError>
    {
        let mut raw = loop
        {
            let available = match self
                .reader
                .fill_buf()
            {
                Ok(chunk) => chunk,
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(CodecError::Io(err)),
            };
            if available.is_empty()
            {
                if self
                    .buf
                    .is_empty()
                {
                    return Ok(None);
                }
                break std::mem::take(&mut self.buf);
            }
            if let Some(pos) = available
                .iter()
                .position(|&b| b == b'\n')
            {
                let take = pos + 1;
                if self
                    .buf
                    .len()
                    + take
                    > self.max_bytes
                {
                    self.buf
                        .clear();
                    self.reader
                        .consume(take);
                    return Err(CodecError::LineTooLong { max: self.max_bytes });
                }
                self.buf
                    .extend_from_slice(&available[..pos]);
                self.reader
                    .consume(take);
                break std::mem::take(&mut self.buf);
            }
            let chunk_len = available.len();
            if self
                .buf
                .len()
                + chunk_len
                > self.max_bytes
            {
                self.buf
                    .clear();
                self.reader
                    .consume(chunk_len);
                return Err(CodecError::LineTooLong { max: self.max_bytes });
            }
            self.buf
                .extend_from_slice(available);
            self.reader
                .consume(chunk_len);
        };
        if raw.last() == Some(&b'\r')
        {
            raw.pop();
        }
        let text = String::from_utf8(raw)
            .map_err(|err| CodecError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, err)))?;
        Ok(Some(text))
    }

    /// Reads and deserializes the next JSON line frame from `self`, returning `None` on EOF.
    pub fn read_message<T: DeserializeOwned>(&mut self) -> Result<Option<T>, CodecError>
    {
        let Some(line) = self.read_line()?
        else
        {
            return Ok(None);
        };
        Ok(Some(serde_json::from_str(&line)?))
    }
}
