//! Bounds-checked big-endian cursor for sequentially reading packet bytes.

/// Typed packet parsing error returned on truncation.
use crate::packet::error::PacketError;

/// Bounds-checked reader over a borrowed network packet byte slice.
pub struct ByteReader<'a> {
    /// Underlying packet byte slice.
    data: &'a [u8],
    /// Current read cursor offset in bytes.
    pos: usize,
}

/// Convenience result alias for packet parsing operations.
pub type PEResult<T> = Result<T, PacketError>;

impl<'a> ByteReader<'a> {
    /// Creates a new `ByteReader` positioned at byte 0 of `data`.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// Returns the current byte offset of the reader cursor.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// Borrows the next `len` bytes and advances `pos`, returning `Truncated` on overflow or EOF.
    pub fn read_bytes(&mut self, len: usize) -> PEResult<&'a [u8]> {
        let end = self.pos.checked_add(len).ok_or(PacketError::Truncated)?;

        let slice = self.data.get(self.pos..end).ok_or(PacketError::Truncated)?;

        self.pos = end;

        Ok(slice)
    }

    /// Reads an exact fixed-size array `[u8; N]` and advances `pos`.
    pub fn read_array<const N: usize>(&mut self) -> PEResult<[u8; N]> {
        self.read_bytes(N)?
            .try_into()
            .map_err(|_| PacketError::Truncated)
    }

    /// Reads the next single unsigned byte (`u8`).
    pub fn read_u8(&mut self) -> PEResult<u8> {
        let byte = self.read_bytes(1)?[0];

        Ok(byte)
    }

    /// Reads the next big-endian `u16`.
    pub fn read_u16(&mut self) -> PEResult<u16> {
        let b = self.read_array::<2>()?;

        Ok(u16::from_be_bytes(b))
    }

    /// Reads the next big-endian `u32`.
    pub fn read_u32(&mut self) -> PEResult<u32> {
        let b = self.read_array::<4>()?;

        Ok(u32::from_be_bytes(b))
    }

    /// Advances the cursor by `len` bytes without returning the skipped slice.
    pub fn skip(&mut self, len: usize) -> PEResult<()> {
        self.read_bytes(len).map(|_| ())
    }

    /// Returns all unread bytes remaining past `pos`.
    pub fn remaining(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }

    /// Shrinks the readable end of the buffer to `max_len`, dropping trailing link-layer padding.
    pub fn truncate(&mut self, max_len: usize) -> PEResult<()> {
        if max_len > self.data.len() || max_len < self.pos {
            return Err(PacketError::Truncated);
        }

        self.data = &self.data[..max_len];

        Ok(())
    }
}
