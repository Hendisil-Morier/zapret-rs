//! Continuous in-order TCP/UDP payload stream reassembler matching `zapret2/nfq2/conntrack.c`.

/// Maximum allowed negative overlap or forward sequence delta (`0x100000` = 1 MiB)
/// before treating a segment as an unsupported out-of-order gap or wraparound mismatch.
const REASM_MAX_NEG: u32 = 0x0010_0000;

/// Linear reassembly buffer accumulating contiguous payload bytes up to an expected message size.
///
/// Mirrors `t_reassemble` in `conntrack.h`: does not support forward out-of-order gaps, handles
/// overlapping retransmissions safely by overwriting old bytes, and detects exact completion.
#[derive(Debug, Default, Clone)]
pub struct StreamReassembler {
    /// Pre-allocated contiguous storage sized to `size` bytes while a session is active.
    buf: Vec<u8>,
    /// Next expected 32-bit sequence number (or cumulative byte offset for UDP streams).
    seq: u32,
    /// Target complete message length requested when the reassembly session started.
    size: usize,
    /// Number of contiguous valid bytes written at the start of `buf`.
    size_present: usize,
}

impl StreamReassembler {
    /// Starts a fresh reassembly session expecting `size_requested` total bytes starting at `seq_start`.
    pub fn init(&mut self, size_requested: usize, seq_start: u32) {
        self.buf.clear();
        self.buf.resize(size_requested, 0);
        self.seq = seq_start;
        self.size = size_requested;
        self.size_present = 0;
    }

    /// Resets the reassembly session to empty and releases buffered payload bytes.
    pub fn clear(&mut self) {
        self.buf = Vec::new();
        self.seq = 0;
        self.size = 0;
        self.size_present = 0;
    }

    /// Returns `true` when no reassembly session is active (`size == 0`).
    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// Returns `true` when an active reassembly session has collected all `size` expected bytes.
    pub const fn is_full(&self) -> bool {
        !self.is_empty() && self.size == self.size_present
    }

    /// Returns `true` if `len` additional new bytes fit within the target `size`.
    pub const fn has_space(&self, len: usize) -> bool {
        self.size.saturating_sub(self.size_present) >= len
    }

    /// Returns the total expected message size for the active session (`0` if inactive).
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns how many contiguous bytes are currently present in the buffer.
    pub const fn size_present(&self) -> usize {
        self.size_present
    }

    /// Returns the next expected sequence number (`seq`) for the stream.
    pub const fn seq(&self) -> u32 {
        self.seq
    }

    /// Returns the currently reassembled contiguous payload slice (`buf[..size_present]`).
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.size_present]
    }

    /// Feeds one payload chunk arriving at sequence `seq` into the active reassembly buffer.
    ///
    /// Returns `false` if no session is active, if `seq` opens an unsupported forward gap
    /// (`0 < dseq < 1 MiB`), if `seq` trails too far behind (`> 1 MiB`), or if payload overflows `size`.
    pub fn feed(&mut self, seq: u32, payload: &[u8]) -> bool {
        if self.size == 0 {
            return false;
        }
        if payload.is_empty() {
            return true;
        }

        let dseq = seq.wrapping_sub(self.seq);
        if dseq != 0 && dseq < REASM_MAX_NEG {
            return false;
        }

        let mut neg_overlap = self.seq.wrapping_sub(seq);
        if neg_overlap > REASM_MAX_NEG {
            return false;
        }

        let szignore = (neg_overlap as usize).saturating_sub(self.size_present);
        if szignore >= payload.len() {
            return true;
        }

        let szcopy = payload.len() - szignore;
        neg_overlap -= szignore as u32;
        let neg_usize = neg_overlap as usize;
        let write_off = self.size_present - neg_usize;

        if write_off + szcopy > self.size {
            return false;
        }

        self.buf[write_off..write_off + szcopy].copy_from_slice(&payload[szignore..]);

        if szcopy > neg_usize {
            let delta = szcopy - neg_usize;
            self.size_present += delta;
            self.seq = self.seq.wrapping_add(delta as u32);
        }

        true
    }
}
