//! Packet position counter axis and range filter parsers matching `zapret2/nfq2/filter.c`.

/// Typed configuration parsing errors returned when packet range tokens are malformed.
use crate::config::error::ConfigError;

/// Position axis selector matching `zapret2`'s `packet_pos.mode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketPosMode {
    /// Total packet count (`n`).
    PacketNum,
    /// Data-bearing packet count (`d`).
    DataPacketNum,
    /// Relative TCP sequence number (`s`).
    RelSeq,
    /// Relative TCP data payload position (`p`).
    DataRelSeq,
    /// Cumulative transferred byte count (`b`).
    ByteCount,
    /// Match nothing (`x`).
    Never,
    /// Unbounded match (`a`).
    Always,
}

impl PacketPosMode {
    /// Returns the single-character mode identifier exposed to Lua (`n`, `d`, `s`, `p`, `b`, `x`, `a`).
    pub const fn as_char(self) -> char {
        match self {
            Self::PacketNum => 'n',
            Self::DataPacketNum => 'd',
            Self::RelSeq => 's',
            Self::DataRelSeq => 'p',
            Self::ByteCount => 'b',
            Self::Never => 'x',
            Self::Always => 'a',
        }
    }
}

/// Lower or upper bound inside a [`PacketRange`] expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketPos {
    /// Position counter axis or wildcard sentinel.
    pub mode: PacketPosMode,
    /// Numeric threshold along `mode` (`0` for `Never` and `Always`).
    pub pos: u32,
}

impl PacketPos {
    /// Sentinel position representing `x0` (never match).
    pub const NEVER: Self = Self {
        mode: PacketPosMode::Never,
        pos: 0,
    };
    /// Sentinel position representing `a0` (unbounded endpoint).
    pub const ALWAYS: Self = Self {
        mode: PacketPosMode::Always,
        pos: 0,
    };

    /// Parses one packet position token (`x`, `a`, or `<mode><u32>`).
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        let mut chars = s.chars();
        let Some(first) = chars.next() else {
            return Err(ConfigError::InvalidPacketRange(raw.to_owned()));
        };
        let rest = chars.as_str();
        let mode = match first {
            'n' => PacketPosMode::PacketNum,
            'd' => PacketPosMode::DataPacketNum,
            's' => PacketPosMode::RelSeq,
            'p' => PacketPosMode::DataRelSeq,
            'b' => PacketPosMode::ByteCount,
            'x' => PacketPosMode::Never,
            'a' => PacketPosMode::Always,
            _ => return Err(ConfigError::InvalidPacketRange(raw.to_owned())),
        };
        if matches!(mode, PacketPosMode::Never | PacketPosMode::Always) {
            if !rest.is_empty() {
                return Err(ConfigError::InvalidPacketRange(raw.to_owned()));
            }
            return Ok(Self { mode, pos: 0 });
        }
        let pos = parse_u32_radix_decimal_only(rest)
            .ok_or_else(|| ConfigError::InvalidPacketRange(raw.to_owned()))?;
        Ok(Self { mode, pos })
    }
}

/// Parses strict unsigned decimal digits without sign or hex prefixes.
fn parse_u32_radix_decimal_only(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse::<u32>().ok()
}

/// Inclusive or exclusive packet range filter matching `zapret2`'s `packet_range`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketRange {
    /// Inclusive starting position.
    pub from: PacketPos,
    /// Ending position (inclusive when `!upper_cutoff`, exclusive when `upper_cutoff`).
    pub to: PacketPos,
    /// Exclusive upper bound flag set when `<` separates `from` and `to`.
    pub upper_cutoff: bool,
}

impl PacketRange {
    /// Range that never matches any packet (`x` .. `x`, default for `in_range`).
    pub const NEVER: Self = Self {
        from: PacketPos::NEVER,
        to: PacketPos::NEVER,
        upper_cutoff: false,
    };
    /// Range that always matches every packet (`a` .. `a`, default for `out_range`).
    pub const ALWAYS: Self = Self {
        from: PacketPos::ALWAYS,
        to: PacketPos::ALWAYS,
        upper_cutoff: false,
    };

    /// Evaluates whether this range matches without connection tracking (`'a'..'a'` only).
    pub const fn matches_without_conntrack(self) -> bool {
        // shortcut: without Milestone 3 conntrack positions, only 'a'..'a' matches (identical to check_pos_range(NULL, range) in zapret2/nfq2/desync.c:683-723).
        matches!(self.from.mode, PacketPosMode::Always)
            && matches!(self.to.mode, PacketPosMode::Always)
    }

    /// Parses `<pos>(-|<)<pos>`, `-<pos>`, `<pos>-`, `x`, or `a` into a [`PacketRange`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(ConfigError::InvalidPacketRange(raw.to_owned()));
        }
        if let Some(rest) = s.strip_prefix('-').or_else(|| s.strip_prefix('<')) {
            let upper_cutoff = s.starts_with('<');
            let to = if rest.is_empty() {
                PacketPos::ALWAYS
            } else {
                PacketPos::parse(rest)?
            };
            return Ok(Self {
                from: PacketPos::ALWAYS,
                to,
                upper_cutoff,
            });
        }
        if let Some(sep_idx) = s.find(['-', '<']) {
            let from = PacketPos::parse(&s[..sep_idx])?;
            if from.mode == PacketPosMode::Never {
                return Err(ConfigError::InvalidPacketRange(raw.to_owned()));
            }
            let sep = s.as_bytes()[sep_idx] as char;
            let rest = &s[sep_idx + 1..];
            let to = if rest.is_empty() {
                PacketPos::ALWAYS
            } else {
                PacketPos::parse(rest)?
            };
            Ok(Self {
                from,
                to,
                upper_cutoff: sep == '<',
            })
        } else {
            let from = PacketPos::parse(s)?;
            match from.mode {
                PacketPosMode::Never => Ok(Self::NEVER),
                PacketPosMode::Always => Ok(Self::ALWAYS),
                _ => Err(ConfigError::InvalidPacketRange(raw.to_owned())),
            }
        }
    }
}
