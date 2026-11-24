//! `zapret2`-compatible port, ICMP, IP protocol, firewall mark, and packet range filters.

/// Typed configuration parsing errors.
use crate::config::error::ConfigError;

/// Parses a decimal or `0x`/`0X`-prefixed hexadecimal unsigned 32-bit integer.
pub fn parse_u32_radix(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else {
        if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        trimmed.parse::<u32>().ok()
    }
}

/// Parses an unsigned 16-bit decimal port number.
fn parse_u16_decimal(raw: &str) -> Option<u16> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u16>().ok()
}

/// Parses an unsigned 8-bit decimal integer (`type`, `code`, or IP protocol number).
fn parse_u8_decimal(raw: &str) -> Option<u8> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || !trimmed.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u8>().ok()
}

/// Inclusive TCP/UDP port range filter matching `zapret2`'s `port_filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortFilter {
    /// Inclusive lower bound (0 combined with `to == 0` encodes deny-all).
    pub from: u16,
    /// Inclusive upper bound.
    pub to: u16,
    /// Invert range match when `true` (port `0` never matches regardless of `neg`).
    pub neg: bool,
}

impl PortFilter {
    /// Returns a sentinel port filter that denies every port (matches `pf_parse("0")`).
    pub const fn deny_all() -> Self {
        Self {
            from: 0,
            to: 0,
            neg: true,
        }
    }

    /// Parses `[~]p1[-p2]|*` into a [`PortFilter`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        if s == "*" {
            return Ok(Self {
                from: 1,
                to: u16::MAX,
                neg: false,
            });
        }
        let (neg, rest) = match s.strip_prefix('~') {
            Some(stripped) => (true, stripped),
            None => (false, s),
        };
        let (from, to) = if let Some((lhs, rhs)) = rest.split_once('-') {
            let from = parse_u16_decimal(lhs)
                .ok_or_else(|| ConfigError::InvalidPortFilter(raw.to_owned()))?;
            let to = parse_u16_decimal(rhs)
                .ok_or_else(|| ConfigError::InvalidPortFilter(raw.to_owned()))?;
            if from > to {
                return Err(ConfigError::InvalidPortFilter(raw.to_owned()));
            }
            (from, to)
        } else {
            let port = parse_u16_decimal(rest)
                .ok_or_else(|| ConfigError::InvalidPortFilter(raw.to_owned()))?;
            (port, port)
        };
        // C `pf_parse` forces `neg = true` when both bounds are 0 so port 0 denies all traffic.
        let neg = if from == 0 && to == 0 { true } else { neg };
        Ok(Self { from, to, neg })
    }

    /// Returns `true` if non-zero `port` satisfies this filter rule.
    pub const fn matches(self, port: u16) -> bool {
        if port == 0 {
            return false;
        }
        let in_range = (self.from == 0 && self.to == 0) || (port >= self.from && port <= self.to);
        in_range ^ self.neg
    }
}

/// Returns `true` if `filters` is empty or at least one rule matches `port`.
pub fn port_filters_match(filters: &[PortFilter], port: u16) -> bool {
    filters.is_empty() || filters.iter().any(|pf| pf.matches(port))
}

/// Wildcard vs explicit filter mode matching `FLTMODE_*` in `zapret2/nfq2/filter.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterMode {
    /// Reject every packet (`"-"`).
    Skip,
    /// Accept every packet (`"*"`).
    Any,
    /// Match concrete type/code or protocol values.
    Filter,
}

/// ICMPv4 / ICMPv6 type and optional code filter matching `zapret2`'s `icmp_filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpFilter {
    /// Filter evaluation mode (`Skip`, `Any`, or `Filter`).
    pub mode: FilterMode,
    /// Required ICMP message type when `mode == FilterMode::Filter`.
    pub icmp_type: u8,
    /// Optional required ICMP code when specified as `type:code`.
    pub code: Option<u8>,
}

impl IcmpFilter {
    /// Returns a sentinel ICMP filter that rejects all ICMP packets (`"-"`).
    pub const fn skip() -> Self {
        Self {
            mode: FilterMode::Skip,
            icmp_type: 0,
            code: None,
        }
    }

    /// Parses `*`, `-`, `type`, or `type:code` into an [`IcmpFilter`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        match s {
            "*" => Ok(Self {
                mode: FilterMode::Any,
                icmp_type: 0,
                code: None,
            }),
            "-" => Ok(Self::skip()),
            _ => {
                if let Some((type_str, code_str)) = s.split_once(':') {
                    let icmp_type = parse_u8_decimal(type_str)
                        .ok_or_else(|| ConfigError::InvalidIcmpFilter(raw.to_owned()))?;
                    let code = parse_u8_decimal(code_str)
                        .ok_or_else(|| ConfigError::InvalidIcmpFilter(raw.to_owned()))?;
                    Ok(Self {
                        mode: FilterMode::Filter,
                        icmp_type,
                        code: Some(code),
                    })
                } else {
                    let icmp_type = parse_u8_decimal(s)
                        .ok_or_else(|| ConfigError::InvalidIcmpFilter(raw.to_owned()))?;
                    Ok(Self {
                        mode: FilterMode::Filter,
                        icmp_type,
                        code: None,
                    })
                }
            }
        }
    }

    /// Returns `true` if `(icmp_type, icmp_code)` matches this filter rule.
    pub fn matches(self, icmp_type: u8, icmp_code: u8) -> bool {
        match self.mode {
            FilterMode::Any => true,
            FilterMode::Skip => false,
            FilterMode::Filter => {
                self.icmp_type == icmp_type && self.code.is_none_or(|c| c == icmp_code)
            }
        }
    }
}

/// Returns `true` if `filters` is empty or at least one rule matches `(icmp_type, icmp_code)`.
pub fn icmp_filters_match(filters: &[IcmpFilter], icmp_type: u8, icmp_code: u8) -> bool {
    filters.is_empty() || filters.iter().any(|icf| icf.matches(icmp_type, icmp_code))
}

/// IP protocol number filter matching `zapret2`'s `ipp_filter`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IppFilter {
    /// Filter evaluation mode (`Skip`, `Any`, or `Filter`).
    pub mode: FilterMode,
    /// Required IP protocol number when `mode == FilterMode::Filter`.
    pub proto: u8,
}

impl IppFilter {
    /// Returns a sentinel IP protocol filter that rejects all non-TCP/UDP/ICMP protocols (`"-"`).
    pub const fn skip() -> Self {
        Self {
            mode: FilterMode::Skip,
            proto: 0xFF,
        }
    }

    /// Parses `*`, `-`, or decimal protocol number `0..=255` into an [`IppFilter`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        match s {
            "*" => Ok(Self {
                mode: FilterMode::Any,
                proto: 0xFF,
            }),
            "-" => Ok(Self::skip()),
            _ => {
                let proto = parse_u8_decimal(s)
                    .ok_or_else(|| ConfigError::InvalidIppFilter(raw.to_owned()))?;
                Ok(Self {
                    mode: FilterMode::Filter,
                    proto,
                })
            }
        }
    }

    /// Returns `true` if `proto` satisfies this filter rule.
    pub const fn matches(self, proto: u8) -> bool {
        match self.mode {
            FilterMode::Any => true,
            FilterMode::Skip => false,
            FilterMode::Filter => self.proto == proto,
        }
    }
}

/// Returns `true` if `filters` is empty or at least one rule matches `proto`.
pub fn ipp_filters_match(filters: &[IppFilter], proto: u8) -> bool {
    filters.is_empty() || filters.iter().any(|ipp| ipp.matches(proto))
}

/// Masked firewall mark matcher (`(fwmark & mask) == mark`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MarkFilter {
    /// Expected masked mark value.
    pub mark: u32,
    /// Bitmask applied before comparison (`0` disables mark filtering).
    pub mask: u32,
}

impl MarkFilter {
    /// Parses `mark` or `mark/mask` (decimal or `0x` hex) into a [`MarkFilter`].
    pub fn parse(raw: &str) -> Result<Self, ConfigError> {
        let s = raw.trim();
        if let Some((mark_str, mask_str)) = s.split_once('/') {
            let mark = parse_u32_radix(mark_str)
                .ok_or_else(|| ConfigError::InvalidMarkFilter(raw.to_owned()))?;
            let mask = parse_u32_radix(mask_str)
                .ok_or_else(|| ConfigError::InvalidMarkFilter(raw.to_owned()))?;
            Ok(Self { mark, mask })
        } else {
            let mark = parse_u32_radix(s)
                .ok_or_else(|| ConfigError::InvalidMarkFilter(raw.to_owned()))?;
            Ok(Self {
                mark,
                mask: u32::MAX,
            })
        }
    }

    /// Returns `true` if `fwmark` satisfies `(fwmark & self.mask) == self.mark`.
    pub const fn matches(self, fwmark: u32) -> bool {
        (fwmark & self.mask) == self.mark
    }
}

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
