//! IPv4 and IPv6 subnet aggregation engine compatible with `zapret2/ip2net/ip2net.c`.

/// Buffered line input and output writer traits for streaming stdin/stdout processing.
use std::io::{BufRead, Write};
/// Canonical IPv4 and IPv6 address parsers and RFC 5952 formatters.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Typed error derivation for CLI option parsing and streaming I/O failures.
use thiserror::Error;

/// Default minimum IPv4 fill numerator (`3/4` = 75%).
pub const DEFAULT_V4_MUL: u32 = 3;
/// Default minimum IPv4 fill denominator (`3/4` = 75%).
pub const DEFAULT_V4_DIV: u32 = 4;
/// Default widest IPv4 host-bit count (`zct = 10`, corresponding to `/22`).
pub const DEFAULT_V4_ZCT_MAX: u32 = 10;
/// Default narrowest IPv4 host-bit count (`zct = 2`, corresponding to `/30`).
pub const DEFAULT_V4_ZCT_MIN: u32 = 2;
/// Default widest IPv6 host-bit count (`zct = 72`, corresponding to `/56`).
pub const DEFAULT_V6_ZCT_MAX: u32 = 72;
/// Default narrowest IPv6 host-bit count (`zct = 64`, corresponding to `/64`).
pub const DEFAULT_V6_ZCT_MIN: u32 = 64;
/// Default minimum distinct IPv6 addresses required to collapse a prefix (`5`).
pub const DEFAULT_V6_THRESHOLD: u32 = 5;

/// Errors returned while validating `ip2net` parameters or streaming I/O.
#[derive(Debug, Error)]
pub enum Ip2NetError
{
    /// `--prefix-length` argument was outside `1..=31` (v4) or `1..=127` (v6), inverted, or malformed.
    #[error("invalid parameter for prefix-length : {0}")]
    InvalidPrefixLength(String),
    /// `--v4-threshold` argument did not match `mul/div` with `div >= 2` and `1 <= mul < div`.
    #[error("invalid parameter for v4-threshold : {0}")]
    InvalidV4Threshold(String),
    /// `--v6-threshold` argument was non-numeric or less than `1`.
    #[error("invalid parameter for v6-threshold : {0}")]
    InvalidV6Threshold(String),
    /// Underlying buffered reader or writer I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
}

/// Address family processed by `ip2net`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ip2NetFamily
{
    /// IPv4 aggregation mode (`-4`, default).
    Ipv4,
    /// IPv6 aggregation mode (`-6`).
    Ipv6,
}

impl Ip2NetFamily
{
    /// Returns the total host-address bit width (`32` for IPv4, `128` for IPv6).
    const fn total_bits(self) -> u32
    {
        match self
        {
            Self::Ipv4 => 32,
            Self::Ipv6 => 128,
        }
    }

    /// Returns the largest permitted grouping prefix length (`31` for IPv4, `127` for IPv6).
    const fn max_prefix_len(self) -> u32
    {
        self.total_bits() - 1
    }

    /// Returns the default `(zct_min, zct_max)` host-bit search range for this family.
    const fn default_zct_range(self) -> (u32, u32)
    {
        match self
        {
            Self::Ipv4 => (DEFAULT_V4_ZCT_MIN, DEFAULT_V4_ZCT_MAX),
            Self::Ipv6 => (DEFAULT_V6_ZCT_MIN, DEFAULT_V6_ZCT_MAX),
        }
    }
}

/// Validated configuration governing `ip2net` subnet collapsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ip2NetConfig
{
    /// Active IP family (`Ipv4` or `Ipv6`).
    pub family: Ip2NetFamily,
    /// Smallest zero-bit suffix length tried during aggregation (`bits - plen_max`).
    pub zct_min: u32,
    /// Largest zero-bit suffix length tried during aggregation (`bits - plen_min`).
    pub zct_max: u32,
    /// IPv4 fill numerator (`mul` in `mul/div`).
    pub v4_mul: u32,
    /// IPv4 fill denominator (`div` in `mul/div`).
    pub v4_div: u32,
    /// Minimum distinct IPv6 hosts needed to form a candidate subnet.
    pub v6_threshold: u32,
}

impl Default for Ip2NetConfig
{
    /// Returns the default IPv4 configuration (`/22..=/30`, `3/4` threshold, v6 threshold `5`).
    fn default() -> Self
    {
        let (zct_min, zct_max) = Ip2NetFamily::Ipv4.default_zct_range();
        Self {
            family: Ip2NetFamily::Ipv4,
            zct_min,
            zct_max,
            v4_mul: DEFAULT_V4_MUL,
            v4_div: DEFAULT_V4_DIV,
            v6_threshold: DEFAULT_V6_THRESHOLD,
        }
    }
}

impl Ip2NetConfig
{
    /// Validates raw CLI string options after `-4`/`-6` resolution so flag order does not matter.
    pub fn from_options(
        family: Ip2NetFamily,
        prefix_length: Option<&str>,
        v4_threshold: Option<&str>,
        v6_threshold: Option<&str>,
    ) -> Result<Self, Ip2NetError>
    {
        let (zct_min, zct_max) = match prefix_length
        {
            Some(spec) => parse_prefix_length(spec, family)?,
            None => family.default_zct_range(),
        };
        let (v4_mul, v4_div) =
            v4_threshold.map_or(Ok((DEFAULT_V4_MUL, DEFAULT_V4_DIV)), parse_v4_threshold)?;
        let v6_threshold = v6_threshold.map_or(Ok(DEFAULT_V6_THRESHOLD), parse_v6_threshold)?;
        Ok(Self { family, zct_min, zct_max, v4_mul, v4_div, v6_threshold })
    }
}

/// Parses `--prefix-length=min[-max]` for `family`, returning `(zct_min, zct_max)`.
pub fn parse_prefix_length(spec: &str, family: Ip2NetFamily) -> Result<(u32, u32), Ip2NetError>
{
    let invalid = || Ip2NetError::InvalidPrefixLength(spec.to_string());
    let (plen1, plen2) = match spec.split_once('-')
    {
        Some((left, right)) => (
            left.parse::<u32>()
                .map_err(|_| invalid())?,
            right
                .parse::<u32>()
                .map_err(|_| invalid())?,
        ),
        None =>
        {
            let single = spec
                .parse::<u32>()
                .map_err(|_| invalid())?;
            (single, single)
        }
    };
    if plen1 == 0 || plen2 < plen1 || plen2 > family.max_prefix_len()
    {
        return Err(invalid());
    }
    let total = family.total_bits();
    Ok((total - plen2, total - plen1))
}

/// Parses `--v4-threshold=mul/div`, enforcing `div >= 2` and `1 <= mul < div`.
pub fn parse_v4_threshold(spec: &str) -> Result<(u32, u32), Ip2NetError>
{
    let invalid = || Ip2NetError::InvalidV4Threshold(spec.to_string());
    let (mul_s, div_s) = spec
        .split_once('/')
        .ok_or_else(invalid)?;
    let mul = mul_s
        .parse::<u32>()
        .map_err(|_| invalid())?;
    let div = div_s
        .parse::<u32>()
        .map_err(|_| invalid())?;
    if div < 2 || mul < 1 || mul >= div
    {
        return Err(invalid());
    }
    Ok((mul, div))
}

/// Parses `--v6-threshold=N`, enforcing `N >= 1`.
pub fn parse_v6_threshold(spec: &str) -> Result<u32, Ip2NetError>
{
    let n = spec
        .parse::<u32>()
        .map_err(|_| Ip2NetError::InvalidV6Threshold(spec.to_string()))?;
    if n < 1
    {
        return Err(Ip2NetError::InvalidV6Threshold(spec.to_string()));
    }
    Ok(n)
}

/// Tracks the narrowest prefix length covering the largest contiguous slice of sorted IPs.
struct BestCoverage
{
    /// Largest qualifying host count found so far at `pos`.
    ip_ct: usize,
    /// Host-bit count (`zct`) achieving `ip_ct`; `0` when no subnet met the threshold.
    zct: u32,
    /// Next slice index immediately following the covered subnet.
    pos_end: usize,
}

impl BestCoverage
{
    /// Initializes an empty candidate covering only the single host at `pos`.
    const fn single(pos: usize) -> Self
    {
        Self { ip_ct: 0, zct: 0, pos_end: pos + 1 }
    }

    /// Updates best candidate to prefer smaller subnets covering the same host count.
    fn record(&mut self, ip_ct: usize, zct: u32, next_pos: usize) -> bool
    {
        if self.ip_ct != 0 && ip_ct != self.ip_ct
        {
            // Smaller prefixes cannot equal an already larger multi-subnet coverage.
            return false;
        }
        self.ip_ct = ip_ct;
        self.zct = zct;
        self.pos_end = next_pos;
        true
    }
}

/// Returns `(subnet_ct, mul, div)` promoted to `u64` so `/1` arithmetic never overflows.
fn v4_ratio(mask: u32, cfg: &Ip2NetConfig) -> (u64, u64, u64)
{
    (u64::from(!mask) + 1, u64::from(cfg.v4_mul), u64::from(cfg.v4_div))
}

/// Family-specific bitmask, threshold, and address conversion contract for subnet collapsing.
trait CollapseInt: Copy + Ord
{
    /// Total bit width of the address (`32` for IPv4, `128` for IPv6).
    const BITS: u32;
    /// Returns `(ip_start, ip_end, mask)` for a candidate network with `zct` trailing host bits.
    fn bounds(self, zct: u32) -> (Self, Self, Self);
    /// Returns `false` when `self` exceeds the fast-prune fill boundary for `mask`.
    fn can_fill(self, ip_start: Self, mask: Self, cfg: &Ip2NetConfig) -> bool;
    /// Returns `true` when `ip_ct` covered hosts meet the configured threshold for `mask`.
    fn meets_threshold(mask: Self, ip_ct: usize, cfg: &Ip2NetConfig) -> bool;
    /// Converts the host integer back into a printable `IpAddr`.
    fn into_ip(self) -> IpAddr;
}

impl CollapseInt for u32
{
    const BITS: u32 = 32;

    fn bounds(self, zct: u32) -> (Self, Self, Self)
    {
        let mask = if zct < 32 { !((1u32 << zct) - 1) } else { 0 };
        let ip_start = self & mask;
        (ip_start, ip_start | !mask, mask)
    }

    fn can_fill(self, ip_start: Self, mask: Self, cfg: &Ip2NetConfig) -> bool
    {
        let (subnet_ct, mul, div) = v4_ratio(mask, cfg);
        u64::from(self) <= u64::from(ip_start) + subnet_ct * (div - mul) / div
    }

    fn meets_threshold(mask: Self, ip_ct: usize, cfg: &Ip2NetConfig) -> bool
    {
        let (subnet_ct, mul, div) = v4_ratio(mask, cfg);
        (ip_ct as u64) >= (subnet_ct * mul / div)
    }

    fn into_ip(self) -> IpAddr
    {
        IpAddr::V4(Ipv4Addr::from(self))
    }
}

impl CollapseInt for u128
{
    const BITS: u32 = 128;

    fn bounds(self, zct: u32) -> (Self, Self, Self)
    {
        let mask = if zct < 128 { !0u128 << zct } else { 0 };
        let ip_start = self & mask;
        (ip_start, ip_start | !mask, mask)
    }

    fn can_fill(self, _ip_start: Self, _mask: Self, _cfg: &Ip2NetConfig) -> bool
    {
        true
    }

    fn meets_threshold(_mask: Self, ip_ct: usize, cfg: &Ip2NetConfig) -> bool
    {
        ip_ct >= cfg.v6_threshold as usize
    }

    fn into_ip(self) -> IpAddr
    {
        IpAddr::V6(Ipv6Addr::from(self))
    }
}

/// Reads lines sequentially from `reader`, skipping invalid non-UTF-8 byte sequences.
fn for_each_utf8_line<R: BufRead>(
    reader: &mut R,
    mut on_line: impl FnMut(&str) -> Result<(), Ip2NetError>,
) -> Result<(), Ip2NetError>
{
    let mut raw = Vec::with_capacity(256);
    loop
    {
        raw.clear();
        if reader.read_until(b'\n', &mut raw)? == 0
        {
            break;
        }
        if let Ok(text) = std::str::from_utf8(&raw)
        {
            on_line(text)?;
        }
    }
    Ok(())
}

/// Sorts, deduplicates, and greedily collapses single host integers into minimal CIDRs.
fn collapse_sorted<T: CollapseInt, W: Write>(
    cfg: &Ip2NetConfig,
    ips: &mut Vec<T>,
    writer: &mut W,
) -> Result<(), Ip2NetError>
{
    ips.sort_unstable();
    ips.dedup();
    let mut pos = 0usize;
    while pos < ips.len()
    {
        let base_ip = ips[pos];
        let mut best = BestCoverage::single(pos);

        for zct in (cfg.zct_min..=cfg.zct_max).rev()
        {
            let (ip_start, ip_end, mask) = base_ip.bounds(zct);
            if !base_ip.can_fill(ip_start, mask, cfg)
            {
                continue;
            }
            let ip_ct = ips[pos..].partition_point(|&candidate| candidate <= ip_end);
            if ip_ct == 1
            {
                break;
            }
            if T::meets_threshold(mask, ip_ct, cfg) && !best.record(ip_ct, zct, pos + ip_ct)
            {
                break;
            }
        }

        if best.zct > 0
        {
            let (net, _, _) = base_ip.bounds(best.zct);
            writeln!(writer, "{}/{}", net.into_ip(), T::BITS - best.zct)?;
        }
        else
        {
            writeln!(writer, "{}", base_ip.into_ip())?;
            best.pos_end = pos + 1;
        }
        pos = best.pos_end;
    }
    Ok(())
}

/// Processes IPv4 addresses, subnets, and ranges and emits aggregated CIDRs to `writer`.
fn run_ipv4<R: BufRead, W: Write>(
    cfg: &Ip2NetConfig,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Ip2NetError>
{
    let mut ips: Vec<u32> = Vec::new();
    for_each_utf8_line(reader, |text| {
        let line = text.trim();
        if line.is_empty()
        {
            return Ok(());
        }
        if let Some((left, right)) = line.split_once('-')
        {
            if let (Ok(a), Ok(b)) = (left.parse::<Ipv4Addr>(), right.parse::<Ipv4Addr>())
            {
                writeln!(writer, "{a}-{b}")?;
            }
            return Ok(());
        }
        if let Some((ip_s, mask_s)) = line.split_once('/')
        {
            if let (Ok(ip), Ok(mask)) = (ip_s.parse::<Ipv4Addr>(), mask_s.parse::<u32>())
            {
                if mask == 32
                {
                    ips.push(u32::from(ip));
                }
                else if mask < 32
                {
                    writeln!(writer, "{ip}/{mask}")?;
                }
            }
            return Ok(());
        }
        if let Ok(ip) = line.parse::<Ipv4Addr>()
        {
            ips.push(u32::from(ip));
        }
        Ok(())
    })?;
    collapse_sorted(cfg, &mut ips, writer)
}

/// Processes IPv6 addresses, subnets, and ranges and emits aggregated CIDRs to `writer`.
fn run_ipv6<R: BufRead, W: Write>(
    cfg: &Ip2NetConfig,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Ip2NetError>
{
    let mut ips: Vec<u128> = Vec::new();
    for_each_utf8_line(reader, |text| {
        let line = text.trim_end_matches(['\n', '\r', ' ', '\t']);
        if line.is_empty()
        {
            return Ok(());
        }
        if let Some((ip_s, mask_s)) = line.split_once('/')
        {
            if let (Ok(ip), Ok(mask)) = (ip_s.parse::<Ipv6Addr>(), mask_s.parse::<u32>())
            {
                if mask == 128
                {
                    ips.push(u128::from(ip));
                }
                else if mask < 128
                {
                    writeln!(writer, "{ip_s}/{mask}")?;
                }
            }
            return Ok(());
        }
        if let Some((left, right)) = line.split_once('-')
        {
            if left
                .parse::<Ipv6Addr>()
                .is_ok()
                && right
                    .parse::<Ipv6Addr>()
                    .is_ok()
            {
                writeln!(writer, "{left}-{right}")?;
            }
            return Ok(());
        }
        if let Ok(ip) = line.parse::<Ipv6Addr>()
        {
            ips.push(u128::from(ip));
        }
        Ok(())
    })?;
    collapse_sorted(cfg, &mut ips, writer)
}

/// Runs `ip2net` streaming aggregation from `reader` into `writer` using `cfg`.
pub fn run_ip2net<R: BufRead, W: Write>(
    cfg: &Ip2NetConfig,
    reader: &mut R,
    writer: &mut W,
) -> Result<(), Ip2NetError>
{
    match cfg.family
    {
        Ip2NetFamily::Ipv4 => run_ipv4(cfg, reader, writer),
        Ip2NetFamily::Ipv6 => run_ipv6(cfg, reader, writer),
    }
}
