//! RFC 1035 DNS binary query construction and reply parsing for `mdig`.

/// Buffered `Read` and `Write` traits for `--dns-make-query` and `--dns-parse-query` I/O.
use std::io::{Read, Write};
/// IPv4 and IPv6 address containers extracted from DNS answer resource records.
use std::net::IpAddr;
/// Sub-second system clock used to seed unpredictable 16-bit DNS transaction IDs.
use std::time::{SystemTime, UNIX_EPOCH};

/// Typed error derivation for DNS packet building, parsing, and stream I/O failures.
use thiserror::Error;

/// Shared RFC 1035 name-skipping and IN `A`/`AAAA` record decoding helpers.
use crate::protocol::{dns_parse_in_ip_rr, dns_skip_name};

/// Maximum binary DNS response packet size accepted from stdin (`mdig.c` 8 KiB buffer).
pub const MDIG_DNS_REPLY_MAX: usize = 8192;
/// DNS Internet class (`IN = 1`).
pub const DNS_CLASS_IN: u8 = 1;
/// DNS address record type (`A = 1`).
pub const DNS_TYPE_A: u8 = 1;
/// DNS IPv6 address record type (`AAAA = 28`).
pub const DNS_TYPE_AAAA: u8 = 28;

/// Address family selection shared across resolver threads and `--dns-make-query`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MdigFamily {
    /// IPv4 only (`--family=4`, default).
    Ipv4,
    /// IPv6 only (`--family=6`).
    Ipv6,
    /// Both IPv4 and IPv6 (`--family=46`).
    Ipv46,
}

impl MdigFamily {
    /// Parses `--family` argument strings `"4"`, `"6"`, or `"46"`.
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "4" => Some(Self::Ipv4),
            "6" => Some(Self::Ipv6),
            "46" => Some(Self::Ipv46),
            _ => None,
        }
    }

    /// Returns `true` when IPv4 literals and `AF_INET` lookups are permitted.
    pub const fn allows_v4(self) -> bool {
        matches!(self, Self::Ipv4 | Self::Ipv46)
    }

    /// Returns `true` when IPv6 literals and `AF_INET6` lookups are permitted.
    pub const fn allows_v6(self) -> bool {
        matches!(self, Self::Ipv6 | Self::Ipv46)
    }

    /// Returns `AAAA` (`28`) for `--family=6` and `A` (`1`) for `4` or `46` (`mdig.c` parity).
    pub const fn query_qtype(self) -> u8 {
        if matches!(self, Self::Ipv6) {
            DNS_TYPE_AAAA
        } else {
            DNS_TYPE_A
        }
    }
}

/// Errors returned by `mdig` binary DNS query building and reply parsing modes.
#[derive(Debug, Error)]
pub enum MdigDnsError {
    /// Domain exceeded RFC 1035 limits or contained invalid/empty labels (exit code `1`).
    #[error("could not make DNS query")]
    InvalidQuery,
    /// Stdin returned empty EOF or an OS read error (exit code `10`).
    #[error("could not read DNS reply blob from stdin")]
    ReadFailed,
    /// Writing binary query bytes or parsed IPs to stdout failed (exit code `10`).
    #[error("could not write DNS output: {0}")]
    WriteFailed(#[source] std::io::Error),
    /// DNS response header or resource record layout failed validation (exit code `11`).
    #[error("could not parse DNS reply blob")]
    ParseFailed,
}

/// Builds a binary RFC 1035 DNS query packet with explicit opcode, class, qtype, and transaction ID.
pub fn build_dns_query_with_id(
    op: u8,
    domain: &str,
    class: u8,
    qtype: u8,
    id: u16,
) -> Option<Vec<u8>> {
    let raw = domain.as_bytes();
    if op > 15 || raw.len() > 255 || raw.contains(&0) {
        return None;
    }
    let trimmed = raw.strip_suffix(b".").unwrap_or(raw);
    if trimmed.ends_with(b".") || trimmed.len() > 253 {
        return None;
    }

    let capacity = 17 + trimmed.len() + usize::from(!trimmed.is_empty());
    let mut buf = Vec::with_capacity(capacity);
    let [id_hi, id_lo] = id.to_be_bytes();
    // Set RD=1 and QDCOUNT=1 matching musl/mdig `dns_mk_query_blob`.
    buf.extend_from_slice(&[id_hi, id_lo, (op << 3) | 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);

    if !trimmed.is_empty() {
        for label in trimmed.split(|&b| b == b'.') {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            buf.push(label.len() as u8);
            buf.extend_from_slice(label);
        }
    }
    buf.extend_from_slice(&[0, 0, qtype, 0, class]);
    Some(buf)
}

/// Builds a standard IN `A`/`AAAA` DNS query packet for `domain` with a clock-seeded ID.
pub fn build_dns_query(domain: &str, family: MdigFamily) -> Option<Vec<u8>> {
    let nsec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    let id = (nsec as u16).wrapping_add((nsec >> 16) as u16);
    build_dns_query_with_id(0, domain, DNS_CLASS_IN, family.query_qtype(), id)
}

/// Decodes IN `A` and `AAAA` answer addresses from a binary RFC 1035 DNS reply packet.
pub fn parse_dns_reply(packet: &[u8]) -> Option<Vec<IpAddr>> {
    if packet.len() < 12 || (packet[2] & 0x80) == 0 {
        return None;
    }
    let qcount = u16::from_be_bytes([packet[4], packet[5]]);
    let acount = u16::from_be_bytes([packet[6], packet[7]]);
    let mut cursor = &packet[12..];

    for _ in 0..qcount {
        cursor = dns_skip_name(cursor)?;
        cursor = cursor.get(4..)?;
    }

    let mut ips = Vec::new();
    for _ in 0..acount {
        cursor = dns_skip_name(cursor)?;
        let (ip_opt, rest) = dns_parse_in_ip_rr(cursor)?;
        if let Some(ip) = ip_opt {
            ips.push(ip);
        }
        cursor = rest;
    }
    Some(ips)
}

/// Reads up to [`MDIG_DNS_REPLY_MAX`] bytes from `reader` and prints one parsed IP per line.
pub fn read_and_parse_dns_reply<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
) -> Result<(), MdigDnsError> {
    let mut buf = Vec::with_capacity(512);
    let read_res = reader
        .take(MDIG_DNS_REPLY_MAX as u64)
        .read_to_end(&mut buf);
    if read_res.is_err() || buf.is_empty() {
        return Err(MdigDnsError::ReadFailed);
    }
    let ips = parse_dns_reply(&buf).ok_or(MdigDnsError::ParseFailed)?;
    for ip in ips {
        writeln!(writer, "{ip}").map_err(MdigDnsError::WriteFailed)?;
    }
    Ok(())
}
