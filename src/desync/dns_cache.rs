//! DNS IN A/AAAA response inspection populating `--ipcache-hostname` lookups.

/// Interior mutability for updating `IpCache` without holding long-lived borrows.
use std::cell::RefCell;
/// IPv4 and IPv6 address containers populated from DNS answer RRs.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Global time-expiring IP-to-hostname cache (`ip_cache`).
use crate::lists::IpCache;

/// Extracts one uncompressed or single-pointer lowercase DNS QNAME (`dns_extract_name`).
fn dns_extract_qname<'a>(packet: &'a [u8], cursor: &'a [u8]) -> Option<(String, &'a [u8])> {
    let first = *cursor.first()?;
    let is_ptr = (first & 0xC0) == 0xC0;
    let mut labels = if is_ptr {
        let second = *cursor.get(1)?;
        let off = (usize::from(first & 0x3F) << 8) | usize::from(second);
        packet.get(off..)?
    } else {
        cursor
    };

    let mut name = String::new();
    while let Some(&len_byte) = labels.first() {
        if len_byte == 0 {
            let next = if is_ptr { &cursor[2..] } else { &labels[1..] };
            return Some((name, next));
        }
        if (len_byte & 0xC0) != 0 {
            return None;
        }
        let label_len = usize::from(len_byte);
        let label = labels.get(1..1 + label_len)?;
        if !name.is_empty() {
            name.push('.');
        }
        for &b in label {
            if name.len() >= 255 {
                return None;
            }
            name.push(char::from(b.to_ascii_lowercase()));
        }
        labels = &labels[1 + label_len..];
    }
    None
}

/// Advances `cursor` past a possibly compressed DNS domain name (`dns_skip_name`).
fn dns_skip_name(mut cursor: &[u8]) -> Option<&[u8]> {
    loop {
        let first = *cursor.first()?;
        if (first & 0xC0) == 0xC0 {
            return cursor.get(2..);
        }
        if first == 0 {
            return Some(&cursor[1..]);
        }
        let label_len = usize::from(first);
        cursor = cursor.get(1 + label_len..)?;
    }
}

/// Parses a DNS IN A/AAAA response packet and records `hostname -> IP` entries in `ipcache`.
pub(crate) fn feed_dns_response(payload: &[u8], ipcache: &RefCell<IpCache>, now_sec: i64) -> bool {
    if !ipcache.borrow().cache_hostname() {
        return true;
    }
    if payload.len() < 12 || (payload[2] & 0x80) == 0 {
        return false;
    }
    let qcount = u16::from_be_bytes([payload[4], payload[5]]);
    let acount = u16::from_be_bytes([payload[6], payload[7]]);
    if qcount == 0 || acount == 0 {
        return false;
    }

    let mut cursor = &payload[12..];
    let mut query_name = String::new();
    for _ in 0..qcount {
        if !query_name.is_empty() {
            return false;
        }
        let Some((name, after_name)) = dns_extract_qname(payload, cursor) else {
            return false;
        };
        if after_name.len() < 4 || after_name[2] != 0 || after_name[3] != 1 {
            return false;
        }
        let qtype = u16::from_be_bytes([after_name[0], after_name[1]]);
        if qtype != 1 && qtype != 28 {
            return false;
        }
        query_name = name;
        cursor = &after_name[4..];
    }
    if query_name.is_empty() {
        return false;
    }

    let mut cache = ipcache.borrow_mut();
    for _ in 0..acount {
        let Some(rr) = dns_skip_name(cursor) else {
            return false;
        };
        if rr.len() < 10 {
            return false;
        }
        let rtype = u16::from_be_bytes([rr[0], rr[1]]);
        let dlen = usize::from(u16::from_be_bytes([rr[8], rr[9]]));
        let Some(rdata_and_rest) = rr.get(10..) else {
            return false;
        };
        if rdata_and_rest.len() < dlen {
            return false;
        }
        if rr[2] == 0 && rr[3] == 1 {
            match rtype {
                1 if dlen == 4 => {
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        rdata_and_rest[0],
                        rdata_and_rest[1],
                        rdata_and_rest[2],
                        rdata_and_rest[3],
                    ));
                    cache.put_hostname(ip, &query_name, false, now_sec);
                }
                28 if dlen == 16 => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&rdata_and_rest[..16]);
                    cache.put_hostname(
                        IpAddr::V6(Ipv6Addr::from(octets)),
                        &query_name,
                        false,
                        now_sec,
                    );
                }
                _ => {}
            }
        }
        cursor = &rdata_and_rest[dlen..];
    }
    true
}
