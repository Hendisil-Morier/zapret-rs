//! DNS IN A/AAAA response inspection populating `--ipcache-hostname` lookups.

/// Interior mutability for updating `IpCache` without holding long-lived borrows.
use std::cell::RefCell;

/// Global time-expiring IP-to-hostname cache (`ip_cache`).
use crate::lists::IpCache;
/// Shared RFC 1035 DNS name-skipping and IN `A`/`AAAA` record decoding helpers.
use crate::protocol::{dns_parse_in_ip_rr, dns_skip_name};

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

/// Parses a DNS IN A/AAAA response packet and records `hostname -> IP` entries in `ipcache`.
pub fn feed_dns_response(payload: &[u8], ipcache: &RefCell<IpCache>, now_sec: i64) -> bool {
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

    let Some(clean_name) = crate::lists::sanitize_wire_hostname(&query_name) else {
        return false;
    };
    let mut cache = ipcache.borrow_mut();
    for _ in 0..acount {
        let Some(rr) = dns_skip_name(cursor) else {
            return false;
        };
        let Some((ip_opt, rest)) = dns_parse_in_ip_rr(rr) else {
            return false;
        };
        if let Some(ip) = ip_opt {
            cache.put_hostname(ip, &clean_name, false, now_sec);
        }
        cursor = rest;
    }
    true
}
