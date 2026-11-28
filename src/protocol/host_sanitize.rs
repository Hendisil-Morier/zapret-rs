//! Wire hostname and HTTP `Host` header sanitization helpers preventing hostlist directive injection.

/// IP address literal parser allowing bare IPv4/IPv6 and bracketed IPv6 `Host` values.
use std::net::{IpAddr, Ipv6Addr};

/// Maximum hostname length in bytes (`char host[256]` minus NUL terminator).
const MAX_HOST_BYTES: usize = 255;

/// Returns `true` when `raw` is a clean DNS/SNI/list hostname (`[a-zA-Z0-9._-]`) or IP literal.
fn is_valid_hostname_body(raw: &str) -> bool
{
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES
    {
        return false;
    }
    if raw
        .parse::<IpAddr>()
        .is_ok()
    {
        return true;
    }
    let bytes = raw.as_bytes();
    if matches!(bytes.first(), Some(b'-' | b'.')) || bytes.last() == Some(&b'-')
    {
        return false;
    }
    if bytes
        .windows(2)
        .any(|w| w == b"..")
    {
        return false;
    }
    let mut has_alnum = false;
    for &b in bytes
    {
        if b.is_ascii_alphanumeric()
        {
            has_alnum = true;
        }
        else if !matches!(b, b'-' | b'.' | b'_')
        {
            return false;
        }
    }
    has_alnum
}

/// Validates and lowercases an untrusted wire hostname or IP literal, rejecting directives and control chars.
pub fn sanitize_wire_hostname(raw: &str) -> Option<String>
{
    is_valid_hostname_body(raw).then(|| raw.to_ascii_lowercase())
}

/// Validates and lowercases an HTTP `Host` header value (`host`, `host:port`, or `[ipv6]:port`).
pub fn sanitize_http_host(raw: &str) -> Option<String>
{
    if raw.is_empty() || raw.len() > MAX_HOST_BYTES
    {
        return None;
    }
    if raw
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b':' | b'[' | b']')))
    {
        return None;
    }
    if let Some(after_open) = raw.strip_prefix('[')
    {
        let close_idx = after_open.find(']')?;
        after_open[..close_idx]
            .parse::<Ipv6Addr>()
            .ok()?;
        let suffix = &after_open[close_idx + 1..];
        if !suffix.is_empty()
        {
            let port_str = suffix.strip_prefix(':')?;
            port_str
                .parse::<u16>()
                .ok()?;
        }
        return Some(raw.to_ascii_lowercase());
    }
    if raw
        .parse::<Ipv6Addr>()
        .is_ok()
    {
        return Some(raw.to_ascii_lowercase());
    }
    if let Some(colon_idx) = raw.rfind(':')
    {
        let host_part = &raw[..colon_idx];
        let port_part = &raw[colon_idx + 1..];
        if !is_valid_hostname_body(host_part)
            || port_part
                .parse::<u16>()
                .is_err()
        {
            return None;
        }
        return Some(raw.to_ascii_lowercase());
    }
    sanitize_wire_hostname(raw)
}
