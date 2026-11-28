//! HTTP protocol detectors, header/host extractors, DPI redirect check, and HTTP markers.

/// IPv4 and IPv6 literal address parsers used when distinguishing hostnames from IP hosts.
use std::net::{Ipv4Addr, Ipv6Addr};

/// Marker position helpers shared across HTTP and TLS resolvers.
use crate::protocol::markers::{PosMarker, any_proto_pos, check_pos, host_pos};

/// HTTP request method prefixes recognized by `IsHttp` (`protocol.c:251`).
const HTTP_METHODS: &[&[u8]] =
    &[b"GET ", b"POST ", b"HEAD ", b"OPTIONS ", b"PUT ", b"DELETE ", b"CONNECT ", b"TRACE ", b"PATCH "];

/// Maximum header value buffer length matching `char loc[256]` / `host[256]` in `protocol.c`.
const MAX_HTTP_HEADER_VAL_LEN: usize = 255;

/// Locates the `level`-th domain label from the right in `dom`, returning `(offset, label_len)`.
///
/// For example, `find_nld(b"sub.example.com", 2)` returns `Some((4, 7))` covering `"example"`,
/// while single-label names return `None` when `level >= 2`.
pub fn find_nld(dom: &[u8], level: usize) -> Option<(usize, usize)>
{
    if level < 1 || dom.is_empty()
    {
        return None;
    }
    let mut p2 = dom.len();
    for _ in 1..level
    {
        p2 = p2.checked_sub(1)?;
        while p2 > 0 && dom[p2] != b'.'
        {
            p2 -= 1;
        }
        if p2 == 0
        {
            return None;
        }
    }
    let mut p1 = p2.checked_sub(1)?;
    while p1 > 0 && dom[p1] != b'.'
    {
        p1 -= 1;
    }
    if dom[p1] == b'.'
    {
        p1 += 1;
    }
    Some((p1, p2 - p1))
}

/// Strips optional `:port` or IPv6 brackets and reports whether the resulting host is an IP literal.
///
/// Mirrors `strip_host_to_ip` in `zapret2/nfq2/helpers.c:183-230`.
pub fn strip_host_to_ip(host: &str) -> (String, bool)
{
    let trimmed = host.trim_start_matches([' ', '\t']);
    if trimmed.len() < 2
    {
        return (host.to_owned(), false);
    }

    if let Some(after_open) = trimmed.strip_prefix('[')
    {
        if let Some(close_idx) = after_open.find(']')
        {
            let inner = &after_open[..close_idx];
            return (
                inner.to_owned(),
                inner
                    .parse::<Ipv6Addr>()
                    .is_ok(),
            );
        }
        return (host.to_owned(), false);
    }

    if trimmed
        .parse::<Ipv6Addr>()
        .is_ok()
    {
        return (trimmed.to_owned(), true);
    }

    let without_port = match trimmed.find(':')
    {
        Some(colon_idx) => &trimmed[..colon_idx],
        None => trimmed,
    };
    (
        without_port.to_owned(),
        without_port
            .parse::<Ipv4Addr>()
            .is_ok(),
    )
}

/// Returns `true` if `data` begins with a valid HTTP/1.x request line (`IsHttp` in `protocol.c`).
pub fn is_http(data: &[u8]) -> bool
{
    if data.len() < 4
        || !HTTP_METHODS
            .iter()
            .any(|m| data.starts_with(m))
    {
        return false;
    }

    let mut pos = 0usize;
    while pos < data.len() && !matches!(data[pos], b' ' | b'\t' | b'\r' | b'\n')
    {
        pos += 1;
    }
    if pos >= data.len() || !matches!(data[pos], b' ' | b'\t')
    {
        return false;
    }
    while pos < data.len() && matches!(data[pos], b' ' | b'\t')
    {
        pos += 1;
    }

    // Skip URI token.
    while pos < data.len() && !matches!(data[pos], b' ' | b'\t' | b'\r' | b'\n')
    {
        pos += 1;
    }
    if pos >= data.len() || !matches!(data[pos], b' ' | b'\t')
    {
        return false;
    }
    while pos < data.len() && matches!(data[pos], b' ' | b'\t')
    {
        pos += 1;
    }

    let rem = &data[pos..];
    rem.len() >= 10 && !matches!(rem[0], b'\r' | b'\n') && rem.starts_with(b"HTTP/1.")
}

/// Searches `data` for `\nHost:` (case-insensitive) and returns the byte offset of `'H'`/`'h'`.
pub fn find_host_header_offset(data: &[u8]) -> Option<usize>
{
    data.windows(6)
        .position(|w| w[0] == b'\n' && w[1..5].eq_ignore_ascii_case(b"host") && w[5] == b':')
        .map(|newline_idx| newline_idx + 1)
}

/// Returns `true` when `data` begins with an HTTP/1.0 or HTTP/1.1 status line (`IsHttpReply`).
pub fn is_http_reply(data: &[u8]) -> bool
{
    data.len() > 14
        && data.starts_with(b"HTTP/1.")
        && matches!(data[7], b'0' | b'1')
        && data[8] == b' '
        && data[9..12]
            .iter()
            .all(u8::is_ascii_digit)
}

/// Extracts the 3-digit status code from an HTTP status line (`HttpReplyCode`).
pub fn http_reply_code(data: &[u8]) -> Option<u16>
{
    if data.len() < 12
        || !data[9..12]
            .iter()
            .all(u8::is_ascii_digit)
    {
        return None;
    }
    let hundreds = u16::from(data[9] - b'0') * 100;
    let tens = u16::from(data[10] - b'0') * 10;
    let ones = u16::from(data[11] - b'0');
    Some(hundreds + tens + ones)
}

/// Extracts and lowercases the first whitespace-delimited value after `header` (`HttpExtractHeader`).
pub fn http_extract_header(data: &[u8], header: &[u8]) -> Option<String>
{
    if header.is_empty() || data.len() < header.len()
    {
        return None;
    }
    let match_idx = data
        .windows(header.len())
        .position(|w| w.eq_ignore_ascii_case(header))?;

    let mut start = match_idx + header.len();
    while start < data.len() && matches!(data[start], b' ' | b'\t')
    {
        start += 1;
    }
    let mut end = start;
    while end < data.len() && !matches!(data[end], b'\r' | b'\n' | b' ' | b'\t')
    {
        end += 1;
    }
    if end == start
    {
        return None;
    }

    let capped_end = start + (end - start).min(MAX_HTTP_HEADER_VAL_LEN);
    let lower_bytes: Vec<u8> = data[start..capped_end]
        .iter()
        .map(u8::to_ascii_lowercase)
        .collect();
    Some(String::from_utf8_lossy(&lower_bytes).into_owned())
}

/// Extracts, sanitizes, and lowercases the `Host:` header value from an HTTP request (`HttpExtractHost`).
pub fn http_extract_host(data: &[u8]) -> Option<String>
{
    let raw = http_extract_header(data, b"\nHost:")?;
    crate::protocol::sanitize_http_host(&raw)
}

/// Maximum body scan window in bytes for HTML `<meta http-equiv="refresh">` ISP block redirects.
const MAX_HTTP_META_SCAN_LEN: usize = 2048;

/// Returns `true` when `url` (`http://...` or `https://...`) targets a different IP or second-level domain than `host`.
fn url_looks_off_domain(url: &str, host: &str, host_is_ip: bool) -> bool
{
    let Some(after_scheme) = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
    else
    {
        return false;
    };
    let auth_end = after_scheme
        .find(['/', '?', '#', '"', '\'', ' ', '\t', '>'])
        .unwrap_or(after_scheme.len());
    let raw_target = &after_scheme[..auth_end];
    if raw_target.is_empty()
    {
        return false;
    }

    let (redirect_host, redir_is_ip) = strip_host_to_ip(raw_target);
    if redir_is_ip != host_is_ip
    {
        return true;
    }
    if redir_is_ip
    {
        return redirect_host != host;
    }

    let Some((dr_off, _)) = find_nld(redirect_host.as_bytes(), 2)
    else
    {
        return false;
    };
    let Some((d_off, _)) = find_nld(host.as_bytes(), 2)
    else
    {
        return true;
    };
    !host[d_off..].eq_ignore_ascii_case(&redirect_host[dr_off..])
}

/// Extracts a lowercased external `http(s)://...` URL from an HTML `<meta http-equiv="refresh">` tag.
fn extract_meta_refresh_url(data: &[u8]) -> Option<String>
{
    let body_start = data
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|pos| pos + 4)
        .or_else(|| {
            data.windows(2)
                .position(|w| w == b"\n\n")
                .map(|pos| pos + 2)
        })?;
    let body = &data[body_start..];
    let scan_len = body
        .len()
        .min(MAX_HTTP_META_SCAN_LEN);
    let lower = String::from_utf8_lossy(&body[..scan_len]).to_ascii_lowercase();
    let meta_pos = lower.find("<meta")?;
    let meta_end = lower[meta_pos..].find('>')?;
    let tag = &lower[meta_pos..meta_pos + meta_end + 1];
    if !tag.contains("http-equiv") || !tag.contains("refresh")
    {
        return None;
    }
    let url_idx = tag.find("url=")?;
    let after_eq = tag[url_idx + 4..].trim_start_matches(['"', '\'', ' ']);
    if after_eq.starts_with("http://") || after_eq.starts_with("https://")
    {
        Some(after_eq.to_owned())
    }
    else
    {
        None
    }
}

/// Returns `true` when an HTTP 302/307 reply redirects to a different second-level domain or IP.
///
/// Mirrors `HttpReplyLooksLikeDPIRedirect` in `zapret2/nfq2/protocol.c:368-417`.
pub fn http_reply_looks_like_dpi_redirect(data: &[u8], host: &str, host_is_ip: bool) -> bool
{
    if host.is_empty() || !is_http_reply(data)
    {
        return false;
    }
    if !matches!(http_reply_code(data), Some(302 | 307))
    {
        return false;
    }
    let Some(loc) = http_extract_header(data, b"\nLocation:")
    else
    {
        return false;
    };
    url_looks_off_domain(&loc, host, host_is_ip)
}

/// Returns `true` when an HTTP reply shows a DPI redirect, HTTP `451`, or off-domain `<meta refresh>` stub.
pub fn http_reply_looks_like_dpi_block(data: &[u8], host: &str, host_is_ip: bool) -> bool
{
    if host.is_empty() || !is_http_reply(data)
    {
        return false;
    }
    if http_reply_looks_like_dpi_redirect(data, host, host_is_ip)
    {
        return true;
    }
    let Some(code) = http_reply_code(data)
    else
    {
        return false;
    };
    if code == 451
    {
        return true;
    }
    if matches!(code, 200 | 403)
        && let Some(url) = extract_meta_refresh_url(data)
    {
        return url_looks_off_domain(&url, host, host_is_ip);
    }
    false
}

/// Resolves an HTTP-specific or generic payload marker (`HttpPos` in `protocol.c:418-458`).
pub fn http_pos(marker: PosMarker, pos: i16, data: &[u8]) -> Option<usize>
{
    match marker
    {
        PosMarker::HttpMethod =>
        {
            if data.len() < 12
            {
                return None;
            }
            let mut m = 0usize;
            if matches!(data.get(m), Some(b'\n' | b'\r'))
            {
                m += 1;
            }
            if matches!(data.get(m), Some(b'\n' | b'\r'))
            {
                m += 1;
            }
            let mut count = 0usize;
            while count < 9
                && data
                    .get(m + count)
                    .is_some_and(u8::is_ascii_uppercase)
            {
                count += 1;
            }
            if count < 3 || data.get(m + count) != Some(&b' ')
            {
                return None;
            }
            let offset = isize::try_from(m)
                .ok()?
                .checked_add(isize::from(pos))?;
            check_pos(data.len(), offset)
        }
        PosMarker::Host
        | PosMarker::HostEnd
        | PosMarker::HostSld
        | PosMarker::HostMidSld
        | PosMarker::HostEndSld =>
        {
            let hdr_off = find_host_header_offset(data)?;
            if hdr_off + 7 >= data.len()
            {
                return None;
            }
            let mut p = hdr_off + 5;
            if matches!(data.get(p), Some(b' ' | b'\t'))
            {
                p += 1;
            }
            let offset_host = p;
            let len_host = if marker == PosMarker::Host
            {
                0
            }
            else
            {
                let mut l = 0usize;
                while offset_host + l < data.len() && !matches!(data[offset_host + l], b'\r' | b'\n')
                {
                    l += 1;
                }
                l
            };
            host_pos(marker, pos, data, offset_host, len_host)
        }
        _ => any_proto_pos(marker, pos, data.len()),
    }
}
