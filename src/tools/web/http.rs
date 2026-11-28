//! Minimal bounded HTTP/1.1 request parser and JSON/error response writers.

/// Buffered reading and exact payload reading over TCP streams.
use std::io::{self, ErrorKind, Read, Write};
/// Total header+body read deadline bounding Slowloris trickle attacks.
use std::time::{Duration, Instant};

/// JSON serialization for structured REST replies.
use serde::Serialize;

/// Maximum accepted HTTP request line + header section size (`16 KiB`).
pub const MAX_HEADER_BYTES: usize = 16 * 1024;
/// Maximum accepted HTTP request body size (`512 KiB`, ample for `nfqws2.toml` uploads).
pub const MAX_BODY_BYTES: usize = 512 * 1024;
/// Total deadline across all chunks of a single incoming HTTP request (Slowloris defense).
const REQUEST_READ_DEADLINE: Duration = Duration::from_secs(5);
/// Chunk size used while reading HTTP headers instead of 1-byte syscalls.
const HEADER_READ_CHUNK_BYTES: usize = 2048;

/// Parsed HTTP request method.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpMethod
{
    /// `GET` read/stream request.
    Get,
    /// `POST` state-mutating API request.
    Post,
    /// Any other HTTP method (rejected cleanly with `405` by router).
    Other(String),
}

impl HttpMethod
{
    /// Parses an ASCII HTTP method token.
    fn parse(raw: &str) -> Self
    {
        if raw.eq_ignore_ascii_case("GET")
        {
            Self::Get
        }
        else if raw.eq_ignore_ascii_case("POST")
        {
            Self::Post
        }
        else
        {
            Self::Other(raw.to_owned())
        }
    }
}

/// Parsed single-connection HTTP/1.1 request with lowercase header names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest
{
    /// Parsed HTTP method.
    pub method: HttpMethod,
    /// URL path component without query string (e.g. `"/api/login"`).
    pub path: String,
    /// Optional query string without leading `?`.
    pub query: Option<String>,
    /// Lowercased `(name, value)` header pairs.
    pub headers: Vec<(String, String)>,
    /// Exact `Content-Length` body payload bytes.
    pub body: Vec<u8>,
}

impl HttpRequest
{
    /// Looks up the first header matching `name` case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str>
    {
        let target = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k == &target)
            .map(|(_, v)| v.as_str())
    }
}

/// Typed read/parse failures returned by [`read_http_request`] mapping cleanly to HTTP status codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HttpReadError
{
    /// Request header section exceeded [`MAX_HEADER_BYTES`] (`431`).
    HeadersTooLarge,
    /// Request body `Content-Length` exceeded [`MAX_BODY_BYTES`] (`413`).
    BodyTooLarge,
    /// Client requested unsupported `Transfer-Encoding: chunked` (`501`).
    UnsupportedEncoding,
    /// Malformed request line, non-UTF8 headers, invalid `Content-Length`, or truncated body (`400`).
    BadRequest(String),
    /// Underlying socket timeout or I/O error.
    Io(String),
}

impl HttpReadError
{
    /// Maps parser errors into `(http_status, reason, user_message)` tuples.
    pub fn http_status(&self) -> (u16, &'static str, String)
    {
        match self
        {
            Self::HeadersTooLarge =>
            {
                (431, "Request Header Fields Too Large", "headers exceed limit".to_owned())
            }
            Self::BodyTooLarge => (413, "Payload Too Large", "request body exceeds limit".to_owned()),
            Self::UnsupportedEncoding => (501, "Not Implemented", "chunked encoding unsupported".to_owned()),
            Self::BadRequest(msg) => (400, "Bad Request", msg.clone()),
            Self::Io(msg) => (408, "Request Timeout", msg.clone()),
        }
    }
}

/// Reads chunks until `\r\n\r\n` up to [`MAX_HEADER_BYTES`] within `deadline`, preserving trailing body bytes.
fn read_header_block<R: Read>(
    reader: &mut R,
    deadline: Instant,
) -> Result<Option<(usize, Vec<u8>)>, HttpReadError>
{
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; HEADER_READ_CHUNK_BYTES];
    loop
    {
        if Instant::now() >= deadline
        {
            return Err(HttpReadError::Io("HTTP header read deadline exceeded".to_owned()));
        }
        let max_to_read = (MAX_HEADER_BYTES.saturating_sub(buf.len())).min(chunk.len());
        if max_to_read == 0
        {
            return Err(HttpReadError::HeadersTooLarge);
        }
        match reader.read(&mut chunk[..max_to_read])
        {
            Ok(0) if buf.is_empty() => return Ok(None),
            Ok(0) =>
            {
                return Err(HttpReadError::BadRequest("unexpected EOF before header terminator".to_owned()));
            }
            Ok(n) =>
            {
                let prev_len = buf.len();
                buf.extend_from_slice(&chunk[..n]);
                let search_from = prev_len.saturating_sub(3);
                if let Some(rel) = buf[search_from..]
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                {
                    let head_end = search_from + rel + 4;
                    if head_end > MAX_HEADER_BYTES
                    {
                        return Err(HttpReadError::HeadersTooLarge);
                    }
                    return Ok(Some((head_end, buf)));
                }
                if buf.len() >= MAX_HEADER_BYTES
                {
                    return Err(HttpReadError::HeadersTooLarge);
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(HttpReadError::Io(err.to_string())),
        }
    }
}

/// Reads and validates one HTTP/1.1 request from `reader` (`Ok(None)` on clean client EOF).
pub fn read_http_request<R: Read>(reader: &mut R) -> Result<Option<HttpRequest>, HttpReadError>
{
    let deadline = Instant::now() + REQUEST_READ_DEADLINE;
    let Some((head_len, raw_buf)) = read_header_block(reader, deadline)?
    else
    {
        return Ok(None);
    };
    let head_str = std::str::from_utf8(&raw_buf[..head_len])
        .map_err(|_| HttpReadError::BadRequest("non-UTF8 HTTP headers".to_owned()))?;
    let mut lines = head_str.split("\r\n");
    let req_line = lines
        .next()
        .unwrap_or("");
    let mut req_parts = req_line.split_whitespace();
    let (Some(method_s), Some(target), Some(proto), None) =
        (req_parts.next(), req_parts.next(), req_parts.next(), req_parts.next())
    else
    {
        return Err(HttpReadError::BadRequest("malformed HTTP request line".to_owned()));
    };
    if !proto.starts_with("HTTP/1.")
    {
        return Err(HttpReadError::BadRequest(format!("unsupported HTTP version '{proto}'")));
    }

    let (path, query) = match target.split_once('?')
    {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (target.to_owned(), None),
    };

    let mut headers = Vec::new();
    let mut content_len: usize = 0;
    let mut seen_host = false;
    for line in lines
    {
        if line.is_empty()
        {
            continue;
        }
        let Some((k, v)) = line.split_once(':')
        else
        {
            return Err(HttpReadError::BadRequest("malformed HTTP header line".to_owned()));
        };
        let key = k
            .trim()
            .to_ascii_lowercase();
        let val = v
            .trim()
            .to_owned();
        if key == "host"
        {
            if seen_host
            {
                return Err(HttpReadError::BadRequest("duplicate Host header".to_owned()));
            }
            seen_host = true;
        }
        if key == "transfer-encoding"
            && val
                .to_ascii_lowercase()
                .contains("chunked")
        {
            return Err(HttpReadError::UnsupportedEncoding);
        }
        if key == "content-length"
        {
            content_len = val
                .parse::<usize>()
                .map_err(|_| HttpReadError::BadRequest("invalid Content-Length".to_owned()))?;
            if content_len > MAX_BODY_BYTES
            {
                return Err(HttpReadError::BodyTooLarge);
            }
        }
        headers.push((key, val));
    }

    let mut body = vec![0u8; content_len];
    if content_len > 0
    {
        let already = &raw_buf[head_len..];
        let copy_len = already
            .len()
            .min(content_len);
        body[..copy_len].copy_from_slice(&already[..copy_len]);
        let mut offset = copy_len;
        while offset < content_len
        {
            if Instant::now() >= deadline
            {
                return Err(HttpReadError::Io("HTTP body read deadline exceeded".to_owned()));
            }
            match reader.read(&mut body[offset..])
            {
                Ok(0) =>
                {
                    return Err(HttpReadError::BadRequest(
                        "incomplete request body: unexpected EOF".to_owned(),
                    ));
                }
                Ok(n) => offset += n,
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(HttpReadError::Io(err.to_string())),
            }
        }
    }

    Ok(Some(HttpRequest { method: HttpMethod::parse(method_s), path, query, headers, body }))
}

/// Writes one complete HTTP/1.1 response with safe default security headers.
pub fn write_response(
    writer: &mut impl Write,
    status: u16,
    reason: &str,
    content_type: &str,
    extra_headers: &[(&str, &str)],
    body: &[u8],
) -> io::Result<()>
{
    write!(
        writer,
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'\r\n\
         Connection: close\r\n",
        body.len()
    )?;
    for &(name, val) in extra_headers
    {
        write!(writer, "{name}: {val}\r\n")?;
    }
    writer.write_all(b"\r\n")?;
    writer.write_all(body)?;
    writer.flush()
}

/// Serializes `value` as JSON and writes an HTTP response.
pub fn write_json(
    writer: &mut impl Write,
    status: u16,
    reason: &str,
    extra_headers: &[(&str, &str)],
    value: &impl Serialize,
) -> io::Result<()>
{
    let payload = serde_json::to_vec(value).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    write_response(writer, status, reason, "application/json; charset=utf-8", extra_headers, &payload)
}

/// Writes a uniform `{ "error": "..." }` JSON error reply.
pub fn write_error(writer: &mut impl Write, status: u16, reason: &str, message: &str) -> io::Result<()>
{
    write_json(writer, status, reason, &[], &serde_json::json!({ "error": message }))
}
