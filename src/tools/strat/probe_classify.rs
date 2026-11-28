//! `curl` connectivity probe outcome types and HTTP/TLS/spoof-redirect classifiers.

/// `curl -w` format read by [`classify_curl_output`]: status code, redirect target, total seconds.
pub const PROBE_WRITE_OUT: &str = "%{http_code}\n%{redirect_url}\n%{time_total}\n";

/// Outcome of probing one domain over a specific protocol and IP family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome
{
    /// Server responded normally without DPI interception or foreign redirect.
    Available
    {
        /// Observed HTTP status code (e.g., `200`, `301`, `403`, `404`).
        http_code: u16,
        /// Measured request latency in milliseconds.
        latency_ms: u64,
    },
    /// HTTP 3xx response redirected to an unrelated host (typical ISP DPI block page).
    SpoofRedirect
    {
        /// Raw `Location` redirect URL returned by the interceptor.
        location: String,
    },
    /// Connection or handshake timed out (DPI blackhole/drop).
    Timeout,
    /// Connection was reset or refused by peer/DPI (TCP RST).
    TcpReset,
    /// TLS/QUIC handshake failed with an SSL/crypto error.
    TlsError
    {
        /// Underlying `curl` exit code (e.g., `35`, `56`, `60`).
        code: i32,
    },
    /// Unclassified transport or tool failure.
    Failed
    {
        /// Process exit code (`-1` if spawning failed).
        code: i32,
        /// Short diagnostic text from stderr or spawn error.
        detail: String,
    },
}

/// Maps common `curl` non-zero exit codes to concise human-readable diagnostic hints.
fn curl_exit_hint(code: i32) -> Option<&'static str>
{
    match code
    {
        6 => Some("DNS resolve failed"),
        7 => Some("connect failed"),
        23 => Some("output write error"),
        28 => Some("timeout"),
        35 => Some("TLS handshake error"),
        52 => Some("empty reply"),
        56 => Some("recv/reset error"),
        60 => Some("TLS cert verify failed"),
        _ => None,
    }
}

impl ProbeOutcome
{
    /// Returns `true` when the probe reached the target server cleanly.
    pub const fn is_success(&self) -> bool
    {
        matches!(self, Self::Available { .. })
    }

    /// Returns measured latency in milliseconds when the probe succeeded.
    pub const fn latency_ms(&self) -> Option<u64>
    {
        match self
        {
            Self::Available { latency_ms, .. } => Some(*latency_ms),
            _ => None,
        }
    }

    /// Returns a compact single-line summary suitable for progress logs and reports.
    pub fn summary(&self) -> String
    {
        match self
        {
            Self::Available { http_code, latency_ms } => format!("OK (HTTP {http_code}, {latency_ms} ms)"),
            Self::SpoofRedirect { location } => format!("SPOOF_REDIRECT ({location})"),
            Self::Timeout => "TIMEOUT".to_owned(),
            Self::TcpReset => "TCP_RESET".to_owned(),
            Self::TlsError { code } => format!("TLS_ERROR (curl {code})"),
            Self::Failed { code, detail } =>
            {
                let tag = match curl_exit_hint(*code)
                {
                    Some(hint) => format!("code {code} [{hint}]"),
                    None => format!("code {code}"),
                };
                if detail.is_empty()
                {
                    format!("FAILED ({tag})")
                }
                else
                {
                    format!("FAILED ({tag}: {detail})")
                }
            }
        }
    }
}

/// Extracts the normalized lowercase host (without port or IPv6 brackets) from an HTTP URL.
fn extract_url_host(url: &str) -> Option<String>
{
    let rest = url.trim().strip_prefix("http://").or_else(|| url.trim().strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty()
    {
        return None;
    }
    let host = if let Some(v6) = host_port.strip_prefix('[')
    {
        v6.split(']').next().unwrap_or("")
    }
    else
    {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

/// Returns `true` when `location` redirects `domain` to an unrelated external host (ISP block page).
///
/// Mirrors `zapret2`'s `is_dpi_redirect`: same-host and subdomain/parent-domain transitions
/// (such as `example.com` -> `www.example.com`) are legitimate; foreign hosts are spoofed.
pub fn is_spoof_redirect(domain: &str, location: &str) -> bool
{
    let Some(target_host) = extract_url_host(location)
    else
    {
        return false;
    };
    let origin = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let target = target_host.trim_end_matches('.');
    if target == origin || target.ends_with(&format!(".{origin}")) || origin.ends_with(&format!(".{target}"))
    {
        return false;
    }
    // Also allow sibling subdomains sharing the same registrable second-level suffix (e.g., `m.foo.com` <-> `www.foo.com`).
    let orig_parts: Vec<&str> = origin.split('.').collect();
    let targ_parts: Vec<&str> = target.split('.').collect();
    if orig_parts.len() >= 2 && targ_parts.len() >= 2
    {
        let orig_tail = &orig_parts[orig_parts.len() - 2..];
        let targ_tail = &targ_parts[targ_parts.len() - 2..];
        if orig_tail == targ_tail
        {
            return false;
        }
    }
    true
}

/// Classifies raw `curl` exit code, `-w` stdout lines, and stderr into a [`ProbeOutcome`].
pub fn classify_curl_output(
    domain: &str,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
    fallback_elapsed_ms: u64,
) -> ProbeOutcome
{
    if exit_code == 0
    {
        let mut lines = stdout.lines();
        let http_code = lines.next().and_then(|s| s.trim().parse::<u16>().ok()).unwrap_or(0);
        let redirect_url = lines.next().unwrap_or("").trim();
        let latency_ms = lines
            .next()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|t| t.is_finite() && *t >= 0.0)
            .map_or(fallback_elapsed_ms, |secs| (secs * 1000.0).round() as u64);

        if (300..=399).contains(&http_code)
            && !redirect_url.is_empty()
            && is_spoof_redirect(domain, redirect_url)
        {
            return ProbeOutcome::SpoofRedirect { location: redirect_url.to_owned() };
        }
        if http_code > 0
        {
            return ProbeOutcome::Available { http_code, latency_ms };
        }
        return ProbeOutcome::Failed { code: 0, detail: "empty HTTP response".to_owned() };
    }

    let stderr_low = stderr.to_ascii_lowercase();
    match exit_code
    {
        28 => ProbeOutcome::Timeout,
        52 | 56 if stderr_low.contains("reset") || stderr_low.contains("empty reply") =>
        {
            ProbeOutcome::TcpReset
        }
        56 if stderr_low.contains("ssl") || stderr_low.contains("tls") =>
        {
            ProbeOutcome::TlsError { code: exit_code }
        }
        56 | 52 => ProbeOutcome::TcpReset,
        35 | 51 | 58 | 59 | 60 | 77 | 80 | 83 | 90 | 91 | 95 | 96 =>
        {
            ProbeOutcome::TlsError { code: exit_code }
        }
        7 if stderr_low.contains("reset") || stderr_low.contains("refused") => ProbeOutcome::TcpReset,
        other => ProbeOutcome::Failed {
            code: other,
            detail: stderr.lines().next().unwrap_or("").trim().to_owned(),
        },
    }
}
