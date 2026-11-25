//! HTTP/TLS/QUIC connectivity probe backends (`curl` + mockable [`ProbeBackend`] trait).

/// Unix `pre_exec` extension stripping all Linux capabilities before spawning `curl`.
use std::os::unix::process::CommandExt as _;
/// Filesystem paths for the external `curl` executable.
use std::path::{Path, PathBuf};
/// Subprocess spawning for `curl` probes.
use std::process::Command;
/// Monotonic timing and request timeout durations.
use std::time::{Duration, Instant};

/// Async-signal-safe child privilege stripper (`capset(0)` + `PR_SET_NO_NEW_PRIVS`).
use crate::runtime::clear_child_privileges;
/// Target protocol and IP family enums shared with the strategy catalog.
use crate::tools::strat_catalog::{IpFamily, ProbeProtocol};

/// Outcome of probing one domain over a specific protocol and IP family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Server responded normally without DPI interception or foreign redirect.
    Available {
        /// Observed HTTP status code (e.g., `200`, `301`, `403`, `404`).
        http_code: u16,
        /// Measured request latency in milliseconds.
        latency_ms: u64,
    },
    /// HTTP 3xx response redirected to an unrelated host (typical ISP DPI block page).
    SpoofRedirect {
        /// Raw `Location` redirect URL returned by the interceptor.
        location: String,
    },
    /// Connection or handshake timed out (DPI blackhole/drop).
    Timeout,
    /// Connection was reset or refused by peer/DPI (TCP RST).
    TcpReset,
    /// TLS/QUIC handshake failed with an SSL/crypto error.
    TlsError {
        /// Underlying `curl` exit code (e.g., `35`, `56`, `60`).
        code: i32,
    },
    /// Unclassified transport or tool failure.
    Failed {
        /// Process exit code (`-1` if spawning failed).
        code: i32,
        /// Short diagnostic text from stderr or spawn error.
        detail: String,
    },
}

impl ProbeOutcome {
    /// Returns `true` when the probe reached the target server cleanly.
    pub const fn is_success(&self) -> bool {
        matches!(self, Self::Available { .. })
    }

    /// Returns measured latency in milliseconds when the probe succeeded.
    pub const fn latency_ms(&self) -> Option<u64> {
        match self {
            Self::Available { latency_ms, .. } => Some(*latency_ms),
            _ => None,
        }
    }

    /// Returns a compact single-line summary suitable for progress logs and reports.
    pub fn summary(&self) -> String {
        match self {
            Self::Available { http_code, latency_ms } => format!("OK (HTTP {http_code}, {latency_ms} ms)"),
            Self::SpoofRedirect { location } => format!("SPOOF_REDIRECT ({location})"),
            Self::Timeout => "TIMEOUT".to_owned(),
            Self::TcpReset => "TCP_RESET".to_owned(),
            Self::TlsError { code } => format!("TLS_ERROR (curl {code})"),
            Self::Failed { code, detail } => {
                if detail.is_empty() {
                    format!("FAILED (code {code})")
                } else {
                    format!("FAILED (code {code}: {detail})")
                }
            }
        }
    }
}

/// Parameters describing one connectivity probe request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest {
    /// Target hostname (no scheme or path, e.g., `"example.com"`).
    pub domain: String,
    /// Protocol to test (`Http`, `Tls12`, `Tls13`, or `Http3`).
    pub proto: ProbeProtocol,
    /// IP address family (`V4` or `V6`).
    pub ipv: IpFamily,
    /// Maximum wall-clock time allowed for the request.
    pub timeout: Duration,
}

/// Injectable connectivity probe interface allowing live `curl` execution and offline mocks.
pub trait ProbeBackend {
    /// Returns `true` if this backend supports HTTP/3 (QUIC) probing.
    fn supports_http3(&self) -> bool;

    /// Executes one connectivity probe against `req` and classifies the result.
    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome;
}

/// Live [`ProbeBackend`] invoking the system `curl` binary.
#[derive(Debug, Clone)]
pub struct CurlProbeBackend {
    /// Path or executable name of `curl` (defaults to `"curl"`).
    curl_bin: PathBuf,
}

impl Default for CurlProbeBackend {
    /// Constructs a [`CurlProbeBackend`] using `"curl"` from `PATH`.
    fn default() -> Self {
        Self { curl_bin: PathBuf::from("curl") }
    }
}

impl CurlProbeBackend {
    /// Constructs a [`CurlProbeBackend`] pointing at an explicit `curl` binary path.
    pub fn new(curl_bin: PathBuf) -> Self {
        Self { curl_bin }
    }

    /// Returns the configured `curl` binary path.
    pub fn curl_bin(&self) -> &Path {
        &self.curl_bin
    }

    /// Builds the `curl` argument list for `req` (separated for deterministic unit testing).
    pub fn build_args(req: &ProbeRequest) -> Vec<String> {
        let secs = req.timeout.as_secs().max(1).to_string();
        let scheme = if req.proto == ProbeProtocol::Http { "http" } else { "https" };
        let url = format!("{scheme}://{}/", req.domain);
        let mut args = vec![
            "-sS".to_owned(),
            "-o".to_owned(),
            "/dev/null".to_owned(),
            "--noproxy".to_owned(),
            "*".to_owned(),
            "--connect-timeout".to_owned(),
            secs.clone(),
            "--max-time".to_owned(),
            secs,
            if req.ipv == IpFamily::V4 { "-4" } else { "-6" }.to_owned(),
            "-w".to_owned(),
            "%{http_code}\n%{redirect_url}\n%{time_total}\n".to_owned(),
        ];
        match req.proto {
            ProbeProtocol::Http => args.push("--http1.1".to_owned()),
            ProbeProtocol::Tls12 => {
                args.push("--tlsv1.2".to_owned());
                args.push("--tls-max".to_owned());
                args.push("1.2".to_owned());
            }
            ProbeProtocol::Tls13 => args.push("--tlsv1.3".to_owned()),
            ProbeProtocol::Http3 => args.push("--http3-only".to_owned()),
        }
        args.push(url);
        args
    }
    /// Creates a [`Command`] for `self.curl_bin` that drops all Linux capabilities and sets
    /// `PR_SET_NO_NEW_PRIVS` in the child before `execve`.
    fn unprivileged_command(&self) -> Command {
        let mut cmd = Command::new(&self.curl_bin);
        // SAFETY: `clear_child_privileges` invokes only async-signal-safe `prctl` and `SYS_capset`.
        unsafe {
            cmd.pre_exec(clear_child_privileges);
        }
        cmd
    }
}

impl ProbeBackend for CurlProbeBackend {
    /// Runs `curl --version` unprivileged and checks whether `HTTP3` appears in `Features:`.
    fn supports_http3(&self) -> bool {
        let Ok(out) = self.unprivileged_command().arg("--version").output() else {
            return false;
        };
        if !out.status.success() {
            return false;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .any(|line| line.starts_with("Features:") && line.split_whitespace().any(|tok| tok == "HTTP3"))
    }

    /// Invokes `curl` unprivileged for `req` and classifies status code, redirect target, and errors.
    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome {
        let args = Self::build_args(req);
        let start = Instant::now();
        let output = match self.unprivileged_command().args(&args).output() {
            Ok(out) => out,
            Err(err) => {
                return ProbeOutcome::Failed {
                    code: -1,
                    detail: format!("failed to spawn {}: {err}", self.curl_bin.display()),
                };
            }
        };
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_curl_output(&req.domain, exit_code, &stdout, &stderr, elapsed_ms)
    }
}

/// Extracts the normalized lowercase host (without port or IPv6 brackets) from an HTTP URL.
fn extract_url_host(url: &str) -> Option<String> {
    let rest = url
        .trim()
        .strip_prefix("http://")
        .or_else(|| url.trim().strip_prefix("https://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit('@').next().unwrap_or(authority);
    if host_port.is_empty() {
        return None;
    }
    let host = if let Some(v6) = host_port.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

/// Returns `true` when `location` redirects `domain` to an unrelated external host (ISP block page).
///
/// Mirrors `zapret2`'s `is_dpi_redirect`: same-host and subdomain/parent-domain transitions
/// (such as `example.com` -> `www.example.com`) are legitimate; foreign hosts are spoofed.
pub fn is_spoof_redirect(domain: &str, location: &str) -> bool {
    let Some(target_host) = extract_url_host(location) else {
        return false;
    };
    let origin = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let target = target_host.trim_end_matches('.');
    if target == origin
        || target.ends_with(&format!(".{origin}"))
        || origin.ends_with(&format!(".{target}"))
    {
        return false;
    }
    // Also allow sibling subdomains sharing the same registrable second-level suffix (e.g., `m.foo.com` <-> `www.foo.com`).
    let orig_parts: Vec<&str> = origin.split('.').collect();
    let targ_parts: Vec<&str> = target.split('.').collect();
    if orig_parts.len() >= 2 && targ_parts.len() >= 2 {
        let orig_tail = &orig_parts[orig_parts.len() - 2..];
        let targ_tail = &targ_parts[targ_parts.len() - 2..];
        if orig_tail == targ_tail {
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
) -> ProbeOutcome {
    if exit_code == 0 {
        let mut lines = stdout.lines();
        let http_code = lines.next().and_then(|s| s.trim().parse::<u16>().ok()).unwrap_or(0);
        let redirect_url = lines.next().unwrap_or("").trim();
        let latency_ms = lines
            .next()
            .and_then(|s| s.trim().parse::<f64>().ok())
            .filter(|t| t.is_finite() && *t >= 0.0)
            .map_or(fallback_elapsed_ms, |secs| (secs * 1000.0).round() as u64);

        if (300..=399).contains(&http_code) && !redirect_url.is_empty() && is_spoof_redirect(domain, redirect_url) {
            return ProbeOutcome::SpoofRedirect { location: redirect_url.to_owned() };
        }
        if http_code > 0 {
            return ProbeOutcome::Available { http_code, latency_ms };
        }
        return ProbeOutcome::Failed { code: 0, detail: "empty HTTP response".to_owned() };
    }

    let stderr_low = stderr.to_ascii_lowercase();
    match exit_code {
        28 => ProbeOutcome::Timeout,
        52 | 56 if stderr_low.contains("reset") || stderr_low.contains("empty reply") => ProbeOutcome::TcpReset,
        56 if stderr_low.contains("ssl") || stderr_low.contains("tls") => ProbeOutcome::TlsError { code: exit_code },
        56 | 52 => ProbeOutcome::TcpReset,
        35 | 51 | 58 | 59 | 60 | 77 | 80 | 83 | 90 | 91 | 95 | 96 => ProbeOutcome::TlsError { code: exit_code },
        7 if stderr_low.contains("reset") || stderr_low.contains("refused") => ProbeOutcome::TcpReset,
        other => ProbeOutcome::Failed {
            code: other,
            detail: stderr.lines().next().unwrap_or("").trim().to_owned(),
        },
    }
}
