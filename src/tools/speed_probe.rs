//! Timed `curl` samples (connect, first byte, throughput) for the before/after speed comparison.

/// Wall-clock fallback timing and per-target timeouts.
use std::time::{Duration, Instant};

/// Target IP family selector shared with the strategy catalog.
use crate::tools::strat::catalog::IpFamily;
/// Reused `curl` runner, outcome classification, and argument builder from the strategy scanner.
use crate::tools::strat::probe::{CurlProbeBackend, ProbeOutcome, classify_curl_output};

/// Hostname of the unaffected control target used to expose queue overhead separately.
pub const CONTROL_HOST: &str = "speed.cloudflare.com";
/// 25 MB download large enough to reach steady-state throughput on a typical home link.
pub const CONTROL_URL: &str = "https://speed.cloudflare.com/__down?bytes=25000000";
/// Time allowed for an ordinary domain's front page.
const DOMAIN_TIMEOUT: Duration = Duration::from_secs(8);
/// Time allowed for the 25 MB control download.
const CONTROL_TIMEOUT: Duration = Duration::from_secs(20);

/// `curl -w` format: the three lines [`classify_curl_output`] reads, then connect, first byte, speed.
pub const SPEED_WRITE_OUT: &str = "%{http_code}\n%{redirect_url}\n%{time_total}\n%{time_connect}\n%{time_starttransfer}\n%{speed_download}\n";

/// One URL to measure with a label for the results table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedTarget {
    /// Short name shown in the table (domain, or `control` for the download target).
    pub label: String,
    /// Hostname used for spoof-redirect detection.
    pub host: String,
    /// Full URL fetched by `curl`.
    pub url: String,
    /// Maximum wall-clock time for the transfer.
    pub timeout: Duration,
}

/// Result of measuring one [`SpeedTarget`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedSample {
    /// Classified result; only [`ProbeOutcome::Available`] carries meaningful timings below.
    pub outcome: ProbeOutcome,
    /// TCP connect time in milliseconds (`0` when the probe failed).
    pub connect_ms: u64,
    /// Time to first response byte in milliseconds (`0` when the probe failed).
    pub ttfb_ms: u64,
    /// Average download speed in bytes per second (`0` when the probe failed).
    pub bytes_per_sec: u64,
}

/// Builds the target fetching the front page of `domain` over HTTPS.
pub fn domain_target(domain: &str) -> SpeedTarget {
    SpeedTarget {
        label: domain.to_owned(),
        host: domain.to_owned(),
        url: format!("https://{domain}/"),
        timeout: DOMAIN_TIMEOUT,
    }
}

/// Builds the fixed unaffected 25 MB download target.
pub fn control_target() -> SpeedTarget {
    SpeedTarget {
        label: format!("control ({CONTROL_HOST})"),
        host: CONTROL_HOST.to_owned(),
        url: CONTROL_URL.to_owned(),
        timeout: CONTROL_TIMEOUT,
    }
}

/// Converts a `curl` seconds field such as `0.026674` into whole milliseconds.
fn secs_field_to_ms(field: Option<&str>) -> u64 {
    field
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map_or(0, |secs| (secs * 1000.0).round() as u64)
}

/// Parses the connect time, first-byte time, and speed from the last three `-w` lines.
///
/// Missing or malformed fields become `0` rather than failing the whole sample.
pub fn parse_timing_lines(stdout: &str) -> (u64, u64, u64) {
    let mut lines = stdout.lines().skip(3);
    let connect_ms = secs_field_to_ms(lines.next());
    let ttfb_ms = secs_field_to_ms(lines.next());
    let bytes_per_sec = lines
        .next()
        .and_then(|s| s.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v >= 0.0)
        .map_or(0, |v| v.round() as u64);
    (connect_ms, ttfb_ms, bytes_per_sec)
}

/// Wraps a failure `outcome` in a sample with zeroed timings.
fn failed_sample(outcome: ProbeOutcome) -> SpeedSample {
    SpeedSample { outcome, connect_ms: 0, ttfb_ms: 0, bytes_per_sec: 0 }
}

/// Runs `curl` unprivileged against `target` and returns its classified, timed sample.
pub fn measure(backend: &CurlProbeBackend, target: &SpeedTarget, ipv: IpFamily) -> SpeedSample {
    let args = CurlProbeBackend::build_url_args(&target.url, None, ipv, target.timeout, SPEED_WRITE_OUT);
    let start = Instant::now();
    let output = match backend.unprivileged_command().args(&args).output() {
        Ok(out) => out,
        Err(err) => {
            return failed_sample(ProbeOutcome::Failed {
                code: -1,
                detail: format!("failed to spawn {}: {err}", backend.curl_bin().display()),
            });
        }
    };
    let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let outcome = classify_curl_output(
        &target.host,
        output.status.code().unwrap_or(-1),
        &stdout,
        &stderr,
        elapsed_ms,
    );
    if !outcome.is_success() {
        return failed_sample(outcome);
    }
    let (connect_ms, ttfb_ms, bytes_per_sec) = parse_timing_lines(&stdout);
    SpeedSample { outcome, connect_ms, ttfb_ms, bytes_per_sec }
}
