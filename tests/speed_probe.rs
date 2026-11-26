//! Tests for the timed speed probe: output parsing, argument shape, and a fake-`curl` end to end run.

/// Executable bit for the temporary fake `curl` script.
use std::os::unix::fs::PermissionsExt as _;
/// Temporary script location.
use std::path::PathBuf;
/// Timeout value passed to the argument builder.
use std::time::Duration;

/// Probe types under test.
use zapret_rs::tools::{
    CurlProbeBackend, IpFamily, PROBE_WRITE_OUT, ProbeOutcome, SpeedSample, classify_curl_output,
    control_target, domain_target, measure, parse_timing_lines,
};
/// Write-out format with the three extra timing lines.
use zapret_rs::tools::speed_probe::SPEED_WRITE_OUT;

/// Numbers copied from a real run against the control download.
const REAL_OUTPUT: &str = "200\n\n2.308858\n0.026674\n0.111902\n10827906.000\n";

/// Writes an executable shell script that prints `body` and exits with `code`, returning its path.
fn fake_curl(tag: &str, body: &str, code: i32) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zapret-speed-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let path = dir.join("curl");
    std::fs::write(&path, format!("#!/bin/sh\nprintf '{body}'\nexit {code}\n")).expect("write script");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    path
}

#[test]
fn timing_lines_parse_connect_ttfb_and_speed() {
    assert_eq!(parse_timing_lines(REAL_OUTPUT), (27, 112, 10_827_906));
}

#[test]
fn timing_lines_tolerate_missing_or_garbage_fields() {
    assert_eq!(parse_timing_lines("200\n\n1.0\n"), (0, 0, 0));
    assert_eq!(parse_timing_lines("200\n\n1.0\nnope\n-1\nNaN\n"), (0, 0, 0));
}

#[test]
fn speed_output_still_classifies_through_the_shared_classifier() {
    let outcome = classify_curl_output("speed.cloudflare.com", 0, REAL_OUTPUT, "", 0);
    assert_eq!(outcome, ProbeOutcome::Available { http_code: 200, latency_ms: 2309 });
}

#[test]
fn url_args_leave_tls_unpinned_and_keep_scan_args_unchanged() {
    let speed = CurlProbeBackend::build_url_args(
        "https://example.com/",
        None,
        IpFamily::V4,
        Duration::from_secs(8),
        SPEED_WRITE_OUT,
    );
    assert!(!speed.iter().any(|a| a.starts_with("--tls") || a.starts_with("--http")));
    assert!(speed.contains(&"-4".to_owned()));
    assert_eq!(speed.last().map(String::as_str), Some("https://example.com/"));
    assert_eq!(speed[speed.iter().position(|a| a == "-w").expect("-w") + 1], SPEED_WRITE_OUT);
    assert!(SPEED_WRITE_OUT.starts_with(PROBE_WRITE_OUT));

    let v6 = CurlProbeBackend::build_url_args("https://x/", None, IpFamily::V6, Duration::from_secs(1), "");
    assert!(v6.contains(&"-6".to_owned()));
}

#[test]
fn targets_have_expected_urls_and_control_gets_longer_timeout() {
    let d = domain_target("example.com");
    assert_eq!((d.label.as_str(), d.url.as_str()), ("example.com", "https://example.com/"));
    let c = control_target();
    assert!(c.url.contains("bytes=25000000") && c.timeout > d.timeout);
}

#[test]
fn measure_returns_timings_for_success_and_zeroes_for_timeout() {
    let ok = fake_curl("ok", "200\\n\\n2.3\\n0.03\\n0.11\\n10000000.0\\n", 0);
    let sample = measure(&CurlProbeBackend::new(ok), &control_target(), IpFamily::V4);
    assert_eq!(
        sample,
        SpeedSample {
            outcome: ProbeOutcome::Available { http_code: 200, latency_ms: 2300 },
            connect_ms: 30,
            ttfb_ms: 110,
            bytes_per_sec: 10_000_000,
        }
    );

    let slow = fake_curl("timeout", "", 28);
    let sample = measure(&CurlProbeBackend::new(slow), &domain_target("blocked.test"), IpFamily::V4);
    assert_eq!(sample.outcome, ProbeOutcome::Timeout);
    assert_eq!((sample.connect_ms, sample.ttfb_ms, sample.bytes_per_sec), (0, 0, 0));
}
