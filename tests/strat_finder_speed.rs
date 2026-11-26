//! Offline tests for Strategy Finder scan speedups (fractional timeouts, `--resolve`, batching).

/// Network address types for verifying IPv4/IPv6 `--resolve` formatting.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Command-line parsing verification for fractional `--timeout` and default changes.
use clap::Parser;
/// Timeout duration passed to argument builders and batch tests.
use std::time::Duration;

/// Strategy finder probe and CLI symbols under test.
use zapret_rs::tools::{
    CurlProbeBackend, IpFamily, ProbeProtocol, ProbeRequest, StratFinderCli, format_resolve_arg,
};

/// Verifies fractional second formatting for `--connect-timeout` and `--max-time` across bounds.
#[test]
fn build_args_supports_fractional_subsecond_and_clamped_timeouts() {
    let req_sub = ProbeRequest {
        domain: "example.com".to_owned(),
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V4,
        timeout: Duration::from_millis(1500),
    };
    let args_sub = CurlProbeBackend::build_args(&req_sub);
    let max_idx = args_sub.iter().position(|a| a == "--max-time").expect("--max-time missing");
    assert_eq!(args_sub[max_idx + 1], "1.5");

    let req_floor = ProbeRequest { timeout: Duration::from_millis(50), ..req_sub.clone() };
    let args_floor = CurlProbeBackend::build_args(&req_floor);
    let floor_idx = args_floor.iter().position(|a| a == "--connect-timeout").expect("--connect-timeout");
    assert_eq!(args_floor[floor_idx + 1], "0.2");

    let req_whole = ProbeRequest { timeout: Duration::from_secs(2), ..req_sub };
    let args_whole = CurlProbeBackend::build_args(&req_whole);
    let whole_idx = args_whole.iter().position(|a| a == "--max-time").expect("--max-time");
    assert_eq!(args_whole[whole_idx + 1], "2");
}

/// Verifies IPv4 and bracketed IPv6 formatting for `curl --resolve` pins.
#[test]
fn format_resolve_arg_brackets_ipv6_and_leaves_ipv4_bare() {
    let v4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let v6 = IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x0220, 1, 0x0248, 0x1893, 0x25c8, 0x1946));
    assert_eq!(format_resolve_arg("example.com", 443, v4), "example.com:443:93.184.216.34");
    assert_eq!(
        format_resolve_arg("example.com", 443, v6),
        "example.com:443:[2606:2800:220:1:248:1893:25c8:1946]"
    );
}

/// Verifies `StratFinderCli --timeout` parses fractional values and defaults to `2.0` seconds.
#[test]
fn cli_timeout_accepts_fractional_values_and_defaults_to_two_seconds() {
    let default_cli = StratFinderCli::try_parse_from(["strat_finder"]).expect("default cli parses");
    assert!((default_cli.timeout - 2.0).abs() < f64::EPSILON);

    let frac_cli =
        StratFinderCli::try_parse_from(["strat_finder", "--timeout", "1.25"]).expect("frac cli parses");
    assert!((frac_cli.timeout - 1.25).abs() < f64::EPSILON);
}

/// Verifies `CurlProbeBackend::probe_batch` preserves request indices across a multi-item batch.
#[cfg(unix)]
#[test]
fn curl_probe_batch_runs_requests_and_preserves_index_order() {
    use std::os::unix::fs::PermissionsExt as _;
    use zapret_rs::tools::{ProbeBackend as _, ProbeOutcome};

    let dir = std::env::temp_dir().join(format!("zapret-probe-batch-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let fake = dir.join("curl");
    // Reflect request domain count by returning distinct HTTP codes based on target URL.
    let script = "#!/bin/sh\nfor a in \"$@\"; do last=\"$a\"; done\ncase \"$last\" in\n  *d0*) printf '200\\n\\n0.010\\n' ;;\n  *d1*) printf '201\\n\\n0.020\\n' ;;\n  *d2*) exit 28 ;;\n  *) printf '204\\n\\n0.030\\n' ;;\nesac\n";
    std::fs::write(&fake, script).expect("write fake curl");
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).expect("chmod");

    let backend = CurlProbeBackend::new(fake);
    let reqs: Vec<ProbeRequest> = (0..4)
        .map(|i| ProbeRequest {
            domain: format!("d{i}.localhost"),
            proto: if i == 2 { ProbeProtocol::Tls12 } else { ProbeProtocol::Http },
            ipv: IpFamily::V4,
            timeout: Duration::from_millis(500),
        })
        .collect();

    let outcomes = backend.probe_batch(&reqs);
    assert_eq!(outcomes.len(), 4);
    assert_eq!(outcomes[0], ProbeOutcome::Available { http_code: 200, latency_ms: 10 });
    assert_eq!(outcomes[1], ProbeOutcome::Available { http_code: 201, latency_ms: 20 });
    assert_eq!(outcomes[2], ProbeOutcome::Timeout);
    assert_eq!(outcomes[3], ProbeOutcome::Available { http_code: 204, latency_ms: 30 });

    let _ = std::fs::remove_dir_all(&dir);
}
