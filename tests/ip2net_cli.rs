//! Integration and CLI parity tests for the `ip2net` library module and binary.

/// Buffered cursor input/output helpers for testing streaming `run_ip2net`.
use std::io::{BufReader, Cursor};
/// Subprocess execution and piped stdin/stdout assertions on the `ip2net` binary.
use std::process::{Command, Stdio};
/// Writing synthetic test inputs into the child process stdin pipe.
use std::io::Write;

/// `ip2net` configuration, validation parsers, error variants, and streaming runner.
use zapret_rs::tools::{
    Ip2NetConfig, Ip2NetError, Ip2NetFamily, parse_prefix_length, parse_v4_threshold,
    parse_v6_threshold, run_ip2net,
};

/// Returns a `zapret-rs ip2net` command backed by the compiled unified binary.
fn ip2net_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("ip2net");
    cmd
}

/// Runs `run_ip2net` on an arbitrary byte slice and returns UTF-8 stdout output.
fn run_bytes(cfg: &Ip2NetConfig, input: &[u8]) -> String {
    let mut reader = BufReader::new(Cursor::new(input));
    let mut out = Vec::new();
    run_ip2net(cfg, &mut reader, &mut out).expect("streaming ip2net execution");
    String::from_utf8(out).expect("UTF-8 ip2net output")
}

/// Spawns `ip2net` with `args`, feeds `stdin_bytes`, and returns `(code, stdout, stderr)`.
fn exec_ip2net(args: &[&str], stdin_bytes: &[u8]) -> (Option<i32>, String, String) {
    let mut child = ip2net_cmd()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ip2net binary");
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin_bytes)
        .expect("write ip2net stdin");
    let output = child.wait_with_output().expect("collect ip2net output");
    (
        output.status.code(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn ipv4_grouping_dedup_and_below_threshold() {
    let cfg = Ip2NetConfig::default();
    let input = b"\
10.0.0.3
10.0.0.1
10.0.0.2
10.0.0.2
192.168.1.1
192.168.1.3
";
    assert_eq!(
        run_bytes(&cfg, input),
        "\
10.0.0.0/30
192.168.1.1
192.168.1.3
"
    );
}

#[test]
fn ipv4_anti_carpet_bombing_vs_strictly_larger_coverage() {
    // At threshold 1/4 over prefix-length 29-30, 3 hosts in .0/30 fit both /29 and /30;
    // ip2net selects the narrower /30 rather than carpet-bombing /29.
    let cfg_narrow = Ip2NetConfig::from_options(
        Ip2NetFamily::Ipv4,
        Some("29-30"),
        Some("1/4"),
        None,
    )
    .expect("valid narrow config");
    assert_eq!(
        run_bytes(&cfg_narrow, b"10.0.0.1\n10.0.0.2\n10.0.0.3\n"),
        "10.0.0.0/30\n"
    );

    // At threshold 3/4 over prefix-length 29-30, 6 hosts spread across .0-.7 cover
    // strictly more than any /30 (6 > 3), so /29 wins over /30.
    let cfg_wide = Ip2NetConfig::from_options(
        Ip2NetFamily::Ipv4,
        Some("29-30"),
        Some("3/4"),
        None,
    )
    .expect("valid wide config");
    assert_eq!(
        run_bytes(
            &cfg_wide,
            b"10.0.0.0\n10.0.0.1\n10.0.0.2\n10.0.0.5\n10.0.0.6\n10.0.0.7\n"
        ),
        "10.0.0.0/29\n"
    );
}

#[test]
fn ipv4_fast_prune_boundary_matches_c() {
    let cfg = Ip2NetConfig::default();
    // {.1, .2, .3} starts at offset 1 == 4 * (4 - 3) / 4 -> collapses to 10.0.0.0/30.
    assert_eq!(
        run_bytes(&cfg, b"10.0.0.1\n10.0.0.2\n10.0.0.3\n"),
        "10.0.0.0/30\n"
    );
    // {.2, .3} starts at offset 2 > 1 and only has 2/4 hosts -> emitted individually.
    assert_eq!(
        run_bytes(&cfg, b"10.0.0.2\n10.0.0.3\n"),
        "10.0.0.2\n10.0.0.3\n"
    );

    // Verify large /1 prefix math avoids 32-bit overflow with 1/2 threshold.
    let cfg_large =
        Ip2NetConfig::from_options(Ip2NetFamily::Ipv4, Some("1"), Some("1/2"), None)
            .expect("valid /1 prefix config");
    assert_eq!(run_bytes(&cfg_large, b"0.0.0.1\n0.0.0.2\n"), "0.0.0.1\n0.0.0.2\n");
}

#[test]
fn ipv4_passthrough_ordering_slash32_folding_and_junk_ignored() {
    let cfg = Ip2NetConfig::default();
    let mut input = Vec::new();
    input.extend_from_slice(
        b"\
# comment line ignored
not an ip

198.51.100.3/32
198.51.100.1/32
203.0.113.0/24
198.51.100.99/33
192.0.2.10-192.0.2.20
198.51.100.2
",
    );
    // Inject an invalid UTF-8 line that must be skipped without erroring.
    input.extend_from_slice(b"\xff\xfe\n");

    // Existing CIDRs (< /32) and valid ranges emit during input streaming before grouped /32 singles.
    assert_eq!(
        run_bytes(&cfg, &input),
        "\
203.0.113.0/24
192.0.2.10-192.0.2.20
198.51.100.0/30
"
    );
}

#[test]
fn ipv6_grouping_thresholds_anti_carpet_bombing_and_passthrough() {
    let cfg = Ip2NetConfig::default();
    let cfg_v6 = Ip2NetConfig {
        family: Ip2NetFamily::Ipv6,
        zct_min: 64,
        zct_max: 72,
        ..cfg
    };

    // Pass-through CIDR (< /128) preserves prefix string; /128 folds; range passes through.
    // Five addresses in 2001:db8:1::/64 satisfy threshold 5 and prefer /64 over /56.
    // Four addresses in 2001:db8:2::/64 stay below threshold 5 and emit compressed.
    let input = b"\
2001:0db8:0000:0000::/48
2001:db8:9::1-2001:db8:9::20
2001:db8:1::1/128
2001:db8:1::2
2001:db8:1::3
2001:db8:1::4
2001:db8:1::5
2001:db8:1::5
2001:0db8:2::a
2001:db8:2::b
2001:db8:2::c
2001:db8:2::d
2001:db8:bad::1/129
bad:ipv6:line
";
    assert_eq!(
        run_bytes(&cfg_v6, input),
        "\
2001:0db8:0000:0000::/48
2001:db8:9::1-2001:db8:9::20
2001:db8:1::/64
2001:db8:2::a
2001:db8:2::b
2001:db8:2::c
2001:db8:2::d
"
    );
}

#[test]
fn option_parsers_validate_bounds_and_flag_order() {
    assert_eq!(
        parse_prefix_length("24", Ip2NetFamily::Ipv4).expect("single prefix v4"),
        (8, 8)
    );
    assert_eq!(
        parse_prefix_length("22-30", Ip2NetFamily::Ipv4).expect("range v4"),
        (2, 10)
    );
    assert_eq!(
        parse_prefix_length("56-64", Ip2NetFamily::Ipv6).expect("range v6"),
        (64, 72)
    );
    assert_eq!(parse_v4_threshold("3/4").expect("3/4"), (3, 4));
    assert_eq!(parse_v6_threshold("5").expect("5"), 5);

    for bad in ["0", "30-22", "32", "22-32", "abc", "22-24-30"] {
        assert!(
            matches!(
                parse_prefix_length(bad, Ip2NetFamily::Ipv4),
                Err(Ip2NetError::InvalidPrefixLength(_))
            ),
            "expected InvalidPrefixLength for v4 '{bad}'"
        );
    }
    assert!(matches!(
        parse_prefix_length("128", Ip2NetFamily::Ipv6),
        Err(Ip2NetError::InvalidPrefixLength(_))
    ));
    for bad in ["4/4", "0/4", "1/1", "3/2", "3", "a/b"] {
        assert!(
            matches!(parse_v4_threshold(bad), Err(Ip2NetError::InvalidV4Threshold(_))),
            "expected InvalidV4Threshold for '{bad}'"
        );
    }
    for bad in ["0", "-1", "abc"] {
        assert!(
            matches!(parse_v6_threshold(bad), Err(Ip2NetError::InvalidV6Threshold(_))),
            "expected InvalidV6Threshold for '{bad}'"
        );
    }

    // Prefix length 56-64 only valid once family=Ipv6 is resolved regardless of flag order.
    let cfg = Ip2NetConfig::from_options(Ip2NetFamily::Ipv6, Some("56-64"), None, Some("2"))
        .expect("v6 prefix valid with family=Ipv6");
    assert_eq!((cfg.zct_min, cfg.zct_max, cfg.v6_threshold), (64, 72, 2));
}

#[test]
fn binary_cli_v4_v6_flag_overrides_and_errors() {
    let (code, stdout, _) = exec_ip2net(&["--version"], b"");
    assert_eq!(code, Some(0));
    assert!(stdout.starts_with("ip2net "));

    let (code, stdout, _) = exec_ip2net(&["--help"], b"");
    assert_eq!(code, Some(0));
    assert!(stdout.contains("--prefix-length"));

    // `-4 -6` selects IPv6 and supports `--prefix-length=56-64` regardless of order.
    let (code, stdout, stderr) = exec_ip2net(
        &["--prefix-length=56-64", "-4", "-6", "--v6-threshold=2"],
        b"2001:db8:5::1\n2001:db8:5::2\n",
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stdout, "2001:db8:5::/64\n");

    // `-6 -4` switches back to IPv4 and accepts repeated `-4` flags.
    let (code, stdout, stderr) = exec_ip2net(
        &["-6", "-4", "-4"],
        b"198.51.100.1\n198.51.100.2\n198.51.100.3\n",
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(stdout, "198.51.100.0/30\n");

    // Invalid prefix length returns exit code 1 with diagnostic on stderr.
    let (code, _, stderr) = exec_ip2net(&["-4", "--prefix-length=0"], b"");
    assert_eq!(code, Some(1));
    assert!(stderr.contains("invalid parameter for prefix-length"));

    // Unknown flag returns exit code 1.
    let (code, _, _) = exec_ip2net(&["--unknown-flag"], b"");
    assert_eq!(code, Some(1));
}
