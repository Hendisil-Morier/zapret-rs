//! Offline integration and CLI tests for the `mdig` DNS packet helpers, resolver pool, and binary.

/// Synchronized lookup counters inside the offline `DnsResolver` test double.
use std::collections::HashMap;
/// Temporary log files and directory setup for `--log-resolved` / `--log-failed` CLI checks.
use std::fs;
/// In-memory cursor readers and stdin pipe writing helpers.
use std::io::{BufReader, Cursor, Write};
/// Parsed IPv4 and IPv6 addresses returned by query parsing and mocked lookups.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Temporary filesystem paths for log-file tests.
use std::path::PathBuf;
/// Synchronizing concurrent mock attempt counters across `mdig` worker threads.
use std::sync::Mutex;

/// Subprocess invocation for CLI binary smoke and exit-code parity verification.
use std::process::{Command, Stdio};

/// `mdig` DNS packet builders/parsers, resolver runner, configuration parser, and error types.
use zapret_rs::tools::{
    DNS_CLASS_IN, DNS_TYPE_A, DNS_TYPE_AAAA, DnsResolver, MdigConfig, MdigConfigError, MdigFamily,
    MdigOutputs, ResolveError, build_dns_query, build_dns_query_with_id, parse_dns_reply,
    read_and_parse_dns_reply, run_mdig_resolver,
};

/// Returns a `zapret-rs mdig` command backed by the compiled unified binary.
fn mdig_cmd() -> Command
{
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("mdig");
    cmd
}

/// Creates a clean temporary directory scoped to the current test process and label.
fn fresh_temp_dir(label: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-mdig-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    dir
}

/// Spawns `mdig` with `args`, feeds `stdin_bytes`, and returns `(code, stdout, stderr)`.
fn exec_mdig(args: &[&str], stdin_bytes: &[u8]) -> (Option<i32>, Vec<u8>, String)
{
    let mut child = mdig_cmd()
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn mdig binary");
    child.stdin.take().expect("piped stdin").write_all(stdin_bytes).expect("write mdig stdin");
    let output = child.wait_with_output().expect("collect mdig output");
    (output.status.code(), output.stdout, String::from_utf8_lossy(&output.stderr).into_owned())
}

/// Builds a synthetic RFC 1035 DNS reply packet for testing compressed and uncompressed answers.
fn sample_dns_reply(compressed_answers: bool) -> Vec<u8>
{
    let mut pkt = vec![
        0x12, 0x34, 0x81, 0x80, // id=0x1234, QR=1, RD=1, RA=1
        0x00, 0x01, 0x00, 0x03, // qdcount=1, ancount=3
        0x00, 0x00, 0x00, 0x00,
    ];
    // Question: a.b + type A + class IN
    let qname = [1, b'a', 1, b'b', 0];
    pkt.extend_from_slice(&qname);
    pkt.extend_from_slice(&[0, 1, 0, 1]);

    // RR 1: CNAME "x" in IN class (must be ignored safely without breaking cursor)
    if compressed_answers
    {
        pkt.extend_from_slice(&[0xC0, 0x0C]);
    }
    else
    {
        pkt.extend_from_slice(&qname);
    }
    pkt.extend_from_slice(&[0, 5, 0, 1, 0, 0, 0, 60, 0, 3, 1, b'x', 0]);

    // RR 2: IN A = 198.51.100.7
    pkt.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 51, 100, 7]);
    // RR 3: IN AAAA = 2001:db8::42
    pkt.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
    pkt.extend_from_slice(&Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x42).octets());
    pkt
}

#[test]
fn dns_make_query_and_parse_reply_roundtrip_a_and_aaaa()
{
    let pkt_a = build_dns_query_with_id(0, "example.com.", DNS_CLASS_IN, DNS_TYPE_A, 0xBEEF)
        .expect("build A query with trailing dot");
    assert_eq!(
        pkt_a,
        vec![
            0xBE, 0xEF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7, b'e', b'x', b'a',
            b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0x00, 0x01, 0x00, 0x01
        ]
    );

    let pkt_aaaa = build_dns_query("v6.example", MdigFamily::Ipv6).expect("build AAAA query");
    assert_eq!(&pkt_aaaa[pkt_aaaa.len() - 4..], &[0, DNS_TYPE_AAAA, 0, DNS_CLASS_IN]);
    let pkt_46 = build_dns_query("both.example", MdigFamily::Ipv46).expect("build A query for 46");
    assert_eq!(&pkt_46[pkt_46.len() - 4..], &[0, DNS_TYPE_A, 0, DNS_CLASS_IN]);

    // Root domain produces a 17-byte query packet matching mdig.c.
    assert_eq!(build_dns_query(".", MdigFamily::Ipv4).expect("root dot").len(), 17);
    assert_eq!(build_dns_query("", MdigFamily::Ipv4).expect("empty root").len(), 17);

    // Invalid names rejected cleanly.
    let long_label = "a".repeat(64);
    for bad in ["..", ".leading.com", "a..b", &long_label, &"a".repeat(254), "nul\0byte"]
    {
        assert!(build_dns_query(bad, MdigFamily::Ipv4).is_none(), "expected None for {bad:?}");
    }
    assert!(build_dns_query_with_id(16, "a.com", 1, 1, 1).is_none());

    // Parse compressed and uncompressed replies cleanly.
    let expected = vec![
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x42)),
    ];
    assert_eq!(parse_dns_reply(&sample_dns_reply(true)), Some(expected.clone()));
    assert_eq!(parse_dns_reply(&sample_dns_reply(false)), Some(expected));

    // Malformed packets rejected.
    assert!(parse_dns_reply(&pkt_a).is_none()); // QR bit unset
    assert!(parse_dns_reply(&[0u8; 11]).is_none()); // short header
    let mut bad_label = sample_dns_reply(true);
    bad_label[12] = 0x40; // reserved RFC 1035 label type
    assert!(parse_dns_reply(&bad_label).is_none());

    let mut parsed_out = Vec::new();
    let mut cursor = Cursor::new(sample_dns_reply(true));
    read_and_parse_dns_reply(&mut cursor, &mut parsed_out).expect("stream reply parse");
    assert_eq!(String::from_utf8(parsed_out).expect("utf8"), "198.51.100.7\n2001:db8::42\n");
}

/// Deterministic offline DNS stub tracking attempts per domain.
struct MockResolver
{
    /// Recorded call counts per queried hostname.
    attempts: Mutex<HashMap<String, usize>>,
}

impl MockResolver
{
    /// Creates a new empty mock resolver.
    fn new() -> Self
    {
        Self { attempts: Mutex::new(HashMap::new()) }
    }

    /// Returns how many times `domain` was passed to [`DnsResolver::resolve`].
    fn count(&self, domain: &str) -> usize
    {
        self.attempts.lock().expect("lock mock map").get(domain).copied().unwrap_or(0)
    }
}

impl DnsResolver for MockResolver
{
    fn resolve(&self, domain: &str, family: MdigFamily) -> Result<Vec<IpAddr>, ResolveError>
    {
        let attempt = {
            let mut map = self.attempts.lock().expect("lock mock map");
            let entry = map.entry(domain.to_string()).or_insert(0);
            *entry += 1;
            *entry
        };
        #[cfg(unix)]
        const EAI_AGAIN: i32 = libc::EAI_AGAIN;
        #[cfg(not(unix))]
        const EAI_AGAIN: i32 = 11002;
        #[cfg(unix)]
        const EAI_NONAME: i32 = libc::EAI_NONAME;
        #[cfg(not(unix))]
        const EAI_NONAME: i32 = 11001;
        match domain
        {
            "flaky.example" if attempt < 3 => Err(ResolveError { code: EAI_AGAIN }),
            "flaky.example" => Ok(vec![IpAddr::V4(Ipv4Addr::new(198, 51, 100, 42))]),
            "dead.example" => Err(ResolveError { code: EAI_AGAIN }),
            "missing.example" => Err(ResolveError { code: EAI_NONAME }),
            "dual.example" =>
            {
                let mut res = Vec::new();
                if family.allows_v4()
                {
                    res.push(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
                }
                if family.allows_v6()
                {
                    res.push(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
                }
                Ok(res)
            }
            _ => Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]),
        }
    }
}

/// Runs [`run_mdig_resolver`] in memory and returns `(started, stdout, stderr, resolved, failed)`.
fn run_in_memory(
    cfg: &MdigConfig,
    resolver: &dyn DnsResolver,
    input: &[u8],
) -> (usize, String, String, String, String)
{
    let mut reader = BufReader::new(Cursor::new(input));
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut log_resolved = Vec::new();
    let mut log_failed = Vec::new();
    let started = run_mdig_resolver(
        cfg,
        resolver,
        &mut reader,
        MdigOutputs {
            stdout: &mut stdout,
            stderr: &mut stderr,
            log_resolved: Some(&mut log_resolved),
            log_failed: Some(&mut log_failed),
        },
    );
    (
        started,
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        String::from_utf8_lossy(&log_resolved).into_owned(),
        String::from_utf8_lossy(&log_failed).into_owned(),
    )
}

#[test]
fn resolver_passthrough_ip_and_cidr_family_filtering()
{
    let mock = MockResolver::new();
    let input = b"\
1.2.3.4
1.2.3.4/32
10.0.0.0/24
1.2.3.4/33
2001:db8::1
";
    let cfg_v4 = MdigConfig { family: MdigFamily::Ipv4, verbose: true, ..MdigConfig::default() };
    let (_, stdout, stderr, resolved, failed) = run_in_memory(&cfg_v4, &mock, input);
    assert_eq!(stdout, "1.2.3.4\n1.2.3.4\n10.0.0.0/24\n");
    assert_eq!(resolved, "1.2.3.4\n1.2.3.4/32\n10.0.0.0/24\n");
    assert_eq!(failed, "1.2.3.4/33\n2001:db8::1\n");
    assert!(stderr.contains("bad ip/subnet 1.2.3.4/33"));
    assert!(stderr.contains("wrong address family 2001:db8::1"));

    let v6_input = b"2001:db8::1/128\n2001:db8::/48\n2001:db8::1/129\n192.0.2.1\n";
    let cfg_v6 = MdigConfig { family: MdigFamily::Ipv6, verbose: true, ..MdigConfig::default() };
    let (_, stdout6, stderr6, resolved6, failed6) = run_in_memory(&cfg_v6, &mock, v6_input);
    assert_eq!(stdout6, "2001:db8::1\n2001:db8::/48\n");
    assert_eq!(resolved6, "2001:db8::1/128\n2001:db8::/48\n");
    assert_eq!(failed6, "2001:db8::1/129\n192.0.2.1\n");
    assert!(stderr6.contains("bad ip/subnet 2001:db8::1/129"));
    assert!(stderr6.contains("wrong address family 192.0.2.1"));
}

#[test]
fn resolver_multithreaded_eagain_retries_stats_and_logs()
{
    let mock = MockResolver::new();
    let cfg = MdigConfig {
        family: MdigFamily::Ipv46,
        threads: 4,
        eagain: 3,
        eagain_delay_ms: 0,
        verbose: true,
        stats_every: 3,
    };
    let mut input = Vec::new();
    input.extend_from_slice(
        b"\
flaky.example
dead.example
missing.example
dual.example
203.0.113.5/32

bad/dom\x01
",
    );
    input.extend_from_slice(b"\xff\xfe\n");

    let (started, stdout, stderr, resolved, failed) = run_in_memory(&cfg, &mock, &input);
    assert_eq!(started, 4);

    assert_eq!(mock.count("flaky.example"), 3);
    assert_eq!(mock.count("dead.example"), 3);
    assert_eq!(mock.count("missing.example"), 1);

    let mut out_lines: Vec<&str> = stdout.lines().collect();
    out_lines.sort_unstable();
    assert_eq!(out_lines, vec!["198.51.100.42", "2001:db8::1", "203.0.113.1", "203.0.113.5"]);

    let mut res_lines: Vec<&str> = resolved.lines().collect();
    res_lines.sort_unstable();
    assert_eq!(res_lines, vec!["203.0.113.5/32", "dual.example", "flaky.example"]);

    // 4 failed non-empty lines: dead.example, missing.example, bad/dom\x01, and non-UTF-8;
    // blank line increments stats count (8 total) without entering resolved/failed logs.
    assert_eq!(failed.lines().count(), 4);
    assert!(stderr.contains("invalid domain : bad/dom?"));
    assert!(stderr.contains("invalid domain : ??"));
    assert!(stderr.contains("EAI_AGAIN"));
    assert!(stderr.contains("EAI_NONAME"));
    assert!(stderr.contains("] started"));
    assert!(stderr.contains("] ended"));
    assert!(stderr.contains("domains=8 success=3 error=5"));
    assert!(stderr.contains("domains=3 "));
    assert!(stderr.contains("domains=6 "));
}

#[test]
fn config_validation_bounds()
{
    let ok = MdigConfig::from_options(Some("46"), Some("100"), Some("1000"), Some("0"), true, Some("-1"))
        .expect("boundary config");
    assert_eq!(
        (ok.family, ok.threads, ok.eagain, ok.eagain_delay_ms, ok.stats_every),
        (MdigFamily::Ipv46, 100, 1000, 0, 0)
    );

    let max_delay = MdigConfig::from_options(None, Some("1"), Some("1"), Some("100000"), false, Some("25"))
        .expect("max delay config");
    assert_eq!((max_delay.eagain_delay_ms, max_delay.stats_every), (100_000, 25));

    assert!(matches!(
        MdigConfig::from_options(Some("9"), None, None, None, false, None),
        Err(MdigConfigError::InvalidFamily(_))
    ));
    for bad in ["0", "101", "x"]
    {
        assert!(matches!(
            MdigConfig::from_options(None, Some(bad), None, None, false, None),
            Err(MdigConfigError::InvalidThreads(_))
        ));
    }
    for bad in ["0", "1001", "x"]
    {
        assert!(matches!(
            MdigConfig::from_options(None, None, Some(bad), None, false, None),
            Err(MdigConfigError::InvalidEagain(_))
        ));
    }
    for bad in ["-1", "100001", "x"]
    {
        assert!(matches!(
            MdigConfig::from_options(None, None, None, Some(bad), false, None),
            Err(MdigConfigError::InvalidEagainDelay(_))
        ));
    }
    assert!(matches!(
        MdigConfig::from_options(None, None, None, None, false, Some("bad")),
        Err(MdigConfigError::InvalidStats(_))
    ));
}

#[test]
fn binary_cli_dns_modes_passthrough_and_exit_codes()
{
    let (code, stdout, _) = exec_mdig(&["--version"], b"");
    assert_eq!(code, Some(0));
    assert!(String::from_utf8_lossy(&stdout).starts_with("mdig "));

    let (code, stdout, _) = exec_mdig(&["--help"], b"");
    assert_eq!(code, Some(0));
    assert!(String::from_utf8_lossy(&stdout).contains("--dns-make-query"));

    let (code, qblob, stderr) = exec_mdig(&["--family=6", "--dns-make-query=example.com"], b"");
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(qblob.len(), 29);
    assert_eq!(&qblob[qblob.len() - 4..], &[0, DNS_TYPE_AAAA, 0, DNS_CLASS_IN]);

    let (code, _, stderr) = exec_mdig(&["--dns-make-query=.bad"], b"");
    assert_eq!(code, Some(1));
    assert!(stderr.contains("could not make DNS query"));

    let (code, stdout, stderr) = exec_mdig(&["--dns-parse-query"], &sample_dns_reply(true));
    assert_eq!(code, Some(0), "stderr: {stderr}");
    assert_eq!(String::from_utf8_lossy(&stdout), "198.51.100.7\n2001:db8::42\n");

    assert_eq!(exec_mdig(&["--dns-parse-query"], b"").0, Some(10));
    assert_eq!(exec_mdig(&["--dns-parse-query"], b"\x00\x01\x00\x00\x00\x00").0, Some(11));

    // Offline pass-through CLI check with --log-resolved and --log-failed.
    let tmp = fresh_temp_dir("cli-logs");
    let ok_log = tmp.join("resolved.log");
    let fail_log = tmp.join("failed.log");
    let (code, stdout, stderr) = exec_mdig(
        &[
            "--family=46",
            "--threads=2",
            "--stats=10",
            "--log-resolved",
            &ok_log.to_string_lossy(),
            "--log-failed",
            &fail_log.to_string_lossy(),
        ],
        b"192.0.2.10/32\n2001:db8::/64\n192.0.2.1/33\n",
    );
    assert_eq!(code, Some(0), "stderr: {stderr}");
    let out_str = String::from_utf8_lossy(&stdout);
    let mut out_lines: Vec<&str> = out_str.lines().collect();
    out_lines.sort_unstable();
    assert_eq!(out_lines, vec!["192.0.2.10", "2001:db8::/64"]);
    assert!(stderr.contains("domains=3 success=2 error=1"));
    let ok_str = fs::read_to_string(&ok_log).expect("read ok log");
    let mut ok_lines: Vec<&str> = ok_str.lines().collect();
    ok_lines.sort_unstable();
    assert_eq!(ok_lines, vec!["192.0.2.10/32", "2001:db8::/64"]);
    assert_eq!(fs::read_to_string(&fail_log).expect("read fail log"), "192.0.2.1/33\n");

    // Unwritable log path returns exit code 5; invalid --threads returns exit code 1.
    let bad_path = tmp.to_string_lossy().into_owned();
    assert_eq!(exec_mdig(&["--log-resolved", &bad_path], b"").0, Some(5));
    assert_eq!(exec_mdig(&["--threads=101"], b"").0, Some(1));
    let _ = fs::remove_dir_all(&tmp);
}
