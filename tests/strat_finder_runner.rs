//! Offline integration tests for `strat_finder` probe classification, `nftables` script
//! generation, and multi-domain scan orchestration over mock backends.

/// Shared interior mutability linking mock strategy applier and mock probe backend.
use std::cell::RefCell;
/// Lookup table mapping `(domain, active_strategy_id)` to deterministic probe outcomes.
use std::collections::HashMap;
/// Filesystem helpers for temporary `--write-config` CLI tests.
use std::fs;
/// Subprocess execution for testing the compiled `strat_finder` CLI binary.
use std::process::Command;
/// Shared reference counting for coordinating mock state between applier and probe.
use std::rc::Rc;
/// Lock-free shutdown flag passed to [`run_scan`].
use std::sync::atomic::AtomicBool;
/// Timeout durations configured on [`ScanConfig`].
use std::time::Duration;

/// Application and desync profile models parsed from CLI-generated TOML.
use zapret_rs::config::{AppConfig, DesyncProfile};
/// Probe, firewall, runner, and catalog symbols under test.
use zapret_rs::tools::{
    CurlProbeBackend, IpFamily, NftFirewallBackend, ProbeBackend, ProbeOutcome, ProbeProtocol,
    ProbeRequest, ProgressEvent, STRAT_FINDER_NFT_TABLE, ScanConfig, ScanLevel, StrategyApplier,
    classify_curl_output, is_spoof_redirect, run_scan,
};

/// Shared mock state tracking the currently active strategy ID and scripted responses.
#[derive(Default)]
struct MockNetState {
    /// Active strategy ID installed by the mock applier (`None` = baseline pass-through).
    active_strategy: Option<String>,
    /// Scripted `(domain, Option<strategy_id>) -> ProbeOutcome` table.
    outcomes: HashMap<(String, Option<String>), ProbeOutcome>,
    /// Default outcome returned when `(domain, active_strategy)` is absent from `outcomes`.
    default_outcome: Option<ProbeOutcome>,
    /// Whether `supports_http3()` returns `true`.
    http3_supported: bool,
    /// Total number of `apply_profiles` calls made by the orchestrator.
    swap_count: usize,
}

/// Mock [`StrategyApplier`] recording active profile names without touching NFQUEUE.
struct MockApplier(Rc<RefCell<MockNetState>>);

impl StrategyApplier for MockApplier {
    /// Updates `active_strategy` to the first profile's name (or `None` when cleared).
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String> {
        let mut st = self.0.borrow_mut();
        st.swap_count += 1;
        st.active_strategy = profiles.first().and_then(|p| p.name.clone());
        Ok(())
    }
}

/// Mock [`ProbeBackend`] returning scripted outcomes based on the currently active strategy.
struct MockProbe(Rc<RefCell<MockNetState>>);

impl ProbeBackend for MockProbe {
    /// Returns scripted HTTP/3 capability.
    fn supports_http3(&self) -> bool {
        self.0.borrow().http3_supported
    }

    /// Looks up `(req.domain, active_strategy)` in scripted outcomes.
    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome {
        let st = self.0.borrow();
        if let Some(out) = st.outcomes.get(&(req.domain.clone(), st.active_strategy.clone())) {
            return out.clone();
        }
        st.default_outcome.clone().unwrap_or(ProbeOutcome::Timeout)
    }
}

/// Verifies `classify_curl_output`, `is_spoof_redirect`, and `CurlProbeBackend::build_args`.
#[test]
fn curl_output_classifier_and_spoof_redirect_detection() {
    // Legitimate same-domain and subdomain redirects are NOT spoofed.
    assert!(!is_spoof_redirect("example.com", "https://www.example.com/home"));
    assert!(!is_spoof_redirect("www.example.com", "https://example.com/"));
    assert!(!is_spoof_redirect("m.example.com", "https://www.example.com/"));
    // Redirect to an unrelated ISP block page host IS spoofed.
    assert!(is_spoof_redirect("blocked.org", "http://warning.isp.local/block?site=blocked.org"));
    assert!(is_spoof_redirect("blocked.org", "http://10.0.0.1/blocked"));

    let ok = classify_curl_output("example.com", 0, "200\n\n0.123\n", "", 999);
    assert_eq!(ok, ProbeOutcome::Available { http_code: 200, latency_ms: 123 });

    let leg_redir = classify_curl_output("example.com", 0, "301\nhttps://www.example.com/\n0.045\n", "", 999);
    assert_eq!(leg_redir, ProbeOutcome::Available { http_code: 301, latency_ms: 45 });

    let spoof = classify_curl_output("blocked.org", 0, "302\nhttp://isp-block.example/denied\n0.012\n", "", 999);
    assert_eq!(
        spoof,
        ProbeOutcome::SpoofRedirect { location: "http://isp-block.example/denied".to_owned() }
    );

    assert_eq!(classify_curl_output("blocked.org", 28, "", "timed out", 3000), ProbeOutcome::Timeout);
    assert_eq!(
        classify_curl_output("blocked.org", 56, "", "Recv failure: Connection reset by peer", 20),
        ProbeOutcome::TcpReset
    );
    assert_eq!(
        classify_curl_output("blocked.org", 35, "", "SSL_ERROR_SYSCALL", 30),
        ProbeOutcome::TlsError { code: 35 }
    );

    let req = ProbeRequest {
        domain: "example.com".to_owned(),
        proto: ProbeProtocol::Tls12,
        ipv: IpFamily::V6,
        timeout: Duration::from_secs(3),
    };
    let args = CurlProbeBackend::build_args(&req);
    assert!(args.contains(&"-6".to_owned()));
    assert!(args.contains(&"--tlsv1.2".to_owned()));
    assert!(args.contains(&"https://example.com/".to_owned()));
}

/// Verifies `NftFirewallBackend::build_nft_script` uses multi-line syntax, `bypass`, and `fwmark`.
#[test]
fn nft_script_renders_multiline_bypass_queue_and_fwmark_guard() {
    let script = NftFirewallBackend::build_nft_script(210, 0x4000_0000, &[80, 443], &[443]);
    assert!(script.contains(&format!("table inet {STRAT_FINDER_NFT_TABLE}\n{{")));
    assert!(script.contains("meta mark & 0x40000000 != 0 accept"));
    assert!(script.contains("tcp dport { 80, 443 } queue num 210 bypass"));
    assert!(script.contains("udp dport { 443 } queue num 210 bypass"));
    assert!(script.contains("tcp sport { 80, 443 } ct original packets 1-6 queue num 210 bypass"));
}

/// Verifies baseline skipping for unblocked sites, spoof-redirect rejection during sweeps,
/// latency/weight ranking, and multi-domain minimal set cover.
#[test]
fn scan_orchestrator_skips_unblocked_rejects_spoofs_and_computes_cover() {
    let state = Rc::new(RefCell::new(MockNetState::default()));
    {
        let mut st = state.borrow_mut();
        // `open.test` is reachable on baseline -> must skip strategy sweep.
        st.outcomes.insert(
            ("open.test".to_owned(), None),
            ProbeOutcome::Available { http_code: 200, latency_ms: 15 },
        );
        // `a.blocked` returns spoof redirect on baseline and on `multisplit:1`,
        // works with `multisplit:midsld` (weight 20, 40ms) and `fake:ttl=3` (weight 45, 25ms).
        st.outcomes.insert(
            ("a.blocked".to_owned(), None),
            ProbeOutcome::SpoofRedirect { location: "http://isp.block/a".to_owned() },
        );
        st.outcomes.insert(
            ("a.blocked".to_owned(), Some("tls13:ipv4:multisplit:1".to_owned())),
            ProbeOutcome::SpoofRedirect { location: "http://isp.block/still-blocked".to_owned() },
        );
        st.outcomes.insert(
            ("a.blocked".to_owned(), Some("tls13:ipv4:multisplit:midsld".to_owned())),
            ProbeOutcome::Available { http_code: 200, latency_ms: 40 },
        );
        st.outcomes.insert(
            ("a.blocked".to_owned(), Some("tls13:ipv4:fake:ttl=3".to_owned())),
            ProbeOutcome::Available { http_code: 200, latency_ms: 25 },
        );
        // `b.blocked` times out on baseline and also works with `multisplit:midsld` (60ms).
        st.outcomes.insert(("b.blocked".to_owned(), None), ProbeOutcome::Timeout);
        st.outcomes.insert(
            ("b.blocked".to_owned(), Some("tls13:ipv4:multisplit:midsld".to_owned())),
            ProbeOutcome::Available { http_code: 200, latency_ms: 60 },
        );
    }

    let cfg = ScanConfig {
        domains: vec!["open.test".to_owned(), "a.blocked".to_owned(), "b.blocked".to_owned()],
        protos: vec![ProbeProtocol::Tls13],
        families: vec![IpFamily::V4],
        level: ScanLevel::Quick,
        timeout: Duration::from_secs(2),
        stop_on_first: false,
        force_blocked: false,
    };

    let probe = MockProbe(Rc::clone(&state));
    let mut applier = MockApplier(Rc::clone(&state));
    let stop = AtomicBool::new(false);
    let report = run_scan(&cfg, &probe, &mut applier, &stop, |_| {}).expect("scan ok");

    assert!(!report.interrupted);
    assert_eq!(report.targets.len(), 3);
    assert!(report.targets[0].skipped_unblocked);
    assert_eq!(report.targets[0].tested_count, 0);

    // `a.blocked` had 2 valid matches (`multisplit:midsld` ranked ahead of heavier `fake:ttl=3`).
    assert!(!report.targets[1].skipped_unblocked);
    assert_eq!(report.targets[1].matches.len(), 2);
    assert_eq!(report.targets[1].matches[0].strategy.id, "tls13:ipv4:multisplit:midsld");
    assert_eq!(report.targets[1].matches[1].strategy.id, "tls13:ipv4:fake:ttl=3");

    // Set cover merges `a.blocked` and `b.blocked` into a single profile!
    assert_eq!(report.cover.len(), 1);
    assert_eq!(report.cover[0].strategy.id, "tls13:ipv4:multisplit:midsld");
    assert_eq!(report.cover[0].domains, vec!["a.blocked".to_owned(), "b.blocked".to_owned()]);
    assert_eq!(report.cover[0].avg_latency_ms, 50);
}

/// Verifies `--stop-on-first`, HTTP/3 unavailability skipping, and graceful `stop` interruption.
#[test]
fn scan_orchestrator_honors_stop_on_first_http3_skip_and_interrupt() {
    let state = Rc::new(RefCell::new(MockNetState::default()));
    {
        let mut st = state.borrow_mut();
        st.http3_supported = false;
        st.outcomes.insert(("x.blocked".to_owned(), None), ProbeOutcome::TcpReset);
        st.outcomes.insert(
            ("x.blocked".to_owned(), Some("tls13:ipv4:multisplit:1".to_owned())),
            ProbeOutcome::Available { http_code: 200, latency_ms: 33 },
        );
        st.outcomes.insert(
            ("x.blocked".to_owned(), Some("tls13:ipv4:multisplit:midsld".to_owned())),
            ProbeOutcome::Available { http_code: 200, latency_ms: 20 },
        );
    }

    let cfg = ScanConfig {
        domains: vec!["x.blocked".to_owned()],
        protos: vec![ProbeProtocol::Tls13, ProbeProtocol::Http3],
        families: vec![IpFamily::V4],
        level: ScanLevel::Quick,
        timeout: Duration::from_secs(2),
        stop_on_first: true,
        force_blocked: false,
    };

    let probe = MockProbe(Rc::clone(&state));
    let mut applier = MockApplier(Rc::clone(&state));
    let stop = AtomicBool::new(false);
    let mut saw_h3_skip = false;

    let report = run_scan(&cfg, &probe, &mut applier, &stop, |ev| {
        if matches!(ev, ProgressEvent::Http3Unavailable) {
            saw_h3_skip = true;
        }
    })
    .expect("scan ok");

    assert!(saw_h3_skip, "should notify when HTTP/3 is unavailable");
    assert_eq!(report.targets.len(), 1, "HTTP/3 target must be skipped");
    assert_eq!(report.targets[0].matches.len(), 1);
    assert_eq!(report.targets[0].tested_count, 1, "stop-on-first must stop on candidate #1");

    // Pre-signaled stop flag interrupts immediately before probing.
    let interrupted_stop = AtomicBool::new(true);
    let interrupted = run_scan(&cfg, &probe, &mut applier, &interrupted_stop, |_| {})
        .expect("interrupted scan returns partial report");
    assert!(interrupted.interrupted);
    assert!(interrupted.targets.is_empty());
}

/// Verifies the compiled `strat_finder` CLI handles `--version`, `--help`, invalid flags,
/// and `--list-strategies --write-config` without requiring root privileges.
#[test]
fn strat_finder_cli_version_help_invalid_and_list_write_config() {
    let bin = env!("CARGO_BIN_EXE_strat_finder");

    let ver = Command::new(bin).arg("--version").output().expect("run --version");
    assert!(ver.status.success());
    let ver_str = String::from_utf8_lossy(&ver.stdout);
    assert_eq!(ver_str.trim(), format!("strat_finder {}", env!("CARGO_PKG_VERSION")));

    let help = Command::new(bin).arg("--help").output().expect("run --help");
    assert!(help.status.success());
    let help_str = String::from_utf8_lossy(&help.stdout);
    assert!(help_str.contains("--domain"));
    assert!(help_str.contains("--write-config"));
    assert!(help_str.contains("--list-strategies"));

    let bad = Command::new(bin)
        .args(["--level", "invalid_level", "--list-strategies"])
        .output()
        .expect("run invalid --level");
    assert!(!bad.status.success());
    let bad_err = String::from_utf8_lossy(&bad.stderr);
    assert!(bad_err.contains("invalid scan level"));

    let tmp_path = std::env::temp_dir().join(format!(
        "strat_finder_cli_test_{}.toml",
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp_path);

    let list = Command::new(bin)
        .args([
            "--list-strategies",
            "--level",
            "quick",
            "--proto",
            "http,tls13,http3",
            "--domain",
            "example.com",
            "--write-config",
        ])
        .arg(&tmp_path)
        .output()
        .expect("run --list-strategies");
    assert!(
        list.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&list.stderr)
    );
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(list_out.contains("# http/ipv4 (quick):"));
    assert!(list_out.contains("# tls13/ipv4 (quick):"));
    assert!(list_out.contains("# http3/ipv4 (quick):"));

    let parsed = AppConfig::from_toml_file(&tmp_path).expect("CLI-written TOML must parse");
    assert_eq!(parsed.profiles.len(), 3);
    let _ = fs::remove_file(&tmp_path);
}
