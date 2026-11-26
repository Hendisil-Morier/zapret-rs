//! Offline tests for Strategy Finder scan speedups (fractional timeouts, `--resolve`, batching).

/// Shared interior mutability linking mock applier and mock probe backend.
use std::cell::RefCell;
/// Scripted outcome map keyed by `(domain, strategy_id)`.
use std::collections::HashMap;
/// Network address types for verifying IPv4/IPv6 `--resolve` formatting.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Reference counting for mock test harness state.
use std::rc::Rc;
/// Shutdown flag passed into [`run_scan`].
use std::sync::atomic::AtomicBool;
/// Command-line parsing verification for fractional `--timeout` and default changes.
use clap::Parser;
/// Timeout duration passed to argument builders and batch tests.
use std::time::Duration;

/// Strategy profile config type used in mock `StrategyApplier`.
use zapret_rs::config::DesyncProfile;
/// Strategy finder probe, runner, and CLI symbols under test.
use zapret_rs::tools::{
    CurlProbeBackend, IpFamily, ProbeBackend, ProbeOutcome, ProbeProtocol, ProbeRequest,
    ScanConfig, ScanLevel, StratFinderCli, StrategyApplier, build_catalog, format_resolve_arg,
    prioritize_sticky, run_scan,
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

/// Shared state for mock probe/applier tests recording batch sizes and profile swaps.
#[derive(Default)]
struct SpeedMockState {
    active_strategy: Option<String>,
    outcomes: HashMap<(String, Option<String>), ProbeOutcome>,
    batch_sizes: Vec<usize>,
    clear_count: usize,
    swap_count: usize,
}

/// Mock applier tracking `clear()` vs non-empty `apply_profiles()` calls.
struct SpeedMockApplier(Rc<RefCell<SpeedMockState>>);

impl StrategyApplier for SpeedMockApplier {
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String> {
        let mut st = self.0.borrow_mut();
        if profiles.is_empty() {
            st.clear_count += 1;
            st.active_strategy = None;
        } else {
            st.swap_count += 1;
            st.active_strategy = profiles.first().and_then(|p| p.name.clone());
        }
        Ok(())
    }
}

/// Mock probe recording `probe_batch` call sizes and resolving scripted outcomes.
struct SpeedMockProbe(Rc<RefCell<SpeedMockState>>);

impl ProbeBackend for SpeedMockProbe {
    fn supports_http3(&self) -> bool { false }

    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome {
        let st = self.0.borrow();
        st.outcomes
            .get(&(req.domain.clone(), st.active_strategy.clone()))
            .cloned()
            .unwrap_or(ProbeOutcome::Timeout)
    }

    fn probe_batch(&self, reqs: &[ProbeRequest]) -> Vec<ProbeOutcome> {
        self.0.borrow_mut().batch_sizes.push(reqs.len());
        reqs.iter().map(|r| self.probe(r)).collect()
    }
}

/// Verifies `prioritize_sticky` puts same-family winners first, then cross-family, preserving order.
#[test]
fn prioritize_sticky_orders_same_family_then_cross_family_without_duplicates() {
    let cat = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V6);
    let last_suffix = cat.last().expect("non-empty catalog").id
        .split_once(':').and_then(|(_, r)| r.split_once(':')).expect("suffix").1.to_owned();
    let mid_suffix = cat[2].id
        .split_once(':').and_then(|(_, r)| r.split_once(':')).expect("suffix").1.to_owned();

    let sticky = vec![(IpFamily::V4, mid_suffix.clone()), (IpFamily::V6, last_suffix.clone())];
    let reordered = prioritize_sticky(cat.clone(), &sticky);
    assert_eq!(reordered.len(), cat.len());
    assert!(reordered[0].id.ends_with(&format!(":{last_suffix}")), "same-family match first");
    assert!(reordered[1].id.ends_with(&format!(":{mid_suffix}")), "cross-family match second");
}

/// Verifies `run_scan` batches all baselines in one `probe_batch` wave and promotes sticky strategies.
#[test]
fn run_scan_batches_baselines_and_promotes_sticky_winner_to_first_probe() {
    let cat_t12 = build_catalog(ProbeProtocol::Tls12, ScanLevel::Quick, IpFamily::V4);
    let winner_t12 = cat_t12.last().expect("last tls12").id.clone();
    let suffix = winner_t12
        .split_once(':').and_then(|(_, r)| r.split_once(':')).expect("suffix").1.to_owned();
    let winner_t13 = format!("tls13:ipv4:{suffix}");

    let state = Rc::new(RefCell::new(SpeedMockState::default()));
    {
        let mut st = state.borrow_mut();
        st.outcomes.insert(("d1.blocked".to_owned(), Some(winner_t12)), ProbeOutcome::Available { http_code: 200, latency_ms: 20 });
        st.outcomes.insert(("d1.blocked".to_owned(), Some(winner_t13.clone())), ProbeOutcome::Available { http_code: 200, latency_ms: 21 });
        st.outcomes.insert(("d2.blocked".to_owned(), Some(winner_t13)), ProbeOutcome::Available { http_code: 200, latency_ms: 22 });
    }

    let cfg = ScanConfig {
        domains: vec!["d1.blocked".to_owned(), "d2.blocked".to_owned()],
        protos: vec![ProbeProtocol::Tls12, ProbeProtocol::Tls13],
        families: vec![IpFamily::V4],
        level: ScanLevel::Quick,
        timeout: Duration::from_secs(2),
        stop_on_first: true,
        force_blocked: false,
    };
    let mut applier = SpeedMockApplier(Rc::clone(&state));
    let probe = SpeedMockProbe(Rc::clone(&state));
    let stop = AtomicBool::new(false);

    let report = run_scan(&cfg, &probe, &mut applier, &stop, |_| {}).expect("scan ok");
    let st = state.borrow();
    // Single baseline batch for all 4 `(domain, proto)` targets, and 1 clear before + 1 clear after.
    assert_eq!(st.batch_sizes[0], 4);
    assert_eq!(st.clear_count, 2);

    // First target (`d1.blocked`, `tls12`) needed the whole catalog; sticky promotion makes
    // subsequent `tls13` targets pass on candidate #1 (`tested_count == 1`).
    assert_eq!(report.targets.len(), 4);
    assert_eq!(report.targets[0].tested_count, cat_t12.len());
    assert_eq!(report.targets[1].tested_count, 1, "sticky winner promoted to index 0 on tls13");
    assert_eq!(report.targets[3].tested_count, 1, "sticky winner promoted to index 0 on d2");
}
