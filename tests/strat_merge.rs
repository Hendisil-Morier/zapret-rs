//! Unit tests for non-destructive `nfqws2.toml` profile merging and hostlist domain extraction.

/// Parsed config verification and strategy TOML helpers under test.
use zapret_rs::config::AppConfig;
/// Catalog and rendering primitives used to build realistic strategy TOML fixtures.
use zapret_rs::tools::{
    CoveredProfile, IpFamily, ProbeProtocol, ScanLevel, TomlRenderOptions, build_catalog,
    extract_hostlist_domains, merge_nfqws2_toml, render_nfqws2_toml,
};

#[test]
fn merge_preserves_existing_profiles_deduplicates_matching_and_replaces_conflicts() {
    let tls_strats = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4);
    let http_strats = build_catalog(ProbeProtocol::Http, ScanLevel::Quick, IpFamily::V4);
    let strat_a = tls_strats[0].clone();
    let strat_b = tls_strats[1].clone();
    let strat_http = http_strats[0].clone();

    let existing = render_nfqws2_toml(
        &[
            CoveredProfile {
                strategy: strat_a.clone(),
                domains: vec!["youtube.com".to_owned(), "discord.com".to_owned()],
                avg_latency_ms: 40,
            },
            CoveredProfile {
                strategy: strat_http.clone(),
                domains: vec!["legacy.example".to_owned()],
                avg_latency_ms: 30,
            },
        ],
        &TomlRenderOptions { qnum: 205, fwmark: 0x1000_0000, lua_init: Vec::new() },
    );

    // Scan `discord.com` (new strat_b replaces its old slot in strat_a) and `steam.com` (extends strat_a).
    let incoming = render_nfqws2_toml(
        &[
            CoveredProfile {
                strategy: strat_a.clone(),
                domains: vec!["store.steampowered.com".to_owned()],
                avg_latency_ms: 55,
            },
            CoveredProfile {
                strategy: strat_b.clone(),
                domains: vec!["discord.com".to_owned()],
                avg_latency_ms: 35,
            },
        ],
        &TomlRenderOptions::default(),
    );

    let merged = merge_nfqws2_toml(&existing, &incoming).expect("merge succeeds");
    let cfg = AppConfig::from_toml_str(&merged, None).expect("valid merged AppConfig");

    // Preserves existing qnum/fwmark rather than resetting to incoming defaults.
    assert_eq!((cfg.qnum, cfg.fwmark), (205, 0x1000_0000));

    // HTTP legacy profile kept untouched, strat_a keeps youtube.com + adds steam while dropping discord.com,
    // and strat_b owns discord.com.
    let a = cfg.profiles.iter().find(|p| p.name.as_deref() == Some(&strat_a.id)).expect("strat_a");
    assert_eq!(a.lists.hostlist_domains, vec!["youtube.com", "store.steampowered.com"]);
    let b = cfg.profiles.iter().find(|p| p.name.as_deref() == Some(&strat_b.id)).expect("strat_b");
    assert_eq!(b.lists.hostlist_domains, vec!["discord.com"]);
    assert!(cfg.profiles.iter().any(|p| p.name.as_deref() == Some(&strat_http.id)));

    // Domain extraction returns unique domains across all profiles in order.
    let extracted = extract_hostlist_domains(&cfg);
    assert_eq!(
        extracted,
        vec!["youtube.com", "store.steampowered.com", "legacy.example", "discord.com"]
    );
}
