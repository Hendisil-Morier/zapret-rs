//! Unit tests for non-destructive `nfqws2.toml` profile merging and hostlist domain extraction.

/// Parsed config verification and strategy TOML helpers under test.
use zapret_rs::config::AppConfig;
/// Catalog and rendering primitives used to build realistic strategy TOML fixtures.
use zapret_rs::tools::{
    CoveredProfile, DEFAULT_AUTOHOSTLIST_FILE, DomainScope, IpFamily, ProbeProtocol, ScanLevel,
    TomlRenderOptions, build_catalog, extract_hostlist_domains, merge_nfqws2_toml,
    render_nfqws2_toml, render_nfqws2_toml_scoped,
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

#[test]
fn domain_scope_renders_catch_all_and_autohostlist_profiles_cleanly() {
    let strat = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4)[0].clone();
    let cover = vec![CoveredProfile {
        strategy: strat,
        domains: vec!["youtube.com".to_owned()],
        avg_latency_ms: 40,
    }];
    let opts = TomlRenderOptions::default();

    let all_toml = render_nfqws2_toml_scoped(&cover, &opts, DomainScope::AllDomains);
    let all_cfg = AppConfig::from_toml_str(&all_toml, None).expect("valid catch-all TOML");
    assert!(all_cfg.profiles[0].lists.hostlist_domains.is_empty());
    assert!(all_cfg.profiles[0].lists.hostlist_auto.is_none());

    let auto_toml = render_nfqws2_toml_scoped(&cover, &opts, DomainScope::AutoHostlist);
    let auto_cfg = AppConfig::from_toml_str(&auto_toml, None).expect("valid autolist TOML");
    assert!(auto_cfg.profiles[0].lists.hostlist_domains.is_empty());
    assert_eq!(
        auto_cfg.profiles[0].lists.hostlist_auto.as_deref(),
        Some(std::path::Path::new(DEFAULT_AUTOHOSTLIST_FILE))
    );
}

#[test]
fn slot_wide_render_and_merge_keep_one_profile_per_protocol_slot() {
    let tls_strats = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4);
    let http_strats = build_catalog(ProbeProtocol::Http, ScanLevel::Quick, IpFamily::V4);
    let tls_a = tls_strats[0].clone();
    let tls_b = tls_strats[1].clone();
    let http_a = http_strats[0].clone();
    let opts = TomlRenderOptions::default();

    // Multi-strategy cover for TLS + HTTP collapses to one winner per protocol slot outside ScannedOnly.
    let multi_cover = vec![
        CoveredProfile { strategy: http_a.clone(), domains: vec!["a.com".to_owned()], avg_latency_ms: 20 },
        CoveredProfile { strategy: tls_a.clone(), domains: vec!["a.com".to_owned()], avg_latency_ms: 25 },
        CoveredProfile { strategy: tls_b.clone(), domains: vec!["b.com".to_owned()], avg_latency_ms: 30 },
    ];
    for scope in [DomainScope::AllDomains, DomainScope::AutoHostlist] {
        let rendered = render_nfqws2_toml_scoped(&multi_cover, &opts, scope);
        let cfg = AppConfig::from_toml_str(&rendered, None).expect("valid deduplicated TOML");
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.profiles[0].name.as_deref(), Some(http_a.id.as_str()));
        assert_eq!(cfg.profiles[1].name.as_deref(), Some(tls_a.id.as_str()));
    }

    // Merging a new AutoHostlist TLS winner replaces the old TLS autolist profile while keeping HTTP.
    let existing = render_nfqws2_toml_scoped(&multi_cover, &opts, DomainScope::AutoHostlist);
    let incoming_tls = render_nfqws2_toml_scoped(
        &[CoveredProfile { strategy: tls_b.clone(), domains: vec!["c.com".to_owned()], avg_latency_ms: 15 }],
        &opts,
        DomainScope::AutoHostlist,
    );
    let merged = merge_nfqws2_toml(&existing, &incoming_tls).expect("slot merge succeeds");
    let cfg = AppConfig::from_toml_str(&merged, None).expect("valid slot-merged TOML");
    assert_eq!(cfg.profiles.len(), 2);
    assert_eq!(cfg.profiles[0].name.as_deref(), Some(http_a.id.as_str()));
    assert_eq!(cfg.profiles[1].name.as_deref(), Some(tls_b.id.as_str()));

    // A domain-scoped profile merges ahead of trailing AutoHostlist fallback rules.
    let incoming_domain = render_nfqws2_toml(
        &[CoveredProfile { strategy: tls_a.clone(), domains: vec!["d.com".to_owned()], avg_latency_ms: 10 }],
        &opts,
    );
    let with_specific = merge_nfqws2_toml(&merged, &incoming_domain).expect("domain merge succeeds");
    let specific_cfg = AppConfig::from_toml_str(&with_specific, None).expect("valid hybrid TOML");
    assert_eq!(specific_cfg.profiles.len(), 3);
    assert_eq!(specific_cfg.profiles[0].lists.hostlist_domains, vec!["d.com"]);
    assert!(specific_cfg.profiles[1].lists.hostlist_auto.is_some());
    assert!(specific_cfg.profiles[2].lists.hostlist_auto.is_some());
}
