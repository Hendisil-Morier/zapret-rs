//! Integration tests for `DesyncEngine::replace_profiles`, strategy catalog expansion,
//! minimal cross-domain set cover, and `nfqws2.toml` round-trip serialization.

/// Shared interior mutability for mock raw packet senders.
use std::cell::RefCell;
/// Standard IPv4 address for testing `IpCache` clearing during profile hot-swap.
use std::net::{IpAddr, Ipv4Addr};
/// Paths for verifying real `zapret2` Lua scripts and TOML `lua_init` rendering.
use std::path::{Path, PathBuf};
/// Reference counting for constructing [`DesyncEngine::with_sender`].
use std::rc::Rc;

/// Configuration models and TOML parser under test.
use zapret_rs::config::{AppConfig, LuaInitEntry};
/// Stateful desync engine whose `replace_profiles` hot-swap is verified.
use zapret_rs::desync::DesyncEngine;
/// Mock packet sender implementation avoiding raw sockets in unit tests.
use zapret_rs::rawsend::{PacketSender, RawSendError};
/// Strategy catalog, set cover, and TOML renderer under test.
use zapret_rs::tools::{
    CoveredProfile, DomainStrategies, IpFamily, ProbeProtocol, ScanLevel, StrategyMatch,
    TomlRenderOptions, build_catalog, rank_matches, render_nfqws2_toml, select_minimal_cover,
};

/// No-op [`PacketSender`] recording zero I/O for offline engine hot-swap tests.
struct NoopSender;

impl PacketSender for NoopSender {
    /// Accepts every packet without touching real network sockets.
    fn send(
        &mut self,
        _dst: IpAddr,
        _fwmark: u32,
        _ifout: Option<&str>,
        _packet: &[u8],
    ) -> Result<(), RawSendError> {
        Ok(())
    }
}

/// Verifies `DesyncEngine::replace_profiles` swaps profiles, rejects unknown Lua functions,
/// and clears both `conntrack` and `ipcache` state.
#[test]
fn engine_replace_profiles_validates_and_clears_state() {
    let mut cfg = AppConfig::default();
    cfg.ipcache.hostname = true;
    cfg.lua_init.push(LuaInitEntry::Inline(
        "function fake(ctx, desync) return VERDICT_PASS end\n\
         function multisplit(ctx, desync) return VERDICT_PASS end"
            .to_owned(),
    ));
    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(NoopSender));
    let mut engine = DesyncEngine::with_sender(&cfg, sender).expect("engine init");

    // Seed ipcache so we can verify `replace_profiles` clears it.
    let target_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    engine
        .ipcache()
        .borrow_mut()
        .put_hostname(target_ip, "example.com", false, 100);
    assert!(!engine.ipcache().borrow().is_empty());

    let catalog = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4);
    let split = catalog
        .iter()
        .find(|s| s.family == "multisplit")
        .expect("multisplit candidate");
    let profile = split.to_profile(1, &["example.com".to_owned()]);

    engine
        .replace_profiles(vec![profile.clone()])
        .expect("valid Lua callbacks should swap cleanly");
    assert_eq!(engine.profiles().len(), 1);
    assert_eq!(engine.profiles()[0].name, profile.name);
    assert!(
        engine.ipcache().borrow().is_empty(),
        "ipcache must be cleared after profile hot-swap"
    );

    // A profile referencing an undefined Lua callback must fail without clobbering active profiles.
    let mut broken = profile.clone();
    broken.actions[0].func = "nonexistent_lua_desync_fn".to_owned();
    let err = engine
        .replace_profiles(vec![broken])
        .expect_err("missing Lua callback must be rejected");
    assert!(
        err.to_string().contains("nonexistent_lua_desync_fn"),
        "unexpected error: {err}"
    );
    assert_eq!(
        engine.profiles().len(),
        1,
        "failed swap must preserve previous profiles"
    );
}

/// Verifies catalog sizes grow monotonically across `Quick < Standard < Force` and include IPv6
/// extension headers and TLS 1.2 `wssize` variants where expected.
#[test]
fn catalog_expands_deterministically_by_level_proto_and_family() {
    for proto in [
        ProbeProtocol::Http,
        ProbeProtocol::Tls12,
        ProbeProtocol::Tls13,
        ProbeProtocol::Http3,
    ] {
        for ipv in [IpFamily::V4, IpFamily::V6] {
            let quick = build_catalog(proto, ScanLevel::Quick, ipv);
            let standard = build_catalog(proto, ScanLevel::Standard, ipv);
            let force = build_catalog(proto, ScanLevel::Force, ipv);

            assert!(!quick.is_empty(), "{proto}/{ipv} quick catalog empty");
            assert!(
                quick.len() < standard.len(),
                "{proto}/{ipv}: quick ({}) should be smaller than standard ({})",
                quick.len(),
                standard.len()
            );
            assert!(
                standard.len() < force.len(),
                "{proto}/{ipv}: standard ({}) should be smaller than force ({})",
                standard.len(),
                force.len()
            );
            // Weight ordering must be non-decreasing.
            assert!(force.windows(2).all(|w| w[0].weight <= w[1].weight));
        }
    }

    let v6_tls = build_catalog(ProbeProtocol::Tls13, ScanLevel::Standard, IpFamily::V6);
    assert!(
        v6_tls.iter().any(|s| s.id.contains("ip6_hopbyhop")),
        "IPv6 catalog should include IPv6 extension-header foolings"
    );
    let tls12_std = build_catalog(ProbeProtocol::Tls12, ScanLevel::Standard, IpFamily::V4);
    assert!(
        tls12_std.iter().any(|s| s.id.contains("wssize")),
        "TLS 1.2 standard catalog should include wssize combinations"
    );
}

/// Verifies every catalog strategy across all protocols round-trips cleanly through
/// `render_nfqws2_toml` and `AppConfig::from_toml_str`.
#[test]
fn rendered_toml_parses_cleanly_for_every_catalog_strategy() {
    let mut covered = Vec::new();
    for proto in [
        ProbeProtocol::Http,
        ProbeProtocol::Tls12,
        ProbeProtocol::Tls13,
        ProbeProtocol::Http3,
    ] {
        for ipv in [IpFamily::V4, IpFamily::V6] {
            for strategy in build_catalog(proto, ScanLevel::Force, ipv) {
                covered.push(CoveredProfile {
                    strategy,
                    domains: vec!["example.com".to_owned(), "test.org".to_owned()],
                    avg_latency_ms: 42,
                });
            }
        }
    }

    let opts = TomlRenderOptions {
        qnum: 205,
        fwmark: 0x4000_0000,
        lua_init: vec![
            PathBuf::from("/opt/zapret/lua/zapret-lib.lua"),
            PathBuf::from("/opt/zapret/lua/zapret-antidpi.lua"),
        ],
    };
    let toml_text = render_nfqws2_toml(&covered, &opts);
    let parsed = AppConfig::from_toml_str(&toml_text, None).expect("generated TOML must parse");

    assert_eq!(parsed.qnum, 205);
    assert_eq!(parsed.fwmark, 0x4000_0000);
    assert_eq!(parsed.lua_init.len(), 2);
    assert_eq!(parsed.profiles.len(), covered.len());

    // Spot-check OOB (`in_range = "-s1"`) and syndata (`out_range = "-d1"`) round-trip fidelity.
    for (orig, loaded) in covered.iter().zip(parsed.profiles.iter()) {
        assert_eq!(loaded.name.as_deref(), Some(orig.strategy.id.as_str()));
        assert_eq!(loaded.actions.len(), orig.strategy.actions.len());
        for (a, b) in orig.strategy.actions.iter().zip(loaded.actions.iter()) {
            assert_eq!(a.func, b.func);
            assert_eq!(a.payload_mask, b.payload_mask);
            assert_eq!(a.in_range, b.in_range);
            assert_eq!(a.out_range, b.out_range);
            assert_eq!(a.args, b.args);
        }
    }
}

/// Verifies ranking and greedy multi-domain set cover minimize profile count and break ties
/// by strategy weight and latency.
#[test]
fn minimal_set_cover_selects_shared_simplest_fastest_profiles() {
    let tls_cat = build_catalog(ProbeProtocol::Tls13, ScanLevel::Quick, IpFamily::V4);
    let s_simple = tls_cat[0].clone();
    let s_mid = tls_cat[tls_cat.len() / 2].clone();
    let s_heavy = tls_cat[tls_cat.len() - 1].clone();

    let mut ranked = vec![
        StrategyMatch { strategy: s_heavy.clone(), latency_ms: 10 },
        StrategyMatch { strategy: s_simple.clone(), latency_ms: 80 },
        StrategyMatch { strategy: s_simple.clone(), latency_ms: 20 },
    ];
    rank_matches(&mut ranked);
    assert_eq!(ranked[0].strategy.id, s_simple.id);
    assert_eq!(ranked[0].latency_ms, 20);

    // Three domains: A and B share `s_mid`, C only works with `s_heavy`, A also works with `s_simple`.
    // Greedy set cover must choose `s_mid` for {A, B} (covers 2) + `s_heavy` for {C} (covers 1) = 2 profiles.
    let results = vec![
        DomainStrategies {
            domain: "a.example".to_owned(),
            proto: ProbeProtocol::Tls13,
            ipv: IpFamily::V4,
            matches: vec![
                StrategyMatch { strategy: s_simple.clone(), latency_ms: 15 },
                StrategyMatch { strategy: s_mid.clone(), latency_ms: 30 },
            ],
        },
        DomainStrategies {
            domain: "b.example".to_owned(),
            proto: ProbeProtocol::Tls13,
            ipv: IpFamily::V4,
            matches: vec![StrategyMatch { strategy: s_mid.clone(), latency_ms: 50 }],
        },
        DomainStrategies {
            domain: "c.example".to_owned(),
            proto: ProbeProtocol::Tls13,
            ipv: IpFamily::V4,
            matches: vec![StrategyMatch { strategy: s_heavy.clone(), latency_ms: 40 }],
        },
    ];

    let cover = select_minimal_cover(&results);
    assert_eq!(cover.len(), 2);
    assert_eq!(cover[0].strategy.id, s_mid.id);
    assert_eq!(cover[0].domains, vec!["a.example".to_owned(), "b.example".to_owned()]);
    assert_eq!(cover[0].avg_latency_ms, 40);
    assert_eq!(cover[1].strategy.id, s_heavy.id);
    assert_eq!(cover[1].domains, vec!["c.example".to_owned()]);
}

/// Verifies every Lua action function emitted by `build_catalog` exists in the sibling
/// `zapret2/lua/zapret-antidpi.lua` script when present in the workspace.
#[test]
fn all_catalog_lua_callbacks_exist_in_zapret2_antidpi() {
    let lua_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../zapret2/lua");
    let lib_lua = lua_dir.join("zapret-lib.lua");
    let antidpi_lua = lua_dir.join("zapret-antidpi.lua");
    if !lib_lua.is_file() || !antidpi_lua.is_file() {
        return;
    }

    let mut cfg = AppConfig::default();
    cfg.lua_init.push(LuaInitEntry::File(lib_lua));
    cfg.lua_init.push(LuaInitEntry::File(antidpi_lua));
    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(NoopSender));
    let mut engine = DesyncEngine::with_sender(&cfg, sender).expect("engine with zapret2 lua");

    let mut profiles = Vec::new();
    let mut idx = 1u32;
    for proto in [
        ProbeProtocol::Http,
        ProbeProtocol::Tls12,
        ProbeProtocol::Tls13,
        ProbeProtocol::Http3,
    ] {
        for spec in build_catalog(proto, ScanLevel::Force, IpFamily::V6) {
            profiles.push(spec.to_profile(idx, &[]));
            idx += 1;
        }
    }

    engine
        .replace_profiles(profiles)
        .expect("every catalog action function must resolve in zapret-antidpi.lua");
}
