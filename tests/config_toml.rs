//! Integration tests for TOML schema loading, `filter_defaults`, relative path resolution, and `clap` CLI overrides.

/// Filesystem read/write helpers for testing TOML file and relative blob path loading.
use std::fs;
/// Path helper for clean temporary test directory management.
use std::path::PathBuf;

/// `clap` error kind and parser trait used to exercise `CliArgs` flags without spawning a subprocess.
use clap::{Parser, error::ErrorKind};

/// Config, schema, filter, L7, and CLI types under test.
use zapret_rs::config::{
    AppConfig, CliArgs, ConfigError, L7Payload, L7Proto, LuaInitEntry, PacketRange,
    ProfileMatchInput, l7_payload_matches, resolve_config,
};
/// IP protocol numbers used to verify cross-L4 `filter_defaults` denial.
use zapret_rs::packet::constants::{IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

/// Returns a unique temporary directory path under `std::env::temp_dir()`.
fn unique_temp_dir(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("zapret-rs-{}-{label}", std::process::id()))
}

/// Verifies the golden TOML configuration shape deserializes blobs, init scripts, profiles, and action args.
#[test]
fn toml_file_loads_blobs_profiles_actions_and_relative_paths() {
    let dir = unique_temp_dir("toml-golden");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");

    let blob_path = dir.join("fake_tls.bin");
    fs::write(&blob_path, b"SKIP_BYTES\x16\x03\x01\x00\x05hello").expect("write blob file");

    let toml_path = dir.join("nfqws2.toml");
    let toml_body = r#"
qnum = 210
fwmark = 0x20000000
bind_fix4 = true
bind_fix6 = true
debug = true
lua_init = ["lua/zapret-lib.lua", { inline = "DLOG('hi')" }]

[blobs]
custom_hex = "0xdeadbeef"
custom_tls = { file = "fake_tls.bin", offset = 10 }

[[profiles]]
name = "disabled"
skip = true

[[profiles]]
name = "https"
cookie = "profile-cookie"
filter_l3 = ["ipv4"]
filter_tcp = ["443"]
filter_l7 = ["tls"]
filter_mark = "0x10/0xff"

[[profiles.actions]]
payload = ["tls_client_hello"]
out_range = "-d1"
func = "fake"
args = { blob = "fake_default_tls", tcp_md5 = true, disabled_flag = false, repeats = 3 }
"#;
    fs::write(&toml_path, toml_body).expect("write temp toml");

    let cfg = AppConfig::from_toml_file(&toml_path).expect("TOML should parse cleanly");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(cfg.qnum, 210);
    assert_eq!(cfg.fwmark, 0x2000_0000);
    assert!(cfg.bind_fix4);
    assert!(cfg.bind_fix6);
    assert!(cfg.debug);

    assert_eq!(
        cfg.lua_init,
        vec![
            LuaInitEntry::File(dir.join("lua/zapret-lib.lua")),
            LuaInitEntry::Inline("DLOG('hi')".to_owned()),
        ]
    );
    assert_eq!(cfg.blobs["custom_hex"], vec![0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(cfg.blobs["custom_tls"], b"\x16\x03\x01\x00\x05hello");
    assert!(cfg.blobs.contains_key("fake_default_tls"));

    // Skipped profile is excluded, leaving the active profile as index 1.
    assert_eq!(cfg.profiles.len(), 1);
    let profile = &cfg.profiles[0];
    assert_eq!(profile.index, 1);
    assert_eq!(profile.name.as_deref(), Some("https"));
    assert_eq!(profile.cookie.as_deref(), Some("profile-cookie"));
    assert!(profile.filter_ipv4);
    assert!(!profile.filter_ipv6);

    assert_eq!(profile.actions.len(), 1);
    let action = &profile.actions[0];
    assert_eq!(action.func, "fake");
    assert!(l7_payload_matches(L7Payload::TlsClientHello, action.payload_mask));
    assert!(!l7_payload_matches(L7Payload::HttpReq, action.payload_mask));
    assert_eq!(action.in_range, PacketRange::NEVER);
    assert_eq!(action.out_range, PacketRange::parse("-d1").expect("-d1"));
    assert_eq!(action.args["blob"], "fake_default_tls");
    assert_eq!(action.args["tcp_md5"], "");
    assert!(!action.args.contains_key("disabled_flag"));
    assert_eq!(action.args["repeats"], "3");
}

/// Verifies `filter_defaults`: specifying `filter_tcp` implicitly denies UDP, ICMP, and other IP protocols.
#[test]
fn profile_matching_applies_l3_mark_and_cross_l4_denial() {
    let toml_body = r#"
[[profiles]]
name = "tcp-only"
filter_l3 = ["ipv4"]
filter_tcp = ["443"]
filter_l7 = ["tls"]
filter_mark = "0x10/0xff"
"#;
    let cfg = AppConfig::from_toml_str(toml_body, None).expect("profile parses");
    let p = &cfg.profiles[0];

    let matching = ProfileMatchInput {
        is_v6: false,
        l4proto: IPPROTO_TCP,
        port: 443,
        icmp_type: 0,
        icmp_code: 0,
        fwmark: 0x1234_0010,
        l7proto: L7Proto::Tls,
    };
    assert!(p.matches(&matching));

    // Wrong TCP port, IPv6, fwmark mismatch, wrong L7, UDP, ICMP, or GRE are all rejected.
    assert!(!p.matches(&ProfileMatchInput { port: 80, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { is_v6: true, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { fwmark: 0x11, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { l7proto: L7Proto::Http, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { l4proto: IPPROTO_UDP, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { l4proto: IPPROTO_ICMP, port: 0, ..matching }));
    assert!(!p.matches(&ProfileMatchInput { l4proto: 47, port: 0, ..matching }));
}

/// Verifies strict TOML validation rejects unknown fields and malformed values.
#[test]
fn toml_rejects_unknown_fields_and_empty_action_func() {
    let unknown = r#"nonexistent_field = 123"#;
    assert!(matches!(
        AppConfig::from_toml_str(unknown, None),
        Err(ConfigError::TomlParse(_))
    ));

    let empty_func = r#"
[[profiles]]
[[profiles.actions]]
func = "   "
"#;
    assert!(matches!(
        AppConfig::from_toml_str(empty_func, None),
        Err(ConfigError::Validation(_))
    ));
}

/// Verifies `clap` CLI flags, `--version`, overrides over TOML, conflict errors, and target config conversion.
#[test]
fn clap_cli_parses_overrides_version_and_validates_conflicts() {
    let dir = unique_temp_dir("cli-override");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let toml_path = dir.join("base.toml");
    fs::write(&toml_path, "qnum = 200\nfwmark = 0x40000000\ndebug = false\n")
        .expect("write base toml");

    let cli = CliArgs::try_parse_from([
        "nfqws2",
        "--config",
        toml_path.to_str().expect("utf8 path"),
        "--qnum",
        "350",
        "--fwmark",
        "0x1000",
        "--bind-fix4",
        "--debug",
        "--intercept=false",
        "--dry-run",
    ])
    .expect("CLI should parse");
    assert!(cli.dry_run);

    let resolved = resolve_config(&cli).expect("config resolution should succeed");
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(resolved.qnum, 350);
    assert_eq!(resolved.fwmark, 0x1000);
    assert!(resolved.bind_fix4);
    assert!(!resolved.bind_fix6);
    assert!(resolved.debug);
    assert!(!resolved.intercept);

    let qcfg = resolved.to_queue_config();
    assert_eq!(qcfg.queue_num, 350);
    assert_eq!(qcfg.desync_fwmark, 0x1000);

    let lcfg = resolved.to_lua_config();
    assert_eq!(lcfg.qnum, 350);
    assert_eq!(lcfg.desync_fwmark, 0x1000);
    assert!(lcfg.bind_fix4);
    assert!(lcfg.debug);

    let conflict = CliArgs::try_parse_from(["nfqws2", "--user=nobody", "--uid=65534"])
        .expect("syntax is valid");
    assert!(matches!(
        resolve_config(&conflict),
        Err(ConfigError::Validation(_))
    ));

    let ver_err = CliArgs::try_parse_from(["nfqws2", "--version"]).expect_err("version displays");
    assert_eq!(ver_err.kind(), ErrorKind::DisplayVersion);
}
