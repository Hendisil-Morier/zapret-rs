//! Integration tests for TOML schema loading, `filter_defaults`, relative path resolution, and `clap` CLI overrides.

/// Filesystem read/write helpers for testing TOML file and relative blob path loading.
use std::fs;
/// Path helper for clean temporary test directory management.
use std::path::PathBuf;

/// `clap` error kind and parser trait used to exercise `CliArgs` flags without spawning a subprocess.
use clap::{Parser, error::ErrorKind};

/// Config, schema, filter, L7, and CLI types under test.
use zapret_rs::config::{
    AppConfig, CliArgs, ConfigError, ControlSocketConfig, L7Payload, L7Proto, LuaInitEntry, PacketRange,
    ProfileMatchInput, l7_payload_matches, resolve_config,
};
/// NFQUEUE queue config constructor verified from resolved configuration.
use zapret_rs::intercepter::QueueConfig;
/// Lua runtime configuration derived from [`AppConfig`].
use zapret_rs::lua::LuaConfig;
/// IP protocol numbers used to verify cross-L4 `filter_defaults` denial.
use zapret_rs::packet::constants::{IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP};

/// Returns a unique temporary directory path under `std::env::temp_dir()`.
fn unique_temp_dir(label: &str) -> PathBuf
{
    std::env::temp_dir().join(format!("zapret-rs-{}-{label}", std::process::id()))
}

/// Verifies decoded action and profile filter fields from the golden TOML configuration.
fn assert_golden_profile_fields(cfg: &AppConfig)
{
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

/// Verifies the golden TOML configuration shape deserializes blobs, init scripts, profiles, and action args.
#[test]
fn toml_file_loads_blobs_profiles_actions_and_relative_paths()
{
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

    assert_golden_profile_fields(&cfg);
}

/// Verifies `filter_defaults`: specifying `filter_tcp` implicitly denies UDP, ICMP, and other IP protocols.
#[test]
fn profile_matching_applies_l3_mark_and_cross_l4_denial()
{
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
fn toml_rejects_unknown_fields_and_empty_action_func()
{
    let unknown = r#"nonexistent_field = 123"#;
    assert!(matches!(AppConfig::from_toml_str(unknown, None), Err(ConfigError::TomlParse(_))));

    let empty_func = r#"
[[profiles]]
[[profiles.actions]]
func = "   "
"#;
    assert!(matches!(AppConfig::from_toml_str(empty_func, None), Err(ConfigError::Validation(_))));
}

/// Verifies `clap` CLI flags, `--version`, overrides over TOML, conflict errors, and target config conversion.
#[test]
fn clap_cli_parses_overrides_version_and_validates_conflicts()
{
    let dir = unique_temp_dir("cli-override");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let toml_path = dir.join("base.toml");
    fs::write(&toml_path, "qnum = 200\nfwmark = 0x40000000\ndebug = false\n").expect("write base toml");

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

    let qcfg = QueueConfig::with_fwmark(resolved.qnum, resolved.fwmark);
    assert_eq!(qcfg.queue_num, 350);
    assert_eq!(qcfg.desync_fwmark, 0x1000);

    let lcfg = LuaConfig::from(&resolved);
    assert_eq!(lcfg.qnum, 350);
    assert_eq!(lcfg.desync_fwmark, 0x1000);
    assert!(lcfg.bind_fix4);
    assert!(lcfg.debug);

    let conflict =
        CliArgs::try_parse_from(["nfqws2", "--user=nobody", "--uid=65534"]).expect("syntax is valid");
    assert!(matches!(resolve_config(&conflict), Err(ConfigError::Validation(_))));

    let ver_err = CliArgs::try_parse_from(["nfqws2", "--version"]).expect_err("version displays");
    assert_eq!(ver_err.kind(), ErrorKind::DisplayVersion);
}

/// Verifies numeric `0`/`1` CLI bool flags and repeatable `--lua-init` `@file`/inline handling.
#[test]
fn clap_cli_parses_numeric_bools_and_lua_init_entries()
{
    let cli = CliArgs::try_parse_from([
        "nfqws2",
        "--intercept=0",
        "--debug=1",
        "--lua-init=@script.lua",
        "--lua-init=DLOG(\"ok\")",
    ])
    .expect("CLI numeric bool and lua-init syntax should parse");

    let resolved = resolve_config(&cli).expect("resolved config should succeed");
    assert!(!resolved.intercept);
    assert!(resolved.debug);
    assert_eq!(
        resolved.lua_init,
        vec![
            LuaInitEntry::File(PathBuf::from("script.lua")),
            LuaInitEntry::Inline("DLOG(\"ok\")".to_owned()),
        ]
    );

    let empty_file = CliArgs::try_parse_from(["nfqws2", "--lua-init=@"])
        .expect("clap syntax accepts string before validation");
    assert!(matches!(resolve_config(&empty_file), Err(ConfigError::Validation(_))));
}

/// Verifies parsed per-profile hostlist, autohostlist, and ipset paths under `dir`.
fn assert_m3_profile_lists(cfg: &AppConfig, dir: &std::path::Path)
{
    let p = &cfg.profiles[0];
    assert_eq!(p.lists.hostlist, vec![dir.join("lists/include.txt")]);
    assert_eq!(p.lists.hostlist_domains, vec!["example.com", "example.org"]);
    assert_eq!(p.lists.hostlist_exclude, vec![dir.join("lists/exclude.txt.gz")]);
    assert_eq!(p.lists.hostlist_exclude_domains, vec!["skip.example.com"]);
    assert_eq!(p.lists.hostlist_auto, Some(dir.join("lists/auto.txt")));
    assert_eq!(p.lists.hostlist_auto_settings.fail_threshold, 4);
    assert_eq!(p.lists.hostlist_auto_settings.fail_time_sec, 90);
    assert!(!p.lists.hostlist_auto_settings.retrans_reset);
    assert_eq!(p.lists.hostlist_auto_settings.udp_out, 6);
    assert_eq!(p.lists.hostlist_auto_settings.udp_in, 2);
    assert_eq!(p.lists.hostlist_auto_settings.fail_cooldown_sec, 5);
    assert_eq!(p.lists.hostlist_auto_settings.sibling_threshold, 3);
    assert!(p.lists.hostlist_auto_settings.confirm_block);
    assert_eq!(p.lists.ipset, vec![dir.join("lists/cidrs.txt")]);
    assert_eq!(p.lists.ipset_ip, vec!["10.0.0.0/8", "192.0.2.1"]);
    assert_eq!(p.lists.ipset_exclude, vec![dir.join("lists/skip-cidrs.txt")]);
    assert_eq!(p.lists.ipset_exclude_ip, vec!["127.0.0.0/8"]);
}

/// Verifies M3 TOML options, relative list path resolution, `to_lua_config`, and autohostlist guards.
#[test]
fn parses_m3_toml_lists_timeouts_and_validates_autohostlist_constraints()
{
    let dir = unique_temp_dir("m3-toml");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    let toml_path = dir.join("m3.toml");
    let toml_body = r#"
server = false
ctrack_timeouts = "12:34:56:78"
ctrack_disable = false
ipcache_lifetime = 900
ipcache_hostname = true
payload_disable = ["dns_query"]
reasm_disable = ["tls_client_hello", "quic_initial"]
hostlist_auto_debug = "logs/auto.log"

[[profiles]]
name = "auto"
hostlist = ["lists/include.txt"]
hostlist_domains = ["example.com,example.org"]
hostlist_exclude = ["lists/exclude.txt.gz"]
hostlist_exclude_domains = ["skip.example.com"]
hostlist_auto = "lists/auto.txt"
hostlist_auto_fail_threshold = 4
hostlist_auto_fail_time = 90
hostlist_auto_retrans_threshold = 3
hostlist_auto_retrans_maxseq = 16384
hostlist_auto_retrans_reset = false
hostlist_auto_incoming_maxseq = 2048
hostlist_auto_udp_out = 6
hostlist_auto_udp_in = 2
hostlist_auto_fail_cooldown = 5
hostlist_auto_sibling_threshold = 3
hostlist_auto_confirm = true
ipset = ["lists/cidrs.txt"]
ipset_ip = ["10.0.0.0/8,192.0.2.1"]
ipset_exclude = ["lists/skip-cidrs.txt"]
ipset_exclude_ip = ["127.0.0.0/8"]
"#;
    fs::write(&toml_path, toml_body).expect("write M3 TOML");

    let cfg = AppConfig::from_toml_file(&toml_path).expect("M3 TOML should parse");
    let _ = fs::remove_dir_all(&dir);

    assert!(!cfg.server);
    assert_eq!(cfg.conntrack.timeouts.syn, 12);
    assert_eq!(cfg.conntrack.timeouts.established, 34);
    assert_eq!(cfg.conntrack.timeouts.fin, 56);
    assert_eq!(cfg.conntrack.timeouts.udp, 78);
    assert_eq!(cfg.ipcache.lifetime_sec, 900);
    assert!(cfg.ipcache.hostname);
    assert_ne!(cfg.payload_disable, 0);
    assert_ne!(cfg.reasm_disable, 0);
    assert_eq!(cfg.hostlist_auto_debug, Some(dir.join("logs/auto.log")));

    assert_m3_profile_lists(&cfg, &dir);

    let lcfg = LuaConfig::from(&cfg);
    assert!(lcfg.cache_hostname);
    assert_eq!(lcfg.ctrack_timeouts.established, 34);

    let srv_conflict = "server = true\n[[profiles]]\nhostlist_auto = \"auto.txt\"\n";
    assert!(matches!(AppConfig::from_toml_str(srv_conflict, None), Err(ConfigError::Validation(_))));
    let ct_conflict = "ctrack_disable = true\n[[profiles]]\nhostlist_auto = \"auto.txt\"\n";
    assert!(matches!(AppConfig::from_toml_str(ct_conflict, None), Err(ConfigError::Validation(_))));
}

/// Verifies M3 CLI flags override TOML values and bare `--payload-disable` disables all payloads.
#[test]
fn cli_m3_flags_override_toml_settings()
{
    let dir = unique_temp_dir("m3-cli");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test dir");
    let toml_path = dir.join("base.toml");
    fs::write(
        &toml_path,
        "server = false\nipcache_lifetime = 3600\n[[profiles]]\nhostlist_auto = \"auto.txt\"\n",
    )
    .expect("write base toml");

    let cli = CliArgs::try_parse_from([
        "nfqws2",
        "--config",
        toml_path.to_str().expect("utf8 path"),
        "--ctrack-timeouts=5:10:15",
        "--ipcache-lifetime=120",
        "--ipcache-hostname=1",
        "--payload-disable",
        "--reasm-disable=quic_initial",
        "--hostlist-auto-debug=/tmp/auto-dbg.log",
    ])
    .expect("M3 CLI flags parse");
    let resolved = resolve_config(&cli).expect("M3 CLI resolution succeeds");
    assert_eq!(resolved.conntrack.timeouts.syn, 5);
    assert_eq!(resolved.conntrack.timeouts.udp, 60);
    assert_eq!(resolved.ipcache.lifetime_sec, 120);
    assert!(resolved.ipcache.hostname);
    assert_eq!(resolved.payload_disable, 0);
    assert_eq!(resolved.hostlist_auto_debug, Some(PathBuf::from("/tmp/auto-dbg.log")));

    let err_cli =
        CliArgs::try_parse_from(["nfqws2", "--config", toml_path.to_str().expect("utf8 path"), "--server"])
            .expect("CLI syntax valid");
    assert!(matches!(resolve_config(&err_cli), Err(ConfigError::Validation(_))));
    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `control_socket` and `control_pass_sample` TOML fields and CLI overrides.
#[test]
fn control_socket_and_sample_rate_parse_from_toml_and_cli()
{
    let dir = unique_temp_dir("ctl-cfg");
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    let toml_path = dir.join("ctl.toml");
    fs::write(&toml_path, "control_socket = \"run/custom.sock\"\ncontrol_pass_sample = 7\n")
        .expect("write ctl toml");

    let cfg = AppConfig::from_toml_file(&toml_path).expect("parse ctl toml");
    assert_eq!(cfg.control_socket, ControlSocketConfig::Custom(dir.join("run/custom.sock")));
    assert_eq!(cfg.control_pass_sample, 7);

    let off_cli = CliArgs::try_parse_from([
        "nfqws2",
        "--config",
        toml_path.to_str().expect("utf8 path"),
        "--control-socket=off",
        "--control-pass-sample=0",
    ])
    .expect("CLI parses");
    let resolved = resolve_config(&off_cli).expect("resolve off override");
    assert_eq!(resolved.control_socket, ControlSocketConfig::Disabled);
    assert_eq!(resolved.control_pass_sample, 0);

    let default_cfg = AppConfig::from_toml_str("control_socket = true\n", None).expect("default true");
    assert_eq!(default_cfg.control_socket, ControlSocketConfig::Default);
    assert!(!default_cfg.auto_nft);

    let nft_cfg = AppConfig::from_toml_str("auto_nft = true\n", None).expect("auto_nft parses");
    assert!(nft_cfg.auto_nft);
    let nft_cli =
        CliArgs::try_parse_from(["nfqws2", "--config", toml_path.to_str().expect("utf8 path"), "--nft"])
            .expect("--nft parses");
    assert!(resolve_config(&nft_cli).expect("resolve --nft").auto_nft);
    let no_nft_cli = CliArgs::try_parse_from(["nfqws2", "--nft=0"]).expect("--nft=0 parses");
    assert!(!resolve_config(&no_nft_cli).expect("resolve --nft=0").auto_nft);
    let _ = fs::remove_dir_all(&dir);
}
