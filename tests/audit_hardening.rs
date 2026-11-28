//! Security regression tests added during audit remediation (Findings 1-16).

/// Filesystem helpers for creating decoy executables and verifying they are never executed.
#[cfg(unix)]
use std::fs;
/// Permission mode setup on Unix for executable decoys.
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
/// Temp directory and path construction.
#[cfg(unix)]
use std::path::{Path, PathBuf};

/// Firewall backend under test for rejecting poisoned `PATH` and untrusted `--nft-bin` paths.
#[cfg(unix)]
use zapret_rs::tools::NftFirewallBackend;

/// Creates an isolated scratch directory under `std::env::temp_dir()`.
#[cfg(unix)]
fn make_temp_dir(tag: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-audit-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp test directory");
    dir
}

/// Verifies trusted binary resolution rejects relative/traversal names and never resolves into `/tmp`.
#[cfg(unix)]
#[test]
fn trusted_bin_rejects_traversal_relative_and_user_owned_binaries()
{
    use zapret_rs::runtime::{resolve_trusted_system_bin, validate_trusted_bin_path};

    assert!(resolve_trusted_system_bin("").is_err());
    assert!(resolve_trusted_system_bin("../sh").is_err());
    assert!(resolve_trusted_system_bin("a/b").is_err());

    let dir = make_temp_dir("trusted-bin");
    let fake_bin = dir.join("fake-tool");
    fs::write(&fake_bin, "#!/bin/sh\nexit 0\n").expect("write fake script");
    fs::set_permissions(&fake_bin, fs::Permissions::from_mode(0o755)).expect("chmod fake script");

    assert!(validate_trusted_bin_path(Path::new("./nft")).is_err());
    assert!(validate_trusted_bin_path(&fake_bin).is_err());

    if let Ok(sh_path) = resolve_trusted_system_bin("sh")
    {
        assert!(!sh_path.starts_with(&dir), "trusted sh must not resolve inside temp dir");
        assert!(sh_path.is_absolute());
    }

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `NftFirewallBackend` refuses explicit untrusted `--nft-bin` paths under `/tmp`
/// without ever spawning them.
#[cfg(unix)]
#[test]
fn nft_backend_refuses_untrusted_explicit_nft_bin_without_executing()
{
    let dir = make_temp_dir("nft-decoy");
    let marker = dir.join("pwned");
    let decoy = dir.join("nft");
    fs::write(&decoy, format!("#!/bin/sh\ntouch {}\n", marker.display())).expect("write decoy");
    fs::set_permissions(&decoy, fs::Permissions::from_mode(0o755)).expect("chmod decoy");

    let backend = NftFirewallBackend::new(decoy);
    let err = backend
        .install_non_interactive(210, 0x4000_0000, &[443], &[443])
        .err()
        .expect("untrusted --nft-bin must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(!marker.exists(), "decoy nft script must never be executed");

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `prepare_control_socket_dir` and `ensure_writable_dir` reject symlinks,
/// reject world-writable non-sticky directories, and refuse taking ownership of pre-existing shared dirs.
#[cfg(unix)]
#[test]
fn socket_and_writable_dir_preserve_existing_ownership_and_reject_unsafe_modes()
{
    use std::os::unix::fs::symlink;
    use zapret_rs::config::WritableDirConfig;
    use zapret_rs::control::prepare_control_socket_dir;
    use zapret_rs::runtime::{IdentitySpec, ensure_writable_dir};

    let dir = make_temp_dir("dir-hardening");
    let link_parent = dir.join("sym_parent");
    let real_target = dir.join("real_target");
    fs::create_dir(&real_target).expect("create real target");
    symlink(&real_target, &link_parent).expect("create symlink");
    assert!(prepare_control_socket_dir(&link_parent.join("control.sock"), None, None).is_err());

    let world_dir = dir.join("world_dir");
    fs::create_dir(&world_dir).expect("create world dir");
    fs::set_permissions(&world_dir, fs::Permissions::from_mode(0o777)).expect("chmod 0777");
    assert!(prepare_control_socket_dir(&world_dir.join("control.sock"), None, None).is_err());
    assert!(ensure_writable_dir(&WritableDirConfig::Custom(world_dir.clone()), None).is_err());

    // Pre-existing directory owned by current user cannot be hijacked to a foreign UID.
    let existing = dir.join("existing");
    fs::create_dir(&existing).expect("create existing");
    let foreign_id = IdentitySpec { uid: u32::MAX - 2, gids: vec![u32::MAX - 2], user: None };
    assert!(
        prepare_control_socket_dir(
            &existing.join("control.sock"),
            Some(foreign_id.uid),
            Some(foreign_id.gids[0])
        )
        .is_err()
    );
    assert!(ensure_writable_dir(&WritableDirConfig::Custom(existing), Some(&foreign_id)).is_err());

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies standalone TUI daemon launch emits valid `--nft=false` flag accepted by `nfqws2`
/// instead of the nonexistent `--no-nft` option.
#[cfg(not(windows))]
#[test]
fn tui_daemon_launch_uses_valid_nft_false_flag()
{
    use clap::Parser as _;
    use zapret_rs::config::CliArgs;
    use zapret_rs::tui::daemon_launch::build_daemon_common_args;

    let args = build_daemon_common_args(Path::new("/tmp/nfqws2.toml"), Path::new("/tmp/control.sock"), true);
    let mut full = vec![std::ffi::OsString::from("nfqws2"), "--intercept=0".into()];
    full.extend(
        args.iter()
            .cloned(),
    );
    let parsed = CliArgs::try_parse_from(&full).expect("daemon common args with --nft=false must parse");
    assert_eq!(parsed.nft, Some(false), "--nft=false must parse as Some(false)");
}

/// Verifies `detect_lua_dir(None)` ignores an untrusted `./lua` directory in CWD.
#[cfg(unix)]
#[test]
fn lua_discovery_ignores_cwd_dot_lua_directory()
{
    use zapret_rs::tools::detect_lua_dir;

    let dir = make_temp_dir("cwd-lua");
    let cwd_lua = dir.join("lua");
    fs::create_dir_all(&cwd_lua).expect("create ./lua");
    fs::write(cwd_lua.join("zapret-lib.lua"), "-- decoy").expect("write zapret-lib.lua");
    fs::write(cwd_lua.join("zapret-antidpi.lua"), "-- decoy").expect("write zapret-antidpi.lua");

    let orig = std::env::current_dir().expect("read current_dir");
    std::env::set_current_dir(&dir).expect("chdir to scratch dir");
    let detected = detect_lua_dir(None);
    let _ = std::env::set_current_dir(orig);

    if let Some(found) = detected
    {
        assert_ne!(
            fs::canonicalize(&found).ok(),
            fs::canonicalize(&cwd_lua).ok(),
            "detect_lua_dir(None) must never pick untrusted CWD ./lua"
        );
    }

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `collect_config_port_ranges`, `collect_config_ports`, and `build_nft_script_ranges`
/// preserve non-singleton port intervals such as `50000-50099` and `8080-8082`.
#[test]
fn collect_config_port_ranges_preserves_port_intervals_and_renders_nft()
{
    use zapret_rs::config::AppConfig;
    use zapret_rs::tools::{NftFirewallBackend, collect_config_port_ranges, collect_config_ports};

    let toml = r#"
[[profiles]]
filter_tcp = ["80", "443", "8080-8082"]
filter_udp = ["50000-50099"]
[[profiles.actions]]
func = "fake"
"#;
    let cfg = AppConfig::from_toml_str(toml, None).expect("parse port range config");
    let (tcp_ranges, udp_ranges) = collect_config_port_ranges(&cfg);
    assert_eq!(tcp_ranges, vec![(80, 80), (443, 443), (8080, 8082)]);
    assert_eq!(udp_ranges, vec![(50_000, 50_099)]);

    let (tcp_flat, udp_flat) = collect_config_ports(&cfg);
    assert_eq!(tcp_flat, vec![80, 443, 8080, 8081, 8082]);
    assert_eq!(udp_flat.len(), 100);
    assert_eq!((udp_flat[0], udp_flat[99]), (50_000, 50_099));

    let script = NftFirewallBackend::build_nft_script_ranges(210, 0x4000_0000, &tcp_ranges, &udp_ranges);
    assert!(script.contains("tcp dport { 80, 443 } queue num 210 bypass"));
    assert!(script.contains("tcp dport 8080-8082 queue num 210 bypass"));
    assert!(script.contains("udp dport 50000-50099 queue num 210 bypass"));
    assert!(script.contains("tcp sport 8080-8082 ct original packets 1-6 queue num 210 bypass"));
}

/// Verifies `LineReader` preserves leading frame bytes when a read times out mid-line.
#[test]
fn control_line_reader_preserves_partial_frame_across_timed_out_poll()
{
    use std::collections::VecDeque;
    use std::io::{self, BufReader, Read};
    use zapret_rs::control::{CodecError, LineReader, Request, encode_line};

    struct StagedStream(VecDeque<io::Result<Vec<u8>>>);
    impl Read for StagedStream
    {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>
        {
            match self
                .0
                .pop_front()
            {
                None => Ok(0),
                Some(Err(err)) => Err(err),
                Some(Ok(chunk)) =>
                {
                    let n = chunk
                        .len()
                        .min(buf.len());
                    buf[..n].copy_from_slice(&chunk[..n]);
                    if n < chunk.len()
                    {
                        self.0
                            .push_front(Ok(chunk[n..].to_vec()));
                    }
                    Ok(n)
                }
            }
        }
    }

    let wire = encode_line(&Request::Status).expect("encode Request::Status");
    let split = 7;
    let stream = StagedStream(VecDeque::from([
        Ok(wire[..split].to_vec()),
        Err(io::Error::new(io::ErrorKind::TimedOut, "40ms poll expired")),
        Ok(wire[split..].to_vec()),
    ]));
    let mut reader = LineReader::new(BufReader::new(stream));

    match reader.read_message::<Request>()
    {
        Err(CodecError::Io(e)) if e.kind() == io::ErrorKind::TimedOut =>
        {}
        other => panic!("expected first poll TimedOut, got {other:?}"),
    }
    let decoded = reader
        .read_message::<Request>()
        .expect("second poll must complete frame")
        .expect("decoded frame must be Some");
    assert_eq!(decoded, Request::Status);
}

/// Verifies `CurlProbeBackend` passes `--globoff` and `parse_clean_domain` rejects
/// SSRF/globbing domain inputs (`127.0.0.1`, `localhost`, `@`, `{}`/`[]`).
#[test]
fn probe_uses_globoff_and_domain_parser_rejects_ssrf_and_globs()
{
    use std::time::Duration;
    use zapret_rs::tools::{CurlProbeBackend, IpFamily, ProbeProtocol, ProbeRequest, parse_clean_domain};

    let req = ProbeRequest {
        domain: "example.com".to_owned(),
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V4,
        timeout: Duration::from_secs(2),
    };
    let args = CurlProbeBackend::build_args(&req);
    assert!(args.contains(&"--globoff".to_owned()), "curl args must include --globoff");

    assert_eq!(parse_clean_domain("127.0.0.1"), None);
    assert_eq!(parse_clean_domain("169.254.169.254"), None);
    assert_eq!(parse_clean_domain("localhost"), None);
    assert_eq!(parse_clean_domain("api.localhost"), None);
    assert_eq!(parse_clean_domain("user@evil.com"), None);
    assert_eq!(parse_clean_domain("sub[1-3].example.com"), None);
    assert_eq!(parse_clean_domain("sub{a,b}.example.com"), None);
    assert_eq!(parse_clean_domain("-bad.example.com"), None);
    assert_eq!(parse_clean_domain("ok-host.example.com").as_deref(), Some("ok-host.example.com"));
}

/// Verifies `CurlProbeBackend::probe` halts early when DNS resolves to loopback without spawning `curl`,
/// and `run_scan` skips candidate sweeps for that target.
#[test]
fn probe_aborts_early_when_dns_resolves_to_loopback()
{
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;
    use zapret_rs::config::DesyncProfile;
    use zapret_rs::tools::{
        CurlProbeBackend, IpFamily, ProbeBackend, ProbeOutcome, ProbeProtocol, ProbeRequest, ScanConfig,
        ScanLevel, StrategyApplier, run_scan,
    };

    /// Minimal applier tracking how many strategy profiles were installed.
    struct NoopApplier(usize);
    impl StrategyApplier for NoopApplier
    {
        fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String>
        {
            if !profiles.is_empty()
            {
                self.0 += 1;
            }
            Ok(())
        }
    }

    let backend = CurlProbeBackend::new(PathBuf::from("/nonexistent/curl-never-spawned"));
    let req = ProbeRequest {
        domain: "localhost".to_owned(),
        proto: ProbeProtocol::Tls13,
        ipv: IpFamily::V4,
        timeout: Duration::from_secs(1),
    };
    let outcome = backend.probe(&req);
    assert!(
        matches!(&outcome, ProbeOutcome::Failed { code: -1, detail } if detail.contains("blocked/local IP")),
        "expected early loopback diagnostic, got {outcome:?}"
    );

    let cfg = ScanConfig {
        domains: vec!["localhost".to_owned()],
        protos: vec![ProbeProtocol::Tls13],
        families: vec![IpFamily::V4],
        level: ScanLevel::Quick,
        timeout: Duration::from_secs(1),
        stop_on_first: true,
        force_blocked: false,
    };
    let mut applier = NoopApplier(0);
    let stop = AtomicBool::new(false);
    let report = run_scan(&cfg, &backend, &mut applier, &stop, |_| {}).expect("scan report");
    assert_eq!(applier.0, 0, "candidate sweep should be skipped when baseline resolves to loopback");
    assert_eq!(
        report
            .targets
            .len(),
        1
    );
    assert_eq!(report.targets[0].tested_count, 0);
}

/// Verifies `WebIpcBridge::shutdown` succeeds cleanly even while held behind shared `Arc` clones.
#[test]
fn web_ipc_bridge_shutdown_works_through_shared_arc()
{
    use std::sync::Arc;
    use zapret_rs::tools::WebIpcBridge;

    let bridge = Arc::new(WebIpcBridge::spawn(None));
    let _extra_ref = Arc::clone(&bridge);
    assert!(
        bridge
            .subscribe_sse()
            .is_some()
    );
    bridge.shutdown();
    // After shutdown clears sse_clients and sets stop, further snapshot/shutdown calls stay safe.
    let _ = bridge.snapshot();
}

/// Constructs a complete TLS `ClientHello` record of exact byte `len` (>= 11) with optional SID byte.
fn make_minimal_client_hello(len: usize, sid_len: u8) -> Vec<u8>
{
    let mut rec = vec![0u8; len];
    let rec_payload = (len - 5) as u16;
    let hs_payload = (len - 9) as u32;
    rec[0] = 0x16;
    rec[1] = 0x03;
    rec[2] = 0x01;
    rec[3..5].copy_from_slice(&rec_payload.to_be_bytes());
    rec[5] = 0x01;
    rec[6..9].copy_from_slice(&hs_payload.to_be_bytes()[1..]);
    rec[9] = 0x03;
    rec[10] = 0x03;
    if len >= 44
    {
        rec[43] = sid_len;
    }
    rec
}

/// Verifies `tls_mod` rejects short 11..=43-byte and truncated-SID `ClientHello`s without panicking.
#[test]
fn tls_mod_rejects_short_and_truncated_sid_client_hello_without_panic()
{
    use zapret_rs::protocol::{FakeTlsMod, tls_mod};

    let spec = FakeTlsMod::parse_list("rnd").expect("rnd mod spec should parse");
    for len in [11usize, 20, 43]
    {
        let ch = make_minimal_client_hello(len, 0);
        assert!(tls_mod(&spec, None, &ch).is_none(), "len={len} must return None");
    }

    let ok_44 = make_minimal_client_hello(44, 0);
    assert_eq!(tls_mod(&spec, None, &ok_44).map(|v| v.len()), Some(44));

    let trunc_sid = make_minimal_client_hello(44, 16);
    assert!(tls_mod(&spec, None, &trunc_sid).is_none(), "truncated SID must return None");
}
