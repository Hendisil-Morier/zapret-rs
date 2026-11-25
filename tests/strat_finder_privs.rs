//! Privilege-separation, zero-capability `curl` child, `--print-nft`, and `O_NOFOLLOW` tests.

/// Filesystem helpers for symlink-refusal config-write tests.
use std::fs;
/// Unix `pre_exec` hook to verify [`clear_child_privileges`] on real spawned processes.
use std::os::unix::fs::symlink;
/// Unix `CommandExt::pre_exec` trait for child process capability stripping.
use std::os::unix::process::CommandExt as _;
/// Subprocess execution for inspecting `/proc/self/status` and `nfqws2 --strat-finder`.
use std::process::Command;

/// Child privilege stripper under test.
use zapret_rs::runtime::clear_child_privileges;
/// Firewall backend, permission classifier, and symlink-safe TOML writer under test.
use zapret_rs::tools::{
    FirewallBackend, NftFirewallBackend, STRAT_FINDER_NFT_TABLE, build_nft_cleanup_cmd,
    is_nft_perm_denied, write_config_nofollow,
};

/// Extracts the value for `key` (e.g., `"CapEff:"` or `"NoNewPrivs:"`) from `/proc/self/status`.
fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key).map(str::trim))
}

/// Spawns `cat /proc/self/status` with [`clear_child_privileges`] in `pre_exec` and asserts
/// all capability masks are zero and `NoNewPrivs` is `1`.
fn assert_child_has_zero_caps_and_no_new_privs() {
    let mut cmd = Command::new("/bin/cat");
    cmd.arg("/proc/self/status");
    // SAFETY: `clear_child_privileges` uses only async-signal-safe `prctl` and `SYS_capset`.
    unsafe {
        cmd.pre_exec(clear_child_privileges);
    }
    let out = cmd.output().expect("spawn cat /proc/self/status");
    assert!(out.status.success(), "cat failed: {}", String::from_utf8_lossy(&out.stderr));
    let text = String::from_utf8_lossy(&out.stdout);

    assert_eq!(status_field(&text, "CapEff:"), Some("0000000000000000"));
    assert_eq!(status_field(&text, "CapPrm:"), Some("0000000000000000"));
    assert_eq!(status_field(&text, "CapInh:"), Some("0000000000000000"));
    if let Some(amb) = status_field(&text, "CapAmb:") {
        assert_eq!(amb, "0000000000000000");
    }
    assert_eq!(status_field(&text, "NoNewPrivs:"), Some("1"));
}

/// Verifies spawned children using [`clear_child_privileges`] get zero caps and `NoNewPrivs=1`.
#[test]
fn child_pre_exec_clears_capabilities_and_sets_no_new_privs() {
    assert_child_has_zero_caps_and_no_new_privs();
}

/// Verifies inside a root-mapped user/network namespace (`unshare -r -n`) that a parent with full
/// capabilities still strips every capability from children via [`clear_child_privileges`].
#[test]
#[ignore = "requires unshare -r -n with full namespace capabilities"]
fn live_child_pre_exec_strips_root_capabilities() {
    assert_child_has_zero_caps_and_no_new_privs();
}

/// Verifies inside `unshare -r -n` that [`NftFirewallBackend::install`] loads valid `nftables`
/// rules directly into the kernel and [`Drop`] removes `table inet zapret_strat_finder` cleanly.
#[test]
#[ignore = "requires unshare -r -n with CAP_NET_ADMIN and nft binary"]
fn live_nft_firewall_backend_installs_and_cleans_up_table() {
    let nft = NftFirewallBackend::default();
    let guard = nft
        .install(210, 0x4000_0000, &[80, 443], &[443])
        .expect("real nft -f - install must succeed");

    let list_active = Command::new("nft")
        .args(["list", "table", "inet", STRAT_FINDER_NFT_TABLE])
        .output()
        .expect("nft list table");
    assert!(
        list_active.status.success(),
        "table should exist while guard is alive: {}",
        String::from_utf8_lossy(&list_active.stderr)
    );
    let active_text = String::from_utf8_lossy(&list_active.stdout);
    assert!(
        active_text.contains("bypass") && active_text.contains("210"),
        "unexpected nft list output:\n{active_text}"
    );

    drop(guard);

    let list_after = Command::new("nft")
        .args(["list", "table", "inet", STRAT_FINDER_NFT_TABLE])
        .output()
        .expect("nft list table after drop");
    assert!(
        !list_after.status.success(),
        "table must be deleted when NftQueueGuard drops"
    );
}

/// Verifies `--print-nft`, `is_nft_perm_denied`, and the non-root `setcap` error guidance.
#[test]
fn print_nft_perm_classifier_and_setcap_guidance() {
    assert!(is_nft_perm_denied("Error: Could not process rule: Operation not permitted"));
    assert!(is_nft_perm_denied("nft: Permission denied"));
    assert!(!is_nft_perm_denied("Error: syntax error, unexpected newline"));
    assert_eq!(build_nft_cleanup_cmd(), "nft delete table inet zapret_strat_finder");

    let nfqws2 = env!("CARGO_BIN_EXE_nfqws2");
    let out = Command::new(nfqws2)
        .args(["--strat-finder", "--print-nft", "--proto", "http,tls13,http3", "--qnum", "215"])
        .output()
        .expect("run --print-nft");
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("table inet zapret_strat_finder"));
    assert!(stdout.contains("tcp dport { 80, 443 } queue num 215 bypass"));
    assert!(stdout.contains("udp dport { 443 } queue num 215 bypass"));
    assert!(stdout.contains("nft delete table inet zapret_strat_finder"));

    // Running without capabilities prints the one-time `setcap` instruction instead of crashing.
    if unsafe { libc::geteuid() } != 0 {
        let missing = Command::new(nfqws2)
            .args(["--strat-finder", "--domain", "example.com", "--no-nft"])
            .output()
            .expect("run without caps");
        assert!(!missing.status.success());
        let stderr = String::from_utf8_lossy(&missing.stderr);
        assert!(
            stderr.contains("setcap cap_net_admin,cap_net_raw+ep"),
            "expected setcap hint in stderr, got: {stderr}"
        );
    }
}

/// Verifies [`write_config_nofollow`] writes regular files and refuses symlink targets (`ELOOP`).
#[test]
fn write_config_nofollow_writes_regular_file_and_refuses_symlink() {
    let dir = std::env::temp_dir().join(format!("strat_privs_test_{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");

    let target = dir.join("victim.txt");
    fs::write(&target, "untouched").expect("seed victim");

    let link = dir.join("config_link.toml");
    symlink(&target, &link).expect("create symlink");

    let err = write_config_nofollow(&link, "qnum = 200\n")
        .expect_err("symlink destination must be refused");
    assert_eq!(err.raw_os_error(), Some(libc::ELOOP));
    assert_eq!(fs::read_to_string(&target).expect("read victim"), "untouched");

    let regular = dir.join("nfqws2.toml");
    write_config_nofollow(&regular, "qnum = 200\n").expect("write regular file");
    assert_eq!(fs::read_to_string(&regular).expect("read regular"), "qnum = 200\n");

    let _ = fs::remove_dir_all(&dir);
}
