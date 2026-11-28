//! Integration tests for `zapret-rs install` / `uninstall` and systemd unit rendering.

/// Temp directory cleanup and installed artifact assertions.
use std::fs;
/// Path inspection for rendered service unit and temp prefix directories.
use std::path::{Path, PathBuf};
/// End-to-end execution of `zapret-rs install` and `uninstall` against temp `--prefix`.
use std::process::Command;

/// Installer symbols and symlink constants under test.
use zapret_rs::tools::{
    BUNDLED_LUA_SCRIPTS, SYMLINK_NAMES, render_systemd_service, try_render_systemd_service,
};

/// Creates a clean temporary prefix directory scoped to `tag`.
fn temp_prefix(tag: &str) -> PathBuf
{
    let dir = std::env::temp_dir().join(format!("zapret-rs-inst-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp prefix");
    dir
}

#[test]
fn systemd_unit_rendering_substitutes_binary_user_home_and_condition()
{
    let rendered = render_systemd_service(Path::new("/opt/bin/zapret-rs"), "alice", Path::new("/home/alice"));
    assert!(rendered.contains("ConditionPathExists=/home/alice/.config/zapret-rs/nfqws2.toml"));
    assert!(rendered.contains("User=alice"));
    assert!(
        rendered.contains(
            "ExecStart=/opt/bin/zapret-rs daemon --config /home/alice/.config/zapret-rs/nfqws2.toml"
        )
    );
    assert!(!rendered.contains("__USER__") && !rendered.contains("__HOME__"));
}

#[test]
fn install_and_uninstall_prefix_deploy_binary_symlinks_and_bundled_lua()
{
    let bin = env!("CARGO_BIN_EXE_zapret-rs");
    let prefix = temp_prefix("roundtrip");

    let inst = Command::new(bin)
        .args(["install", "--prefix"])
        .arg(&prefix)
        .args(["--symlinks", "--no-caps", "--source-bin", bin])
        .output()
        .expect("run zapret-rs install");
    assert!(
        inst.status.success(),
        "install failed ({}): {}",
        inst.status,
        String::from_utf8_lossy(&inst.stderr)
    );

    let installed_bin = prefix.join("bin/zapret-rs");
    assert!(installed_bin.is_file());
    let installed_lua = prefix.join("share/zapret-rs/lua");
    for (name, _) in BUNDLED_LUA_SCRIPTS
    {
        assert!(installed_lua.join(name).is_file(), "missing extracted lua file {name}");
    }
    #[cfg(unix)]
    for name in SYMLINK_NAMES
    {
        let link = prefix.join("bin").join(name);
        let meta = fs::symlink_metadata(&link).expect("symlink metadata");
        assert!(meta.file_type().is_symlink(), "{name} should be a symlink");
    }

    // Verify installed binary executes cleanly directly and through the `nfqws2` symlink.
    let daemon_ver = Command::new(prefix.join("bin/nfqws2"))
        .arg("--version")
        .output()
        .expect("run installed nfqws2 symlink");
    assert!(daemon_ver.status.success());
    assert!(String::from_utf8_lossy(&daemon_ver.stdout).contains("nfqws2"));

    let uninst = Command::new(bin)
        .args(["uninstall", "--prefix"])
        .arg(&prefix)
        .output()
        .expect("run zapret-rs uninstall");
    assert!(
        uninst.status.success(),
        "uninstall failed ({}): {}",
        uninst.status,
        String::from_utf8_lossy(&uninst.stderr)
    );
    assert!(!installed_bin.exists());
    assert!(!installed_lua.exists());
    for name in SYMLINK_NAMES
    {
        assert!(fs::symlink_metadata(prefix.join("bin").join(name)).is_err());
    }

    let _ = fs::remove_dir_all(&prefix);
}

#[cfg(unix)]
#[test]
fn install_replaces_existing_symlink_pointing_to_source_bin()
{
    let bin = env!("CARGO_BIN_EXE_zapret-rs");
    let prefix = temp_prefix("replace-symlink");
    let bin_dir = prefix.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let dst_bin = bin_dir.join("zapret-rs");
    std::os::unix::fs::symlink(bin, &dst_bin).expect("seed pre-existing symlink");

    let inst = Command::new(bin)
        .args(["install", "--prefix"])
        .arg(&prefix)
        .args(["--no-caps", "--source-bin", bin])
        .output()
        .expect("run install over pre-existing symlink");
    assert!(inst.status.success(), "stderr={}", String::from_utf8_lossy(&inst.stderr));

    let meta = fs::symlink_metadata(&dst_bin).expect("dst metadata");
    assert!(
        meta.file_type().is_file() && !meta.file_type().is_symlink(),
        "dst must become a real file for setcap"
    );

    let _ = fs::remove_dir_all(&prefix);
}

#[test]
fn systemd_unit_rendering_rejects_and_strips_newline_injections()
{
    assert!(
        try_render_systemd_service(
            Path::new("/usr/local/bin/zapret-rs"),
            "alice\nExecStartPre=/bin/evil",
            Path::new("/home/alice"),
        )
        .is_err()
    );
    assert!(
        try_render_systemd_service(
            Path::new("/usr/local/bin/zapret-rs"),
            "alice",
            Path::new("/home/alice\r\nEnvironment=PWN=1"),
        )
        .is_err()
    );

    let baseline =
        render_systemd_service(Path::new("/usr/local/bin/zapret-rs"), "alice", Path::new("/home/alice"));
    let sanitized = render_systemd_service(
        Path::new("/usr/local/bin/zapret-rs"),
        "alice\nExecStart=/evil",
        Path::new("/home/alice"),
    );
    assert_eq!(
        sanitized.lines().count(),
        baseline.lines().count(),
        "newlines must never inject extra unit lines"
    );
    assert!(sanitized.lines().all(|l| !l.trim_start().starts_with("ExecStart=/evil")));
}

#[cfg(unix)]
#[test]
fn uninstall_preserves_unrelated_non_symlink_binaries_in_bin_dir()
{
    let bin = env!("CARGO_BIN_EXE_zapret-rs");
    let prefix = temp_prefix("preserve-foreign-bin");
    let bin_dir = prefix.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");

    let inst = Command::new(bin)
        .args(["install", "--prefix"])
        .arg(&prefix)
        .args(["--no-caps", "--source-bin", bin])
        .output()
        .expect("run install");
    assert!(inst.status.success());

    // Pre-existing regular binary colliding with a compatibility symlink name must not be deleted.
    let custom_mdig = bin_dir.join("mdig");
    fs::write(&custom_mdig, "custom-binary").expect("write custom binary");

    let uninst =
        Command::new(bin).args(["uninstall", "--prefix"]).arg(&prefix).output().expect("run uninstall");
    assert!(uninst.status.success());
    assert!(!bin_dir.join("zapret-rs").exists());
    assert_eq!(fs::read_to_string(&custom_mdig).expect("custom binary kept"), "custom-binary");

    let _ = fs::remove_dir_all(&prefix);
}
