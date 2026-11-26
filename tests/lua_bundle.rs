//! Integration tests for embedded Lua script bundling, extraction safety, and strict `--lua-dir`.

/// Temporary directory creation and symlink security checks during bundled extraction.
use std::fs;
/// File permissions and Unix symlink helpers for `O_NOFOLLOW` verification.
#[cfg(unix)]
use std::os::unix::fs::symlink;
/// Unique path construction under `std::env::temp_dir`.
use std::path::PathBuf;

/// Bundled Lua constants and extraction helpers under test.
use zapret_rs::tools::{BUNDLED_LUA_SCRIPTS, extract_bundled_lua, resolve_lua_scripts};

/// Creates a unique temporary directory removed cleanly by the test.
fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zapret-rs-lua-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

#[test]
fn extract_bundled_lua_writes_all_scripts_and_is_idempotent() {
    let dir = temp_dir("extract");
    let written = extract_bundled_lua(&dir).expect("extract bundled lua scripts");
    assert_eq!(written.len(), BUNDLED_LUA_SCRIPTS.len());
    assert!(dir.join("zapret-lib.lua").is_file());
    assert!(dir.join("zapret-antidpi.lua").is_file());

    let lib_len = fs::metadata(dir.join("zapret-lib.lua")).expect("metadata").len();
    assert!(lib_len > 10_000, "embedded zapret-lib.lua unexpectedly small: {lib_len}");

    // Second call succeeds without errors and preserves valid script pair discovery.
    let resolved = resolve_lua_scripts(Some(&dir)).expect("resolve extracted lua dir");
    assert_eq!(resolved.len(), 2);
    let repeat = extract_bundled_lua(&dir).expect("idempotent re-extract");
    assert_eq!(repeat.len(), BUNDLED_LUA_SCRIPTS.len());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn resolve_lua_scripts_keeps_missing_explicit_dir_strict() {
    let missing = std::env::temp_dir().join("zapret-rs-definitely-missing-lua-dir");
    let _ = fs::remove_dir_all(&missing);
    let err = resolve_lua_scripts(Some(&missing)).expect_err("explicit missing dir must fail");
    assert!(err.contains("zapret-lib.lua"));
}

#[cfg(unix)]
#[test]
fn extract_bundled_lua_refuses_symlinks_with_nofollow() {
    let dir = temp_dir("symlink");
    let target = dir.join("decoy.txt");
    fs::write(&target, "keep").expect("write decoy target");
    symlink(&target, dir.join("zapret-lib.lua")).expect("create symlink");

    let err = extract_bundled_lua(&dir).expect_err("O_NOFOLLOW must reject symlink");
    assert!(err.contains("zapret-lib.lua"));
    assert_eq!(fs::read_to_string(&target).expect("read decoy"), "keep");

    let _ = fs::remove_dir_all(&dir);
}
