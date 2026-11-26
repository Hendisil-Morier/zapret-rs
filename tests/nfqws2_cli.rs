//! End-to-end CLI, PID file, POSIX signal, and runtime lifecycle tests for `nfqws2`.

/// Standard filesystem helpers for temporary configs, scripts, and PID files.
use std::fs;
/// Reader trait used to drain piped child stderr on premature failure.
use std::io::Read;
/// Path types for resolving workspace fixtures and temporary test files.
use std::path::{Path, PathBuf};
/// Subprocess execution, stdout/stderr capture, and cooperative child reaping.
use std::process::{Child, Command, ExitStatus, Stdio};
/// Monotonic deadline polling intervals for bounded child process synchronization.
use std::time::{Duration, Instant};

/// Runtime process lifecycle primitives under test.
use zapret_rs::runtime::{
    PidFileGuard, ProcessError, parse_uid_spec, resolve_identity, resolve_user_spec,
};

/// Returns a `zapret-rs daemon` command backed by the compiled unified binary.
fn daemon_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("daemon");
    cmd
}

/// Returns a unique temporary directory under `std::env::temp_dir()`, cleaning stale leftovers.
fn fresh_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zapret-rs-cli-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temporary test dir");
    dir
}

/// RAII guard killing and reaping a child process on unwind so failed tests never leak processes.
struct ChildGuard {
    /// Owned spawned child handle until `wait_bounded` or drop.
    child: Option<Child>,
}

impl ChildGuard {
    /// Wraps a spawned child process.
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Returns the OS process identifier of the guarded child.
    fn id(&self) -> u32 {
        self.child.as_ref().expect("child present").id()
    }

    /// Polls `try_wait` up to `timeout`, checking non-exit when `should_be_running` matters.
    fn try_wait(&mut self) -> Option<ExitStatus> {
        self.child
            .as_mut()
            .expect("child present")
            .try_wait()
            .expect("try_wait child")
    }

    /// Reads and drains any piped stderr stream captured from the child process.
    fn take_stderr_output(&mut self) -> String {
        let Some(mut stderr) = self.child.as_mut().and_then(|c| c.stderr.take()) else {
            return String::new();
        };
        let mut buf = String::new();
        let _ = stderr.read_to_string(&mut buf);
        buf
    }

    /// Waits up to `timeout` for the child process to exit, panicking on timeout.
    fn wait_bounded(mut self, timeout: Duration) -> ExitStatus {
        let mut child = self.child.take().expect("child present");
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("poll child exit") {
                return status;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("child process did not exit within {timeout:?}");
    }
}

impl Drop for ChildGuard {
    /// Kills and reaps any still-owned child process on early test failure or panic.
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Sends a POSIX signal (`SIGTERM`, `SIGINT`, `SIGHUP`) directly to `pid` via `libc::kill`.
fn send_signal(pid: u32, sig: libc::c_int) {
    // SAFETY: `pid` is a positive child PID returned by `std::process::Child::id`.
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    assert_eq!(rc, 0, "kill(pid={pid}, sig={sig}) failed");
}

/// Polls `pidfile` until it contains `expected_pid`, or aborts with child exit diagnostics.
fn wait_for_pidfile(pidfile: &Path, child: &mut ChildGuard, timeout: Duration) {
    let expected = child.id().to_string();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(content) = fs::read_to_string(pidfile)
            && content.trim() == expected
        {
            return;
        }
        if let Some(status) = child.try_wait() {
            let stderr = child.take_stderr_output();
            panic!(
                "child exited prematurely ({status}) before writing pidfile; stderr={stderr}"
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!(
        "timed out waiting for pidfile {} to contain {expected}",
        pidfile.display()
    );
}

/// Verifies `--version`, `--dry-run`, missing `@lua-init` files, unknown `--user`, and malformed `--uid`.
#[test]
fn cli_version_and_dry_run_validate_config_and_reject_bad_inputs() {
    let dir = fresh_temp_dir("dry-run");
    let toml_path = dir.join("config.toml");
    let lua_path = dir.join("ok.lua");
    fs::write(&lua_path, "function noop() end\n").expect("write lua");
    fs::write(
        &toml_path,
        format!(
            "qnum = 250\nlua_init = [\"{}\"]\n",
            lua_path.to_string_lossy().replace('\\', "\\\\")
        ),
    )
    .expect("write config.toml");

    let ver = daemon_cmd()
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(ver.status.success());
    assert!(String::from_utf8_lossy(&ver.stdout).contains("nfqws2"));

    let dry = daemon_cmd()
        .args(["--config", toml_path.to_str().expect("utf8"), "--dry-run"])
        .output()
        .expect("run --dry-run");
    assert!(
        dry.status.success(),
        "dry-run stderr: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    assert!(String::from_utf8_lossy(&dry.stdout).contains("configuration verified"));

    let missing_lua = daemon_cmd()
        .args(["--dry-run", "--lua-init=@/nonexistent_zapret_script.lua"])
        .output()
        .expect("run missing lua-init");
    assert!(!missing_lua.status.success());

    let bad_user = daemon_cmd()
        .args(["--dry-run", "--user", "no_such_zapret_user_99999"])
        .output()
        .expect("run invalid user");
    assert!(!bad_user.status.success());

    let bad_uid = daemon_cmd()
        .args(["--dry-run", "--uid", "abc:def"])
        .output()
        .expect("run invalid uid");
    assert!(!bad_uid.status.success());

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `--intercept=0` loads `zapret2/lua/zapret-lib.lua`, evaluates inline Lua, and exits 0.
#[test]
fn cli_intercept_zero_loads_zapret_lib_and_runs_inline_lua() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let zapret_lib = manifest_dir.join("../zapret2/lua/zapret-lib.lua");
    assert!(
        zapret_lib.exists(),
        "expected zapret-lib.lua at {}",
        zapret_lib.display()
    );

    let out = daemon_cmd()
        .current_dir(manifest_dir)
        .args([
            "--intercept=0",
            "--lua-init=@../zapret2/lua/zapret-lib.lua",
            "--lua-init=DLOG_CONDUP(\"ok\")",
        ])
        .output()
        .expect("run nfqws2 --intercept=0");

    assert!(
        out.status.success(),
        "nfqws2 exited with {}; stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("LUA: ok"),
        "unexpected stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

/// Verifies `--intercept=0` executes oneshot timers to completion and removes its `--pidfile` on exit.
#[test]
fn cli_intercept_zero_executes_timers_and_removes_pidfile() {
    let dir = fresh_temp_dir("timers");
    let pidfile = dir.join("nfqws2.pid");

    let start = Instant::now();
    let out = daemon_cmd()
        .args([
            "--intercept=0",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
            "--lua-init",
            r#"timer_set("once", function(name) DLOG_CONDUP("fired:" .. name) end, 20, true)"#,
        ])
        .output()
        .expect("run timer --intercept=0");

    assert!(start.elapsed() < Duration::from_secs(2));
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("LUA: fired:once"));
    assert!(
        !pidfile.exists(),
        "pidfile must be cleaned up automatically after exit"
    );

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `SIGHUP` is non-fatal and `SIGTERM` exits cleanly without leaking `--pidfile`.
#[test]
fn cli_sighup_is_nonfatal_and_sigterm_exits_cleanly_without_pidfile_leak() {
    let dir = fresh_temp_dir("sigterm");
    let pidfile = dir.join("daemon.pid");

    let raw_child = daemon_cmd()
        .args([
            "--intercept=0",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
            "--lua-init",
            r#"timer_set("hold", function() end, 10000, false)"#,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nfqws2");
    let mut child = ChildGuard::new(raw_child);

    wait_for_pidfile(&pidfile, &mut child, Duration::from_secs(2));
    let pid = child.id();

    send_signal(pid, libc::SIGHUP);
    std::thread::sleep(Duration::from_millis(80));
    assert!(
        child.try_wait().is_none(),
        "SIGHUP must not terminate nfqws2"
    );

    send_signal(pid, libc::SIGTERM);
    let status = child.wait_bounded(Duration::from_secs(2));
    assert!(status.success(), "SIGTERM must yield clean exit 0 ({status})");
    assert!(!pidfile.exists(), "pidfile must be removed after SIGTERM");

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `SIGINT` wakes `--intercept=0` promptly and removes `--pidfile`.
#[test]
fn cli_sigint_exits_cleanly_without_pidfile_leak() {
    let dir = fresh_temp_dir("sigint");
    let pidfile = dir.join("sigint.pid");

    let raw_child = daemon_cmd()
        .args([
            "--intercept=0",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
            "--lua-init",
            r#"timer_set("hold", function() end, 10000, false)"#,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn nfqws2");
    let mut child = ChildGuard::new(raw_child);

    wait_for_pidfile(&pidfile, &mut child, Duration::from_secs(2));
    send_signal(child.id(), libc::SIGINT);
    let status = child.wait_bounded(Duration::from_secs(2));
    assert!(status.success(), "SIGINT must yield clean exit 0 ({status})");
    assert!(!pidfile.exists(), "pidfile must be removed after SIGINT");

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `--chdir <dir>` changes working directory before resolving relative `--lua-init=@file` paths.
#[test]
fn cli_chdir_resolves_relative_lua_init_script() {
    let dir = fresh_temp_dir("chdir");
    fs::write(dir.join("rel.lua"), r#"DLOG_CONDUP("chdir_ok")"#).expect("write rel.lua");

    let out = daemon_cmd()
        .args([
            "--intercept=0",
            "--chdir",
            dir.to_str().expect("utf8 dir"),
            "--lua-init=@rel.lua",
        ])
        .output()
        .expect("run nfqws2 --chdir");

    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("LUA: chdir_ok"));

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies UID/GID parsing, `getpwnam_r` account lookup, and [`PidFileGuard`] RAII teardown.
#[test]
fn runtime_identity_parsing_and_pidfile_guard_cleanup() {
    let uid_only = parse_uid_spec("1000").expect("uid only parses");
    assert_eq!(uid_only.uid, 1000);
    assert_eq!(uid_only.gids, vec![0x7FFF_FFFF]);
    assert_eq!(uid_only.user, None);

    let with_gids = parse_uid_spec("1000:100,200,300").expect("uid with gids parses");
    assert_eq!(with_gids.uid, 1000);
    assert_eq!(with_gids.gids, vec![100, 200, 300]);

    assert!(matches!(
        parse_uid_spec("1000:"),
        Err(ProcessError::InvalidUidSpec(_))
    ));
    assert!(matches!(
        parse_uid_spec("abc"),
        Err(ProcessError::InvalidUidSpec(_))
    ));

    let root = resolve_user_spec("root").expect("root exists in /etc/passwd");
    assert_eq!(root.uid, 0);
    assert_eq!(root.user.as_deref(), Some("root"));
    assert!(matches!(
        resolve_user_spec("no_such_zapret_user_99999"),
        Err(ProcessError::UserLookup(_))
    ));
    assert!(matches!(
        resolve_identity(Some("root"), Some("0")),
        Err(ProcessError::UserLookup(_))
    ));

    let dir = fresh_temp_dir("pidguard");
    let pid_path = dir.join("guard.pid");
    {
        let mut guard = PidFileGuard::create(&pid_path).expect("create guard");
        guard.write_current_pid().expect("write pid");
        let text = fs::read_to_string(guard.path()).expect("read guard pidfile");
        assert_eq!(text, std::process::id().to_string());
    }
    assert!(!pid_path.exists(), "PidFileGuard drop must remove pidfile");
    let _ = fs::remove_dir_all(&dir);
}

/// Verifies live NFQUEUE bind, `--pidfile` write, and clean `SIGTERM` shutdown inside a privileged namespace.
#[test]
#[ignore = "requires CAP_NET_ADMIN and CAP_NET_RAW (run in unshare -r -n or as root)"]
fn live_nfqueue_daemon_starts_and_exits_on_sigterm() {
    let dir = fresh_temp_dir("live-nfq");
    let pidfile = dir.join("live.pid");

    let raw_child = daemon_cmd()
        .args([
            "--qnum",
            "299",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live nfqws2");
    let mut child = ChildGuard::new(raw_child);

    wait_for_pidfile(&pidfile, &mut child, Duration::from_secs(2));
    send_signal(child.id(), libc::SIGTERM);
    let status = child.wait_bounded(Duration::from_secs(2));
    assert!(status.success(), "live nfqws2 failed cleanly with {status}");
    assert!(!pidfile.exists(), "live pidfile must be cleaned up");

    let _ = fs::remove_dir_all(&dir);
}

/// Verifies `--dry-run` rejects missing list files and accepts valid Milestone 3 CLI flags.
#[test]
fn cli_dry_run_validates_lists_and_accepts_m3_flags() {
    let dir = fresh_temp_dir("m3-dryrun");
    let bad_cfg = dir.join("missing-list.toml");
    fs::write(&bad_cfg, "[[profiles]]\nhostlist = [\"does-not-exist.txt\"]\n").expect("write bad");
    let fail = daemon_cmd()
        .args(["--dry-run", "--config", bad_cfg.to_str().expect("utf8")])
        .output()
        .expect("run bad dry-run");
    assert!(!fail.status.success(), "missing hostlist must fail dry-run");

    let hl = dir.join("hosts.txt");
    let good_cfg = dir.join("valid-m3.toml");
    fs::write(&hl, "example.com\n").expect("write hosts.txt");
    fs::write(&good_cfg, format!("[[profiles]]\nhostlist = [\"{}\"]\n", hl.display())).expect("ok");
    let ok = daemon_cmd()
        .args([
            "--dry-run",
            "--config",
            good_cfg.to_str().expect("utf8"),
            "--ctrack-timeouts=10:20:30",
            "--ipcache-hostname=1",
            "--payload-disable=dns_query",
            "--reasm-disable=quic_initial",
        ])
        .output()
        .expect("run valid m3 dry-run");
    let _ = fs::remove_dir_all(&dir);
    assert!(ok.status.success(), "valid M3 dry-run failed: {}", String::from_utf8_lossy(&ok.stderr));
}
