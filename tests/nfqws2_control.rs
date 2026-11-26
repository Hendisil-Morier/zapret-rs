//! End-to-end tests spawning real `nfqws2 --intercept=0` with its Unix control socket.

use std::fs;
use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zapret_rs::control::{
    CONTROL_PROTOCOL_VERSION, Request, Response, read_message, write_message,
};

fn daemon_cmd() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("daemon");
    cmd
}

fn fresh_temp_dir(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("zapret-nfqws2-ctl-{}-{label}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("child").id()
    }

    fn wait_bounded(mut self, timeout: Duration) -> std::process::ExitStatus {
        let mut child = self.child.take().expect("child");
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("try_wait") {
                return status;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        panic!("nfqws2 did not exit within {timeout:?}");
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn connect_with_retry(sock: &Path, child: &mut ChildGuard, timeout: Duration) -> UnixStream {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(sock) {
            return stream;
        }
        if let Some(status) = child.child.as_mut().and_then(|c| c.try_wait().ok().flatten()) {
            panic!("nfqws2 exited prematurely ({status}) before binding control socket");
        }
        std::thread::sleep(Duration::from_millis(15));
    }
    panic!("timed out waiting for control socket {}", sock.display());
}

#[test]
fn real_nfqws2_control_socket_answers_status_reloads_and_stops_cleanly() {
    let dir = fresh_temp_dir("lifecycle");
    let pidfile = dir.join("daemon.pid");
    let sock_dir = dir.join("missing_parent");
    let sock = sock_dir.join("control.sock");

    let raw_child = daemon_cmd()
        .args([
            "--intercept=0",
            "--qnum",
            "244",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
            "--control-socket",
            sock.to_str().expect("utf8 sock"),
            "--control-pass-sample",
            "5",
            "--lua-init",
            r#"timer_set("hold", function() end, 10000, false)"#,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn nfqws2");
    let mut child = ChildGuard::new(raw_child);

    let mut stream = connect_with_retry(&sock, &mut child, Duration::from_secs(3));
    stream.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let mut reader = BufReader::new(stream.try_clone().expect("clone"));

    // Missing parent dir should be created mode 0700 and socket mode 0600.
    let dir_mode = fs::symlink_metadata(&sock_dir).expect("dir stat").permissions().mode() & 0o777;
    assert_eq!(dir_mode, 0o700);
    let sock_mode = fs::symlink_metadata(&sock).expect("sock stat").permissions().mode() & 0o777;
    assert_eq!(sock_mode, 0o600);

    write_message(&mut stream, &Request::Hello { version: CONTROL_PROTOCOL_VERSION })
        .expect("hello");
    assert!(matches!(
        read_message::<_, Response>(&mut reader).expect("hello read"),
        Some(Response::HelloOk { version: CONTROL_PROTOCOL_VERSION, .. })
    ));

    write_message(&mut stream, &Request::Status).expect("status");
    match read_message::<_, Response>(&mut reader).expect("status read") {
        Some(Response::Status(st)) => {
            assert_eq!(st.pid, child.id());
            assert_eq!(st.qnum, 244);
            assert!(!st.intercept);
            assert_eq!(st.pass_sample_rate, 5);
        }
        other => panic!("expected Status reply, got {other:?}"),
    }

    write_message(&mut stream, &Request::ReloadLists).expect("reload_lists");
    assert!(matches!(
        read_message::<_, Response>(&mut reader).expect("reload read"),
        Some(Response::Ack { op, .. }) if op == "reload_lists"
    ));

    // Real nfqws2 validates and swaps profiles on reload_config, rejecting invalid/qnum edits.
    write_message(
        &mut stream,
        &Request::ReloadConfig { toml: "qnum = 999\n".to_owned() },
    )
    .expect("reload_config bad qnum");
    assert!(matches!(
        read_message::<_, Response>(&mut reader).expect("bad reload read"),
        Some(Response::Error { message, .. }) if message.contains("restart")
    ));

    write_message(
        &mut stream,
        &Request::ReloadConfig {
            toml: "qnum = 244\n[[profiles]]\nname = \"live_reloaded\"\nfilter_tcp = [\"443\"]\n".to_owned(),
        },
    )
    .expect("reload_config ok");
    assert!(matches!(
        read_message::<_, Response>(&mut reader).expect("good reload read"),
        Some(Response::Ack { op, .. }) if op == "reload_config"
    ));
    write_message(&mut stream, &Request::Status).expect("status after reload");
    match read_message::<_, Response>(&mut reader).expect("status2 read") {
        Some(Response::Status(st)) => {
            assert_eq!(st.profile_names, vec!["live_reloaded".to_owned()]);
        }
        other => panic!("expected updated profiles in status, got {other:?}"),
    }

    write_message(&mut stream, &Request::Stop).expect("stop");
    assert!(matches!(
        read_message::<_, Response>(&mut reader).expect("stop read"),
        Some(Response::Ack { op, .. }) if op == "stop"
    ));

    drop(reader);
    drop(stream);
    let status = child.wait_bounded(Duration::from_secs(3));
    assert!(status.success(), "stop command must exit cleanly (got {status})");
    assert!(!sock.exists(), "socket file must be removed on exit");
    assert!(!pidfile.exists(), "pidfile must be removed on exit");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn real_nfqws2_control_socket_off_exits_without_binding() {
    let dir = fresh_temp_dir("disabled");
    let pidfile = dir.join("off.pid");

    let out = daemon_cmd()
        .args([
            "--intercept=0",
            "--control-socket=off",
            "--pidfile",
            pidfile.to_str().expect("utf8 pidfile"),
            "--lua-init",
            r#"timer_set("once", function() end, 15, true)"#,
        ])
        .output()
        .expect("run nfqws2 --control-socket=off");

    assert!(out.status.success(), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    assert!(!pidfile.exists());
    let _ = fs::remove_dir_all(&dir);
}
