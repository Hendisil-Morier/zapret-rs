//! Multi-client Unix control socket server lifecycle, accept loop, and telemetry fanout.

/// I/O would-block detection for non-blocking listener accepts.
use std::io::ErrorKind;
/// Half-shutdown used to drop rejected or over-limit client streams cleanly.
use std::net::Shutdown;
/// Raw FD access for applying optional `SO_SNDBUF` limits in tests.
use std::os::fd::AsRawFd;
/// Unix domain stream connections accepted from local peers.
use std::os::unix::net::UnixStream;
/// Filesystem socket path owned by [`ControlServer`].
use std::path::{Path, PathBuf};
/// Atomic lifecycle state and monotonically unique client IDs.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
/// Timeout error classification in the fanout loop.
use std::sync::mpsc;
/// Shared stop flags and client join tracking across accept, fanout, and worker threads.
use std::sync::{Arc, Mutex};
/// Worker threads and clean join shutdown.
use std::thread::{self, JoinHandle};
/// Periodic counter tick interval.
use std::time::{Duration, Instant};

/// Per-client reader/writer session handler.
use crate::control::client_session::serve_client;
/// Wire writer used when rejecting clients above the connection cap.
use crate::control::codec::write_message;
/// Telemetry hub driving subscriber fanout and status snapshots.
use crate::control::hub::TelemetryHub;
/// Peer UID authorization via `SO_PEERCRED` with injectable test predicate.
use crate::control::peer::{PeerUidCheck, current_euid, peer_credentials, same_uid};
/// Control wire protocol response types for broadcast and rejection replies.
use crate::control::protocol::{ControlErrorCode, CountersSnapshot, Response};
/// Safe `0600` socket binding, stale-socket replacement, poll helper, and shutdown unlink.
use crate::control::socket::{
    BoundSocket, ControlServerError, bind_control_socket, poll_listener_readable,
    unlink_if_same_socket,
};
/// Verdict check so `PASS` sampling preferences can apply per subscriber.
use crate::telemetry::PacketVerdict;

/// Default bounded outbound queue depth per connected control client.
const DEFAULT_CLIENT_QUEUE_CAP: usize = 256;
/// Maximum concurrent connected control clients permitted at once.
const MAX_CONTROL_CLIENTS: usize = 16;
/// Poll slice in the accept loop so `shutdown()` wakes cleanly.
const ACCEPT_POLL_MS: i32 = 40;
/// Write timeout for one-shot rejection errors sent to over-limit clients.
const REJECT_WRITE_TIMEOUT: Duration = Duration::from_millis(100);
/// Periodic counter snapshot cadence pushed to subscribed clients when counts change.
const COUNTER_TICK_INTERVAL: Duration = Duration::from_millis(150);

/// Configuration options controlling socket path, UID checks, and per-client queue bounds.
#[derive(Clone)]
pub struct ControlServerConfig {
    /// Filesystem path where the Unix stream listener will be bound.
    pub socket_path: PathBuf,
    /// Daemon version banner returned inside `hello_ok` replies.
    pub daemon_version: String,
    /// Expected UID for peer authorization (`None` uses current `geteuid()`).
    pub expected_uid: Option<u32>,
    /// Injectable peer UID authorization check (defaults to [`same_uid`]).
    pub uid_check: PeerUidCheck,
    /// Bounded outbound message queue depth per client before dropping slow readers.
    pub client_queue_cap: usize,
    /// Optional `SO_SNDBUF` size in bytes applied to accepted client sockets (mostly for tests).
    pub client_sndbuf: Option<i32>,
}

impl ControlServerConfig {
    /// Builds default same-UID configuration binding `socket_path` with production limits.
    pub fn new(socket_path: PathBuf, daemon_version: impl Into<String>) -> Self {
        Self {
            socket_path,
            daemon_version: daemon_version.into(),
            expected_uid: None,
            uid_check: same_uid,
            client_queue_cap: DEFAULT_CLIENT_QUEUE_CAP,
            client_sndbuf: None,
        }
    }
}

/// Running local Unix control socket server stopped automatically on [`Drop`].
pub struct ControlServer {
    /// Bound socket path returned by [`ControlServer::socket_path`].
    socket_path: PathBuf,
    /// Cooperative shutdown flag shared with accept, fanout, and client threads.
    stop: Arc<AtomicBool>,
    /// Accept loop thread handle.
    accept_join: Option<JoinHandle<()>>,
    /// Telemetry fanout thread handle.
    fanout_join: Option<JoinHandle<()>>,
    /// Spawned per-client worker thread handles joined on shutdown.
    client_joins: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl ControlServer {
    /// Binds `config.socket_path`, spawns accept/fanout threads, and begins serving `hub`.
    pub fn start(
        config: ControlServerConfig,
        hub: Arc<TelemetryHub>,
    ) -> Result<Self, ControlServerError> {
        let bound = bind_control_socket(&config.socket_path)?;
        let socket_path = bound.path.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let client_joins: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));

        let fanout_hub = Arc::clone(&hub);
        let fanout_stop = Arc::clone(&stop);
        let fanout_join = thread::spawn(move || run_fanout_loop(fanout_hub, fanout_stop));

        let accept_stop = Arc::clone(&stop);
        let accept_joins = Arc::clone(&client_joins);
        let accept_join = thread::spawn(move || {
            run_accept_loop(bound, config, hub, accept_stop, accept_joins);
        });

        Ok(Self {
            socket_path,
            stop,
            accept_join: Some(accept_join),
            fanout_join: Some(fanout_join),
            client_joins,
        })
    }

    /// Returns the filesystem path of the bound control socket.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Signals shutdown, joins all server threads, and ensures the socket file is removed.
    pub fn shutdown(mut self) {
        self.stop_inner();
    }

    /// Idempotent internal teardown invoked by both [`ControlServer::shutdown`] and [`Drop`].
    fn stop_inner(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.accept_join.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.fanout_join.take() {
            let _ = handle.join();
        }
        if let Ok(mut guard) = self.client_joins.lock() {
            for handle in guard.drain(..) {
                let _ = handle.join();
            }
        }
    }
}

impl Drop for ControlServer {
    /// Stops background threads and unlinks the owned socket if caller did not call `shutdown()`.
    fn drop(&mut self) {
        self.stop_inner();
    }
}

/// Applies an optional `SO_SNDBUF` hint on an accepted socket when configured in tests.
fn apply_optional_sndbuf(stream: &UnixStream, sndbuf: Option<i32>) {
    if let Some(bytes) = sndbuf {
        // SAFETY: `stream` owns a valid socket descriptor and `bytes` points to an initialized `c_int`.
        unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&raw const bytes).cast::<libc::c_void>(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

/// Accepts local Unix peers, enforces `SO_PEERCRED` UID authorization, and cleans up socket on exit.
fn run_accept_loop(
    bound: BoundSocket,
    config: ControlServerConfig,
    hub: Arc<TelemetryHub>,
    stop: Arc<AtomicBool>,
    client_joins: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let expected_uid = config.expected_uid.unwrap_or_else(current_euid);
    let next_id = AtomicU64::new(1);

    while !stop.load(Ordering::Acquire) {
        if !poll_listener_readable(&bound.listener, ACCEPT_POLL_MS) {
            continue;
        }
        loop {
            match bound.listener.accept() {
                Ok((stream, _addr)) => {
                    let allowed = match peer_credentials(&stream) {
                        Ok(creds) => (config.uid_check)(creds.uid, expected_uid),
                        Err(_) => false,
                    };
                    if !allowed {
                        let _ = stream.shutdown(Shutdown::Both);
                        drop(stream);
                        continue;
                    }
                    if let Ok(mut guard) = client_joins.lock() {
                        guard.retain(|h| !h.is_finished());
                        if guard.len() >= MAX_CONTROL_CLIENTS {
                            write_error_and_close(
                                stream,
                                ControlErrorCode::CommandFailed,
                                "too many control clients connected",
                            );
                            continue;
                        }
                        let id = next_id.fetch_add(1, Ordering::Relaxed);
                        apply_optional_sndbuf(&stream, config.client_sndbuf);
                        let cfg = config.clone();
                        let h = Arc::clone(&hub);
                        let st = Arc::clone(&stop);
                        guard.push(thread::spawn(move || serve_client(id, stream, cfg, h, st)));
                    }
                }
                Err(err) if err.kind() == ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    drop(bound.listener);
    unlink_if_same_socket(&bound.path, bound.dev, bound.ino);
}

/// Writes a single error line to a rejected extra client before dropping its stream.
fn write_error_and_close(mut stream: UnixStream, code: ControlErrorCode, message: &str) {
    let _ = stream.set_write_timeout(Some(REJECT_WRITE_TIMEOUT));
    let _ = write_message(&mut stream, &Response::Error { code, message: message.to_owned() });
    let _ = stream.shutdown(Shutdown::Both);
}

/// Drains packet records from `hub` and emits periodic counter snapshots to active subscribers.
fn run_fanout_loop(hub: Arc<TelemetryHub>, stop: Arc<AtomicBool>) {
    let Some(pkt_rx) = hub.take_packet_receiver() else {
        return;
    };
    let mut last_counters = hub.counters().snapshot();
    let mut last_tick = Instant::now();

    while !stop.load(Ordering::Acquire) {
        match pkt_rx.recv_timeout(COUNTER_TICK_INTERVAL) {
            Ok(rec) => {
                let is_pass = rec.verdict == PacketVerdict::Pass;
                hub.broadcast(&Response::Packet(rec), is_pass);
                if hub.has_subscribers() && last_tick.elapsed() >= COUNTER_TICK_INTERVAL {
                    maybe_broadcast_counters(&hub, &mut last_counters, &mut last_tick);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if hub.has_subscribers() {
                    maybe_broadcast_counters(&hub, &mut last_counters, &mut last_tick);
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
}

/// Emits a `Response::Counters` event if counters changed since the previous broadcast.
fn maybe_broadcast_counters(
    hub: &TelemetryHub,
    last: &mut (u64, u64, u64, u64, u64),
    last_tick: &mut Instant,
) {
    let current = hub.counters().snapshot();
    if current != *last {
        *last = current;
        hub.broadcast(&Response::Counters(CountersSnapshot::from(&**hub.counters())), false);
    }
    *last_tick = Instant::now();
}
