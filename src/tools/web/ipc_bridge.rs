//! Background `ControlStream` subscriber bridging daemon status, counters, and packets to SSE.

/// Ring buffer retaining recent sampled packets for immediate display on page load.
use std::collections::VecDeque;
/// Buffered JSON line reading over `ControlStream` plus timeout error classification.
use std::io::{BufReader, ErrorKind};
/// Bidirectional socket shutdown used to wake the background reader on shutdown.
use std::net::Shutdown;
/// Optional explicit control socket override configured via CLI.
use std::path::{Path, PathBuf};
/// Cooperative shutdown flag observed by reconnect, reader, and SSE loops.
use std::sync::atomic::{AtomicBool, Ordering};
/// Bounded per-client SSE channels and synchronous command reply channels.
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
/// Shared snapshot state, active socket writer, and SSE fanout list.
use std::sync::{Arc, Mutex};
/// Background connector/reader thread handle joined cleanly on drop.
use std::thread::{self, JoinHandle};
/// Poll slices and synchronous control command reply timeouts.
use std::time::Duration;

/// Control socket auto-detection, protocol types, and framed JSON helpers.
use crate::control::{
    CONTROL_PROTOCOL_VERSION, CodecError, ControlStream, DaemonStatus, LineReader, Request, Response,
    control_socket_candidates, is_live_control_socket, write_message,
};
/// Sampled telemetry packet records forwarded to the Monitor feed.
use crate::telemetry::PacketRecord;

/// Maximum concurrent SSE subscribers accepted before rejecting with `503 Service Unavailable`.
pub const MAX_SSE_CLIENTS: usize = 8;
/// Maximum recent sampled packets cached in [`WebStatusSnapshot`] for initial page load.
const MAX_RECENT_PACKETS: usize = 40;
/// Bounded per-SSE-client queue capacity preventing slow mobile tabs from blocking IPC reads.
const SSE_CLIENT_QUEUE_CAP: usize = 64;
/// Initial control socket handshake timeout.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Reader poll slice keeping `shutdown()` responsive.
const READER_POLL_TIMEOUT: Duration = Duration::from_millis(120);
/// Idle pause between daemon socket discovery probes when disconnected.
const RECONNECT_SLEEP: Duration = Duration::from_millis(250);
/// Synchronous wait timeout for daemon `reload_lists`, `reload_config`, or `stop` ACKs.
const COMMAND_ACK_TIMEOUT: Duration = Duration::from_secs(3);

/// Serialized status snapshot returned by `GET /api/status` and `event: status`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct WebStatusSnapshot
{
    /// `true` when attached to a live `nfqws2` control endpoint.
    pub connected: bool,
    /// Socket/rendezvous path currently attached (or last attempted).
    pub socket_path: Option<String>,
    /// Last connection or protocol error message, if any.
    pub error: Option<String>,
    /// Latest daemon status and live counters when connected.
    pub daemon: Option<DaemonStatus>,
    /// Recent sampled packets capped at [`MAX_RECENT_PACKETS`].
    pub recent_packets: Vec<PacketRecord>,
}

impl Default for WebStatusSnapshot
{
    /// Returns a disconnected empty snapshot.
    fn default() -> Self
    {
        Self { connected: false, socket_path: None, error: None, daemon: None, recent_packets: Vec::new() }
    }
}

/// Shared mutable bridge state protected separately from synchronous command serialization.
#[derive(Default)]
struct BridgeShared
{
    /// Latest connection state, daemon status, and recent packet ring.
    snapshot: WebStatusSnapshot,
    /// Rolling packet buffer mirrored into `snapshot.recent_packets` on demand.
    packet_ring: VecDeque<PacketRecord>,
    /// Active outbound control stream writer when connected.
    writer: Option<Arc<Mutex<ControlStream>>>,
    /// Pending synchronous command reply channel satisfied by the background reader thread.
    pending_cmd: Option<SyncSender<Result<Option<String>, String>>>,
    /// Connected SSE subscriber queues receiving preformatted `event: ...\ndata: ...\n\n` frames.
    sse_clients: Vec<SyncSender<String>>,
}

impl BridgeShared
{
    /// Appends one packet into the bounded recent-packet ring.
    fn push_packet(&mut self, rec: PacketRecord)
    {
        if self
            .packet_ring
            .len()
            >= MAX_RECENT_PACKETS
        {
            self.packet_ring
                .pop_front();
        }
        self.packet_ring
            .push_back(rec);
        self.snapshot
            .recent_packets = self
            .packet_ring
            .iter()
            .cloned()
            .collect();
    }

    /// Formats one SSE frame and sends it non-blockingly to live subscribers, pruning dead ones.
    fn broadcast(&mut self, event: &str, json_body: &str)
    {
        let frame = format!("event: {event}\ndata: {json_body}\n\n");
        self.sse_clients
            .retain(|tx| match tx.try_send(frame.clone())
            {
                Ok(()) | Err(TrySendError::Full(_)) => true,
                Err(TrySendError::Disconnected(_)) => false,
            });
    }

    /// Emits a full serialized `status` event reflecting the current snapshot.
    fn broadcast_status(&mut self)
    {
        if let Ok(json) = serde_json::to_string(&self.snapshot)
        {
            self.broadcast("status", &json);
        }
    }
}

/// Background IPC bridge maintaining a live control-socket subscription and SSE fanout hub.
pub struct WebIpcBridge
{
    /// Shared status snapshot, SSE fanout channels, and active writer.
    shared: Arc<Mutex<BridgeShared>>,
    /// Serializes control commands requiring an in-band `Ack` / `Error` reply.
    cmd_lock: Mutex<()>,
    /// Cooperative shutdown flag observed by the background connector/reader loop.
    stop: Arc<AtomicBool>,
    /// Background thread handle joined on [`Self::shutdown`] or [`Drop`], even behind `Arc`.
    join: Mutex<Option<JoinHandle<()>>>,
}

impl WebIpcBridge
{
    /// Spawns the background control socket auto-connect and SSE telemetry relay thread.
    pub fn spawn(control_socket: Option<PathBuf>) -> Self
    {
        let shared = Arc::new(Mutex::new(BridgeShared::default()));
        let shared_bg = Arc::clone(&shared);
        let stop = Arc::new(AtomicBool::new(false));
        let stop_bg = Arc::clone(&stop);

        let join = thread::Builder::new()
            .name("zapret-web-ipc".to_owned())
            .spawn(move || run_ipc_loop(control_socket, &shared_bg, &stop_bg))
            .ok();

        Self { shared, cmd_lock: Mutex::new(()), stop, join: Mutex::new(join) }
    }

    /// Returns a cloned snapshot of daemon connection state, counters, and recent packets.
    pub fn snapshot(&self) -> WebStatusSnapshot
    {
        self.shared
            .lock()
            .map(|g| {
                g.snapshot
                    .clone()
            })
            .unwrap_or_default()
    }

    /// Broadcasts one custom SSE `event` + JSON payload across all active subscribers.
    pub fn emit_event(&self, event: &str, value: &impl serde::Serialize)
    {
        if let Ok(json) = serde_json::to_string(value)
            && let Ok(mut guard) = self
                .shared
                .lock()
        {
            guard.broadcast(event, &json);
        }
    }

    /// Registers one SSE client queue if under [`MAX_SSE_CLIENTS`], returning `None` when full.
    pub fn subscribe_sse(&self) -> Option<(WebStatusSnapshot, Receiver<String>)>
    {
        let mut guard = self
            .shared
            .lock()
            .ok()?;
        guard
            .sse_clients
            .retain(|tx| !matches!(tx.try_send(String::new()), Err(TrySendError::Disconnected(_))));
        if guard
            .sse_clients
            .len()
            >= MAX_SSE_CLIENTS
        {
            return None;
        }
        let (tx, rx) = mpsc::sync_channel(SSE_CLIENT_QUEUE_CAP);
        guard
            .sse_clients
            .push(tx);
        Some((
            guard
                .snapshot
                .clone(),
            rx,
        ))
    }

    /// Sends one control [`Request`] and waits up to [`COMMAND_ACK_TIMEOUT`] for `Ack` or `Error`.
    pub fn send_command(&self, req: &Request) -> Result<Option<String>, String>
    {
        let _cmd_guard = self
            .cmd_lock
            .lock()
            .map_err(|_| "command lock poisoned".to_owned())?;
        let (writer, ack_rx) = {
            let mut guard = self
                .shared
                .lock()
                .map_err(|_| "IPC state lock poisoned".to_owned())?;
            let Some(writer) = guard
                .writer
                .as_ref()
                .map(Arc::clone)
            else
            {
                return Err("daemon control socket is not connected".to_owned());
            };
            let (tx, rx) = mpsc::sync_channel(1);
            guard.pending_cmd = Some(tx);
            (writer, rx)
        };

        let send_res = {
            let mut stream = writer
                .lock()
                .map_err(|_| "control writer poisoned".to_owned())?;
            write_message(&mut *stream, req).map_err(|err| format!("control send failed: {err}"))
        };
        if let Err(err) = send_res
        {
            if let Ok(mut guard) = self
                .shared
                .lock()
            {
                guard.pending_cmd = None;
            }
            return Err(err);
        }

        match ack_rx.recv_timeout(COMMAND_ACK_TIMEOUT)
        {
            Ok(reply) => reply,
            Err(_) =>
            {
                if let Ok(mut guard) = self
                    .shared
                    .lock()
                {
                    guard.pending_cmd = None;
                }
                Err("timed out waiting for daemon control acknowledgment".to_owned())
            }
        }
    }

    /// Requests immediate stop and joins the background IPC thread even when shared via `Arc`.
    pub fn shutdown(&self)
    {
        self.stop
            .store(true, Ordering::Release);
        if let Ok(mut guard) = self
            .shared
            .lock()
        {
            if let Some(writer) = guard
                .writer
                .take()
                && let Ok(stream) = writer.lock()
            {
                let _ = stream.shutdown(Shutdown::Both);
            }
            guard
                .sse_clients
                .clear();
        }
        if let Ok(mut handle_guard) = self
            .join
            .lock()
            && let Some(handle) = handle_guard.take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for WebIpcBridge
{
    /// Ensures background IPC reader stops and joins cleanly when the server shuts down.
    fn drop(&mut self)
    {
        self.shutdown();
    }
}

/// Connects to `sock`, completes `hello`/`status`/`subscribe`, and relays updates until EOF or `stop`.
fn connect_and_stream(sock: &Path, shared: &Arc<Mutex<BridgeShared>>, stop: &AtomicBool)
-> Result<(), String>
{
    let mut stream = ControlStream::connect(sock).map_err(|err| format!("connect failed: {err}"))?;
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));

    write_message(&mut stream, &Request::Hello { version: CONTROL_PROTOCOL_VERSION })
        .map_err(|err| format!("hello send failed: {err}"))?;
    let reader_raw = stream
        .try_clone()
        .map_err(|err| format!("clone stream failed: {err}"))?;
    let mut reader = LineReader::new(BufReader::new(reader_raw));

    match reader
        .read_message::<Response>()
        .map_err(|err| format!("hello read failed: {err}"))?
    {
        Some(Response::HelloOk { version, .. }) if version == CONTROL_PROTOCOL_VERSION =>
        {}
        Some(Response::Error { message, .. }) => return Err(message),
        other => return Err(format!("unexpected hello reply: {other:?}")),
    }

    write_message(&mut stream, &Request::Status).map_err(|err| format!("status send failed: {err}"))?;
    let initial_status = match reader
        .read_message::<Response>()
        .map_err(|err| format!("status read failed: {err}"))?
    {
        Some(Response::Status(s)) => s,
        Some(Response::Error { message, .. }) => return Err(message),
        other => return Err(format!("unexpected status reply: {other:?}")),
    };

    write_message(&mut stream, &Request::Subscribe { pass_sample_rate: Some(20) })
        .map_err(|err| format!("subscribe failed: {err}"))?;
    let _ = reader
        .get_ref()
        .get_ref()
        .set_read_timeout(Some(READER_POLL_TIMEOUT));

    let writer = Arc::new(Mutex::new(stream));
    if let Ok(mut guard) = shared.lock()
    {
        guard.writer = Some(Arc::clone(&writer));
        guard
            .snapshot
            .connected = true;
        guard
            .snapshot
            .socket_path = Some(
            sock.display()
                .to_string(),
        );
        guard
            .snapshot
            .error = None;
        guard
            .snapshot
            .daemon = Some(initial_status);
        guard.broadcast_status();
    }

    while !stop.load(Ordering::Acquire)
    {
        match reader.read_message::<Response>()
        {
            Ok(Some(msg)) => handle_daemon_message(msg, shared, &writer),
            Ok(None) => break,
            Err(CodecError::Io(err)) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
            }
            Err(err) => return Err(err.to_string()),
        }
    }
    Ok(())
}

/// Applies one decoded daemon [`Response`] to cached state, SSE subscribers, and pending ACKs.
fn handle_daemon_message(msg: Response, shared: &Arc<Mutex<BridgeShared>>, writer: &Arc<Mutex<ControlStream>>)
{
    let Ok(mut guard) = shared.lock()
    else
    {
        return;
    };
    match msg
    {
        Response::Status(status) =>
        {
            guard
                .snapshot
                .daemon = Some(status);
            guard.broadcast_status();
        }
        Response::Counters(counters) =>
        {
            if let Some(d) = &mut guard
                .snapshot
                .daemon
            {
                d.counters = counters;
            }
            if let Ok(json) = serde_json::to_string(&counters)
            {
                guard.broadcast("counters", &json);
            }
        }
        Response::Packet(rec) =>
        {
            if let Ok(json) = serde_json::to_string(&rec)
            {
                guard.broadcast("packet", &json);
            }
            guard.push_packet(rec);
        }
        Response::Ack { op, message } =>
        {
            if let Some(tx) = guard
                .pending_cmd
                .take()
            {
                let _ = tx.send(Ok(message.clone()));
            }
            if op == "reload_lists" || op == "reload_config"
            {
                let writer_clone = Arc::clone(writer);
                drop(guard);
                if let Ok(mut w) = writer_clone.lock()
                {
                    let _ = write_message(&mut *w, &Request::Status);
                }
            }
        }
        Response::Error { message, .. } =>
        {
            if let Some(tx) = guard
                .pending_cmd
                .take()
            {
                let _ = tx.send(Err(message.clone()));
            }
            else
            {
                guard
                    .snapshot
                    .error = Some(message);
                guard.broadcast_status();
            }
        }
        Response::HelloOk { .. } =>
        {}
    }
}

/// Marks bridge disconnected when socket drops or closes and notifies SSE clients if state changed.
fn mark_disconnected(shared: &Arc<Mutex<BridgeShared>>, err_msg: Option<String>)
{
    let Ok(mut guard) = shared.lock()
    else
    {
        return;
    };
    let changed = guard
        .snapshot
        .connected
        || guard
            .snapshot
            .error
            != err_msg;
    guard.writer = None;
    if let Some(tx) = guard
        .pending_cmd
        .take()
    {
        let _ = tx.send(Err("daemon connection closed".to_owned()));
    }
    guard
        .snapshot
        .connected = false;
    guard
        .snapshot
        .daemon = None;
    guard
        .snapshot
        .error = err_msg;
    if changed
    {
        guard.broadcast_status();
    }
}

/// Continuously locates live control sockets and streams telemetry until `stop` becomes `true`.
fn run_ipc_loop(configured: Option<PathBuf>, shared: &Arc<Mutex<BridgeShared>>, stop: &AtomicBool)
{
    while !stop.load(Ordering::Acquire)
    {
        let found = control_socket_candidates(configured.as_deref())
            .into_iter()
            .find(|cand| is_live_control_socket(cand));
        match found
        {
            Some(sock) =>
            {
                let err_msg = connect_and_stream(&sock, shared, stop).err();
                mark_disconnected(shared, err_msg);
            }
            None =>
            {
                mark_disconnected(shared, None);
                thread::sleep(RECONNECT_SLEEP);
            }
        }
    }
}
