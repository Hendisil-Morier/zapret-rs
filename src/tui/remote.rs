//! Control socket auto-detection and background telemetry client for Tab 2 attach mode.

/// Buffered JSON line reading and OS timeout/EOF handling over the client Unix stream.
use std::io::{BufReader, ErrorKind};
/// Bidirectional socket shutdown used to wake the background reader on detach.
use std::net::Shutdown;
/// Candidate socket path inspection and storage.
use std::path::{Path, PathBuf};
/// Cooperative reader loop stop signaling.
use std::sync::atomic::{AtomicBool, Ordering};
/// Channels forwarding streamed packets and control acknowledgments to the UI loop.
use std::sync::mpsc::{self, Receiver};
/// Shared packet counters and serialized outbound command writer.
use std::sync::{Arc, Mutex};
/// Background telemetry reader thread handle.
use std::thread::{self, JoinHandle};
/// Handshake and periodic loop poll timeouts.
use std::time::Duration;

/// Control socket candidate discovery, protocol messages, and bounded codec helpers.
use crate::control::{
    CONTROL_PROTOCOL_VERSION, CodecError, ControlErrorCode, ControlStream, DaemonStatus, LineReader, Request,
    Response, control_socket_candidates, is_live_control_socket, write_message,
};
/// Lock-free packet counters and serializable packet record model.
use crate::telemetry::{PacketCounters, PacketRecord, PacketVerdict};

/// Initial handshake/status timeout before failing attach with a readable error.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Reader poll slice allowing responsive `detach()` without busy waiting.
const READER_POLL_TIMEOUT: Duration = Duration::from_millis(80);
/// Bounded channel capacities matching local Tab 2 worker queues.
const REMOTE_PKT_CHANNEL_CAP: usize = 512;
/// Dedicated bounded channel capacity for non-`PASS` packets (`DESYNC`/`MODIFY`/`REASM`).
const REMOTE_DESYNC_CHANNEL_CAP: usize = 256;
/// Bounded UI notification channel capacity for remote acks, errors, and disconnects.
const REMOTE_EVENT_CHANNEL_CAP: usize = 64;

/// Metadata snapshot describing an attached background `nfqws2` daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDaemonMeta
{
    /// Connected daemon Unix socket path.
    pub socket_path: PathBuf,
    /// Remote daemon binary version banner.
    pub daemon_version: String,
    /// Remote daemon OS process ID.
    pub pid: u32,
    /// Remote daemon NFQUEUE number.
    pub qnum: u16,
    /// Remote daemon desync firewall mark.
    pub fwmark: u32,
    /// Whether the remote daemon is actively intercepting packets.
    pub intercept: bool,
    /// Active profile labels reported by the remote daemon.
    pub profile_names: Vec<String>,
    /// Loaded config file path on the remote daemon, if any.
    pub config_path: Option<String>,
}

/// Asynchronous control/lifecycle notifications streamed from the remote client thread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteEvent
{
    /// Refreshed daemon status snapshot pushed in response to an in-band `status` request.
    StatusUpdated(Box<DaemonStatus>),
    /// Informational acknowledgment or log entry from a remote command (e.g. `reload_lists`).
    InfoLog(String),
    /// Remote command error returned by the daemon.
    Error(String),
    /// Underlying control socket closed cleanly or unexpectedly.
    Disconnected(Option<String>),
}

/// Active background client session streaming telemetry from a running `nfqws2` daemon.
pub struct AttachedDaemon
{
    /// Cooperative shutdown flag stopping the background reader thread.
    stop: Arc<AtomicBool>,
    /// Shared socket handle used to send synchronous control commands (`reload_lists`, `stop`, ...).
    writer: Arc<Mutex<ControlStream>>,
    /// Bounded stream of sampled `PASS` packet records.
    pub(crate) pkt_rx: Receiver<PacketRecord>,
    /// Dedicated bounded stream of `REASM`/`MODIFY`/`DESYNC` packet records.
    pub(crate) desync_rx: Receiver<PacketRecord>,
    /// Non-blocking stream of control acknowledgments, errors, and disconnect notices.
    pub(crate) ev_rx: Receiver<RemoteEvent>,
    /// Joined handle for the background telemetry reader thread.
    join: Option<JoinHandle<()>>,
    /// Set `true` after `Request::Stop` succeeds so expected EOF logs cleanly as a stop.
    pub(crate) stop_requested: bool,
}

impl AttachedDaemon
{
    /// Sends one [`Request`] over the active control socket connection.
    pub fn send_command(&self, req: &Request) -> Result<(), String>
    {
        let mut stream = self.writer.lock().map_err(|_| "control socket writer lock poisoned".to_owned())?;
        write_message(&mut *stream, req).map_err(|err| format!("failed to send control request: {err}"))
    }

    /// Polls one non-`PASS` packet record without blocking.
    pub fn try_recv_desync(&self) -> Option<PacketRecord>
    {
        self.desync_rx.try_recv().ok()
    }

    /// Polls one `PASS` packet record without blocking.
    pub fn try_recv_packet(&self) -> Option<PacketRecord>
    {
        self.pkt_rx.try_recv().ok()
    }

    /// Polls one remote lifecycle or command event without blocking.
    pub fn try_recv_event(&self) -> Option<RemoteEvent>
    {
        self.ev_rx.try_recv().ok()
    }

    /// Signals the reader thread to exit, wakes any blocked socket read, and joins it.
    pub fn detach(&mut self)
    {
        self.stop.store(true, Ordering::Release);
        if let Ok(stream) = self.writer.lock()
        {
            let _ = stream.shutdown(Shutdown::Both);
        }
        if let Some(handle) = self.join.take()
        {
            let _ = handle.join();
        }
    }
}

impl Drop for AttachedDaemon
{
    /// Ensures detaching on drop stops the reader thread cleanly without touching the remote daemon.
    fn drop(&mut self)
    {
        self.detach();
    }
}

/// Probes candidate paths and returns the first live non-symlink control endpoint.
pub fn detect_control_socket(configured: Option<&Path>) -> Option<PathBuf>
{
    control_socket_candidates(configured).into_iter().find(|candidate| is_live_control_socket(candidate))
}

/// Connects to `socket_path`, validates protocol `hello`, queries `status`, subscribes, and starts streaming.
pub fn connect_remote_daemon(
    socket_path: PathBuf,
    counters: Arc<PacketCounters>,
) -> Result<(AttachedDaemon, RemoteDaemonMeta), String>
{
    let stream = ControlStream::connect(&socket_path)
        .map_err(|err| format!("cannot connect to {}: {err}", socket_path.display()))?;
    let _ = stream.set_read_timeout(Some(CONNECT_TIMEOUT));
    let _ = stream.set_write_timeout(Some(CONNECT_TIMEOUT));

    let writer_stream = stream.try_clone().map_err(|err| format!("failed to clone control socket: {err}"))?;
    let mut reader = LineReader::new(BufReader::new(stream));

    let daemon_version = perform_hello(&mut reader)?;
    let status = fetch_initial_status(&mut reader)?;
    status.counters.store_into(&counters);
    send_subscribe(&mut reader)?;

    let _ = reader.get_ref().get_ref().set_read_timeout(Some(READER_POLL_TIMEOUT));

    let meta = RemoteDaemonMeta {
        socket_path,
        daemon_version,
        pid: status.pid,
        qnum: status.qnum,
        fwmark: status.fwmark,
        intercept: status.intercept,
        profile_names: status.profile_names,
        config_path: status.config_path,
    };

    let (pkt_tx, pkt_rx) = mpsc::sync_channel(REMOTE_PKT_CHANNEL_CAP);
    let (desync_tx, desync_rx) = mpsc::sync_channel(REMOTE_DESYNC_CHANNEL_CAP);
    let (ev_tx, ev_rx) = mpsc::sync_channel(REMOTE_EVENT_CHANNEL_CAP);
    let stop = Arc::new(AtomicBool::new(false));
    let reader_stop = Arc::clone(&stop);

    let join = thread::Builder::new()
        .name("tui-nfqws2-remote".to_owned())
        .spawn(move || {
            run_remote_reader(reader, counters, pkt_tx, desync_tx, ev_tx, reader_stop);
        })
        .map_err(|err| format!("failed to spawn remote reader thread: {err}"))?;

    let attached = AttachedDaemon {
        stop,
        writer: Arc::new(Mutex::new(writer_stream)),
        pkt_rx,
        desync_rx,
        ev_rx,
        join: Some(join),
        stop_requested: false,
    };
    Ok((attached, meta))
}

/// Executes the `hello` handshake and translates version skew into a clear user message.
fn perform_hello(reader: &mut LineReader<BufReader<ControlStream>>) -> Result<String, String>
{
    write_message(reader.get_mut().get_mut(), &Request::Hello { version: CONTROL_PROTOCOL_VERSION })
        .map_err(|err| format!("failed sending hello: {err}"))?;
    match reader.read_message::<Response>()
    {
        Ok(Some(Response::HelloOk { version, daemon_version })) =>
        {
            if version != CONTROL_PROTOCOL_VERSION
            {
                return Err(format!(
                    "control protocol version mismatch: client v{CONTROL_PROTOCOL_VERSION}, daemon v{version}"
                ));
            }
            Ok(daemon_version)
        }
        Ok(Some(Response::Error { code: ControlErrorCode::UnsupportedVersion, message })) =>
        {
            Err(format!("control protocol version mismatch: {message}"))
        }
        Ok(Some(Response::Error { message, .. })) => Err(format!("handshake rejected: {message}")),
        Ok(Some(other)) => Err(format!("unexpected handshake reply: {other:?}")),
        Ok(None) => Err("daemon closed socket during handshake (UID mismatch or stopping)".to_owned()),
        Err(err) => Err(format!("handshake read failed: {err}")),
    }
}

/// Sends `status` and reads the daemon's [`DaemonStatus`] reply.
fn fetch_initial_status(reader: &mut LineReader<BufReader<ControlStream>>) -> Result<DaemonStatus, String>
{
    write_message(reader.get_mut().get_mut(), &Request::Status)
        .map_err(|err| format!("failed requesting status: {err}"))?;
    match reader.read_message::<Response>()
    {
        Ok(Some(Response::Status(st))) => Ok(st),
        Ok(Some(Response::Error { message, .. })) => Err(format!("status failed: {message}")),
        Ok(Some(other)) => Err(format!("unexpected status reply: {other:?}")),
        Ok(None) => Err("daemon closed socket while reading status".to_owned()),
        Err(err) => Err(format!("status read failed: {err}")),
    }
}

/// Sends `subscribe` and awaits the initial acknowledgment before starting the reader thread.
fn send_subscribe(reader: &mut LineReader<BufReader<ControlStream>>) -> Result<(), String>
{
    write_message(reader.get_mut().get_mut(), &Request::Subscribe { pass_sample_rate: None })
        .map_err(|err| format!("failed subscribing to telemetry: {err}"))?;
    match reader.read_message::<Response>()
    {
        Ok(Some(Response::Ack { op, .. })) if op == "subscribe" => Ok(()),
        Ok(Some(Response::Error { message, .. })) => Err(format!("subscribe failed: {message}")),
        Ok(Some(other)) => Err(format!("unexpected subscribe reply: {other:?}")),
        Ok(None) => Err("daemon closed socket during subscribe".to_owned()),
        Err(err) => Err(format!("subscribe read failed: {err}")),
    }
}

/// Continuously decodes streamed server frames into shared counters and inspector queues.
fn run_remote_reader(
    mut reader: LineReader<BufReader<ControlStream>>,
    counters: Arc<PacketCounters>,
    pkt_tx: mpsc::SyncSender<PacketRecord>,
    desync_tx: mpsc::SyncSender<PacketRecord>,
    ev_tx: mpsc::SyncSender<RemoteEvent>,
    stop: Arc<AtomicBool>,
)
{
    let mut reason: Option<String> = None;
    while !stop.load(Ordering::Acquire)
    {
        match reader.read_message::<Response>()
        {
            Ok(Some(resp)) => match resp
            {
                Response::Counters(snap) => snap.store_into(&counters),
                Response::Packet(rec) =>
                {
                    if rec.verdict != PacketVerdict::Pass
                    {
                        let _ = desync_tx.try_send(rec);
                    }
                    else
                    {
                        let _ = pkt_tx.try_send(rec);
                    }
                }
                Response::Status(st) =>
                {
                    st.counters.store_into(&counters);
                    let _ = ev_tx.try_send(RemoteEvent::StatusUpdated(Box::new(st)));
                }
                Response::Ack { op, message } =>
                {
                    let detail = message.unwrap_or_else(|| "ok".to_owned());
                    let _ = ev_tx.try_send(RemoteEvent::InfoLog(format!("[{op}] {detail}")));
                }
                Response::Error { message, .. } =>
                {
                    let _ = ev_tx.try_send(RemoteEvent::Error(message));
                }
                Response::HelloOk { .. } =>
                {}
            },
            Ok(None) =>
            {
                reason = Some("remote daemon closed control socket".to_owned());
                break;
            }
            Err(CodecError::Io(err)) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(err) =>
            {
                reason = Some(err.to_string());
                break;
            }
        }
    }
    if !stop.load(Ordering::Acquire)
    {
        let _ = ev_tx.try_send(RemoteEvent::Disconnected(reason));
    }
}
