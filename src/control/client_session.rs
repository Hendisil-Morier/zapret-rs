//! Per-client control socket reader, writer, handshake gate, and command dispatcher.

/// Authenticated peer control stream.
use crate::control::transport::ControlStream;
/// Buffered JSON line reading and OS timeout/would-block classification.
use std::io::{BufReader, ErrorKind};
/// Bidirectional stream shutdown used to cleanly disconnect stalled or closed peers.
use std::net::Shutdown;
/// Shared telemetry hub reference and disconnect callback wrapper.
use std::sync::Arc;
/// Cooperative liveness flag tracking client disconnects and server shutdown.
use std::sync::atomic::{AtomicBool, Ordering};
/// Bounded outbound event queue and one-shot command reply channels.
use std::sync::mpsc::{self, Receiver, SyncSender};
/// Dedicated per-client socket writer thread.
use std::thread;
/// Client socket read/write timeouts and packet-loop command reply wait budget.
use std::time::Duration;

/// Bounded JSON frame reader/writer and typed codec error mapping.
use crate::control::codec::{CodecError, LineReader, write_message};
/// Telemetry hub, subscriber registration, and command forwarding.
use crate::control::hub::{ControlCommand, SubscriberSink, TelemetryHub};
/// Wire protocol constants, requests, responses, and version validation.
use crate::control::protocol::{
    CONTROL_PROTOCOL_VERSION, ControlErrorCode, CountersSnapshot, Request, Response,
    validate_protocol_version,
};
/// Shared server configuration needed during handshake replies and queue sizing.
use crate::control::server::ControlServerConfig;

/// Read timeout so client reader threads observe `stop` without blocking indefinitely.
const CLIENT_READ_TIMEOUT: Duration = Duration::from_millis(40);
/// Write timeout preventing a stalled peer from wedging its own writer thread.
const CLIENT_WRITE_TIMEOUT: Duration = Duration::from_millis(150);
/// Maximum time a synchronous control command waits for the packet loop to reply.
const COMMAND_REPLY_TIMEOUT: Duration = Duration::from_secs(2);

/// Runs dedicated reader + writer tasks for one UID-authenticated control socket client.
pub(crate) fn serve_client(
    id: u64,
    stream: ControlStream,
    config: ControlServerConfig,
    hub: Arc<TelemetryHub>,
    server_stop: Arc<AtomicBool>,
)
{
    let Ok(writer_stream) = stream.try_clone()
    else
    {
        return;
    };
    let _ = stream.set_read_timeout(Some(CLIENT_READ_TIMEOUT));
    let _ = writer_stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));

    let client_alive = Arc::new(AtomicBool::new(true));
    let (out_tx, out_rx) = mpsc::sync_channel::<Response>(config.client_queue_cap.max(1));

    let writer_alive = Arc::clone(&client_alive);
    let writer_join = thread::spawn(move || {
        run_client_writer(writer_stream, out_rx, writer_alive);
    });

    let mut reader = LineReader::new(BufReader::new(stream));
    let mut handshaked = false;

    while client_alive.load(Ordering::Acquire) && !server_stop.load(Ordering::Acquire)
    {
        match reader.read_message::<Request>()
        {
            Ok(Some(req)) =>
            {
                let keep_open = handle_client_request(
                    id,
                    req,
                    &mut handshaked,
                    &config,
                    &hub,
                    &out_tx,
                    &client_alive,
                    reader.get_ref().get_ref(),
                );
                if !keep_open
                {
                    break;
                }
            }
            Ok(None) => break,
            Err(CodecError::Io(err)) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                continue;
            }
            Err(CodecError::LineTooLong { .. } | CodecError::Json(_)) =>
            {
                let _ = out_tx.try_send(Response::Error {
                    code: ControlErrorCode::BadRequest,
                    message: "malformed or oversized control request".to_owned(),
                });
                break;
            }
            Err(_) => break,
        }
    }

    hub.remove_subscriber(id);
    drop(out_tx);
    let _ = writer_join.join();
    let _ = reader.get_ref().get_ref().shutdown(Shutdown::Both);
}

/// Dispatches one decoded client [`Request`], returning `false` if the connection should close.
#[allow(clippy::too_many_arguments)]
fn handle_client_request(
    id: u64,
    req: Request,
    handshaked: &mut bool,
    config: &ControlServerConfig,
    hub: &Arc<TelemetryHub>,
    out_tx: &SyncSender<Response>,
    client_alive: &Arc<AtomicBool>,
    stream_ref: &ControlStream,
) -> bool
{
    if !*handshaked
    {
        return handle_pre_handshake(req, handshaked, config, out_tx);
    }

    match req
    {
        Request::Hello { version } => handle_hello(version, &config.daemon_version, out_tx),
        Request::Status => send_or_close(out_tx, Response::Status(hub.status_snapshot())),
        Request::Subscribe { pass_sample_rate } =>
        {
            register_subscriber(id, pass_sample_rate, hub, out_tx, client_alive, stream_ref)
        }
        Request::Unsubscribe =>
        {
            hub.remove_subscriber(id);
            send_or_close(out_tx, Response::Ack { op: "unsubscribe".to_owned(), message: None })
        }
        Request::ReloadLists =>
        {
            dispatch_loop_command("reload_lists", hub, out_tx, |reply| ControlCommand::ReloadLists { reply })
        }
        Request::ReloadConfig { toml } => dispatch_loop_command("reload_config", hub, out_tx, |reply| {
            ControlCommand::ReloadConfig { toml, reply }
        }),
        Request::Stop => dispatch_loop_command("stop", hub, out_tx, |reply| ControlCommand::Stop { reply }),
    }
}

/// Rejects non-`hello` commands prior to handshake and validates protocol version on `hello`.
fn handle_pre_handshake(
    req: Request,
    handshaked: &mut bool,
    config: &ControlServerConfig,
    out_tx: &SyncSender<Response>,
) -> bool
{
    match req
    {
        Request::Hello { version } => match validate_protocol_version(version)
        {
            Ok(()) =>
            {
                *handshaked = true;
                send_or_close(
                    out_tx,
                    Response::HelloOk {
                        version: CONTROL_PROTOCOL_VERSION,
                        daemon_version: config.daemon_version.clone(),
                    },
                )
            }
            Err(err) =>
            {
                let _ = send_or_close(
                    out_tx,
                    Response::Error { code: ControlErrorCode::UnsupportedVersion, message: err.to_string() },
                );
                true
            }
        },
        _ => send_or_close(
            out_tx,
            Response::Error {
                code: ControlErrorCode::HandshakeRequired,
                message: "send hello first".to_owned(),
            },
        ),
    }
}

/// Responds to redundant post-handshake `hello` requests consistently.
fn handle_hello(version: u32, daemon_version: &str, out_tx: &SyncSender<Response>) -> bool
{
    match validate_protocol_version(version)
    {
        Ok(()) => send_or_close(
            out_tx,
            Response::HelloOk {
                version: CONTROL_PROTOCOL_VERSION,
                daemon_version: daemon_version.to_owned(),
            },
        ),
        Err(err) => send_or_close(
            out_tx,
            Response::Error { code: ControlErrorCode::UnsupportedVersion, message: err.to_string() },
        ),
    }
}

/// Registers client `id` for live telemetry and immediately emits current counters.
fn register_subscriber(
    id: u64,
    pass_sample_rate: Option<u64>,
    hub: &TelemetryHub,
    out_tx: &SyncSender<Response>,
    client_alive: &Arc<AtomicBool>,
    stream_ref: &ControlStream,
) -> bool
{
    let shutdown_ref = stream_ref.try_clone().ok();
    let alive_flag = Arc::clone(client_alive);
    let disconnect: Arc<dyn Fn() + Send + Sync> = Arc::new(move || {
        alive_flag.store(false, Ordering::Release);
        if let Some(ref sock) = shutdown_ref
        {
            let _ = sock.shutdown(Shutdown::Both);
        }
    });
    hub.add_subscriber(SubscriberSink { id, tx: out_tx.clone(), pass_sample_rate, disconnect });
    if !send_or_close(out_tx, Response::Ack { op: "subscribe".to_owned(), message: None })
    {
        return false;
    }
    send_or_close(out_tx, Response::Counters(CountersSnapshot::from(&**hub.counters())))
}

/// Forwards a command to the packet loop, awaits its reply within `COMMAND_REPLY_TIMEOUT`, and replies.
fn dispatch_loop_command<F>(
    op_name: &str,
    hub: &TelemetryHub,
    out_tx: &SyncSender<Response>,
    make_cmd: F,
) -> bool
where
    F: FnOnce(SyncSender<Result<String, String>>) -> ControlCommand,
{
    let (reply_tx, reply_rx) = mpsc::sync_channel(1);
    if let Err(err) = hub.try_send_command(make_cmd(reply_tx))
    {
        return send_or_close(out_tx, Response::Error { code: ControlErrorCode::ShuttingDown, message: err });
    }
    match reply_rx.recv_timeout(COMMAND_REPLY_TIMEOUT)
    {
        Ok(Ok(msg)) => send_or_close(out_tx, Response::Ack { op: op_name.to_owned(), message: Some(msg) }),
        Ok(Err(err)) =>
        {
            send_or_close(out_tx, Response::Error { code: ControlErrorCode::CommandFailed, message: err })
        }
        Err(_) => send_or_close(
            out_tx,
            Response::Error {
                code: ControlErrorCode::CommandFailed,
                message: format!("timed out waiting for daemon to execute {op_name}"),
            },
        ),
    }
}

/// Non-blocking send to client's writer queue; returns `false` if client stalled or disconnected.
fn send_or_close(out_tx: &SyncSender<Response>, resp: Response) -> bool
{
    out_tx.try_send(resp).is_ok()
}

/// Drains `out_rx` into `stream` until the session drops `out_tx` or `alive` clears.
fn run_client_writer(mut stream: ControlStream, out_rx: Receiver<Response>, alive: Arc<AtomicBool>)
{
    while alive.load(Ordering::Acquire)
    {
        match out_rx.recv_timeout(CLIENT_READ_TIMEOUT)
        {
            Ok(resp) =>
            {
                if write_message(&mut stream, &resp).is_err()
                {
                    break;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    alive.store(false, Ordering::Release);
    let _ = stream.shutdown(Shutdown::Both);
}
