//! Optional non-blocking background TCP/TLS/HTTP active confirmation for autohostlist candidates.

/// Thread-safe deduplicated in-flight host set shared with the worker thread.
use std::collections::HashSet;
/// Buffered read/write I/O traits and error classifications for active probes.
use std::io::{ErrorKind, Read, Write};
/// Standard library TCP socket primitives for short-timeout DPI confirmation probes.
use std::net::{IpAddr, SocketAddr, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
/// Single-thread reference counting for accessing profile autolist handles on the packet thread.
use std::rc::Rc;
/// Bounded worker queue and lock-free result drain channel.
use std::sync::{
    Arc, Mutex,
    mpsc::{self, Receiver, SyncSender},
};
/// Background worker thread handle cleanly joined on drop.
use std::thread::{self, JoinHandle};
/// Connect and read/write bounds preventing hung sockets.
use std::time::Duration;

/// Default TLS ClientHello template re-targeted to each candidate SNI via `tls_mod`.
use crate::config::{DesyncProfile, FAKE_TLS_CLIENTHELLO_DEFAULT};
/// Desync profile runtime state containing fail pool and writable autolist handles.
use crate::desync::profile_state::ProfileRuntime;
/// Shared autohostlist promotion, debug-logging, and failure reset helpers.
use crate::lists::{AutoHostlistAction, AutoHostlistRecordCtx, promote_autohost, reset_autohost_failure};
/// L7 protocol tags, TLS/HTTP DPI-block detectors, and TLS ClientHello SNI mutator.
use crate::protocol::{
    FAKE_TLS_MOD_RND, FAKE_TLS_MOD_SNI, FakeTlsMod, L7Proto, http_reply_looks_like_dpi_block, is_http_reply,
    is_tls_fatal_alert, is_tls_server_hello_partial, tls_mod,
};
/// Boottime monotonic seconds clock recorded alongside promoted autohostlist entries.
use crate::timer::boottime_secs;

/// Maximum queued background confirmation requests before new probes are skipped.
const MAX_CONFIRM_QUEUE: usize = 32;
/// Connect and read timeout bounding each background confirmation socket.
const DEFAULT_CONFIRM_TIMEOUT: Duration = Duration::from_secs(2);
/// Maximum server reply bytes read when inspecting a plain confirmation handshake.
const MAX_PROBE_READ_BYTES: usize = 2048;

/// Queued verification task emitted when a host records a passive failure under `confirm_block`.
#[derive(Debug, Clone)]
pub(crate) struct AutoConfirmRequest
{
    /// Zero-based profile slot at the time the passive failure occurred.
    pub(crate) profile_slot: usize,
    /// Stable 1-based `DesyncProfile::index` guarding against stale results after hot-reload.
    pub(crate) profile_index: u32,
    /// Normalized candidate hostname or IP literal.
    pub(crate) host: String,
    /// Whether `host` is an IP literal (`no_subdomains`).
    pub(crate) host_is_ip: bool,
    /// Remote server IP observed on the failing flow.
    pub(crate) dst_ip: IpAddr,
    /// Remote destination port observed on the failing flow.
    pub(crate) dst_port: u16,
    /// L7 protocol (`Tls` or `Http`) selecting ClientHello vs HTTP `HEAD` probe payload.
    pub(crate) l7proto: L7Proto,
}

/// Asynchronous probe verdict returned from the background worker to the packet thread.
#[derive(Debug, Clone)]
pub(crate) struct AutoConfirmResult
{
    /// Zero-based profile slot originally targeted.
    profile_slot: usize,
    /// Stable 1-based `DesyncProfile::index` matching the target profile.
    profile_index: u32,
    /// Candidate hostname or IP literal.
    host: String,
    /// Whether `host` is an IP literal (`no_subdomains`).
    host_is_ip: bool,
    /// Flow L7 protocol recorded for debug logs.
    l7proto: L7Proto,
    /// `true` when DPI interference was observed, `false` when direct reachability succeeded.
    confirmed_blocked: bool,
}

/// Applies Linux `SO_MARK` onto the connected probe socket so NFQUEUE skips its payload traffic.
#[cfg(target_os = "linux")]
fn apply_probe_fwmark(stream: &TcpStream, fwmark: u32)
{
    if fwmark == 0
    {
        return;
    }
    let mark = fwmark as libc::c_int;
    let fd = stream.as_raw_fd();
    // SAFETY: `fd` stays open for the lifetime of `stream` and `mark` points to valid stack storage.
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            (&raw const mark).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
}

/// Builds an un-desynced TLS ClientHello (retargeted SNI) or HTTP `HEAD` probe for active verification.
fn build_confirm_probe_payload(host: &str, l7proto: L7Proto) -> Option<Vec<u8>>
{
    match l7proto
    {
        L7Proto::Tls =>
        {
            let modifier =
                FakeTlsMod { sni: host.to_owned(), mod_flags: FAKE_TLS_MOD_RND | FAKE_TLS_MOD_SNI };
            tls_mod(&modifier, None, &FAKE_TLS_CLIENTHELLO_DEFAULT)
        }
        L7Proto::Http => Some(
            format!("HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: curl/8.0\r\nConnection: close\r\n\r\n")
                .into_bytes(),
        ),
        _ => None,
    }
}

/// Probes `(dst_ip, dst_port)` with a plain ClientHello/HTTP `HEAD` to distinguish DPI interference from healthy origins.
///
/// Returns `Some(true)` on confirmed DPI block (`RST`, TLS Fatal Alert, DPI block page, early `FIN`, or handshake-then-stall),
/// `Some(false)` on healthy server handshake/response, or `None` when TCP connect fails or L7 is unsupported.
pub fn probe_endpoint_for_dpi(
    dst_ip: IpAddr,
    dst_port: u16,
    host: &str,
    host_is_ip: bool,
    l7proto: L7Proto,
    desync_fwmark: u32,
    timeout: Duration,
) -> Option<bool>
{
    if dst_port == 0
    {
        return None;
    }
    let payload = build_confirm_probe_payload(host, l7proto)?;
    let addr = SocketAddr::new(dst_ip, dst_port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    #[cfg(target_os = "linux")]
    apply_probe_fwmark(&stream, desync_fwmark);
    #[cfg(not(target_os = "linux"))]
    let _ = desync_fwmark;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    if let Err(err) = stream.write_all(&payload)
    {
        return matches!(
            err.kind(),
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe
        )
        .then_some(true);
    }

    let mut buf = [0u8; MAX_PROBE_READ_BYTES];
    match stream.read(&mut buf)
    {
        Ok(0) => Some(true),
        Ok(n) =>
        {
            let reply = &buf[..n];
            match l7proto
            {
                L7Proto::Tls if is_tls_fatal_alert(reply) => Some(true),
                L7Proto::Tls if is_tls_server_hello_partial(reply) => Some(false),
                L7Proto::Http if http_reply_looks_like_dpi_block(reply, host, host_is_ip) => Some(true),
                L7Proto::Http if is_http_reply(reply) => Some(false),
                _ => None,
            }
        }
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::UnexpectedEof
                    | ErrorKind::WouldBlock
                    | ErrorKind::TimedOut
            ) =>
        {
            Some(true)
        }
        Err(_) => None,
    }
}

/// Non-blocking single background worker verifying candidate autohostlist failures out-of-band.
pub(crate) struct AutoConfirmWorker
{
    /// Bounded queue submitting probe requests from the packet thread (`None` after shutdown).
    tx: Option<SyncSender<AutoConfirmRequest>>,
    /// Lock-free result receiver drained between packets.
    rx: Receiver<AutoConfirmResult>,
    /// Deduplicated in-flight lowercase hostnames preventing burst probe storms.
    in_flight: Arc<Mutex<HashSet<String>>>,
    /// Background worker thread joined gracefully when dropped.
    join: Option<JoinHandle<()>>,
}

impl AutoConfirmWorker
{
    /// Spawns the background DPI confirmation worker when at least one profile enables `confirm_block`.
    pub(crate) fn for_profiles(profiles: &[Rc<DesyncProfile>], desync_fwmark: u32) -> Option<Self>
    {
        profiles
            .iter()
            .any(|p| p.lists.hostlist_auto.is_some() && p.lists.hostlist_auto_settings.confirm_block)
            .then(|| Self::spawn(desync_fwmark))
    }

    /// Spawns the background DPI confirmation worker using `desync_fwmark` on Linux probes.
    pub(crate) fn spawn(desync_fwmark: u32) -> Self
    {
        let (req_tx, req_rx) = mpsc::sync_channel::<AutoConfirmRequest>(MAX_CONFIRM_QUEUE);
        let (res_tx, res_rx) = mpsc::channel::<AutoConfirmResult>();
        let in_flight = Arc::new(Mutex::new(HashSet::<String>::new()));
        let flight_bg = Arc::clone(&in_flight);

        let join = thread::Builder::new()
            .name("zapret-autoconfirm".to_owned())
            .spawn(move || {
                while let Ok(req) = req_rx.recv()
                {
                    let probe_res = probe_endpoint_for_dpi(
                        req.dst_ip,
                        req.dst_port,
                        &req.host,
                        req.host_is_ip,
                        req.l7proto,
                        desync_fwmark,
                        DEFAULT_CONFIRM_TIMEOUT,
                    );
                    if let Ok(mut guard) = flight_bg.lock()
                    {
                        guard.remove(&req.host);
                    }
                    if let Some(confirmed_blocked) = probe_res
                        && res_tx
                            .send(AutoConfirmResult {
                                profile_slot: req.profile_slot,
                                profile_index: req.profile_index,
                                host: req.host,
                                host_is_ip: req.host_is_ip,
                                l7proto: req.l7proto,
                                confirmed_blocked,
                            })
                            .is_err()
                    {
                        break;
                    }
                }
            })
            .ok();

        Self { tx: Some(req_tx), rx: res_rx, in_flight, join }
    }

    /// Enqueues `req` without blocking if the host is not already in-flight and queue capacity remains.
    pub(crate) fn try_submit(&self, req: AutoConfirmRequest)
    {
        let Some(tx) = &self.tx
        else
        {
            return;
        };
        if !matches!(req.l7proto, L7Proto::Tls | L7Proto::Http) || req.dst_port == 0
        {
            return;
        }
        {
            let Ok(mut guard) = self.in_flight.lock()
            else
            {
                return;
            };
            if !guard.insert(req.host.clone())
            {
                return;
            }
        }
        if tx.try_send(req.clone()).is_err()
            && let Ok(mut guard) = self.in_flight.lock()
        {
            guard.remove(&req.host);
        }
    }

    /// Drains all completed confirmation results and promotes or resets matching profile entries.
    pub(crate) fn drain_and_apply(
        &self,
        profiles: &[Rc<DesyncProfile>],
        runtimes: &[ProfileRuntime],
        debug_log: Option<&std::path::Path>,
    )
    {
        while let Ok(res) = self.rx.try_recv()
        {
            let Some(profile) = profiles.get(res.profile_slot)
            else
            {
                continue;
            };
            if profile.index != res.profile_index
            {
                continue;
            }
            let rt = &runtimes[res.profile_slot];
            if res.confirmed_blocked
            {
                let Some(autolist_file) = &rt.autolist
                else
                {
                    continue;
                };
                let mut pool = rt.fail_pool.borrow_mut();
                let ctx = AutoHostlistRecordCtx {
                    settings: &profile.lists.hostlist_auto_settings,
                    fail_pool: &mut pool,
                    hostlists: &rt.hostlists,
                    autolist_file,
                    debug_log,
                    profile_n: profile.index,
                    profile_name: profile.name.as_deref().unwrap_or("noname"),
                    client_label: "auto-confirm",
                    l7proto: res.l7proto,
                    now_sec: boottime_secs(),
                };
                if promote_autohost(&ctx, &res.host, res.host_is_ip) == AutoHostlistAction::AddedToList
                {
                    pool.reset(&res.host);
                }
            }
            else
            {
                let mut pool = rt.fail_pool.borrow_mut();
                let _ = reset_autohost_failure(
                    &mut pool,
                    &res.host,
                    debug_log,
                    profile.index,
                    profile.name.as_deref().unwrap_or("noname"),
                    "auto-confirm",
                    res.l7proto,
                );
            }
        }
    }
}

impl Drop for AutoConfirmWorker
{
    fn drop(&mut self)
    {
        self.tx.take();
        if let Some(handle) = self.join.take()
        {
            let _ = handle.join();
        }
    }
}
