//! Linux NFQUEUE binding, non-blocking `poll()` dispatch loop, and verdict submission.

/// Raw OS void pointer cast helper for `setsockopt`.
use std::ffi::c_void;
/// Standard I/O error classification (`WouldBlock`, `Interrupted`).
use std::io::ErrorKind;
/// Raw FD extraction for `SO_RCVBUF` and `libc::poll`.
use std::os::fd::{AsRawFd, RawFd};
/// Lock-free shutdown signaling across signal handlers and the packet loop.
use std::sync::atomic::{AtomicBool, Ordering};
/// Timeout duration conversion for `libc::poll`.
use std::time::Duration;

/// Netfilter queue handle, packet message container, and verdict enum.
use nfq::{Message, Queue, Verdict};

/// Typed error variants for NFQUEUE setup and polling.
use crate::intercepter::error::IntercepterError;
/// Persistent `SIOCGIFNAME` resolver for incoming and outgoing interface names.
use crate::intercepter::ifname::IfNameResolver;
/// NFQUEUE configuration, borrowed packet metadata, [`PacketIntercepter`] trait, and verdict decisions.
use crate::intercepter::types::{Decision, PacketIntercepter, QueueConfig, QueuedPacket};

/// Maximum NFQUEUE messages drained per `poll()` wakeup so timers, IPC, and signals stay responsive.
pub const MAX_NFQUEUE_BATCH_PACKETS: usize = 64;

/// Attempts to grow the netlink socket `SO_RCVBUF` size, ignoring kernel clamping limits.
fn set_socket_rcvbuf(fd: RawFd, rcvbuf_bytes: usize) {
    let val = rcvbuf_bytes.min(libc::c_int::MAX as usize) as libc::c_int;
    // SAFETY: `val` is a valid stack `c_int` matching `size_of::<c_int>()`.
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            (&raw const val).cast::<c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
}

/// Converts an optional wait duration into a `libc::poll` timeout in milliseconds (`-1` for infinite wait).
pub fn poll_timeout_ms(timeout: Option<Duration>) -> libc::c_int {
    match timeout {
        None => -1,
        Some(dur) => libc::c_int::try_from(dur.as_millis()).unwrap_or(libc::c_int::MAX),
    }
}

/// Evaluates `desync_fwmark` loop suppression before invoking `on_packet`.
pub fn dispatch_packet<F>(pkt: &QueuedPacket<'_>, desync_fwmark: u32, on_packet: &mut F) -> Decision
where
    F: FnMut(&QueuedPacket<'_>) -> Decision,
{
    if desync_fwmark != 0 && (pkt.mark & desync_fwmark) != 0 {
        return Decision::Pass;
    }
    on_packet(pkt)
}

/// Applies `decision` to an intercepted `nfq::Message` prior to submitting the verdict.
pub fn apply_decision(msg: &mut Message, decision: Decision) {
    match decision {
        Decision::Pass => msg.set_verdict(Verdict::Accept),
        Decision::Drop => msg.set_verdict(Verdict::Drop),
        Decision::Replace(new_bytes) => {
            msg.set_payload(new_bytes);
            msg.set_verdict(Verdict::Accept);
        }
    }
}

/// Tuned Linux NFQUEUE listener that resolves interfaces and dispatches packets until stopped.
pub struct QueueCatcher {
    /// Bound `nfq::Queue` netlink handle configured in non-blocking mode.
    queue: Queue,
    /// Snapshot of queue configuration applied at bind time.
    config: QueueConfig,
    /// Persistent `SOCK_DGRAM` resolver for `SIOCGIFNAME` lookups.
    ifnames: IfNameResolver,
}

/// Drains up to `max_batch` items from `step`, yielding early on `WouldBlock` or `stop`.
pub fn drain_batch_with<E, R>(
    max_batch: usize,
    stop: &AtomicBool,
    is_would_block: impl Fn(&E) -> bool,
    is_retryable: impl Fn(&E) -> bool,
    mut step: R,
) -> Result<bool, E>
where
    R: FnMut() -> Result<(), E>,
{
    for _ in 0..max_batch {
        match step() {
            Ok(()) => {
                if stop.load(Ordering::Relaxed) {
                    return Ok(true);
                }
            }
            Err(err) if is_would_block(&err) => return Ok(false),
            Err(err) if is_retryable(&err) => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(false)
}

impl QueueCatcher {
    /// Opens, binds, and configures an NFQUEUE handle matching `config`.
    pub fn bind(config: QueueConfig) -> Result<Self, IntercepterError> {
        let ifnames = IfNameResolver::new()?;
        let mut queue = Queue::open()?;
        queue.bind(config.queue_num)?;
        queue.set_queue_max_len(config.queue_num, config.queue_maxlen)?;
        if config.fail_open {
            // Best-effort: `NFQA_CFG_F_FAIL_OPEN` is unsupported on Linux < 3.6.
            let _ = queue.set_fail_open(config.queue_num, true);
        }
        set_socket_rcvbuf(queue.as_raw_fd(), config.rcvbuf_bytes);
        queue.set_nonblocking(true);

        Ok(Self {
            queue,
            config,
            ifnames,
        })
    }

    /// Returns the configuration active on this bound queue catcher.
    pub fn config(&self) -> QueueConfig {
        self.config
    }

    /// Runs the non-blocking `poll()` and verdict loop until `stop` becomes `true`.
    pub fn run_until<F, T>(
        &mut self,
        stop: &AtomicBool,
        mut next_timeout: T,
        mut on_packet: F,
    ) -> Result<(), IntercepterError>
    where
        F: FnMut(&QueuedPacket<'_>) -> Decision,
        T: FnMut() -> Option<Duration>,
    {
        while !stop.load(Ordering::Relaxed) {
            let timeout_ms = poll_timeout_ms(next_timeout());
            if stop.load(Ordering::Relaxed) {
                break;
            }

            let mut pfd = libc::pollfd {
                fd: self.queue.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: `pfd` points to one initialized stack `libc::pollfd` entry for the duration of `poll`.
            let rc = unsafe { libc::poll(&raw mut pfd, 1, timeout_ms) };
            if rc < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(err.into());
            }
            if rc == 0 {
                continue;
            }

            if (pfd.revents & libc::POLLIN) != 0 {
                if self.drain_ready_messages(stop, &mut on_packet)? {
                    return Ok(());
                }
                continue;
            }
            if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return Err(IntercepterError::PollError(pfd.revents));
            }
        }
        Ok(())
    }

    /// Drains up to [`MAX_NFQUEUE_BATCH_PACKETS`] NFQUEUE messages; returns `true` if `stop` fired.
    fn drain_ready_messages<F>(
        &mut self,
        stop: &AtomicBool,
        on_packet: &mut F,
    ) -> Result<bool, IntercepterError>
    where
        F: FnMut(&QueuedPacket<'_>) -> Decision,
    {
        let queue = &mut self.queue;
        let ifnames = &mut self.ifnames;
        let desync_fwmark = self.config.desync_fwmark;
        drain_batch_with(
            MAX_NFQUEUE_BATCH_PACKETS,
            stop,
            |err| matches!(err, IntercepterError::Io(io_err) if io_err.kind() == ErrorKind::WouldBlock),
            |err| matches!(
                err,
                IntercepterError::Io(io_err)
                    if io_err.kind() == ErrorKind::Interrupted
                        || io_err.raw_os_error() == Some(libc::ENOBUFS)
            ),
            || {
                let msg = queue.recv().map_err(IntercepterError::from)?;
                handle_queue_message(queue, ifnames, desync_fwmark, msg, on_packet)
            },
        )
    }
}

/// Evaluates fwmark suppression, resolves interface names, and submits the kernel NFQUEUE verdict.
fn handle_queue_message<F>(
    queue: &mut Queue,
    ifnames: &mut IfNameResolver,
    desync_fwmark: u32,
    mut msg: Message,
    on_packet: &mut F,
) -> Result<(), IntercepterError>
where
    F: FnMut(&QueuedPacket<'_>) -> Decision,
{
    let mark = msg.get_nfmark();
    if desync_fwmark != 0 && (mark & desync_fwmark) != 0 {
        apply_decision(&mut msg, Decision::Pass);
        queue.verdict(msg)?;
        return Ok(());
    }

    let packet_id = msg.get_packet_id();
    let indev = msg.get_indev();
    let outdev = msg.get_outdev();
    let payload = msg.get_payload();
    let decision = ifnames.resolve_pair(indev, outdev, |ifin, ifout| {
        let pkt = QueuedPacket {
            packet_id,
            mark,
            ifin,
            ifout,
            payload,
        };
        dispatch_packet(&pkt, desync_fwmark, on_packet)
    });
    apply_decision(&mut msg, decision);
    queue.verdict(msg)?;
    Ok(())
}

impl PacketIntercepter for QueueCatcher {
    /// Runs the non-blocking `poll()` and verdict loop until `stop` becomes `true`.
    fn run_until<F, T>(
        &mut self,
        stop: &AtomicBool,
        next_timeout: T,
        on_packet: F,
    ) -> Result<(), IntercepterError>
    where
        F: FnMut(&QueuedPacket<'_>) -> Decision,
        T: FnMut() -> Option<Duration>,
    {
        QueueCatcher::run_until(self, stop, next_timeout, on_packet)
    }
}

impl Drop for QueueCatcher {
    /// Best-effort unbind of the netfilter queue when `QueueCatcher` exits scope.
    fn drop(&mut self) {
        let _ = self.queue.unbind(self.config.queue_num);
    }
}
