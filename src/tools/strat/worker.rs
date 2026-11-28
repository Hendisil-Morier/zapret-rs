//! In-process packet interception worker thread (`QueueCatcher` on Linux, `WinDivertIntercepter` on Windows).

/// Single-threaded interior mutability sharing [`DesyncEngine`] and [`CountingSender`].
#[cfg(any(target_os = "linux", windows))]
use std::cell::RefCell;
/// Destination IP address passed through [`CountingSender`] to the underlying [`PacketSender`].
#[cfg(any(target_os = "linux", windows))]
use std::net::IpAddr;
/// Single-threaded shared ownership for [`CountingSender`] injected into [`DesyncEngine`].
#[cfg(any(target_os = "linux", windows))]
use std::rc::Rc;
/// Atomic shutdown signaling and live capture/injection counters.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
/// Synchronous command and ACK channels between coordinator and capture worker.
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
/// Shared thread-safe telemetry and error state read by the scan coordinator.
use std::sync::{Arc, Mutex};
/// Background worker thread handle joined on drop.
use std::thread::{self, JoinHandle};
/// Poll wakeup cadence for profile-swap commands.
#[cfg(any(target_os = "linux", windows))]
use std::time::Duration;

/// Application and profile configuration types applied to the in-process engine.
use crate::config::{AppConfig, DesyncProfile};
/// Stateful DPI desync engine whose profiles are hot-swapped between candidates.
#[cfg(any(target_os = "linux", windows))]
use crate::desync::DesyncEngine;
/// Windows WinDivert intercepter bound once for the entire scan session.
#[cfg(windows)]
use crate::intercepter::WinDivertIntercepter;
/// OS-agnostic packet interception loop contract and packet verdicts.
#[cfg(any(target_os = "linux", windows))]
use crate::intercepter::{Decision, PacketIntercepter};
/// Tuned Linux NFQUEUE catcher bound once for the entire scan session.
#[cfg(target_os = "linux")]
use crate::intercepter::{QueueCatcher, QueueConfig};
/// Linux raw socket injector wrapped by [`CountingSender`].
#[cfg(target_os = "linux")]
use crate::rawsend::RawSender;
/// Windows WinDivert `SEND_ONLY` injector wrapped by [`CountingSender`].
#[cfg(windows)]
use crate::rawsend::WinDivertSender;
/// OS-agnostic packet sender contract and error type wrapped by [`CountingSender`].
#[cfg(any(target_os = "linux", windows))]
use crate::rawsend::{PacketSender, RawSendError};

/// Poll wakeup interval used by the worker thread to service profile-swap commands promptly.
#[cfg(any(target_os = "linux", windows))]
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(15);

/// Control commands delivered from the scan coordinator to the worker thread.
enum WorkerCmd
{
    /// Atomically replace active engine profiles and clear conntrack/ipcache, then reply on `ack`.
    Swap
    {
        /// New active profiles (`empty` puts the worker into pass-through mode).
        profiles: Vec<DesyncProfile>,
        /// Synchronous ACK channel returning `Ok(())` or a Lua validation/load error message.
        ack: SyncSender<Result<(), String>>,
    },
    /// Stop the capture poll loop and exit the worker thread cleanly.
    Shutdown,
}

/// Live packet capture and raw-injection diagnostics collected by [`InProcessWorkerHandle`].
#[derive(Default)]
struct WorkerStats
{
    /// Human-readable description of the bound filter/queue (set once before ready ACK).
    capture_spec: Mutex<String>,
    /// Total packets intercepted by the capture loop.
    captured: AtomicU64,
    /// Packets passed unmodified.
    passed: AtomicU64,
    /// Packets modified in place (`Decision::Replace`).
    modified: AtomicU64,
    /// Packets dropped (`Decision::Drop`, typically replaced by injected desync segments).
    dropped: AtomicU64,
    /// Successful raw packet injections via `PacketSender::send`.
    rawsend_ok: AtomicU64,
    /// Failed raw packet injections via `PacketSender::send`.
    rawsend_err: AtomicU64,
    /// First/most-recent rawsend error message for debugging silent injection failures.
    last_rawsend_err: Mutex<Option<String>>,
}

impl WorkerStats
{
    /// Records one packet interception verdict.
    #[cfg(any(target_os = "linux", windows))]
    fn record_decision(&self, decision: &Decision)
    {
        self.captured
            .fetch_add(1, Ordering::Relaxed);
        match decision
        {
            Decision::Pass =>
            {
                self.passed
                    .fetch_add(1, Ordering::Relaxed);
            }
            Decision::Replace(_) =>
            {
                self.modified
                    .fetch_add(1, Ordering::Relaxed);
            }
            Decision::Drop =>
            {
                self.dropped
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Formats a compact diagnostic summary line for `Live Scan Log` and debug reports.
    fn summary(&self) -> String
    {
        let cap = self
            .captured
            .load(Ordering::Relaxed);
        let pass = self
            .passed
            .load(Ordering::Relaxed);
        let mod_n = self
            .modified
            .load(Ordering::Relaxed);
        let drop_n = self
            .dropped
            .load(Ordering::Relaxed);
        let ok = self
            .rawsend_ok
            .load(Ordering::Relaxed);
        let err = self
            .rawsend_err
            .load(Ordering::Relaxed);
        let base =
            format!("captured={cap} pass={pass} mod={mod_n} drop={drop_n} rawsend_ok={ok} rawsend_err={err}");
        let last = self
            .last_rawsend_err
            .lock()
            .ok()
            .and_then(|g| g.clone());
        match last
        {
            Some(msg) => format!("{base} (last_err: {msg})"),
            None => base,
        }
    }
}

/// Wrapper around a live [`PacketSender`] that counts successes and records injection errors.
#[cfg(any(target_os = "linux", windows))]
struct CountingSender<S>
{
    /// Underlying OS packet injector (`RawSender` or `WinDivertSender`).
    inner: S,
    /// Shared diagnostic counters updated on every `send`.
    stats: Arc<WorkerStats>,
}

#[cfg(any(target_os = "linux", windows))]
impl<S: PacketSender> PacketSender for CountingSender<S>
{
    /// Forwards `send` to `self.inner` while tracking ok/error counts and last error text.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>
    {
        let res = self
            .inner
            .send(dst, fwmark, ifout, packet);
        match &res
        {
            Ok(()) =>
            {
                self.stats
                    .rawsend_ok
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(err) =>
            {
                self.stats
                    .rawsend_err
                    .fetch_add(1, Ordering::Relaxed);
                if let Ok(mut slot) = self
                    .stats
                    .last_rawsend_err
                    .lock()
                {
                    *slot = Some(err.to_string());
                }
            }
        }
        res
    }
}

/// Abstract profile-application handle decoupling scan orchestration from live packet sockets.
pub trait StrategyApplier
{
    /// Installs `profiles` as the active desync set and waits until the swap takes effect.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String>;

    /// Clears all active desync profiles (pass-through mode for baseline probing).
    fn clear(&mut self) -> Result<(), String>
    {
        self.apply_profiles(Vec::new())
    }
}

/// Live [`StrategyApplier`] owning a persistent background capture + [`DesyncEngine`] worker thread.
pub struct InProcessWorkerHandle
{
    /// Channel sending profile swap and shutdown commands to the worker.
    cmd_tx: Option<Sender<WorkerCmd>>,
    /// Local stop flag shared with the worker's `run_until` loop.
    worker_stop: Arc<AtomicBool>,
    /// Shared capture and raw-injection diagnostics for log reporting.
    stats: Arc<WorkerStats>,
    /// Background thread handle joined on drop.
    join: Option<JoinHandle<()>>,
}

impl InProcessWorkerHandle
{
    /// Spawns the persistent capture worker thread, initializing the intercepter and [`DesyncEngine`] once.
    pub fn spawn(base_config: AppConfig, global_stop: &'static AtomicBool) -> Result<Self, String>
    {
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let worker_stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&worker_stop);
        let stats = Arc::new(WorkerStats::default());
        let stats_bg = Arc::clone(&stats);

        let join = thread::Builder::new()
            .name("strat-finder-worker".to_owned())
            .spawn(move || {
                run_worker_thread(base_config, cmd_rx, ready_tx, stop_clone, global_stop, stats_bg);
            })
            .map_err(|err| format!("failed to spawn capture worker thread: {err}"))?;

        match ready_rx.recv()
        {
            Ok(Ok(())) => Ok(Self { cmd_tx: Some(cmd_tx), worker_stop, stats, join: Some(join) }),
            Ok(Err(err)) =>
            {
                let _ = join.join();
                Err(err)
            }
            Err(_) =>
            {
                let _ = join.join();
                Err("capture worker thread exited unexpectedly during startup".to_owned())
            }
        }
    }

    /// Returns a human-readable description of the active packet capture filter or queue.
    pub fn capture_spec(&self) -> String
    {
        self.stats
            .capture_spec
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    /// Returns a single-line summary of captured packets, verdicts, and rawsend results.
    pub fn stats_summary(&self) -> String
    {
        self.stats
            .summary()
    }
}

impl StrategyApplier for InProcessWorkerHandle
{
    /// Sends `profiles` to the worker thread and blocks until `DesyncEngine::replace_profiles` finishes.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String>
    {
        let Some(tx) = &self.cmd_tx
        else
        {
            return Err("capture worker is already shut down".to_owned());
        };
        let (ack_tx, ack_rx) = mpsc::sync_channel(1);
        tx.send(WorkerCmd::Swap { profiles, ack: ack_tx })
            .map_err(|_| "capture worker channel closed".to_owned())?;
        ack_rx
            .recv()
            .map_err(|_| "capture worker terminated before acknowledging profile swap".to_owned())?
    }
}

impl Drop for InProcessWorkerHandle
{
    /// Signals the worker thread to exit and joins it so the intercepter unbinds cleanly.
    fn drop(&mut self)
    {
        self.worker_stop
            .store(true, Ordering::Release);
        if let Some(tx) = self
            .cmd_tx
            .take()
        {
            let _ = tx.send(WorkerCmd::Shutdown);
        }
        if let Some(handle) = self
            .join
            .take()
        {
            let _ = handle.join();
        }
    }
}

/// Builds a [`DesyncEngine`] whose packet injector records send counts and errors into `stats`.
#[cfg(any(target_os = "linux", windows))]
fn build_instrumented_engine(base_config: &AppConfig, stats: Arc<WorkerStats>)
-> Result<DesyncEngine, String>
{
    #[cfg(target_os = "linux")]
    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(CountingSender {
        inner: RawSender::new(base_config.bind_fix4, base_config.bind_fix6),
        stats,
    }));
    #[cfg(windows)]
    let sender: Rc<RefCell<dyn PacketSender>> =
        Rc::new(RefCell::new(CountingSender { inner: WinDivertSender::new(), stats }));
    DesyncEngine::with_sender(base_config, sender).map_err(|err| err.to_string())
}

/// Drains pending profile-swap commands on the worker thread; returns `true` if shutdown was signaled.
#[cfg(any(target_os = "linux", windows))]
fn drain_worker_cmds(cmd_rx: &Receiver<WorkerCmd>, engine: &RefCell<DesyncEngine>) -> bool
{
    while let Ok(cmd) = cmd_rx.try_recv()
    {
        match cmd
        {
            WorkerCmd::Swap { profiles, ack } =>
            {
                let res = engine
                    .borrow_mut()
                    .replace_profiles(profiles)
                    .map_err(|e| e.to_string());
                let _ = ack.send(res);
            }
            WorkerCmd::Shutdown => return true,
        }
    }
    false
}

/// Runs the shared capture + LuaJIT desync loop over any [`PacketIntercepter`] backend.
#[cfg(any(target_os = "linux", windows))]
fn run_catcher_loop<I: PacketIntercepter>(
    catcher: &mut I,
    base_config: &AppConfig,
    cmd_rx: Receiver<WorkerCmd>,
    ready_tx: SyncSender<Result<(), String>>,
    worker_stop: Arc<AtomicBool>,
    global_stop: &'static AtomicBool,
    stats: Arc<WorkerStats>,
)
{
    let engine = match build_instrumented_engine(base_config, Arc::clone(&stats))
    {
        Ok(e) => RefCell::new(e),
        Err(err) =>
        {
            let _ = ready_tx.send(Err(format!("failed to initialize Lua desync engine: {err}")));
            return;
        }
    };
    if ready_tx
        .send(Ok(()))
        .is_err()
    {
        return;
    }
    let loop_stop = Arc::new(AtomicBool::new(false));
    let _ = catcher.run_until(
        &loop_stop,
        || {
            if worker_stop.load(Ordering::Acquire)
                || global_stop.load(Ordering::Acquire)
                || drain_worker_cmds(&cmd_rx, &engine)
            {
                loop_stop.store(true, Ordering::Release);
                return Some(Duration::ZERO);
            }
            Some(WORKER_POLL_INTERVAL)
        },
        |pkt| {
            let decision = engine
                .borrow()
                .process_packet(pkt);
            stats.record_decision(&decision);
            decision
        },
    );
}

/// Runs the platform packet-interception worker thread servicing profile-swap commands.
#[cfg(any(target_os = "linux", windows))]
fn run_worker_thread(
    base_config: AppConfig,
    cmd_rx: Receiver<WorkerCmd>,
    ready_tx: SyncSender<Result<(), String>>,
    worker_stop: Arc<AtomicBool>,
    global_stop: &'static AtomicBool,
    stats: Arc<WorkerStats>,
)
{
    #[cfg(target_os = "linux")]
    let mut catcher = {
        let qcfg = QueueConfig::with_fwmark(base_config.qnum, base_config.fwmark);
        if let Ok(mut spec) = stats
            .capture_spec
            .lock()
        {
            *spec = format!("NFQUEUE queue={} fwmark=0x{:08x}", qcfg.queue_num, base_config.fwmark);
        }
        match QueueCatcher::bind(qcfg)
        {
            Ok(c) => c,
            Err(err) =>
            {
                let _ = ready_tx.send(Err(format!("failed to bind NFQUEUE: {err}")));
                return;
            }
        }
    };
    #[cfg(windows)]
    let mut catcher = {
        let (mut tcp, mut udp) = crate::tools::strat::firewall::collect_config_ports(&base_config);
        // Strategy Finder starts with an empty profile list; restrict capture to HTTP/TLS/QUIC
        // probe ports so WinDivert never intercepts DNS (UDP/53) or unrelated host traffic.
        if tcp.is_empty() && udp.is_empty()
        {
            tcp = vec![80, 443];
            udp = vec![443];
        }
        let filter = crate::tools::strat::windivert::build_windivert_filter(&tcp, &udp);
        if let Ok(mut spec) = stats
            .capture_spec
            .lock()
        {
            *spec = format!("WinDivert filter: {filter}");
        }
        match WinDivertIntercepter::bind(&filter)
        {
            Ok(c) => c,
            Err(err) =>
            {
                let _ = ready_tx.send(Err(format!("failed to bind WinDivert: {err}")));
                return;
            }
        }
    };
    run_catcher_loop(&mut catcher, &base_config, cmd_rx, ready_tx, worker_stop, global_stop, stats);
}

/// Non-Linux/non-Windows stub reporting that live packet interception is not yet implemented.
#[cfg(not(any(target_os = "linux", windows)))]
fn run_worker_thread(
    _base: AppConfig,
    rx: Receiver<WorkerCmd>,
    ready_tx: SyncSender<Result<(), String>>,
    _wstop: Arc<AtomicBool>,
    _gstop: &'static AtomicBool,
    _stats: Arc<WorkerStats>,
)
{
    let _ = ready_tx.send(Err("live packet interception is not yet implemented on this OS".to_owned()));
    while let Ok(cmd) = rx.try_recv()
    {
        match cmd
        {
            WorkerCmd::Swap { ack, .. } =>
            {
                let _ = ack.send(Err("live packet interception unsupported".to_owned()));
            }
            WorkerCmd::Shutdown => break,
        }
    }
}
