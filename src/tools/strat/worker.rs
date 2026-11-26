//! In-process packet interception worker thread (`QueueCatcher` on Linux, `WinDivertIntercepter` on Windows).

/// Single-threaded interior mutability sharing [`DesyncEngine`] between poll callbacks.
#[cfg(any(target_os = "linux", windows))]
use std::cell::RefCell;
/// Lock-free shutdown flags polled by both the scan loop and worker thread.
use std::sync::Arc;
/// Atomic shutdown signaling between coordinator and worker thread.
use std::sync::atomic::{AtomicBool, Ordering};
/// Synchronous command and ACK channels between coordinator and capture worker.
use std::sync::mpsc::{self, Receiver, Sender, SyncSender};
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
/// OS-agnostic packet interception loop contract.
#[cfg(any(target_os = "linux", windows))]
use crate::intercepter::PacketIntercepter;
/// Tuned Linux NFQUEUE catcher bound once for the entire scan session.
#[cfg(target_os = "linux")]
use crate::intercepter::QueueCatcher;
/// Windows WinDivert intercepter bound once for the entire scan session.
#[cfg(windows)]
use crate::intercepter::WinDivertIntercepter;

/// Poll wakeup interval used by the worker thread to service profile-swap commands promptly.
#[cfg(any(target_os = "linux", windows))]
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(15);

/// Control commands delivered from the scan coordinator to the worker thread.
#[cfg_attr(not(any(target_os = "linux", windows)), allow(dead_code))]
enum WorkerCmd {
    /// Atomically replace active engine profiles and clear conntrack/ipcache, then reply on `ack`.
    Swap {
        /// New active profiles (`empty` puts the worker into pass-through mode).
        profiles: Vec<DesyncProfile>,
        /// Synchronous ACK channel returning `Ok(())` or a Lua validation/load error message.
        ack: SyncSender<Result<(), String>>,
    },
    /// Stop the capture poll loop and exit the worker thread cleanly.
    Shutdown,
}

/// Abstract profile-application handle decoupling scan orchestration from live packet sockets.
pub trait StrategyApplier {
    /// Installs `profiles` as the active desync set and waits until the swap takes effect.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String>;

    /// Clears all active desync profiles (pass-through mode for baseline probing).
    fn clear(&mut self) -> Result<(), String> {
        self.apply_profiles(Vec::new())
    }
}

/// Live [`StrategyApplier`] owning a persistent background capture + [`DesyncEngine`] worker thread.
pub struct InProcessWorkerHandle {
    /// Channel sending profile swap and shutdown commands to the worker.
    cmd_tx: Option<Sender<WorkerCmd>>,
    /// Local stop flag shared with the worker's `run_until` loop.
    worker_stop: Arc<AtomicBool>,
    /// Background thread handle joined on drop.
    join: Option<JoinHandle<()>>,
}

impl InProcessWorkerHandle {
    /// Spawns the persistent capture worker thread, initializing the intercepter and [`DesyncEngine`] once.
    pub fn spawn(base_config: AppConfig, global_stop: &'static AtomicBool) -> Result<Self, String> {
        let (cmd_tx, cmd_rx) = mpsc::channel::<WorkerCmd>();
        let (ready_tx, ready_rx) = mpsc::sync_channel::<Result<(), String>>(1);
        let worker_stop = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&worker_stop);

        let join = thread::Builder::new()
            .name("strat-finder-worker".to_owned())
            .spawn(move || {
                run_worker_thread(base_config, cmd_rx, ready_tx, stop_clone, global_stop);
            })
            .map_err(|err| format!("failed to spawn capture worker thread: {err}"))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Self {
                cmd_tx: Some(cmd_tx),
                worker_stop,
                join: Some(join),
            }),
            Ok(Err(err)) => {
                let _ = join.join();
                Err(err)
            }
            Err(_) => {
                let _ = join.join();
                Err("capture worker thread exited unexpectedly during startup".to_owned())
            }
        }
    }
}

impl StrategyApplier for InProcessWorkerHandle {
    /// Sends `profiles` to the worker thread and blocks until `DesyncEngine::replace_profiles` finishes.
    fn apply_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), String> {
        let Some(tx) = &self.cmd_tx else {
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

impl Drop for InProcessWorkerHandle {
    /// Signals the worker thread to exit and joins it so the intercepter unbinds cleanly.
    fn drop(&mut self) {
        self.worker_stop.store(true, Ordering::Release);
        if let Some(tx) = self.cmd_tx.take() {
            let _ = tx.send(WorkerCmd::Shutdown);
        }
        if let Some(handle) = self.join.take() {
            let _ = handle.join();
        }
    }
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
) {
    let engine = match DesyncEngine::new(base_config) {
        Ok(e) => RefCell::new(e),
        Err(err) => {
            let _ = ready_tx.send(Err(format!("failed to initialize Lua desync engine: {err}")));
            return;
        }
    };
    if ready_tx.send(Ok(())).is_err() {
        return;
    }
    let loop_stop = Arc::new(AtomicBool::new(false));
    let _ = catcher.run_until(
        &loop_stop,
        || {
            if worker_stop.load(Ordering::Acquire) || global_stop.load(Ordering::Acquire) {
                loop_stop.store(true, Ordering::Release);
                return Some(Duration::ZERO);
            }
            loop {
                match cmd_rx.try_recv() {
                    Ok(WorkerCmd::Swap { profiles, ack }) => {
                        let res = engine.borrow_mut().replace_profiles(profiles).map_err(|e| e.to_string());
                        let _ = ack.send(res);
                    }
                    Ok(WorkerCmd::Shutdown) | Err(mpsc::TryRecvError::Disconnected) => {
                        loop_stop.store(true, Ordering::Release);
                        return Some(Duration::ZERO);
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                }
            }
            Some(WORKER_POLL_INTERVAL)
        },
        |pkt| engine.borrow().process_packet(pkt),
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
) {
    #[cfg(target_os = "linux")]
    let mut catcher = match QueueCatcher::bind(base_config.to_queue_config()) {
        Ok(c) => c,
        Err(err) => {
            let _ = ready_tx.send(Err(format!("failed to bind NFQUEUE: {err}")));
            return;
        }
    };
    #[cfg(windows)]
    let mut catcher = {
        let (mut tcp, mut udp) = crate::tools::strat::firewall::collect_config_ports(&base_config);
        // Strategy Finder starts with an empty profile list; restrict capture to HTTP/TLS/QUIC
        // probe ports so WinDivert never intercepts DNS (UDP/53) or unrelated host traffic.
        if tcp.is_empty() && udp.is_empty() {
            tcp = vec![80, 443];
            udp = vec![443];
        }
        let filter = crate::tools::strat::windivert::build_windivert_filter(&tcp, &udp);
        match WinDivertIntercepter::bind(&filter) {
            Ok(c) => c,
            Err(err) => {
                let _ = ready_tx.send(Err(format!("failed to bind WinDivert: {err}")));
                return;
            }
        }
    };
    run_catcher_loop(&mut catcher, &base_config, cmd_rx, ready_tx, worker_stop, global_stop);
}

/// Non-Linux/non-Windows stub reporting that live packet interception is not yet implemented.
#[cfg(not(any(target_os = "linux", windows)))]
fn run_worker_thread(
    _base: AppConfig,
    _rx: Receiver<WorkerCmd>,
    ready_tx: SyncSender<Result<(), String>>,
    _wstop: Arc<AtomicBool>,
    _gstop: &'static AtomicBool,
) {
    let _ = ready_tx.send(Err("live packet interception is not yet implemented on this OS".to_owned()));
}
