//! Lock-free telemetry hub and non-blocking command bridge between packet loop and control server.

/// Atomic counters and subscriber tracking so zero-subscriber packet loops pay zero IPC cost.
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
/// Bounded synchronous channels for packet streaming and request/reply daemon commands.
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
/// Shared ownership and mutex/RwLock protection for daemon metadata and subscriber list.
use std::sync::{Arc, Mutex, RwLock};

/// Wire protocol status, counter snapshot, and streamed server response types.
use crate::control::protocol::{CountersSnapshot, DaemonStatus, Response};
/// Shared packet outcome counters, record snapshot, and verdict classification.
use crate::telemetry::{PacketCounters, PacketRecord, PacketVerdict};

/// Maximum queued packet records waiting between the packet loop and the fanout thread.
const HUB_PACKET_CHANNEL_CAP: usize = 512;
/// Maximum pending daemon commands waiting to be drained by the packet loop.
const HUB_COMMAND_CHANNEL_CAP: usize = 32;

/// Mutable daemon runtime metadata included in `Response::Status` snapshots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonStatusMeta
{
    /// Binary package version string.
    pub version: String,
    /// Daemon process ID.
    pub pid: u32,
    /// Active NFQUEUE queue number.
    pub qnum: u16,
    /// Desync firewall mark bitmask.
    pub fwmark: u32,
    /// `true` when NFQUEUE interception is active.
    pub intercept: bool,
    /// Ordered profile names currently active in `DesyncEngine`.
    pub profile_names: Vec<String>,
    /// Loaded TOML configuration path, if any.
    pub config_path: Option<String>,
}

/// Command sent from an authenticated control client to the packet-loop thread.
pub enum ControlCommand
{
    /// Reloads hostlists and ipsets in the running `DesyncEngine`.
    ReloadLists
    {
        /// One-shot reply channel returning a summary or failure message.
        reply: SyncSender<Result<String, String>>,
    },
    /// Parses replacement TOML and swaps profiles inside the running `DesyncEngine`.
    ReloadConfig
    {
        /// Replacement TOML configuration text pushed by a control client.
        toml: String,
        /// One-shot reply channel returning the new profile count or rejection reason.
        reply: SyncSender<Result<String, String>>,
    },
    /// Triggers clean shutdown of the running daemon process.
    Stop
    {
        /// One-shot reply channel confirming shutdown initiation.
        reply: SyncSender<Result<String, String>>,
    },
}

/// Registered subscriber sink maintained by the telemetry fanout thread.
pub(crate) struct SubscriberSink
{
    /// Unique connection identifier.
    pub(crate) id: u64,
    /// Bounded non-blocking channel feeding the client's writer thread.
    pub(crate) tx: SyncSender<Response>,
    /// Optional per-client override (`Some(0)` suppresses PASS records for this client).
    pub(crate) pass_sample_rate: Option<u64>,
    /// Callback invoked when the subscriber queue overflows or disconnects so its socket closes.
    pub(crate) disconnect: Arc<dyn Fn() + Send + Sync>,
}

/// Shared coordination state connecting the packet loop with the control server thread.
pub struct TelemetryHub
{
    /// Shared atomic packet counters updated on every intercepted packet.
    counters: Arc<PacketCounters>,
    /// Mutable daemon metadata snapshot served for `status` requests.
    meta: RwLock<DaemonStatusMeta>,
    /// Current PASS packet sampling divisor (`0` disables PASS forwarding, `N` keeps 1 in `N`).
    pass_sample_rate: AtomicU64,
    /// Monotonic counter used to modulo-sample PASS packets without locking.
    pass_seen: AtomicU64,
    /// Active subscriber count (`0` skips building [`PacketRecord`] completely).
    subscriber_count: AtomicUsize,
    /// Active subscriber list guarded for fanout and disconnect pruning.
    subscribers: Mutex<Vec<SubscriberSink>>,
    /// Non-blocking packet record sender used by the hot packet loop.
    pkt_tx: SyncSender<PacketRecord>,
    /// Receiving end moved into the control server fanout thread when started.
    pkt_rx: Mutex<Option<Receiver<PacketRecord>>>,
    /// Bounded command sender used by control server client handlers.
    cmd_tx: SyncSender<ControlCommand>,
    /// Non-blocking command receiver polled by the packet-loop tick closure.
    cmd_rx: Mutex<Receiver<ControlCommand>>,
}

impl TelemetryHub
{
    /// Constructs a new hub with `counters`, initial `meta`, and PASS sampling rate.
    pub fn new(counters: Arc<PacketCounters>, meta: DaemonStatusMeta, pass_sample_rate: u64) -> Arc<Self>
    {
        let (pkt_tx, pkt_rx) = mpsc::sync_channel(HUB_PACKET_CHANNEL_CAP);
        let (cmd_tx, cmd_rx) = mpsc::sync_channel(HUB_COMMAND_CHANNEL_CAP);
        Arc::new(Self {
            counters,
            meta: RwLock::new(meta),
            pass_sample_rate: AtomicU64::new(pass_sample_rate),
            pass_seen: AtomicU64::new(0),
            subscriber_count: AtomicUsize::new(0),
            subscribers: Mutex::new(Vec::new()),
            pkt_tx,
            pkt_rx: Mutex::new(Some(pkt_rx)),
            cmd_tx,
            cmd_rx: Mutex::new(cmd_rx),
        })
    }

    /// Returns a reference to the shared atomic [`PacketCounters`].
    pub fn counters(&self) -> &Arc<PacketCounters>
    {
        &self.counters
    }

    /// Returns `true` when at least one authenticated client is currently subscribed.
    pub fn has_subscribers(&self) -> bool
    {
        self.subscriber_count.load(Ordering::Relaxed) > 0
    }

    /// Returns the configured PASS packet sampling divisor (`0` disables PASS records).
    pub fn pass_sample_rate(&self) -> u64
    {
        self.pass_sample_rate.load(Ordering::Relaxed)
    }

    /// Returns `true` if the hot path should build and publish a record for `verdict`.
    pub fn should_publish(&self, verdict: PacketVerdict) -> bool
    {
        if !self.has_subscribers()
        {
            return false;
        }
        if verdict != PacketVerdict::Pass
        {
            return true;
        }
        let sample = self.pass_sample_rate();
        if sample == 0
        {
            return false;
        }
        self.pass_seen.fetch_add(1, Ordering::Relaxed).is_multiple_of(sample)
    }

    /// Attempts to queue `record` for subscribed clients without ever blocking the caller.
    pub fn publish_packet(&self, record: PacketRecord)
    {
        let _ = self.pkt_tx.try_send(record);
    }

    /// Replaces the tracked profile list in status responses after a live config reload.
    pub fn set_profile_names(&self, names: Vec<String>)
    {
        if let Ok(mut guard) = self.meta.write()
        {
            guard.profile_names = names;
        }
    }

    /// Builds a consistent [`DaemonStatus`] combining current metadata and atomic counters.
    pub fn status_snapshot(&self) -> DaemonStatus
    {
        let meta = match self.meta.read()
        {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        DaemonStatus {
            version: meta.version,
            pid: meta.pid,
            qnum: meta.qnum,
            fwmark: meta.fwmark,
            intercept: meta.intercept,
            profile_names: meta.profile_names,
            config_path: meta.config_path,
            pass_sample_rate: self.pass_sample_rate(),
            counters: CountersSnapshot::from(&*self.counters),
        }
    }

    /// Enqueues a [`ControlCommand`] toward the packet loop without waiting on completion.
    pub fn try_send_command(&self, cmd: ControlCommand) -> Result<(), String>
    {
        match self.cmd_tx.try_send(cmd)
        {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(_)) => Err("daemon command queue is full".to_owned()),
            Err(TrySendError::Disconnected(_)) => Err("daemon loop is shutting down".to_owned()),
        }
    }

    /// Pops one pending [`ControlCommand`] for non-blocking execution in `next_loop_timeout`.
    pub fn try_recv_command(&self) -> Option<ControlCommand>
    {
        self.cmd_rx.lock().ok()?.try_recv().ok()
    }

    /// Takes the packet receiver once for the control server's fanout thread.
    pub(crate) fn take_packet_receiver(&self) -> Option<Receiver<PacketRecord>>
    {
        self.pkt_rx.lock().ok()?.take()
    }

    /// Registers or updates one subscriber sink and synchronizes `subscriber_count`.
    pub(crate) fn add_subscriber(&self, sink: SubscriberSink)
    {
        if let Ok(mut guard) = self.subscribers.lock()
        {
            guard.retain(|item| item.id != sink.id);
            guard.push(sink);
            self.subscriber_count.store(guard.len(), Ordering::Relaxed);
        }
    }

    /// Removes subscriber `id` and clears `subscriber_count` when none remain.
    pub(crate) fn remove_subscriber(&self, id: u64)
    {
        if let Ok(mut guard) = self.subscribers.lock()
        {
            guard.retain(|item| item.id != id);
            self.subscriber_count.store(guard.len(), Ordering::Relaxed);
        }
    }

    /// Broadcasts `msg` non-blockingly to all subscribers, disconnecting full or dead sinks.
    pub(crate) fn broadcast(&self, msg: &Response, is_pass_packet: bool)
    {
        let mut dropped_hooks = Vec::new();
        if let Ok(mut guard) = self.subscribers.lock()
        {
            guard.retain(|sink| {
                if is_pass_packet && sink.pass_sample_rate == Some(0)
                {
                    return true;
                }
                match sink.tx.try_send(msg.clone())
                {
                    Ok(()) => true,
                    Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) =>
                    {
                        dropped_hooks.push(Arc::clone(&sink.disconnect));
                        false
                    }
                }
            });
            self.subscriber_count.store(guard.len(), Ordering::Relaxed);
        }
        for hook in dropped_hooks
        {
            hook();
        }
    }
}
