//! Wire message schema and handshake version constants for the `nfqws2` control socket.

/// JSON serialization for structured control requests, replies, and streamed events.
use serde::{Deserialize, Serialize};

/// Shared packet counter and decoded packet record types carried over IPC.
use crate::telemetry::{PacketCounters, PacketRecord};

/// Current control socket wire protocol version negotiated during `hello`.
pub const CONTROL_PROTOCOL_VERSION: u32 = 1;
/// Default daemon PASS packet sampling divisor (`1` forwarded per `20` PASS packets).
pub const DEFAULT_PASS_SAMPLE_RATE: u64 = 20;

/// Point-in-time snapshot of [`PacketCounters`] serialized over the control socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CountersSnapshot {
    /// Total packets processed by the desync engine.
    pub total: u64,
    /// Packets passed unmodified by NFQUEUE.
    pub passed: u64,
    /// Multi-segment TLS/QUIC packets held or re-sent untouched via raw socket.
    pub reassembled: u64,
    /// Packets modified in-place by a matched profile.
    pub modified: u64,
    /// Original packets replaced/split via raw socket by a matched profile.
    pub desynced: u64,
}

impl From<&PacketCounters> for CountersSnapshot {
    /// Reads relaxed atomic totals from `counters` into a plain serializable snapshot.
    fn from(counters: &PacketCounters) -> Self {
        let (total, passed, reassembled, modified, desynced) = counters.snapshot();
        Self { total, passed, reassembled, modified, desynced }
    }
}

impl CountersSnapshot {
    /// Stores every snapshot field into lock-free `target` counters for TUI display.
    pub fn store_into(&self, target: &PacketCounters) {
        use std::sync::atomic::Ordering;
        target.total.store(self.total, Ordering::Relaxed);
        target.passed.store(self.passed, Ordering::Relaxed);
        target.reassembled.store(self.reassembled, Ordering::Relaxed);
        target.modified.store(self.modified, Ordering::Relaxed);
        target.desynced.store(self.desynced, Ordering::Relaxed);
    }
}

/// Live `nfqws2` runtime summary returned for a `status` request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Binary package version (e.g., `env!("CARGO_PKG_VERSION")`).
    pub version: String,
    /// Daemon operating system process ID.
    pub pid: u32,
    /// Active NFQUEUE queue number.
    pub qnum: u16,
    /// Configured desync fwmark used to avoid re-intercepting injected packets.
    pub fwmark: u32,
    /// `true` when NFQUEUE packet interception is active (false in `--intercept=0` mode).
    pub intercept: bool,
    /// Ordered profile labels loaded in the active engine.
    pub profile_names: Vec<String>,
    /// Path to the loaded configuration file, when started from TOML.
    pub config_path: Option<String>,
    /// Active PASS packet sampling divisor (`0` disables PASS streaming).
    pub pass_sample_rate: u64,
    /// Current packet outcome counters.
    pub counters: CountersSnapshot,
}

/// Machine-readable error categories returned in [`Response::Error`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlErrorCode {
    /// Client requested an unsupported protocol version during `hello`.
    UnsupportedVersion,
    /// Client issued another command before completing `hello`.
    HandshakeRequired,
    /// Request line was malformed or exceeded protocol bounds.
    BadRequest,
    /// Daemon could not fulfill the command (e.g., invalid config or list reload error).
    CommandFailed,
    /// Daemon is already shutting down.
    ShuttingDown,
}

/// Client-to-daemon control request sent as one JSON line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Negotiates wire protocol compatibility before issuing commands.
    Hello {
        /// Client protocol version (must match [`CONTROL_PROTOCOL_VERSION`]).
        version: u32,
    },
    /// Requests current daemon configuration metadata and packet counters.
    Status,
    /// Subscribes this connection to live `counters` and `packet` telemetry events.
    Subscribe {
        /// Optional client hint requesting a specific PASS sampling divisor (`0` = no PASS).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pass_sample_rate: Option<u64>,
    },
    /// Stops streaming live telemetry events to this connection.
    Unsubscribe,
    /// Reloads hostlist and ipset files in the running daemon engine.
    ReloadLists,
    /// Parses `toml` and swaps active desync profiles live (rejects `qnum`/`fwmark` changes).
    ReloadConfig {
        /// Full replacement `nfqws2.toml` document text.
        toml: String,
    },
    /// Requests graceful shutdown of the running daemon process.
    Stop,
}

/// Daemon-to-client reply or unsolicited telemetry event sent as one JSON line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Successful handshake confirmation returned for [`Request::Hello`].
    HelloOk {
        /// Agreed protocol version.
        version: u32,
        /// Daemon package version string.
        daemon_version: String,
    },
    /// Synchronous acknowledgment for commands such as `subscribe`, `reload_lists`, or `stop`.
    Ack {
        /// Operation name that succeeded (`"subscribe"`, `"unsubscribe"`, `"reload_lists"`, `"stop"`).
        op: String,
        /// Optional human-readable detail returned by the daemon handler.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Full daemon status snapshot returned for [`Request::Status`].
    Status(DaemonStatus),
    /// Periodic or update-driven counters event sent to subscribed clients.
    Counters(CountersSnapshot),
    /// Decoded intercepted packet snapshot sent to subscribed clients.
    Packet(PacketRecord),
    /// Typed protocol or execution failure returned for a client request.
    Error {
        /// Categorized failure code.
        code: ControlErrorCode,
        /// Human-readable diagnostic explanation.
        message: String,
    },
}

/// Validates `client_version` against [`CONTROL_PROTOCOL_VERSION`], reporting skew distinctly.
pub fn validate_protocol_version(client_version: u32) -> Result<(), super::CodecError> {
    if client_version == CONTROL_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(super::CodecError::UnsupportedVersion {
            expected: CONTROL_PROTOCOL_VERSION,
            got: client_version,
        })
    }
}
