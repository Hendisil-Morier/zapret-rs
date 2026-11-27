//! Configuration constants, queued packet metadata, and verdict decisions for packet interception.

/// Atomic shutdown flag shared with the packet interception loop.
use std::sync::atomic::AtomicBool;
/// Poll timeout duration returned by the caller's timer scheduler.
use std::time::Duration;

/// Typed interception error returned by [`PacketIntercepter`] implementations.
use crate::intercepter::error::IntercepterError;
/// Default Linux NFQUEUE number and loop-prevention firewall mark shared across config and Lua.
pub use crate::packet::constants::{DEFAULT_DESYNC_FWMARK, DEFAULT_QUEUE_NUM};

/// Default Linux NFQUEUE kernel packet backlog (`Q_MAXLEN` in `params.h`).
pub const DEFAULT_QUEUE_MAXLEN: u32 = 4096;
/// Default Linux NFQUEUE netlink socket receive buffer size in bytes (`Q_RCVBUF` in `params.h`).
pub const DEFAULT_QUEUE_RCVBUF: usize = 1024 * 1024;

/// Kernel NFQUEUE binding and loop-prevention settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueConfig {
    /// Netfilter queue number (`--qnum`).
    pub queue_num: u16,
    /// Firewall mark bitmask used by generated raw packets to bypass re-processing.
    pub desync_fwmark: u32,
    /// Maximum number of packets queued in the kernel before fail-open/drop triggers.
    pub queue_maxlen: u32,
    /// Requested netlink receive socket buffer size (`SO_RCVBUF`).
    pub rcvbuf_bytes: usize,
    /// Whether the kernel should accept overflow packets instead of dropping them (`NFQA_CFG_F_FAIL_OPEN`).
    pub fail_open: bool,
}

impl Default for QueueConfig {
    /// Returns the standard `zapret2` Linux NFQUEUE defaults.
    fn default() -> Self {
        Self {
            queue_num: DEFAULT_QUEUE_NUM,
            desync_fwmark: DEFAULT_DESYNC_FWMARK,
            queue_maxlen: DEFAULT_QUEUE_MAXLEN,
            rcvbuf_bytes: DEFAULT_QUEUE_RCVBUF,
            fail_open: true,
        }
    }
}

impl QueueConfig {
    /// Returns default NFQUEUE settings bound to `queue_num`.
    pub fn with_queue_num(queue_num: u16) -> Self {
        Self {
            queue_num,
            ..Self::default()
        }
    }

    /// Returns default NFQUEUE settings overriding both `queue_num` and `desync_fwmark`.
    pub fn with_fwmark(queue_num: u16, desync_fwmark: u32) -> Self {
        Self {
            queue_num,
            desync_fwmark,
            ..Self::default()
        }
    }
}

/// Borrowed view of an intercepted NFQUEUE packet and its resolved interface metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedPacket<'a> {
    /// Netfilter packet sequence identifier within the queue.
    pub packet_id: u32,
    /// Kernel netfilter mark (`nfmark` / `fwmark`) attached to the skb.
    pub mark: u32,
    /// Resolved incoming interface name, if present (`indev > 0`).
    pub ifin: Option<&'a str>,
    /// Resolved outgoing interface name, if present (`outdev > 0`).
    pub ifout: Option<&'a str>,
    /// Raw L3/L4 wire packet bytes received from the kernel queue.
    pub payload: &'a [u8],
}

/// Final verdict returned to the kernel for an intercepted packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Accept and continue forwarding the original packet unmodified.
    Pass,
    /// Drop the packet silently inside netfilter.
    Drop,
    /// Replace the packet bytes with the supplied payload before accepting.
    Replace(Vec<u8>),
}

/// OS-agnostic packet interception loop contract implemented by platform drivers such as `QueueCatcher`.
pub trait PacketIntercepter {
    /// Runs the non-blocking interception loop until `stop` becomes `true`.
    fn run_until<F, T>(
        &mut self,
        stop: &AtomicBool,
        next_timeout: T,
        on_packet: F,
    ) -> Result<(), IntercepterError>
    where
        F: FnMut(&QueuedPacket<'_>) -> Decision,
        T: FnMut() -> Option<Duration>;
}
