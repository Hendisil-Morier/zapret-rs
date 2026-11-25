//! Core connection tracking tuple keys, directional counters, timestamps, and delayed replay snapshots.

/// Standard IP address representation shared between IPv4 and IPv6 5-tuple keys.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Protocol numbers (`IPPROTO_*`) used to key L3/L4 connection tuples cleanly.
use crate::packet::constants::{IPPROTO_IP, IPPROTO_IPV6, IPPROTO_TCP, IPPROTO_UDP};
/// Dissected packet view extracted into bidirectional 5-tuple connection keys.
use crate::packet::types::DissectedPacket;
/// Monotonic boottime `timespec` representation matching `zapret2`'s `t_start`/`t_last`.
use crate::timer::MonotonicTime;

/// Default idle timeout in seconds for connections in `SYN` state (`CTRACK_T_SYN`).
pub const DEFAULT_CTRACK_TIMEOUT_SYN: u32 = 60;
/// Default idle timeout in seconds for connections in `ESTABLISHED` state (`CTRACK_T_EST`).
pub const DEFAULT_CTRACK_TIMEOUT_EST: u32 = 300;
/// Default idle timeout in seconds for connections in `FIN`/`RST` state (`CTRACK_T_FIN`).
pub const DEFAULT_CTRACK_TIMEOUT_FIN: u32 = 60;
/// Default idle timeout in seconds for UDP flows (`CTRACK_T_UDP`).
pub const DEFAULT_CTRACK_TIMEOUT_UDP: u32 = 60;
/// Default interval in seconds between rate-limited conntrack purge scans (`nfqws.c`).
pub const DEFAULT_CTRACK_PURGE_INTERVAL: i64 = 10;
/// Default maximum number of active flows tracked simultaneously (`DEFAULT_CTRACK_MAX_ENTRIES`).
pub const DEFAULT_CTRACK_MAX_ENTRIES: usize = 65_536;
/// Sentinel value disabling further retransmission counting (`RETRANS_COUNTER_STOP` = `255`).
pub const RETRANS_COUNTER_STOP: u8 = u8::MAX;
/// Maximum number of raw packets queued while reassembling one multi-segment payload.
pub const RAW_PACKET_QUEUE_DELAYED_MAX: usize = 64;
/// Maximum client-side TCP payload buffer size in bytes (`TCP_MAX_REASM`).
pub const TCP_MAX_REASM: usize = 16384;
/// Maximum client-side UDP decrypted payload buffer size in bytes (`UDP_MAX_REASM`).
pub const UDP_MAX_REASM: usize = 16384;

/// 5-tuple lookup key identifying a single TCP or UDP flow (`t_conn` in `conntrack.h`).
///
/// Client initiator endpoints are always stored in `(src, sport)` and server responder
/// endpoints in `(dst, dport)`, with `l3proto` equal to `IPPROTO_IP` or `IPPROTO_IPV6`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnKey {
    /// Initiating (client) L3 IPv4 or IPv6 address.
    pub src: IpAddr,
    /// Responding (server) L3 IPv4 or IPv6 address.
    pub dst: IpAddr,
    /// Initiating (client) TCP/UDP port in host byte order.
    pub sport: u16,
    /// Responding (server) TCP/UDP port in host byte order.
    pub dport: u16,
    /// Network layer protocol identifier (`IPPROTO_IP` = 0 or `IPPROTO_IPV6` = 41).
    pub l3proto: u8,
    /// Transport layer protocol identifier (`IPPROTO_TCP` = 6 or `IPPROTO_UDP` = 17).
    pub l4proto: u8,
}

impl ConnKey {
    /// Extracts a normalized 5-tuple from `dis`, returning `None` for non-TCP/UDP or invalid L3 packets.
    ///
    /// Passing `reverse = true` swaps source/destination addresses and ports (used when a
    /// `SYN-ACK` creates the connection entry so `src/sport` still represents the client).
    pub fn extract(dis: &DissectedPacket, reverse: bool) -> Option<Self> {
        let (l3proto, ip_src, ip_dst) = match (&dis.ip, &dis.ip6) {
            (Some(ip), None) => (
                IPPROTO_IP,
                IpAddr::V4(Ipv4Addr::from(ip.src)),
                IpAddr::V4(Ipv4Addr::from(ip.dst)),
            ),
            (None, Some(ip6)) => (
                IPPROTO_IPV6,
                IpAddr::V6(Ipv6Addr::from(ip6.src)),
                IpAddr::V6(Ipv6Addr::from(ip6.dst)),
            ),
            _ => return None,
        };

        let (l4proto, p_src, p_dst) = match (&dis.tcp, &dis.udp) {
            (Some(tcp), None) => (IPPROTO_TCP, tcp.s_port, tcp.d_port),
            (None, Some(udp)) => (IPPROTO_UDP, udp.s_port, udp.d_port),
            _ => return None,
        };

        if reverse {
            Some(Self {
                src: ip_dst,
                dst: ip_src,
                sport: p_dst,
                dport: p_src,
                l3proto,
                l4proto,
            })
        } else {
            Some(Self {
                src: ip_src,
                dst: ip_dst,
                sport: p_src,
                dport: p_dst,
                l3proto,
                l4proto,
            })
        }
    }

    /// Returns a copy with source and destination addresses and ports exchanged.
    pub const fn swapped(self) -> Self {
        Self {
            src: self.dst,
            dst: self.src,
            sport: self.dport,
            dport: self.sport,
            l3proto: self.l3proto,
            l4proto: self.l4proto,
        }
    }
}

/// High-level TCP connection lifecycle state matching `zapret2`'s `t_connstate`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ConnState {
    /// Initial handshake phase before non-SYN traffic arrives (`SYN`).
    #[default]
    Syn,
    /// Active data-transfer phase (`ESTABLISHED`).
    Established,
    /// Closing or reset phase after observing `TH_FIN` or `TH_RST` (`FIN`).
    Fin,
}

/// Per-direction packet, byte, IPv6 flow, and TCP sequence tracking state (`t_ctrack_position`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CtrackPosition {
    /// Total packets observed from this endpoint (`pcounter`).
    pub pcounter: u64,
    /// Packets carrying non-zero L4 payload observed from this endpoint (`pdcounter`).
    pub pdcounter: u64,
    /// Cumulative L4 payload bytes sent by this endpoint including retransmissions (`pbcounter`).
    pub pbcounter: u64,
    /// Host-order IPv6 version/traffic-class/flow-label word captured on TCP traffic (`ip6flow`).
    pub ip6flow: u32,
    /// Ending TCP sequence number of the last packet sent by this endpoint (`seq_last + payload_len`).
    pub pos: u32,
    /// Highest cumulative TCP sequence end observed from this endpoint (`uppos`).
    pub uppos: u32,
    /// Value of `uppos` prior to the current data packet, used to detect retransmissions (`uppos_prev`).
    pub uppos_prev: u32,
    /// Most recent TCP `th_seq` sent by this endpoint (`seq_last`) or ACK observed from peer.
    pub seq_last: u32,
    /// Initial TCP sequence number established during `SYN` / `SYN-ACK` (`seq0`).
    pub seq0: u32,
    /// Unscaled advertised TCP receive window (`th_win`).
    pub winsize: u16,
    /// Negotiated TCP Maximum Segment Size option from `SYN`/`SYN-ACK` (`0` if omitted).
    pub mss: u16,
    /// Scaled TCP window size (`winsize << scale` after `SYN` phase completes).
    pub winsize_calc: u32,
    /// Negotiated RFC 7323 TCP window scale shift factor (`0..=14`).
    pub scale: u8,
    /// Sticky latch set once modular sequence delta `seq_last - seq0` crosses 2 GiB (`rseq_over_2G`).
    pub rseq_over_2g: bool,
}

impl CtrackPosition {
    /// Returns the relative starting sequence offset (`seq_last - seq0`) in modular 32-bit space.
    pub const fn rseq(self) -> u32 {
        self.seq_last.wrapping_sub(self.seq0)
    }

    /// Returns the relative end sequence position (`pos - seq0`) in modular 32-bit space.
    pub const fn rel_pos(self) -> u32 {
        self.pos.wrapping_sub(self.seq0)
    }

    /// Returns the relative high-water sequence offset (`uppos - seq0`) in modular 32-bit space.
    pub const fn rel_uppos(self) -> u32 {
        self.uppos.wrapping_sub(self.seq0)
    }

    /// Returns the prior relative high-water offset (`uppos_prev - seq0`) in modular 32-bit space.
    pub const fn rel_uppos_prev(self) -> u32 {
        self.uppos_prev.wrapping_sub(self.seq0)
    }

    /// Returns `true` when the latest segment ended at or behind `uppos_prev` (`!((uppos_prev - pos) & 0x8000_0000)`).
    pub const fn is_retransmission(self) -> bool {
        (self.uppos_prev.wrapping_sub(self.pos) & 0x8000_0000) == 0
    }
}

/// Snapshot of connection state timestamps and bidirectional positions (`t_ctrack_positions`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CtrackPositions {
    /// Monotonic boottime of the most recent packet belonging to this flow.
    pub t_last: MonotonicTime,
    /// Current TCP handshake/teardown state (`Syn` for UDP flows until inactivity purge).
    pub state: ConnState,
    /// Traffic counters and TCP sequence state originating from the client endpoint.
    pub client: CtrackPosition,
    /// Traffic counters and TCP sequence state originating from the server endpoint.
    pub server: CtrackPosition,
    /// Wire L4 protocol number (`IPPROTO_TCP` or `IPPROTO_UDP`).
    pub ipproto: u8,
}

/// Queued raw packet and frozen conntrack position snapshot held during stream reassembly.
#[derive(Debug, Clone)]
pub struct DelayedPacket {
    /// Original L3 packet bytes captured at interception time.
    pub raw: Vec<u8>,
    /// Kernel netfilter mark attached to the packet (`nfmark`).
    pub fwmark: u32,
    /// Incoming network interface name at interception time, if known.
    pub ifin: Option<String>,
    /// Outgoing network interface name at interception time, if known.
    pub ifout: Option<String>,
    /// Connection position snapshot frozen at the moment this segment arrived.
    pub tpos: CtrackPositions,
}

/// Idle expiration thresholds (seconds) and purge cadence configured for [`crate::conntrack::ConntrackPool`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackTimeouts {
    /// Expiration timeout in seconds for connections in [`ConnState::Syn`].
    pub syn: u32,
    /// Expiration timeout in seconds for connections in [`ConnState::Established`].
    pub established: u32,
    /// Expiration timeout in seconds for connections in [`ConnState::Fin`].
    pub fin: u32,
    /// Expiration timeout in seconds for UDP flows.
    pub udp: u32,
    /// Minimum elapsed seconds between periodic conntrack expiration sweeps.
    pub purge_interval: i64,
}

impl Default for ConntrackTimeouts {
    /// Returns `zapret2`'s default timeouts (`60:300:60:60`, purge interval `10s`).
    fn default() -> Self {
        Self {
            syn: DEFAULT_CTRACK_TIMEOUT_SYN,
            established: DEFAULT_CTRACK_TIMEOUT_EST,
            fin: DEFAULT_CTRACK_TIMEOUT_FIN,
            udp: DEFAULT_CTRACK_TIMEOUT_UDP,
            purge_interval: DEFAULT_CTRACK_PURGE_INTERVAL,
        }
    }
}
