//! Live packet inspector data model, L3/L4/L7 record decoder, and verdict filter state.

/// Bounded ring buffer holding recently captured packets for Tab 2 inspection.
use std::collections::VecDeque;
/// IPv4 and IPv6 address formatting helpers.
use std::net::{Ipv4Addr, Ipv6Addr};

/// Keyboard codes handled by [`PacketInspectorState`].
use crossterm::event::KeyCode;
/// Terminal color mapping for verdict badges.
use ratatui::style::Color;

/// Kernel packet metadata and verdict decision recorded per intercepted packet.
use crate::intercepter::{Decision, QueuedPacket};
/// L3/L4 wire packet dissector and TCP flag bitmasks.
use crate::packet::{TH_ACK, TH_FIN, TH_PUSH, TH_RST, TH_SYN, TH_URG, dissect_packet};
/// L7 protocol probes for TLS SNI, HTTP Host, QUIC Initial, and DNS labels.
use crate::protocol::{
    http_extract_host, is_dns_query, is_dns_response, is_http, is_quic_initial,
    tls_hello_extract_host,
};

/// Maximum payload bytes copied per captured packet for hex/ASCII preview.
const MAX_PAYLOAD_PREVIEW: usize = 128;
/// Maximum recent packets retained in memory for live TUI inspection.
const MAX_INSPECT_PACKETS: usize = 300;

/// Simplified verdict classification displayed in the live packet table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketVerdict {
    /// Packet passed unmodified (`Decision::Pass`).
    Pass,
    /// Packet payload was modified in-place (`Decision::Replace`).
    Modify,
    /// Original packet was dropped (typically replaced by split/fake sends, `Decision::Drop`).
    Drop,
}

impl PacketVerdict {
    /// Returns a compact uppercase verdict label.
    pub const fn label(self) -> &'static str {
        match self { Self::Pass => "PASS", Self::Modify => "MODIFY", Self::Drop => "DROP" }
    }

    /// Returns the terminal color associated with this verdict.
    pub const fn color(self) -> Color {
        match self { Self::Pass => Color::Green, Self::Modify => Color::Yellow, Self::Drop => Color::Red }
    }
}

/// Interactive verdict filter cycled via `f` on Tab 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictFilter {
    /// Display all packets.
    All,
    /// Display only `MODIFY` and `DROP` packets (desynced traffic).
    ModifiedOrDropped,
    /// Display only `DROP` packets.
    DropOnly,
    /// Display only `PASS` packets.
    PassOnly,
}

impl VerdictFilter {
    /// Cycles through `All -> ModifiedOrDropped -> DropOnly -> PassOnly -> All`.
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::ModifiedOrDropped,
            Self::ModifiedOrDropped => Self::DropOnly,
            Self::DropOnly => Self::PassOnly,
            Self::PassOnly => Self::All,
        }
    }

    /// Returns a short display badge for the table title.
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::ModifiedOrDropped => "MOD+DROP",
            Self::DropOnly => "DROP",
            Self::PassOnly => "PASS",
        }
    }

    /// Returns `true` when `verdict` passes this filter.
    pub const fn matches(self, verdict: PacketVerdict) -> bool {
        match self {
            Self::All => true,
            Self::ModifiedOrDropped => matches!(verdict, PacketVerdict::Modify | PacketVerdict::Drop),
            Self::DropOnly => matches!(verdict, PacketVerdict::Drop),
            Self::PassOnly => matches!(verdict, PacketVerdict::Pass),
        }
    }
}

/// Decoded snapshot of one intercepted packet captured on Tab 2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord {
    /// 1-based monotonic capture sequence number.
    pub seq: u64,
    /// Packet direction (`"OUT"` or `"IN"`).
    pub direction: &'static str,
    /// Transport protocol label (`"TCP"`, `"UDP"`, `"ICMP"`, or `"IP"`).
    pub proto: &'static str,
    /// Formatted source endpoint (`ip:port` or `ip`).
    pub src: String,
    /// Formatted destination endpoint (`ip:port` or `ip`).
    pub dst: String,
    /// IPv4 TTL or IPv6 Hop Limit.
    pub ttl: u8,
    /// Kernel firewall mark (`nfmark`).
    pub fwmark: u32,
    /// Relevant network interface name (`ifout` for outgoing, `ifin` for incoming).
    pub iface: String,
    /// L4 payload byte length.
    pub payload_len: usize,
    /// Detailed TCP header fields for the detail modal (`None` for non-TCP).
    pub tcp_detail: Option<String>,
    /// Concise summary (TCP flags + decoded TLS SNI, HTTP Host, QUIC, or DNS tag).
    pub info: String,
    /// Engine verdict applied to this packet.
    pub verdict: PacketVerdict,
    /// Leading payload bytes (up to 128 bytes) for hex + ASCII inspection.
    pub payload_preview: Vec<u8>,
}

/// Self-contained state for Tab 2's live Packet Inspector table and detail popup.
#[derive(Debug)]
pub struct PacketInspectorState {
    /// Bounded ring buffer of recently captured packets (oldest at front, newest at back).
    pub packets: VecDeque<PacketRecord>,
    /// Active verdict filter (`ALL`, `MOD+DROP`, `DROP`, `PASS`).
    pub filter: VerdictFilter,
    /// When `true`, incoming packets are ignored so the current table stays frozen.
    pub paused: bool,
    /// 0-based selection index into newest-first filtered packets.
    pub selected: usize,
    /// When `true`, renders the centered detail popup for the selected packet.
    pub detail_open: bool,
}

impl Default for PacketInspectorState {
    /// Returns an empty, live (`paused = false`) inspector showing all verdicts.
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            filter: VerdictFilter::All,
            paused: false,
            selected: 0,
            detail_open: false,
        }
    }
}

impl PacketInspectorState {
    /// Records one packet unless paused, enforcing [`MAX_INSPECT_PACKETS`].
    pub fn push(&mut self, record: PacketRecord) {
        if self.paused {
            return;
        }
        if self.packets.len() >= MAX_INSPECT_PACKETS {
            self.packets.pop_front();
        }
        self.packets.push_back(record);
    }

    /// Clears captured packets and resets selection/detail state.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.selected = 0;
        self.detail_open = false;
    }

    /// Returns the currently selected packet under the active [`VerdictFilter`], if any.
    pub fn selected_record(&self) -> Option<&PacketRecord> {
        let visible = filtered_packets(&self.packets, self.filter);
        if visible.is_empty() {
            return None;
        }
        let idx = self.selected.min(visible.len() - 1);
        visible.get(idx).copied()
    }

    /// Handles inspector navigation/filter/pause/detail keys; returns `Some(status)` when consumed.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<String> {
        if self.detail_open {
            if matches!(code, KeyCode::Esc | KeyCode::Char('d') | KeyCode::Enter) {
                self.detail_open = false;
                return Some("Closed packet detail.".to_owned());
            }
            return Some(String::new());
        }
        let count = filtered_packets(&self.packets, self.filter).len();
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Some(String::new())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if count > 0 {
                    self.selected = (self.selected + 1).min(count - 1);
                }
                Some(String::new())
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.selected = 0;
                Some(format!("Packet filter: {}", self.filter.label()))
            }
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                Some(if self.paused { "Packet inspector paused." } else { "Packet inspector resumed." }.to_owned())
            }
            KeyCode::Char('d') => {
                if self.selected_record().is_some() {
                    self.detail_open = true;
                    Some("Viewing packet detail (press Esc or d to close).".to_owned())
                } else {
                    Some("No packet selected to inspect.".to_owned())
                }
            }
            _ => None,
        }
    }
}

/// Returns filtered packet references in newest-first display order.
pub fn filtered_packets(packets: &VecDeque<PacketRecord>, filter: VerdictFilter) -> Vec<&PacketRecord> {
    packets.iter().rev().filter(|p| filter.matches(p.verdict)).collect()
}

/// Formats active TCP flags (`SYN`, `ACK`, `PSH`, `RST`, `FIN`, `URG`) as a compact CSV string.
fn format_tcp_flags(flags: u8) -> String {
    let mut parts = Vec::with_capacity(6);
    if (flags & TH_SYN) != 0 { parts.push("SYN"); }
    if (flags & TH_ACK) != 0 { parts.push("ACK"); }
    if (flags & TH_PUSH) != 0 { parts.push("PSH"); }
    if (flags & TH_FIN) != 0 { parts.push("FIN"); }
    if (flags & TH_RST) != 0 { parts.push("RST"); }
    if (flags & TH_URG) != 0 { parts.push("URG"); }
    if parts.is_empty() { "-".to_owned() } else { parts.join(",") }
}

/// Inspects L4 payload bytes for TLS SNI, HTTP Host, QUIC Initial, or DNS tags.
fn detect_l7_info(is_udp: bool, payload: &[u8]) -> Option<String> {
    if payload.is_empty() {
        return None;
    }
    if !is_udp {
        if let Some(sni) = tls_hello_extract_host(payload, true) {
            return Some(format!("TLS SNI={sni}"));
        }
        if is_http(payload) {
            return Some(match http_extract_host(payload) {
                Some(host) => format!("HTTP Host={host}"),
                None => "HTTP request".to_owned(),
            });
        }
    } else {
        if is_quic_initial(payload) { return Some("QUIC Initial".to_owned()); }
        if is_dns_query(payload) { return Some("DNS query".to_owned()); }
        if is_dns_response(payload) { return Some("DNS response".to_owned()); }
    }
    None
}

/// Dissects `pkt` and `decision` into a lightweight [`PacketRecord`] for the TUI inspector.
pub fn build_packet_record(seq: u64, pkt: &QueuedPacket<'_>, decision: &Decision) -> PacketRecord {
    let verdict = match decision {
        Decision::Pass => PacketVerdict::Pass,
        Decision::Replace(_) => PacketVerdict::Modify,
        Decision::Drop => PacketVerdict::Drop,
    };
    let (direction, iface) = if let Some(out) = pkt.ifout.filter(|s| !s.is_empty()) {
        ("OUT", out.to_owned())
    } else if let Some(inn) = pkt.ifin.filter(|s| !s.is_empty()) {
        ("IN", inn.to_owned())
    } else {
        ("OUT", "-".to_owned())
    };

    let dis = dissect_packet(pkt.payload, false);
    let payload = dis.payload.as_deref().unwrap_or(&[]);
    let (src_ip, dst_ip, ttl) = if let Some(ip4) = &dis.ip {
        (Ipv4Addr::from(ip4.src).to_string(), Ipv4Addr::from(ip4.dst).to_string(), ip4.ttl)
    } else if let Some(ip6) = &dis.ip6 {
        (format!("[{}]", Ipv6Addr::from(ip6.src)), format!("[{}]", Ipv6Addr::from(ip6.dst)), ip6.hop_limit)
    } else {
        ("?".to_owned(), "?".to_owned(), 0)
    };

    let (proto, src, dst, tcp_detail, info) = if let Some(tcp) = &dis.tcp {
        let flags = format_tcp_flags(tcp.flags);
        let detail = format!("seq={} ack={} win={} flags=[{}]", tcp.seq, tcp.ack, tcp.window, flags);
        let info = match detect_l7_info(false, payload) {
            Some(tag) => format!("[{flags}] {tag}"),
            None => format!("[{flags}]"),
        };
        ("TCP", format!("{src_ip}:{}", tcp.s_port), format!("{dst_ip}:{}", tcp.d_port), Some(detail), info)
    } else if let Some(udp) = &dis.udp {
        let info = detect_l7_info(true, payload).unwrap_or_else(|| format!("len={}", udp.len));
        ("UDP", format!("{src_ip}:{}", udp.s_port), format!("{dst_ip}:{}", udp.d_port), None, info)
    } else if let Some(icmp) = &dis.icmp {
        ("ICMP", src_ip, dst_ip, None, format!("type={} code={}", icmp.icmp_type, icmp.icmp_code))
    } else {
        ("IP", src_ip, dst_ip, None, format!("{}B raw", pkt.payload.len()))
    };

    let preview_src = if payload.is_empty() { pkt.payload } else { payload };
    let preview_len = preview_src.len().min(MAX_PAYLOAD_PREVIEW);

    PacketRecord {
        seq,
        direction,
        proto,
        src,
        dst,
        ttl,
        fwmark: pkt.mark,
        iface,
        payload_len: payload.len(),
        tcp_detail,
        info,
        verdict,
        payload_preview: preview_src[..preview_len].to_vec(),
    }
}
