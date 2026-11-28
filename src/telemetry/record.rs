//! Serializable packet verdict classification and L3/L4/L7 snapshot decoder.

/// IPv4 and IPv6 address formatting helpers.
use std::net::{Ipv4Addr, Ipv6Addr};

/// Wire serialization for streaming packet records over the control socket.
use serde::{Deserialize, Serialize};

/// Kernel packet metadata recorded per intercepted packet.
use crate::intercepter::QueuedPacket;
/// L3/L4 wire packet dissector and TCP flag bitmasks.
use crate::packet::{TH_ACK, TH_FIN, TH_PUSH, TH_RST, TH_SYN, TH_URG, dissect_packet};
/// L7 protocol probes for TLS SNI, HTTP Host, QUIC Initial, and DNS labels.
use crate::protocol::{
    http_extract_host, is_dns_query, is_dns_response, is_http, is_quic_initial, tls_hello_extract_host,
};

/// Maximum payload bytes copied per captured packet for hex/ASCII preview.
const MAX_PAYLOAD_PREVIEW: usize = 128;

/// High-level reason behind an intercepted packet's kernel verdict.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PacketOutcome
{
    /// Passed unmodified by NFQUEUE (`Decision::Pass`).
    #[default]
    Pass,
    /// Held or re-sent unmodified via raw socket during multi-segment TLS/QUIC reassembly.
    Reasm,
    /// Modified in-place by a matched desync profile (`Decision::Replace`), carrying its profile name.
    Modify(Option<String>),
    /// Replaced or dropped by a matched desync profile (e.g., `multisplit`), carrying its profile name.
    Desync(Option<String>),
}

/// Simplified packet outcome classification displayed in the inspector and control stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketVerdict
{
    /// Packet passed unmodified by NFQUEUE.
    Pass,
    /// Multi-segment TLS/QUIC packet held or re-sent untouched via raw socket (no profile hit).
    Reasm,
    /// Packet payload was modified in-place by a matched profile.
    Modify,
    /// Original packet was replaced/split via raw socket by a matched profile (e.g., `multisplit`).
    Desync,
}

impl PacketVerdict
{
    /// Returns a compact uppercase outcome label.
    pub const fn label(self) -> &'static str
    {
        match self
        {
            Self::Pass => "PASS",
            Self::Reasm => "REASM",
            Self::Modify => "MODIFY",
            Self::Desync => "DESYNC",
        }
    }
}

/// Decoded snapshot of one intercepted packet captured for live inspection or streaming.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketRecord
{
    /// 1-based monotonic capture sequence number.
    pub seq: u64,
    /// Packet direction (`"OUT"` or `"IN"`).
    pub direction: String,
    /// Transport protocol label (`"TCP"`, `"UDP"`, `"ICMP"`, or `"IP"`).
    pub proto: String,
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
    /// Engine outcome classification applied to this packet.
    pub verdict: PacketVerdict,
    /// Matched desync profile name when `verdict` is `Modify` or `Desync`.
    pub profile: Option<String>,
    /// Leading payload bytes (up to 128 bytes) for hex + ASCII inspection.
    pub payload_preview: Vec<u8>,
}

/// Formats active TCP flags (`SYN`, `ACK`, `PSH`, `RST`, `FIN`, `URG`) as a compact CSV string.
fn format_tcp_flags(flags: u8) -> String
{
    let mut parts = Vec::with_capacity(6);
    if (flags & TH_SYN) != 0
    {
        parts.push("SYN");
    }
    if (flags & TH_ACK) != 0
    {
        parts.push("ACK");
    }
    if (flags & TH_PUSH) != 0
    {
        parts.push("PSH");
    }
    if (flags & TH_FIN) != 0
    {
        parts.push("FIN");
    }
    if (flags & TH_RST) != 0
    {
        parts.push("RST");
    }
    if (flags & TH_URG) != 0
    {
        parts.push("URG");
    }
    if parts.is_empty() { "-".to_owned() } else { parts.join(",") }
}

/// Inspects L4 payload bytes for TLS SNI, HTTP Host, QUIC Initial, or DNS tags.
fn detect_l7_info(is_udp: bool, payload: &[u8]) -> Option<String>
{
    if payload.is_empty()
    {
        return None;
    }
    if !is_udp
    {
        if let Some(sni) = tls_hello_extract_host(payload, true)
        {
            return Some(format!("TLS SNI={sni}"));
        }
        if is_http(payload)
        {
            return Some(match http_extract_host(payload)
            {
                Some(host) => format!("HTTP Host={host}"),
                None => "HTTP request".to_owned(),
            });
        }
    }
    else
    {
        if is_quic_initial(payload)
        {
            return Some("QUIC Initial".to_owned());
        }
        if is_dns_query(payload)
        {
            return Some("DNS query".to_owned());
        }
        if is_dns_response(payload)
        {
            return Some("DNS response".to_owned());
        }
    }
    None
}

/// Dissects `pkt` and `outcome` into a lightweight [`PacketRecord`] for inspection or IPC.
pub fn build_packet_record(seq: u64, pkt: &QueuedPacket<'_>, outcome: &PacketOutcome) -> PacketRecord
{
    let (verdict, profile) = match outcome
    {
        PacketOutcome::Pass => (PacketVerdict::Pass, None),
        PacketOutcome::Reasm => (PacketVerdict::Reasm, None),
        PacketOutcome::Modify(prof) => (PacketVerdict::Modify, prof.clone()),
        PacketOutcome::Desync(prof) => (PacketVerdict::Desync, prof.clone()),
    };
    let (direction, iface) = if let Some(out) = pkt.ifout.filter(|s| !s.is_empty())
    {
        ("OUT".to_owned(), out.to_owned())
    }
    else if let Some(inn) = pkt.ifin.filter(|s| !s.is_empty())
    {
        ("IN".to_owned(), inn.to_owned())
    }
    else
    {
        ("OUT".to_owned(), "-".to_owned())
    };

    let dis = dissect_packet(pkt.payload, false);
    let payload = dis.payload.as_deref().unwrap_or(&[]);
    let (src_ip, dst_ip, ttl) = if let Some(ip4) = &dis.ip
    {
        (Ipv4Addr::from(ip4.src).to_string(), Ipv4Addr::from(ip4.dst).to_string(), ip4.ttl)
    }
    else if let Some(ip6) = &dis.ip6
    {
        (format!("[{}]", Ipv6Addr::from(ip6.src)), format!("[{}]", Ipv6Addr::from(ip6.dst)), ip6.hop_limit)
    }
    else
    {
        ("?".to_owned(), "?".to_owned(), 0)
    };

    let (proto, src, dst, tcp_detail, mut info) = if let Some(tcp) = &dis.tcp
    {
        let flags = format_tcp_flags(tcp.flags);
        let detail = format!("seq={} ack={} win={} flags=[{}]", tcp.seq, tcp.ack, tcp.window, flags);
        let info = match detect_l7_info(false, payload)
        {
            Some(tag) => format!("[{flags}] {tag}"),
            None => format!("[{flags}]"),
        };
        (
            "TCP".to_owned(),
            format!("{src_ip}:{}", tcp.s_port),
            format!("{dst_ip}:{}", tcp.d_port),
            Some(detail),
            info,
        )
    }
    else if let Some(udp) = &dis.udp
    {
        let info = detect_l7_info(true, payload).unwrap_or_else(|| format!("len={}", udp.len));
        ("UDP".to_owned(), format!("{src_ip}:{}", udp.s_port), format!("{dst_ip}:{}", udp.d_port), None, info)
    }
    else if let Some(icmp) = &dis.icmp
    {
        ("ICMP".to_owned(), src_ip, dst_ip, None, format!("type={} code={}", icmp.icmp_type, icmp.icmp_code))
    }
    else
    {
        ("IP".to_owned(), src_ip, dst_ip, None, format!("{}B raw", pkt.payload.len()))
    };
    if let Some(ref prof) = profile
    {
        info.push_str(&format!(" ({prof})"));
    }

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
        profile,
        payload_preview: preview_src[..preview_len].to_vec(),
    }
}
