//! Wire-level L3/L4 header structs and dissected packet containers matching `zapret2`'s `dissect` model.

/// Legacy IPv4 + TCP dissected packet returned by [`crate::packet::dissecter::parse_ipv4_tcp`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dissecter {
    /// Parsed IPv4 header.
    pub ip: Ipv4Header,
    /// Parsed TCP header.
    pub tcp: TcpHeader,
    /// Trailing transport payload bytes.
    pub payload: Vec<u8>,
}

/// Parsed fields from an IPv4 header, matching `zapret2`'s Lua `dis.ip` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Header {
    /// IP version nibble (`ip_v`: always 4 for IPv4).
    pub version: u8,
    /// Header length in 32-bit words (`ip_hl`: 5 equals 20 bytes).
    pub header_len: u8,
    /// Type of Service / DSCP + ECN bits (`ip_tos`).
    pub tos: u8,
    /// Total IPv4 datagram length in bytes (`ip_len`).
    pub total_len: u16,
    /// Packet identification field (`ip_id`).
    pub id: u16,
    /// Fragmentation flags and 13-bit offset in 8-byte units (`ip_off`).
    pub frag_off: u16,
    /// Time to Live hop limit (`ip_ttl`).
    pub ttl: u8,
    /// Inner protocol identifier (`ip_p`: 6 = TCP, 17 = UDP, 1 = ICMP).
    pub protocol: u8,
    /// IPv4 header checksum (`ip_sum`).
    pub checksum: u16,
    /// Source IPv4 address octets (`ip_src`).
    pub src: [u8; 4],
    /// Destination IPv4 address octets (`ip_dst`).
    pub dst: [u8; 4],
    /// Raw IPv4 options beyond byte 20 when `header_len > 5`.
    pub options: Vec<u8>,
}

/// One optional entry attached to the end of a TCP header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpOption {
    /// Option kind identifier (0 = END, 1 = NOOP, 8 = Timestamp, 19 = MD5).
    pub kind: u8,
    /// `None` for 1-byte END/NOOP options, or `Some(bytes)` for length-prefixed options.
    pub data: Option<Vec<u8>>,
}

/// Parsed fields from a TCP header, matching `zapret2`'s Lua `dis.tcp` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpHeader {
    /// Sender TCP port (`th_sport`).
    pub s_port: u16,
    /// Destination TCP port (`th_dport`).
    pub d_port: u16,
    /// TCP sequence number (`th_seq`).
    pub seq: u32,
    /// TCP acknowledgment number (`th_ack`).
    pub ack: u32,
    /// Lower 4 reserved bits of the offset byte (`th_x2`).
    pub reserved: u8,
    /// TCP header size in 32-bit words (`th_off`: 5 equals 20 bytes).
    pub data_offset: u8,
    /// TCP flag bits (`th_flags`: FIN/SYN/RST/PSH/ACK/URG/ECE/CWR).
    pub flags: u8,
    /// Advertised receive window size (`th_win`).
    pub window: u16,
    /// TCP header and payload checksum (`th_sum`).
    pub checksum: u16,
    /// Urgent pointer offset (`th_urp`).
    pub urgent_ptr: u16,
    /// Parsed TCP options beyond byte 20.
    pub options: Vec<TcpOption>,
}

/// One parsed IPv6 extension header matching `zapret2`'s Lua `ip6.exthdr[i]` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6ExtHeader {
    /// Protocol identifier of this extension header (e.g. HOPOPTS, FRAGMENT, AH).
    pub header_type: u8,
    /// `Next Header` field stored inside this extension header (`next`).
    pub next_header: u8,
    /// Raw payload bytes after the 2-byte `(next, len/reserved)` prefix.
    pub data: Vec<u8>,
}

/// Parsed fields from an IPv6 base header plus extension header chain (`dis.ip6`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Header {
    /// Version (4 bits = 6), traffic class (8 bits), and flow label (20 bits) (`ip6_flow`).
    pub flow: u32,
    /// Optional explicit payload length (`ip6_plen`); `None` asks reconstruction to auto-compute it.
    pub payload_len: Option<u16>,
    /// Next Header protocol number from the 40-byte base header (`ip6_nxt`).
    pub next_header: u8,
    /// IPv6 Hop Limit (`ip6_hlim`).
    pub hop_limit: u8,
    /// Source IPv6 address bytes (`ip6_src`).
    pub src: [u8; 16],
    /// Destination IPv6 address bytes (`ip6_dst`).
    pub dst: [u8; 16],
    /// Ordered list of IPv6 extension headers (`exthdr`).
    pub exthdr: Vec<Ipv6ExtHeader>,
}

/// Parsed fields from an 8-byte UDP header, matching `zapret2`'s Lua `dis.udp` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpHeader {
    /// Sender UDP port (`uh_sport`).
    pub s_port: u16,
    /// Destination UDP port (`uh_dport`).
    pub d_port: u16,
    /// UDP header + payload length (`uh_ulen`).
    pub len: u16,
    /// UDP checksum (`uh_sum`).
    pub checksum: u16,
}

/// Unified 8-byte ICMPv4/ICMPv6 header matching `zapret2`'s `struct icmp46` and Lua `dis.icmp`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpHeader {
    /// ICMP message type (`icmp_type`).
    pub icmp_type: u8,
    /// ICMP message subtype code (`icmp_code`).
    pub icmp_code: u8,
    /// ICMP checksum (`icmp_cksum`).
    pub checksum: u16,
    /// Rest-of-header 32-bit value in host byte order (`icmp_data`).
    pub data: u32,
}

/// Complete L3/L4 dissected packet view matching `zapret2`'s `struct dissect` and Lua `dis`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DissectedPacket {
    /// Resolved inner L4 protocol number (`l4proto`).
    pub l4proto: u8,
    /// Byte length from start of L4 / post-L3 payload to end of IP payload (`transport_len`).
    pub transport_len: usize,
    /// Total L3 header length in bytes including IPv4 options or IPv6 extension headers (`l3_len`).
    pub l3_len: usize,
    /// Total L4 header length in bytes (`l4_len`), or 0 when unparsed or fragmented.
    pub l4_len: usize,
    /// Byte fragment offset when the packet is an IPv4 or IPv6 fragment (`frag_off`).
    pub frag_off: Option<u16>,
    /// Parsed IPv4 header when L3 is IPv4.
    pub ip: Option<Ipv4Header>,
    /// Parsed IPv6 header when L3 is IPv6.
    pub ip6: Option<Ipv6Header>,
    /// Parsed TCP header when non-fragmented L4 is TCP.
    pub tcp: Option<TcpHeader>,
    /// Parsed UDP header when non-fragmented L4 is UDP.
    pub udp: Option<UdpHeader>,
    /// Parsed ICMPv4/ICMPv6 header when non-fragmented L4 is ICMP or ICMPv6.
    pub icmp: Option<IcmpHeader>,
    /// Application or inner payload bytes; `None` when L3 dissection failed.
    pub payload: Option<Vec<u8>>,
}
