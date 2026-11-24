#[derive(Debug, Clone)]
pub struct Dissecter
{
    pub ip: Ipv4Header,
    pub tcp: TcpHeader,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,      // ip_v: always 4 for IPv4
    pub header_len: u8,   // ip_hl: size in 4-byte chunks (5 -> 20 bytes)
    pub tos: u8,          // ip_tos: traffic priority bits
    pub total_len: u16,   // ip_len: full packet size in bytes
    pub id: u16,          // ip_id: packet ID (often changed by bypass tricks)
    pub frag_off: u16,    // ip_off: fragmentation flags and offset
    pub ttl: u8,          // ip_ttl: hop limit (decoys lower this to expire early)
    pub protocol: u8,     // ip_p: inner protocol (6 = TCP, 17 = UDP)
    pub checksum: u16,    // ip_sum: error-check value for the IPv4 header
    pub src: [u8; 4],     // ip_src: sender IP (e.g. [192, 168, 1, 5])
    pub dst: [u8; 4],     // ip_dst: destination IP
    pub options: Vec<u8>, // optional extra bytes when header_len > 5
}

/// One optional entry attached to the end of a TCP header.
#[derive(Debug, Clone)]
pub struct TcpOption {
    pub kind: u8,              // option ID (0 = END, 1 = NOOP, 8 = Timestamp, 19 = MD5)
    pub data: Option<Vec<u8>>, // None for 1-byte options (END/NOOP), Some(bytes) for others
}

/// Parsed fields from a TCP header, matching zapret2's Lua `dis.tcp` table.
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub s_port: u16,              // th_sport: sender port
    pub d_port: u16,              // th_dport: destination port (443 for HTTPS)
    pub seq: u32,                // th_seq: byte position in the stream (used for splitting)
    pub ack: u32,                // th_ack: last byte position confirmed by the other side
    pub reserved: u8,            // th_x2: 4 reserved bits (normally 0)
    pub data_offset: u8,         // th_off: header size in 4-byte chunks (5 -> 20 bytes)
    pub flags: u8,               // th_flags: bit flags (SYN, ACK, PSH, RST, FIN)
    pub window: u16,             // th_win: how many bytes the receiver is ready to take
    pub checksum: u16,           // th_sum: error-check value for TCP header + payload
    pub urgent_ptr: u16,         // th_urp: urgent byte offset (used by rare OOB tricks)
    pub options: Vec<TcpOption>, // extra options appended past the first 20 bytes
}
