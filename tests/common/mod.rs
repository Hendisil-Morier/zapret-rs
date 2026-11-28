//! Shared synthetic packet builders and mock [`PacketSender`] fixtures for desync integration tests.

/// Standard IP address type for checking captured destination addresses.
use std::net::IpAddr;

/// Protocol constants used to construct synthetic IPv4, IPv6, TCP, and UDP test packets.
use zapret_rs::packet::constants::{IPPROTO_HOPOPTS, IPPROTO_TCP, IPPROTO_UDP, TH_ACK, TH_PUSH};
/// Wire packet structures and reconstruction helpers.
use zapret_rs::packet::{
    DissectedPacket, Ipv4Header, Ipv6ExtHeader, Ipv6Header, ReconstructOptions, TcpHeader, UdpHeader,
    reconstruct_packet,
};
/// Raw packet sender trait and error type implemented by [`CapturingSender`].
use zapret_rs::rawsend::{PacketSender, RawSendError};

/// Path to `zapret2`'s unmodified `zapret-lib.lua`.
#[allow(dead_code)]
pub const ZAPRET_LIB_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-lib.lua");

/// One packet captured from Lua `rawsend` / `rawsend_dissect` during desync execution.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CapturedPacket
{
    /// Destination IP passed to `PacketSender::send`.
    pub dst: IpAddr,
    /// Effective firewall mark applied to the outgoing socket.
    pub fwmark: u32,
    /// Optional outgoing interface override.
    pub ifout: Option<String>,
    /// Serialized L3/L4 wire bytes.
    pub data: Vec<u8>,
}

/// Mock [`PacketSender`] recording injected packets without `CAP_NET_RAW`.
#[derive(Default)]
#[allow(dead_code)]
pub struct CapturingSender
{
    /// Ordered list of injected packets.
    pub packets: Vec<CapturedPacket>,
}

impl PacketSender for CapturingSender
{
    /// Records one outgoing raw packet into `self.packets`.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>
    {
        self.packets.push(CapturedPacket {
            dst,
            fwmark,
            ifout: ifout.map(str::to_owned),
            data: packet.to_vec(),
        });
        Ok(())
    }
}

/// Builds a valid IPv4 + TCP wire packet with RFC-compliant checksums.
#[allow(dead_code)]
pub fn build_ipv4_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8>
{
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x1234,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: [10, 0, 0, 2],
            dst: [93, 184, 216, 34],
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: src_port,
            d_port: dst_port,
            seq: 1000,
            ack: 2000,
            reserved: 0,
            data_offset: 5,
            flags: TH_ACK | TH_PUSH,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv4 TCP packet must reconstruct")
}

/// Builds a valid IPv4 + UDP wire packet with RFC-compliant checksums.
#[allow(dead_code)]
pub fn build_ipv4_udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8>
{
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x2222,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_UDP,
            checksum: 0,
            src: [10, 0, 0, 2],
            dst: [8, 8, 8, 8],
            options: Vec::new(),
        }),
        udp: Some(UdpHeader { s_port: src_port, d_port: dst_port, len: 0, checksum: 0 }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv4 UDP packet must reconstruct")
}

/// Builds a valid IPv6 + Hop-by-Hop + TCP wire packet.
#[allow(dead_code)]
pub fn build_ipv6_tcp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8>
{
    let dis = DissectedPacket {
        ip6: Some(Ipv6Header {
            flow: 0x6000_0001,
            payload_len: None,
            next_header: IPPROTO_HOPOPTS,
            hop_limit: 64,
            src: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            dst: [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            exthdr: vec![Ipv6ExtHeader {
                header_type: IPPROTO_HOPOPTS,
                next_header: IPPROTO_TCP,
                data: vec![0; 6],
            }],
        }),
        tcp: Some(TcpHeader {
            s_port: src_port,
            d_port: dst_port,
            seq: 500,
            ack: 1,
            reserved: 0,
            data_offset: 5,
            flags: TH_ACK,
            window: 32768,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("synthetic IPv6 TCP packet must reconstruct")
}
