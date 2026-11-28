//! Packet dissection, checksum calculation, validation, and wire reconstruction modules.

/// Bounds-checked big-endian byte cursor and `PEResult`.
pub mod byte_reader;
/// RFC 1071 / RFC 768 checksum accumulators and header fixup helpers.
pub mod checksum;
/// Wire-level protocol constants, sizes, flags, and Lua compatibility version.
pub mod constants;
/// IPv4/TCP/UDP/ICMP header parsers and full L3/L4 packet dissector.
pub mod dissecter;
/// Typed packet parsing and reconstruction error definitions.
pub mod error;
/// IPv4 and IPv6 fragmentation slicing and packet finalizers.
pub mod fragment;
/// Standalone L3 and L4 wire header serializers.
pub mod header_encode;
/// IPv6 extension-header chain traversal and offset lookup.
pub mod ipv6_ext;
/// Full-packet wire reconstruction orchestrator.
pub mod reconstruct;
/// Dissected L3/L4 header and packet structs.
pub mod types;
/// Wire-level header bounds validators and destination extraction.
pub mod validate;

/// Re-exported protocol constants for convenient crate-wide access.
pub use constants::*;
/// Re-exported packet dissection functions.
pub use dissecter::{
    dissect_icmp_header, dissect_ipv4_header, dissect_packet, dissect_tcp_header, dissect_udp_header,
    parse_ipv4_header, parse_ipv4_tcp,
};
/// Re-exported packet error type.
pub use error::PacketError;
/// Re-exported standalone header serializers.
pub use header_encode::{
    reconstruct_icmp_header, reconstruct_ipv4_header, reconstruct_ipv6_header, reconstruct_tcp_header,
    reconstruct_udp_header,
};
/// Re-exported IPv6 extension-header dissector and finder.
pub use ipv6_ext::{dissect_ipv6_header, find_ipv6_exthdr};
/// Re-exported packet reconstruction options and entry point.
pub use reconstruct::{ReconstructOptions, reconstruct_packet};
/// Re-exported packet header and container structs.
pub use types::{
    DissectedPacket, Dissecter, IcmpHeader, Ipv4Header, Ipv6ExtHeader, Ipv6Header, TcpHeader, TcpOption,
    UdpHeader,
};
/// Re-exported header bounds validators and destination extractor.
pub use validate::{
    check_icmp_header, check_ipv4_header, check_ipv4_payload, check_ipv6_header, check_ipv6_payload,
    check_tcp_header, check_udp_header, check_udp_payload, extract_dst,
};
