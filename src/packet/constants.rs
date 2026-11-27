//! Wire-level protocol constants, header sizes, flags, and Lua compatibility identifiers
//! matching `zapret2`'s `nfq2/lua.c`, `nfq2/darkmagic.h`, and Linux `<netinet/*.h>`.

/// Compatibility version checked by `zapret-lib.lua` on startup (`NFQWS2_COMPAT_VER`).
pub const LUA_COMPAT_VER: u32 = 6;
/// Default IPv6 MSS assumed when no MSS TCP option is negotiated (`DEFAULT_MSS`).
pub const DEFAULT_MSS: u16 = 1220;
/// Maximum buffer size for packet reconstruction (`RECONSTRUCT_MAX_SIZE`).
pub const RECONSTRUCT_MAX_SIZE: usize = 65536;
/// Default raw socket send buffer sizing constant (`RAW_SNDBUF`).
pub const RAW_SNDBUF: usize = 64 * 1024;
/// Default Linux NFQUEUE queue number matching `zapret2`.
pub const DEFAULT_QUEUE_NUM: u16 = 200;
/// Default firewall mark applied to injected raw packets to prevent NFQUEUE loops.
pub const DEFAULT_DESYNC_FWMARK: u32 = 0x4000_0000;

/// Verdict: pass the packet unmodified (`VERDICT_PASS`).
pub const VERDICT_PASS: u8 = 0;
/// Verdict: accept the packet with modified bytes (`VERDICT_MODIFY`).
pub const VERDICT_MODIFY: u8 = 1;
/// Verdict: drop the original packet (`VERDICT_DROP`).
pub const VERDICT_DROP: u8 = 2;
/// Bitmask extracting the base verdict action (`VERDICT_MASK`).
pub const VERDICT_MASK: u8 = 3;
/// Verdict flag: preserve `next` fields in IPv6 extension headers (`VERDICT_PRESERVE_NEXT`).
pub const VERDICT_PRESERVE_NEXT: u8 = 4;
/// Verdict flag: skip transport checksum recalculation (`VERDICT_NOCSUM`).
pub const VERDICT_NOCSUM: u8 = 8;
/// Bitmask of valid verdict flags returned from Lua desync callbacks (`VERDICT_MASK_VALID_LUA`).
pub const VERDICT_MASK_VALID_LUA: u8 = VERDICT_MASK | VERDICT_PRESERVE_NEXT;

/// Minimum IPv4 header length in bytes (`IP_BASE_LEN`).
pub const IP_BASE_LEN: usize = 20;
/// Fixed IPv6 base header length in bytes (`IP6_BASE_LEN`).
pub const IP6_BASE_LEN: usize = 40;
/// Minimum TCP header length in bytes (`TCP_BASE_LEN`).
pub const TCP_BASE_LEN: usize = 20;
/// Fixed UDP header length in bytes (`UDP_BASE_LEN`).
pub const UDP_BASE_LEN: usize = 8;
/// Fixed ICMPv4/ICMPv6 base header length in bytes (`ICMP_BASE_LEN`).
pub const ICMP_BASE_LEN: usize = 8;
/// Maximum byte length of IPv4 options (`60 - 20`).
pub const MAX_IP4_OPTIONS_LEN: usize = 40;
/// Maximum byte length of TCP options (`60 - 20`).
pub const MAX_TCP_OPTIONS_LEN: usize = 40;

/// TCP option kind: End of Option List (`TCP_KIND_END`).
pub const TCP_KIND_END: u8 = 0;
/// TCP option kind: No-Operation (`TCP_KIND_NOOP`).
pub const TCP_KIND_NOOP: u8 = 1;
/// TCP option kind: Maximum Segment Size (`TCP_KIND_MSS`).
pub const TCP_KIND_MSS: u8 = 2;
/// TCP option kind: Window Scale (`TCP_KIND_SCALE`).
pub const TCP_KIND_SCALE: u8 = 3;
/// TCP option kind: SACK Permitted (`TCP_KIND_SACK_PERM`).
pub const TCP_KIND_SACK_PERM: u8 = 4;
/// TCP option kind: Selective Acknowledgment (`TCP_KIND_SACK`).
pub const TCP_KIND_SACK: u8 = 5;
/// TCP option kind: Timestamps (`TCP_KIND_TS`).
pub const TCP_KIND_TS: u8 = 8;
/// TCP option kind: MD5 Signature (`TCP_KIND_MD5`).
pub const TCP_KIND_MD5: u8 = 19;
/// TCP option kind: TCP Authentication Option (`TCP_KIND_AO`).
pub const TCP_KIND_AO: u8 = 29;
/// TCP option kind: TCP Fast Open Cookie (`TCP_KIND_FASTOPEN`).
pub const TCP_KIND_FASTOPEN: u8 = 34;

/// TCP flag bit: FIN (`TH_FIN`).
pub const TH_FIN: u8 = 0x01;
/// TCP flag bit: SYN (`TH_SYN`).
pub const TH_SYN: u8 = 0x02;
/// TCP flag bit: RST (`TH_RST`).
pub const TH_RST: u8 = 0x04;
/// TCP flag bit: PSH (`TH_PUSH`).
pub const TH_PUSH: u8 = 0x08;
/// TCP flag bit: ACK (`TH_ACK`).
pub const TH_ACK: u8 = 0x10;
/// TCP flag bit: URG (`TH_URG`).
pub const TH_URG: u8 = 0x20;
/// TCP flag bit: ECE (`TH_ECE`).
pub const TH_ECE: u8 = 0x40;
/// TCP flag bit: CWR (`TH_CWR`).
pub const TH_CWR: u8 = 0x80;

/// IPv4 header flag: reserved evil bit (`IP_RF`).
pub const IP_RF: u16 = 0x8000;
/// IPv4 header flag: Don't Fragment (`IP_DF`).
pub const IP_DF: u16 = 0x4000;
/// IPv4 header flag: More Fragments (`IP_MF`).
pub const IP_MF: u16 = 0x2000;
/// IPv4 header mask for the 13-bit fragment offset in 8-byte units (`IP_OFFMASK`).
pub const IP_OFFMASK: u16 = 0x1FFF;
/// IPv4 header mask combining all three fragmentation flags (`IP_FLAGMASK`).
pub const IP_FLAGMASK: u16 = IP_RF | IP_DF | IP_MF;

/// IPv4 TOS mask for ECN bits (`IPTOS_ECN_MASK`).
pub const IPTOS_ECN_MASK: u8 = 0x03;
/// IPv4 TOS ECN value: Not-ECT (`IPTOS_ECN_NOT_ECT`).
pub const IPTOS_ECN_NOT_ECT: u8 = 0x00;
/// IPv4 TOS ECN value: ECT(1) (`IPTOS_ECN_ECT1`).
pub const IPTOS_ECN_ECT1: u8 = 0x01;
/// IPv4 TOS ECN value: ECT(0) (`IPTOS_ECN_ECT0`).
pub const IPTOS_ECN_ECT0: u8 = 0x02;
/// IPv4 TOS ECN value: Congestion Experienced (`IPTOS_ECN_CE`).
pub const IPTOS_ECN_CE: u8 = 0x03;
/// IPv4 TOS mask for the 6-bit DSCP field (`IPTOS_DSCP_MASK`).
pub const IPTOS_DSCP_MASK: u8 = 0xFC;

/// IPv6 Fragment extension header mask for byte offset (`IP6F_OFF_MASK`).
/// Already scaled to bytes (upper 13 bits of the 16-bit offset/flags field).
pub const IP6F_OFF_MASK: u16 = 0xFFF8;
/// IPv6 Fragment extension header flag: More Fragments (`IP6F_MORE_FRAG`).
pub const IP6F_MORE_FRAG: u16 = 0x0001;
/// IPv6 mask for the 20-bit flow label (`IPV6_FLOWLABEL_MASK`).
pub const IPV6_FLOWLABEL_MASK: u32 = 0x000F_FFFF;
/// IPv6 mask for traffic class + flow label (`IPV6_FLOWINFO_MASK`).
pub const IPV6_FLOWINFO_MASK: u32 = 0x0FFF_FFFF;
/// Default IPv6 version/traffic-class/flow word (`version = 6`, class/label = 0).
pub const IPV6_DEFAULT_FLOW: u32 = 0x6000_0000;

/// IP protocol number: dummy IPv4 / Hop-by-Hop placeholder (`IPPROTO_IP`).
pub const IPPROTO_IP: u8 = 0;
/// IPv6 extension header: Hop-by-Hop Options (`IPPROTO_HOPOPTS`).
pub const IPPROTO_HOPOPTS: u8 = 0;
/// IP protocol number: ICMPv4 (`IPPROTO_ICMP`).
pub const IPPROTO_ICMP: u8 = 1;
/// IP protocol number: IP-in-IP encapsulation (`IPPROTO_IPIP`).
pub const IPPROTO_IPIP: u8 = 4;
/// IP protocol number: TCP (`IPPROTO_TCP`).
pub const IPPROTO_TCP: u8 = 6;
/// IP protocol number: UDP (`IPPROTO_UDP`).
pub const IPPROTO_UDP: u8 = 17;
/// IP protocol number: IPv6-in-IPv4 encapsulation (`IPPROTO_IPV6`).
pub const IPPROTO_IPV6: u8 = 41;
/// IPv6 extension header: Routing (`IPPROTO_ROUTING`).
pub const IPPROTO_ROUTING: u8 = 43;
/// IPv6 extension header: Fragment (`IPPROTO_FRAGMENT`).
pub const IPPROTO_FRAGMENT: u8 = 44;
/// IP protocol number: Encapsulating Security Payload (`IPPROTO_ESP`).
pub const IPPROTO_ESP: u8 = 50;
/// IPv6 extension header: Authentication Header (`IPPROTO_AH`).
pub const IPPROTO_AH: u8 = 51;
/// IP protocol number: ICMPv6 (`IPPROTO_ICMPV6`).
pub const IPPROTO_ICMPV6: u8 = 58;
/// IPv6 extension header: No Next Header (`IPPROTO_NONE`).
pub const IPPROTO_NONE: u8 = 59;
/// IPv6 extension header: Destination Options (`IPPROTO_DSTOPTS`).
pub const IPPROTO_DSTOPTS: u8 = 60;
/// IP protocol number: SCTP (`IPPROTO_SCTP`).
pub const IPPROTO_SCTP: u8 = 132;
/// IPv6 extension header: Mobility Header (`IPPROTO_MH`).
pub const IPPROTO_MH: u8 = 135;
/// IPv6 extension header: Host Identity Protocol (`IPPROTO_HIP`).
pub const IPPROTO_HIP: u8 = 139;
/// IPv6 extension header: Shim6 (`IPPROTO_SHIM6`).
pub const IPPROTO_SHIM6: u8 = 140;

/// ICMPv4 type: Echo Reply (`ICMP_ECHOREPLY`).
pub const ICMP_ECHOREPLY: u8 = 0;
/// ICMPv4 type: Destination Unreachable (`ICMP_DEST_UNREACH`).
pub const ICMP_DEST_UNREACH: u8 = 3;
/// ICMPv4 type: Redirect (`ICMP_REDIRECT`).
pub const ICMP_REDIRECT: u8 = 5;
/// ICMPv4 type: Echo Request (`ICMP_ECHO`).
pub const ICMP_ECHO: u8 = 8;
/// ICMPv4 type: Time Exceeded (`ICMP_TIME_EXCEEDED`).
pub const ICMP_TIME_EXCEEDED: u8 = 11;
/// ICMPv4 type: Parameter Problem (`ICMP_PARAMETERPROB`).
pub const ICMP_PARAMETERPROB: u8 = 12;
/// ICMPv4 type: Timestamp Request (`ICMP_TIMESTAMP`).
pub const ICMP_TIMESTAMP: u8 = 13;
/// ICMPv4 type: Timestamp Reply (`ICMP_TIMESTAMPREPLY`).
pub const ICMP_TIMESTAMPREPLY: u8 = 14;
/// ICMPv4 type: Information Request (`ICMP_INFO_REQUEST`).
pub const ICMP_INFO_REQUEST: u8 = 15;
/// ICMPv4 type: Information Reply (`ICMP_INFO_REPLY`).
pub const ICMP_INFO_REPLY: u8 = 16;

/// ICMPv4 Destination Unreachable code: Network Unreachable.
pub const ICMP_UNREACH_NET: u8 = 0;
/// ICMPv4 Destination Unreachable code: Host Unreachable.
pub const ICMP_UNREACH_HOST: u8 = 1;
/// ICMPv4 Destination Unreachable code: Protocol Unreachable.
pub const ICMP_UNREACH_PROTOCOL: u8 = 2;
/// ICMPv4 Destination Unreachable code: Port Unreachable.
pub const ICMP_UNREACH_PORT: u8 = 3;
/// ICMPv4 Destination Unreachable code: Fragmentation Needed and DF Set.
pub const ICMP_UNREACH_NEEDFRAG: u8 = 4;
/// ICMPv4 Destination Unreachable code: Source Route Failed.
pub const ICMP_UNREACH_SRCFAIL: u8 = 5;
/// ICMPv4 Destination Unreachable code: Destination Network Unknown.
pub const ICMP_UNREACH_NET_UNKNOWN: u8 = 6;
/// ICMPv4 Destination Unreachable code: Destination Host Unknown.
pub const ICMP_UNREACH_HOST_UNKNOWN: u8 = 7;
/// ICMPv4 Destination Unreachable code: Communication with Network Administratively Prohibited.
pub const ICMP_UNREACH_NET_PROHIB: u8 = 9;
/// ICMPv4 Destination Unreachable code: Communication with Host Administratively Prohibited.
pub const ICMP_UNREACH_HOST_PROHIB: u8 = 10;
/// ICMPv4 Destination Unreachable code: Network Unreachable for Type of Service.
pub const ICMP_UNREACH_TOSNET: u8 = 11;
/// ICMPv4 Destination Unreachable code: Host Unreachable for Type of Service.
pub const ICMP_UNREACH_TOSHOST: u8 = 12;
/// ICMPv4 Destination Unreachable code: Communication Administratively Prohibited.
pub const ICMP_UNREACH_FILTER_PROHIB: u8 = 13;
/// ICMPv4 Destination Unreachable code: Host Precedence Violation.
pub const ICMP_UNREACH_HOST_PRECEDENCE: u8 = 14;
/// ICMPv4 Destination Unreachable code: Precedence Cutoff in Effect.
pub const ICMP_UNREACH_PRECEDENCE_CUTOFF: u8 = 15;

/// ICMPv4 Redirect code: Redirect Datagrams for the Network.
pub const ICMP_REDIRECT_NET: u8 = 0;
/// ICMPv4 Redirect code: Redirect Datagrams for the Host.
pub const ICMP_REDIRECT_HOST: u8 = 1;
/// ICMPv4 Redirect code: Redirect Datagrams for the Type of Service and Network.
pub const ICMP_REDIRECT_TOSNET: u8 = 2;
/// ICMPv4 Redirect code: Redirect Datagrams for the Type of Service and Host.
pub const ICMP_REDIRECT_TOSHOST: u8 = 3;

/// ICMPv4 Time Exceeded code: Time to Live exceeded in transit.
pub const ICMP_TIMXCEED_INTRANS: u8 = 0;
/// ICMPv4 Time Exceeded code: Fragment reassembly time exceeded.
pub const ICMP_TIMXCEED_REASS: u8 = 1;

/// ICMPv6 type: Destination Unreachable (`ICMP6_DST_UNREACH`).
pub const ICMP6_DST_UNREACH: u8 = 1;
/// ICMPv6 type: Packet Too Big (`ICMP6_PACKET_TOO_BIG`).
pub const ICMP6_PACKET_TOO_BIG: u8 = 2;
/// ICMPv6 type: Time Exceeded (`ICMP6_TIME_EXCEEDED`).
pub const ICMP6_TIME_EXCEEDED: u8 = 3;
/// ICMPv6 type: Parameter Problem (`ICMP6_PARAM_PROB`).
pub const ICMP6_PARAM_PROB: u8 = 4;
/// ICMPv6 type: Echo Request (`ICMP6_ECHO_REQUEST`).
pub const ICMP6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 type: Echo Reply (`ICMP6_ECHO_REPLY`).
pub const ICMP6_ECHO_REPLY: u8 = 129;
/// ICMPv6 type: Multicast Listener Query (`MLD_LISTENER_QUERY`).
pub const MLD_LISTENER_QUERY: u8 = 130;
/// ICMPv6 type: Multicast Listener Report (`MLD_LISTENER_REPORT`).
pub const MLD_LISTENER_REPORT: u8 = 131;
/// ICMPv6 type: Multicast Listener Done (`MLD_LISTENER_REDUCTION`).
pub const MLD_LISTENER_REDUCTION: u8 = 132;
/// ICMPv6 type: Neighbor Discovery Router Solicitation (`ND_ROUTER_SOLICIT`).
pub const ND_ROUTER_SOLICIT: u8 = 133;
/// ICMPv6 type: Neighbor Discovery Router Advertisement (`ND_ROUTER_ADVERT`).
pub const ND_ROUTER_ADVERT: u8 = 134;
/// ICMPv6 type: Neighbor Discovery Neighbor Solicitation (`ND_NEIGHBOR_SOLICIT`).
pub const ND_NEIGHBOR_SOLICIT: u8 = 135;
/// ICMPv6 type: Neighbor Discovery Neighbor Advertisement (`ND_NEIGHBOR_ADVERT`).
pub const ND_NEIGHBOR_ADVERT: u8 = 136;
/// ICMPv6 type: Neighbor Discovery Redirect (`ND_REDIRECT`).
pub const ND_REDIRECT: u8 = 137;

/// ICMPv6 Destination Unreachable code: No route to destination.
pub const ICMP6_DST_UNREACH_NOROUTE: u8 = 0;
/// ICMPv6 Destination Unreachable code: Communication administratively prohibited.
pub const ICMP6_DST_UNREACH_ADMIN: u8 = 1;
/// ICMPv6 Destination Unreachable code: Beyond scope of source address.
pub const ICMP6_DST_UNREACH_BEYONDSCOPE: u8 = 2;
/// ICMPv6 Destination Unreachable code: Address unreachable.
pub const ICMP6_DST_UNREACH_ADDR: u8 = 3;
/// ICMPv6 Destination Unreachable code: Port unreachable.
pub const ICMP6_DST_UNREACH_NOPORT: u8 = 4;

/// ICMPv6 Time Exceeded code: Hop limit exceeded in transit.
pub const ICMP6_TIME_EXCEED_TRANSIT: u8 = 0;
/// ICMPv6 Time Exceeded code: Fragment reassembly time exceeded.
pub const ICMP6_TIME_EXCEED_REASSEMBLY: u8 = 1;

/// ICMPv6 Parameter Problem code: Erroneous header field encountered.
pub const ICMP6_PARAMPROB_HEADER: u8 = 0;
/// ICMPv6 Parameter Problem code: Unrecognized Next Header type encountered.
pub const ICMP6_PARAMPROB_NEXTHEADER: u8 = 1;
/// ICMPv6 Parameter Problem code: Unrecognized IPv6 option encountered.
pub const ICMP6_PARAMPROB_OPTION: u8 = 2;
