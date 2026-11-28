//! L7 protocol and payload classification enums, names, and bitmask matchers matching `protocol.h`.

/// Canonical L7 protocol identifiers ordered identically to `t_l7proto` in `zapret2/nfq2/protocol.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum L7Proto
{
    /// Wildcard matching any protocol (`"all"`).
    All = 0,
    /// Unidentified application protocol (`"unknown"`).
    Unknown = 1,
    /// Wildcard matching any identified protocol > `Unknown` (`"known"`).
    Known = 2,
    /// Plaintext HTTP (`"http"`).
    Http = 3,
    /// TLS over TCP (`"tls"`).
    Tls = 4,
    /// DTLS over UDP (`"dtls"`).
    Dtls = 5,
    /// QUIC over UDP (`"quic"`).
    Quic = 6,
    /// WireGuard VPN (`"wireguard"`).
    Wireguard = 7,
    /// BitTorrent DHT (`"dht"`).
    Dht = 8,
    /// Discord voice discovery (`"discord"`).
    Discord = 9,
    /// STUN (`"stun"`).
    Stun = 10,
    /// XMPP / Jabber (`"xmpp"`).
    Xmpp = 11,
    /// DNS (`"dns"`).
    Dns = 12,
    /// Telegram MTProto (`"mtproto"`).
    Mtproto = 13,
    /// BitTorrent TCP handshake (`"bt"`).
    Bt = 14,
    /// BitTorrent uTP handshake (`"utp_bt"`).
    UtpBt = 15,
}

impl L7Proto
{
    /// Parses a `zapret2` L7 protocol name into an [`L7Proto`] variant.
    pub fn from_name(name: &str) -> Option<Self>
    {
        match name.trim()
        {
            "all" => Some(Self::All),
            "unknown" => Some(Self::Unknown),
            "known" => Some(Self::Known),
            "http" => Some(Self::Http),
            "tls" => Some(Self::Tls),
            "dtls" => Some(Self::Dtls),
            "quic" => Some(Self::Quic),
            "wireguard" => Some(Self::Wireguard),
            "dht" => Some(Self::Dht),
            "discord" => Some(Self::Discord),
            "stun" => Some(Self::Stun),
            "xmpp" => Some(Self::Xmpp),
            "dns" => Some(Self::Dns),
            "mtproto" => Some(Self::Mtproto),
            "bt" => Some(Self::Bt),
            "utp_bt" => Some(Self::UtpBt),
            _ => None,
        }
    }

    /// Returns the canonical `zapret2` Lua/CLI name for this L7 protocol.
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::All => "all",
            Self::Unknown => "unknown",
            Self::Known => "known",
            Self::Http => "http",
            Self::Tls => "tls",
            Self::Dtls => "dtls",
            Self::Quic => "quic",
            Self::Wireguard => "wireguard",
            Self::Dht => "dht",
            Self::Discord => "discord",
            Self::Stun => "stun",
            Self::Xmpp => "xmpp",
            Self::Dns => "dns",
            Self::Mtproto => "mtproto",
            Self::Bt => "bt",
            Self::UtpBt => "utp_bt",
        }
    }

    /// Returns the single-bit flag representing `self` inside a 64-bit `filter_l7` mask.
    pub const fn bit(self) -> u64
    {
        1u64 << (self as u8)
    }
}

/// Returns `true` if `proto` satisfies `filter_mask` (`0` or `L7Proto::Known` handled identically to `l7_proto_match`).
pub const fn l7_proto_matches(proto: L7Proto, filter_mask: u64) -> bool
{
    filter_mask == 0
        || (filter_mask & proto.bit()) != 0
        || ((filter_mask & L7Proto::Known.bit()) != 0 && (proto as u8) > (L7Proto::Known as u8))
}

/// Canonical L7 payload identifiers ordered identically to `t_l7payload` in `zapret2/nfq2/protocol.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum L7Payload
{
    /// Wildcard matching any payload (`"all"`).
    All = 0,
    /// Unclassified non-empty payload (`"unknown"`).
    Unknown = 1,
    /// Zero-byte L4 payload (`"empty"`).
    Empty = 2,
    /// Wildcard matching any known payload > `Known` (`"known"`).
    Known = 3,
    /// IPv4 packet payload / encapsulation (`"ipv4"`).
    Ipv4 = 4,
    /// IPv6 packet payload / encapsulation (`"ipv6"`).
    Ipv6 = 5,
    /// ICMP/ICMPv6 packet (`"icmp"`).
    Icmp = 6,
    /// HTTP request message (`"http_req"`).
    HttpReq = 7,
    /// HTTP response message (`"http_reply"`).
    HttpReply = 8,
    /// TLS ClientHello (`"tls_client_hello"`).
    TlsClientHello = 9,
    /// TLS ServerHello (`"tls_server_hello"`).
    TlsServerHello = 10,
    /// DTLS ClientHello (`"dtls_client_hello"`).
    DtlsClientHello = 11,
    /// DTLS ServerHello (`"dtls_server_hello"`).
    DtlsServerHello = 12,
    /// QUIC Initial packet (`"quic_initial"`).
    QuicInitial = 13,
    /// WireGuard handshake initiation (`"wireguard_initiation"`).
    WireguardInitiation = 14,
    /// WireGuard handshake response (`"wireguard_response"`).
    WireguardResponse = 15,
    /// WireGuard cookie reply (`"wireguard_cookie"`).
    WireguardCookie = 16,
    /// WireGuard keepalive (`"wireguard_keepalive"`).
    WireguardKeepalive = 17,
    /// WireGuard encrypted transport data (`"wireguard_data"`).
    WireguardData = 18,
    /// BitTorrent DHT packet (`"dht"`).
    Dht = 19,
    /// Discord IP discovery packet (`"discord_ip_discovery"`).
    DiscordIpDiscovery = 20,
    /// STUN message (`"stun"`).
    Stun = 21,
    /// XMPP stream header (`"xmpp_stream"`).
    XmppStream = 22,
    /// XMPP STARTTLS frame (`"xmpp_starttls"`).
    XmppStarttls = 23,
    /// XMPP STARTTLS proceed frame (`"xmpp_proceed"`).
    XmppProceed = 24,
    /// XMPP stream features frame (`"xmpp_features"`).
    XmppFeatures = 25,
    /// DNS query message (`"dns_query"`).
    DnsQuery = 26,
    /// DNS response message (`"dns_response"`).
    DnsResponse = 27,
    /// Telegram MTProto initial packet (`"mtproto_initial"`).
    MtprotoInitial = 28,
    /// BitTorrent TCP peer handshake (`"bt_handshake"`).
    BtHandshake = 29,
    /// BitTorrent uTP peer handshake (`"utp_bt_handshake"`).
    UtpBtHandshake = 30,
}

impl L7Payload
{
    /// Parses a `zapret2` L7 payload name into an [`L7Payload`] variant.
    pub fn from_name(name: &str) -> Option<Self>
    {
        match name.trim()
        {
            "all" => Some(Self::All),
            "unknown" => Some(Self::Unknown),
            "empty" => Some(Self::Empty),
            "known" => Some(Self::Known),
            "ipv4" => Some(Self::Ipv4),
            "ipv6" => Some(Self::Ipv6),
            "icmp" => Some(Self::Icmp),
            "http_req" => Some(Self::HttpReq),
            "http_reply" => Some(Self::HttpReply),
            "tls_client_hello" => Some(Self::TlsClientHello),
            "tls_server_hello" => Some(Self::TlsServerHello),
            "dtls_client_hello" => Some(Self::DtlsClientHello),
            "dtls_server_hello" => Some(Self::DtlsServerHello),
            "quic_initial" => Some(Self::QuicInitial),
            "wireguard_initiation" => Some(Self::WireguardInitiation),
            "wireguard_response" => Some(Self::WireguardResponse),
            "wireguard_cookie" => Some(Self::WireguardCookie),
            "wireguard_keepalive" => Some(Self::WireguardKeepalive),
            "wireguard_data" => Some(Self::WireguardData),
            "dht" => Some(Self::Dht),
            "discord_ip_discovery" => Some(Self::DiscordIpDiscovery),
            "stun" => Some(Self::Stun),
            "xmpp_stream" => Some(Self::XmppStream),
            "xmpp_starttls" => Some(Self::XmppStarttls),
            "xmpp_proceed" => Some(Self::XmppProceed),
            "xmpp_features" => Some(Self::XmppFeatures),
            "dns_query" => Some(Self::DnsQuery),
            "dns_response" => Some(Self::DnsResponse),
            "mtproto_initial" => Some(Self::MtprotoInitial),
            "bt_handshake" => Some(Self::BtHandshake),
            "utp_bt_handshake" => Some(Self::UtpBtHandshake),
            _ => None,
        }
    }

    /// Returns the canonical `zapret2` Lua/CLI name for this payload type.
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::All => "all",
            Self::Unknown => "unknown",
            Self::Empty => "empty",
            Self::Known => "known",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Icmp => "icmp",
            Self::HttpReq => "http_req",
            Self::HttpReply => "http_reply",
            Self::TlsClientHello => "tls_client_hello",
            Self::TlsServerHello => "tls_server_hello",
            Self::DtlsClientHello => "dtls_client_hello",
            Self::DtlsServerHello => "dtls_server_hello",
            Self::QuicInitial => "quic_initial",
            Self::WireguardInitiation => "wireguard_initiation",
            Self::WireguardResponse => "wireguard_response",
            Self::WireguardCookie => "wireguard_cookie",
            Self::WireguardKeepalive => "wireguard_keepalive",
            Self::WireguardData => "wireguard_data",
            Self::Dht => "dht",
            Self::DiscordIpDiscovery => "discord_ip_discovery",
            Self::Stun => "stun",
            Self::XmppStream => "xmpp_stream",
            Self::XmppStarttls => "xmpp_starttls",
            Self::XmppProceed => "xmpp_proceed",
            Self::XmppFeatures => "xmpp_features",
            Self::DnsQuery => "dns_query",
            Self::DnsResponse => "dns_response",
            Self::MtprotoInitial => "mtproto_initial",
            Self::BtHandshake => "bt_handshake",
            Self::UtpBtHandshake => "utp_bt_handshake",
        }
    }

    /// Returns the single-bit flag representing `self` inside a 64-bit `payload` mask.
    pub const fn bit(self) -> u64
    {
        1u64 << (self as u8)
    }
}

/// Bitmask representing `L7P_NONE` (no payloads selected, used as default disable mask).
pub const L7_PAYLOAD_NONE_MASK: u64 = 1u64 << 31;

/// Returns `true` if `payload` satisfies `filter_mask` (`0` or `L7Payload::Known` handled identically to `l7_payload_match`).
pub const fn l7_payload_matches(payload: L7Payload, filter_mask: u64) -> bool
{
    filter_mask == 0
        || (filter_mask & payload.bit()) != 0
        || ((filter_mask & L7Payload::Known.bit()) != 0 && (payload as u8) > (L7Payload::Known as u8))
}

/// Ordered slice containing every [`L7Payload`] variant in bitmask discriminant order (`0..=30`).
pub const ALL_L7_PAYLOADS: [L7Payload; 31] = [
    L7Payload::All,
    L7Payload::Unknown,
    L7Payload::Empty,
    L7Payload::Known,
    L7Payload::Ipv4,
    L7Payload::Ipv6,
    L7Payload::Icmp,
    L7Payload::HttpReq,
    L7Payload::HttpReply,
    L7Payload::TlsClientHello,
    L7Payload::TlsServerHello,
    L7Payload::DtlsClientHello,
    L7Payload::DtlsServerHello,
    L7Payload::QuicInitial,
    L7Payload::WireguardInitiation,
    L7Payload::WireguardResponse,
    L7Payload::WireguardCookie,
    L7Payload::WireguardKeepalive,
    L7Payload::WireguardData,
    L7Payload::Dht,
    L7Payload::DiscordIpDiscovery,
    L7Payload::Stun,
    L7Payload::XmppStream,
    L7Payload::XmppStarttls,
    L7Payload::XmppProceed,
    L7Payload::XmppFeatures,
    L7Payload::DnsQuery,
    L7Payload::DnsResponse,
    L7Payload::MtprotoInitial,
    L7Payload::BtHandshake,
    L7Payload::UtpBtHandshake,
];

/// Returns canonical payload names enabled in `mask` (`"all"` when `mask == 0`).
pub fn l7_payload_names(mask: u64) -> Vec<&'static str>
{
    if mask == 0
    {
        return vec!["all"];
    }
    ALL_L7_PAYLOADS
        .iter()
        .copied()
        .filter(|pl| (mask & pl.bit()) != 0)
        .map(L7Payload::as_str)
        .collect()
}

/// Formats a payload bitmask as a comma-separated string (`"all"` when `mask == 0`).
pub fn l7_payload_str_list(mask: u64) -> String
{
    l7_payload_names(mask).join(",")
}
