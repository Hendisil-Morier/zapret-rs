//! Strategy candidate domain model and deterministic catalog entrypoint.

/// Human-readable formatting for [`ScanLevel`], [`ProbeProtocol`], and [`IpFamily`].
use std::fmt;
/// CLI parsing support for [`ScanLevel`] and [`ProbeProtocol`].
use std::str::FromStr;

/// Serialization support for storing user-selected scan level in TUI `config.toml`.
use serde::{Deserialize, Serialize};

/// Profile, action, L7 filter, and packet-range models constructed by the catalog.
use crate::config::{
    DesyncAction, DesyncProfile, IcmpFilter, IppFilter, L7Payload, L7Proto, MarkFilter, PortFilter,
    ProfileListsConfig,
};
/// Catalog expansion builders separated into `catalog_rules`.
use crate::tools::strat::catalog_rules::build_catalog_entries;

/// Scan thoroughness controlling the number of strategy candidates expanded per protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanLevel
{
    /// High-yield subset targeting fast discovery.
    #[default]
    Quick,
    /// Practical default sweep matching typical `blockcheck2` coverage.
    Standard,
    /// Exhaustive sweep including extra TTLs, `wssize`, `tcpseg` repeats, and combo attacks.
    Force,
}

impl ScanLevel
{
    /// Returns the lowercase canonical CLI name of this scan level.
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::Quick => "quick",
            Self::Standard => "standard",
            Self::Force => "force",
        }
    }
}

impl fmt::Display for ScanLevel
{
    /// Formats the scan level as its lowercase CLI identifier.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(self.as_str())
    }
}

impl FromStr for ScanLevel
{
    type Err = String;
    /// Parses `"quick"`, `"standard"`, or `"force"` (case-insensitive).
    fn from_str(s: &str) -> Result<Self, Self::Err>
    {
        match s
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "quick" => Ok(Self::Quick),
            "standard" => Ok(Self::Standard),
            "force" => Ok(Self::Force),
            other => Err(format!("invalid scan level '{other}' (expected quick, standard, or force)")),
        }
    }
}

/// Application protocol probed during strategy discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeProtocol
{
    /// Plaintext HTTP/1.1 over TCP port 80.
    Http,
    /// HTTPS forcing TLS 1.2 over TCP port 443.
    Tls12,
    /// HTTPS forcing TLS 1.3 over TCP port 443.
    Tls13,
    /// HTTP/3 (QUIC) over UDP port 443.
    Http3,
}

impl ProbeProtocol
{
    /// Returns the canonical lowercase name of this probe protocol.
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::Http => "http",
            Self::Tls12 => "tls12",
            Self::Tls13 => "tls13",
            Self::Http3 => "http3",
        }
    }

    /// Returns the default destination TCP/UDP port for this protocol.
    pub const fn default_port(self) -> u16
    {
        match self
        {
            Self::Http => 80,
            Self::Tls12 | Self::Tls13 | Self::Http3 => 443,
        }
    }

    /// Returns `true` when this protocol uses UDP (`Http3`) rather than TCP.
    pub const fn is_udp(self) -> bool
    {
        matches!(self, Self::Http3)
    }

    /// Returns the [`L7Proto`] matched by profiles generated for this protocol.
    pub const fn l7_proto(self) -> L7Proto
    {
        match self
        {
            Self::Http => L7Proto::Http,
            Self::Tls12 | Self::Tls13 => L7Proto::Tls,
            Self::Http3 => L7Proto::Quic,
        }
    }

    /// Returns the primary [`L7Payload`] targeted by desync actions for this protocol.
    pub const fn l7_payload(self) -> L7Payload
    {
        match self
        {
            Self::Http => L7Payload::HttpReq,
            Self::Tls12 | Self::Tls13 => L7Payload::TlsClientHello,
            Self::Http3 => L7Payload::QuicInitial,
        }
    }

    /// Returns the built-in default fake blob name for this protocol.
    pub const fn default_fake_blob(self) -> &'static str
    {
        match self
        {
            Self::Http => "fake_default_http",
            Self::Tls12 | Self::Tls13 => "fake_default_tls",
            Self::Http3 => "fake_default_quic",
        }
    }
}

impl fmt::Display for ProbeProtocol
{
    /// Formats the protocol as its lowercase CLI identifier.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(self.as_str())
    }
}

impl FromStr for ProbeProtocol
{
    type Err = String;
    /// Parses `"http"`, `"tls12"`, `"tls13"`, or `"http3"` (also accepting `"quic"`).
    fn from_str(s: &str) -> Result<Self, Self::Err>
    {
        match s
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "http" => Ok(Self::Http),
            "tls12" => Ok(Self::Tls12),
            "tls13" => Ok(Self::Tls13),
            "http3" | "quic" => Ok(Self::Http3),
            other => Err(format!("invalid protocol '{other}' (expected http, tls12, tls13, or http3)")),
        }
    }
}

/// IP address family targeted by a strategy candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IpFamily
{
    /// IPv4 (`filter_l3 = ["ipv4"]`, `ip_ttl`, `ip_autottl`).
    V4,
    /// IPv6 (`filter_l3 = ["ipv6"]`, `ip6_ttl`, `ip6_autottl`, IPv6 extension headers).
    V6,
}

impl IpFamily
{
    /// Returns the `nfqws2` Lua parameter name for fixed TTL (`ip_ttl` or `ip6_ttl`).
    pub const fn ttl_key(self) -> &'static str
    {
        match self
        {
            Self::V4 => "ip_ttl",
            Self::V6 => "ip6_ttl",
        }
    }
    /// Returns the `nfqws2` Lua parameter name for auto TTL (`ip_autottl` or `ip6_autottl`).
    pub const fn autottl_key(self) -> &'static str
    {
        match self
        {
            Self::V4 => "ip_autottl",
            Self::V6 => "ip6_autottl",
        }
    }
    /// Returns the `nfqws2.toml` `filter_l3` string (`"ipv4"` or `"ipv6"`).
    pub const fn as_str(self) -> &'static str
    {
        match self
        {
            Self::V4 => "ipv4",
            Self::V6 => "ipv6",
        }
    }
}

impl fmt::Display for IpFamily
{
    /// Formats the IP family as `"ipv4"` or `"ipv6"`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(self.as_str())
    }
}

/// One concrete DPI-bypass strategy candidate ready to convert into a [`DesyncProfile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategySpec
{
    /// Stable unique identifier describing protocol, IP family, and key parameters.
    pub id: String,
    /// Strategy category (`"basic"`, `"multisplit"`, `"fake"`, `"quic"`, etc.).
    pub family: &'static str,
    /// Complexity weight where smaller values represent simpler, lower-risk strategies.
    pub weight: u32,
    /// Target probe protocol for this strategy.
    pub proto: ProbeProtocol,
    /// Target IP address family for this strategy.
    pub ipv: IpFamily,
    /// Ordered Lua desync actions executed when this strategy is active.
    pub actions: Vec<DesyncAction>,
}

impl StrategySpec
{
    /// Converts this strategy into a validated [`DesyncProfile`] bound to `index` and `domains`.
    pub fn to_profile(&self, index: u32, domains: &[String]) -> DesyncProfile
    {
        let port = self
            .proto
            .default_port();
        let port_rule = PortFilter { from: port, to: port, neg: false };
        let (filter_tcp, filter_udp) = if self
            .proto
            .is_udp()
        {
            (vec![PortFilter::deny_all()], vec![port_rule])
        }
        else
        {
            (vec![port_rule], vec![PortFilter::deny_all()])
        };
        let lists =
            ProfileListsConfig { hostlist_domains: domains.to_vec(), ..ProfileListsConfig::default() };
        DesyncProfile {
            index,
            name: Some(
                self.id
                    .clone(),
            ),
            cookie: None,
            filter_ipv4: matches!(self.ipv, IpFamily::V4),
            filter_ipv6: matches!(self.ipv, IpFamily::V6),
            filter_tcp,
            filter_udp,
            filter_icmp: vec![IcmpFilter::skip()],
            filter_ipp: vec![IppFilter::skip()],
            filter_l7: self
                .proto
                .l7_proto()
                .bit(),
            filter_mark: MarkFilter::default(),
            lists,
            actions: self
                .actions
                .clone(),
        }
    }
}

/// Expands the deterministic, weight-sorted candidate catalog for `(proto, level, ipv)`.
pub fn build_catalog(proto: ProbeProtocol, level: ScanLevel, ipv: IpFamily) -> Vec<StrategySpec>
{
    build_catalog_entries(proto, level, ipv)
}
