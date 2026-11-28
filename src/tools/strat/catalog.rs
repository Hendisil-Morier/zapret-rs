//! Strategy candidate catalog ported from `zapret2/blockcheck2.d/standard/*.sh`.

/// Ordered parameter map and deduplication set used during catalog expansion.
use std::collections::{BTreeMap, HashSet};
/// Human-readable formatting for [`ScanLevel`], [`ProbeProtocol`], and [`IpFamily`].
use std::fmt;
/// CLI parsing support for [`ScanLevel`] and [`ProbeProtocol`].
use std::str::FromStr;

/// Profile, action, L7 filter, and packet-range models constructed by the catalog.
use crate::config::{
    DesyncAction, DesyncProfile, IcmpFilter, IppFilter, L7Payload, L7Proto, MarkFilter, PacketPos,
    PacketPosMode, PacketRange, PortFilter, ProfileListsConfig,
};

/// TCP foolings valid on both IPv4 and IPv6 (`FOOLINGS46_TCP` in `def.inc`).
const TCP_FOOLINGS_46: &[&str] = &[
    "badsum",
    "tcp_md5",
    "tcp_seq=-3000",
    "tcp_seq=1000000",
    "tcp_ack=-66000:tcp_ts_up",
    "tcp_ts=-1000",
    "tcp_flags_unset=ACK",
    "tcp_flags_set=SYN",
];

/// Compact high-yield TCP foolings tested in [`ScanLevel::Quick`].
const TCP_FOOLINGS_QUICK: &[&str] = &["badsum", "tcp_md5", "tcp_seq=-3000"];

/// Additional IPv6 extension-header foolings (`FOOLINGS6_TCP` in `def.inc`).
const IPV6_FOOLINGS: &[&str] =
    &["ip6_hopbyhop", "ip6_hopbyhop:ip6_hopbyhop2", "ip6_destopt", "ip6_routing", "ip6_ah"];

/// Scan thoroughness controlling the number of strategy candidates expanded per protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScanLevel
{
    /// High-yield subset targeting fast discovery.
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
        match s.trim().to_ascii_lowercase().as_str()
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
        match s.trim().to_ascii_lowercase().as_str()
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
        let port = self.proto.default_port();
        let port_rule = PortFilter { from: port, to: port, neg: false };
        let (filter_tcp, filter_udp) = if self.proto.is_udp()
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
            name: Some(self.id.clone()),
            cookie: None,
            filter_ipv4: matches!(self.ipv, IpFamily::V4),
            filter_ipv6: matches!(self.ipv, IpFamily::V6),
            filter_tcp,
            filter_udp,
            filter_icmp: vec![IcmpFilter::skip()],
            filter_ipp: vec![IppFilter::skip()],
            filter_l7: self.proto.l7_proto().bit(),
            filter_mark: MarkFilter::default(),
            lists,
            actions: self.actions.clone(),
        }
    }
}

/// Stateful helper accumulating deduplicated [`StrategySpec`] items for one `(proto, ipv)`.
struct CatalogBuilder
{
    /// Accumulated unique strategies.
    out: Vec<StrategySpec>,
    /// Seen strategy IDs preventing duplicate entries.
    seen: HashSet<String>,
    /// Protocol shared across emitted candidates.
    proto: ProbeProtocol,
    /// IP family shared across emitted candidates.
    ipv: IpFamily,
}

impl CatalogBuilder
{
    /// Creates an empty builder for `(proto, ipv)`.
    fn new(proto: ProbeProtocol, ipv: IpFamily) -> Self
    {
        Self { out: Vec::new(), seen: HashSet::new(), proto, ipv }
    }

    /// Registers one strategy candidate if its generated ID has not yet been emitted.
    fn add(&mut self, family: &'static str, weight: u32, suffix: &str, actions: Vec<DesyncAction>)
    {
        let id = format!("{}:{}:{suffix}", self.proto.as_str(), self.ipv.as_str());
        if self.seen.insert(id.clone())
        {
            self.out.push(StrategySpec { id, family, weight, proto: self.proto, ipv: self.ipv, actions });
        }
    }
}

/// Constructs an outgoing [`DesyncAction`] for `func` restricted to `payload` with `args`.
fn make_action(func: &str, payload: L7Payload, args: &[(&str, &str)]) -> DesyncAction
{
    let mut map = BTreeMap::new();
    for &(k, v) in args
    {
        map.insert(k.to_owned(), v.to_owned());
    }
    DesyncAction {
        func: func.to_owned(),
        payload_mask: if payload == L7Payload::All { 0 } else { payload.bit() },
        in_range: PacketRange::NEVER,
        out_range: PacketRange::ALWAYS,
        args: map,
    }
}

/// Constructs an action like [`make_action`] and merges colon-separated fooling tokens into `args`.
fn make_fooled_action(func: &str, payload: L7Payload, args: &[(&str, &str)], fooling: &str) -> DesyncAction
{
    let mut act = make_action(func, payload, args);
    for token in fooling.split(':')
    {
        let trimmed = token.trim();
        if trimmed.is_empty()
        {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=')
        {
            act.args.insert(k.to_owned(), v.to_owned());
        }
        else
        {
            act.args.insert(trimmed.to_owned(), String::new());
        }
    }
    act
}

/// Returns the list of TCP fooling strings expanded for `level` and `ipv`.
fn tcp_foolings(level: ScanLevel, ipv: IpFamily) -> Vec<&'static str>
{
    let mut out: Vec<&'static str> = match level
    {
        ScanLevel::Quick => TCP_FOOLINGS_QUICK.to_vec(),
        ScanLevel::Standard | ScanLevel::Force => TCP_FOOLINGS_46.to_vec(),
    };
    if ipv == IpFamily::V6
    {
        out.extend_from_slice(if level == ScanLevel::Quick { &IPV6_FOOLINGS[..2] } else { IPV6_FOOLINGS });
    }
    out
}

/// Appends HTTP-specific basic header-case and EOL strategies (`10-http-basic.sh`).
fn add_http_basic(b: &mut CatalogBuilder)
{
    let p = L7Payload::HttpReq;
    b.add("basic", 10, "http_hostcase", vec![make_action("http_hostcase", p, &[])]);
    b.add("basic", 10, "http_hostcase_spell", vec![make_action("http_hostcase", p, &[("spell", "hoSt")])]);
    b.add("basic", 10, "http_domcase", vec![make_action("http_domcase", p, &[])]);
    b.add("basic", 12, "http_methodeol", vec![make_action("http_methodeol", p, &[])]);
    b.add("basic", 12, "http_unixeol", vec![make_action("http_unixeol", p, &[])]);
}

/// Appends TCP split, disorder, seqovl, OOB, syndata, fake, faked, hostfake, and combo strategies.
fn add_tcp_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    let (proto, ipv, payload, blob) = (b.proto, b.ipv, b.proto.l7_payload(), b.proto.default_fake_blob());
    let split_positions: &[&str] = match (proto, level)
    {
        (ProbeProtocol::Http, ScanLevel::Quick) => &["method+2", "midsld"],
        (ProbeProtocol::Http, _) => &["method+2", "midsld", "method+2,midsld"],
        (_, ScanLevel::Quick) => &["1", "midsld", "sniext+1"],
        (_, ScanLevel::Standard) => &["2", "1", "sniext+1", "host+1", "midsld", "1,midsld"],
        (_, ScanLevel::Force) => &[
            "2",
            "1",
            "sniext+1",
            "sniext+4",
            "host+1",
            "midsld",
            "1,midsld",
            "1,midsld,1220",
            "1,sniext+1,host+1,midsld-2,midsld,midsld+2,endhost-1",
        ],
    };
    for &pos in split_positions
    {
        b.add(
            "multisplit",
            20,
            &format!("multisplit:{pos}"),
            vec![make_action("multisplit", payload, &[("pos", pos)])],
        );
        b.add(
            "multidisorder",
            25,
            &format!("multidisorder:{pos}"),
            vec![make_action("multidisorder", payload, &[("pos", pos)])],
        );
    }
    if proto == ProbeProtocol::Tls12 && level != ScanLevel::Quick
    {
        let ws = make_action("wssize", L7Payload::All, &[("wsize", "1"), ("scale", "6")]);
        for &pos in &["1", "midsld"]
        {
            b.add(
                "multisplit",
                32,
                &format!("wssize+multisplit:{pos}"),
                vec![ws.clone(), make_action("multisplit", payload, &[("pos", pos)])],
            );
        }
    }
    let seqovl_pos = if proto == ProbeProtocol::Http { "method+2" } else { "10,midsld" };
    b.add(
        "seqovl",
        35,
        "multisplit:seqovl=1",
        vec![make_action("multisplit", payload, &[("pos", seqovl_pos), ("seqovl", "1")])],
    );
    if level != ScanLevel::Quick
    {
        let pat_len = format!("#{blob}");
        b.add(
            "seqovl",
            38,
            "multisplit:seqovl_pat",
            vec![make_action(
                "multisplit",
                payload,
                &[("pos", seqovl_pos), ("seqovl", &pat_len), ("seqovl_pattern", blob)],
            )],
        );
        let mut oob = make_action("oob", L7Payload::All, &[("urp", "midsld")]);
        oob.in_range = PacketRange {
            from: PacketPos::ALWAYS,
            to: PacketPos { mode: PacketPosMode::RelSeq, pos: 1 },
            upper_cutoff: false,
        };
        b.add("oob", 36, "oob:midsld", vec![oob]);
        if proto != ProbeProtocol::Http
        {
            let mut syn = make_action("syndata", L7Payload::All, &[("blob", blob)]);
            syn.out_range = PacketRange {
                from: PacketPos::ALWAYS,
                to: PacketPos { mode: PacketPosMode::DataPacketNum, pos: 1 },
                upper_cutoff: false,
            };
            b.add("syndata", 65, "syndata", vec![syn]);
        }
    }
    let ttls: &[u8] = match level
    {
        ScanLevel::Quick => &[3, 5, 7],
        ScanLevel::Standard => &[2, 4, 6, 8, 10],
        ScanLevel::Force => &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
    };
    for &ttl in ttls
    {
        let ttl_s = ttl.to_string();
        b.add(
            "fake",
            45,
            &format!("fake:ttl={ttl}"),
            vec![make_action("fake", payload, &[("blob", blob), (ipv.ttl_key(), &ttl_s)])],
        );
    }
    let attls: &[u8] = match level
    {
        ScanLevel::Quick => &[2],
        ScanLevel::Standard => &[1, 2, 3],
        ScanLevel::Force => &[1, 2, 3, 4, 5],
    };
    for &d in attls
    {
        let spec = format!("-{d},3-20");
        b.add(
            "fake",
            48,
            &format!("fake:autottl=-{d}"),
            vec![make_action("fake", payload, &[("blob", blob), (ipv.autottl_key(), &spec)])],
        );
    }
    for fooling in tcp_foolings(level, ipv)
    {
        b.add(
            "fake",
            50,
            &format!("fake:{fooling}"),
            vec![make_fooled_action("fake", payload, &[("blob", blob)], fooling)],
        );
        if proto != ProbeProtocol::Http && level != ScanLevel::Quick
        {
            b.add(
                "fake",
                54,
                &format!("fake:tls_mod:{fooling}"),
                vec![make_fooled_action(
                    "fake",
                    payload,
                    &[("blob", blob), ("tls_mod", "rnd,dupsid")],
                    fooling,
                )],
            );
        }
    }
    if level != ScanLevel::Quick
    {
        let combo_foolings =
            if level == ScanLevel::Force { tcp_foolings(level, ipv) } else { vec!["badsum", "tcp_md5"] };
        for fooling in &combo_foolings
        {
            b.add(
                "fakedsplit",
                60,
                &format!("fakedsplit:{fooling}"),
                vec![make_fooled_action("fakedsplit", payload, &[("pos", "midsld")], fooling)],
            );
            b.add(
                "fakeddisorder",
                62,
                &format!("fakeddisorder:{fooling}"),
                vec![make_fooled_action("fakeddisorder", payload, &[("pos", "midsld")], fooling)],
            );
            b.add(
                "hostfakesplit",
                64,
                &format!("hostfakesplit:{fooling}"),
                vec![make_fooled_action("hostfakesplit", payload, &[("midhost", "midsld")], fooling)],
            );
        }
    }
    if level == ScanLevel::Force
    {
        for &rep in &["1", "20", "100"]
        {
            let pos = if proto == ProbeProtocol::Http { "0,method+2" } else { "0,1" };
            b.add(
                "tcpseg",
                42,
                &format!("tcpseg:rep={rep}"),
                vec![make_action("tcpseg", payload, &[("pos", pos), ("ip_id", "rnd"), ("repeats", rep)])],
            );
        }
        for fooling in &["badsum", "tcp_md5", "tcp_seq=-3000"]
        {
            let fk = make_fooled_action("fake", payload, &[("blob", blob)], fooling);
            b.add(
                "fake-multi",
                78,
                &format!("fake+multisplit:{fooling}"),
                vec![fk.clone(), make_action("multisplit", payload, &[("pos", "midsld")])],
            );
            b.add(
                "fake-multi",
                80,
                &format!("fake+multidisorder:{fooling}"),
                vec![fk, make_action("multidisorder", payload, &[("pos", "midsld")])],
            );
        }
    }
}

/// Appends QUIC/HTTP3 UDP fake, IPv6 extension header, and IP fragmentation strategies (`90-quic.sh`).
fn add_quic_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    let (p, blob) = (L7Payload::QuicInitial, ProbeProtocol::Http3.default_fake_blob());
    let repeats: &[&str] = match level
    {
        ScanLevel::Quick => &["1", "5"],
        ScanLevel::Standard => &["1", "2", "5", "10"],
        ScanLevel::Force => &["1", "2", "5", "10", "20"],
    };
    for &rep in repeats
    {
        b.add(
            "quic",
            30,
            &format!("fake:rep={rep}"),
            vec![make_action("fake", p, &[("blob", blob), ("repeats", rep)])],
        );
    }
    if b.ipv == IpFamily::V6
    {
        for &fool in &["ip6_hopbyhop", "ip6_destopt", "ip6_hopbyhop:ip6_destopt"]
        {
            b.add(
                "quic",
                40,
                &format!("send:{fool}"),
                vec![make_fooled_action("send", p, &[], fool), make_action("drop", p, &[])],
            );
        }
    }
    let frags: &[&str] = if level == ScanLevel::Quick { &["8", "32"] } else { &["8", "16", "32", "64"] };
    for &pos in frags
    {
        let send = make_action("send", p, &[("ipfrag", ""), ("ipfrag_pos_udp", pos)]);
        let drop = make_action("drop", p, &[]);
        b.add("quic", 55, &format!("ipfrag:{pos}"), vec![send.clone(), drop.clone()]);
        if level != ScanLevel::Quick
        {
            b.add(
                "quic",
                70,
                &format!("fake+ipfrag:{pos}"),
                vec![make_action("fake", p, &[("blob", blob), ("repeats", "1")]), send, drop],
            );
        }
    }
}

/// Expands the deterministic, weight-sorted candidate catalog for `(proto, level, ipv)`.
pub fn build_catalog(proto: ProbeProtocol, level: ScanLevel, ipv: IpFamily) -> Vec<StrategySpec>
{
    let mut builder = CatalogBuilder::new(proto, ipv);
    match proto
    {
        ProbeProtocol::Http =>
        {
            add_http_basic(&mut builder);
            add_tcp_strategies(&mut builder, level);
        }
        ProbeProtocol::Tls12 | ProbeProtocol::Tls13 => add_tcp_strategies(&mut builder, level),
        ProbeProtocol::Http3 => add_quic_strategies(&mut builder, level),
    }
    builder.out.sort_by(|a, b| a.weight.cmp(&b.weight).then_with(|| a.id.cmp(&b.id)));
    builder.out
}
