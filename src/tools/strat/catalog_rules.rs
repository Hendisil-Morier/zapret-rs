//! Strategy catalog expansion helpers ported from `zapret2/blockcheck2.d/standard/*.sh`.

/// Ordered parameter map and deduplication set used during catalog expansion.
use std::collections::{BTreeMap, HashSet};

/// Profile action, L7 payload, and packet-range types built into candidate strategies.
use crate::config::{DesyncAction, L7Payload, PacketPos, PacketPosMode, PacketRange};
/// Strategy domain enums and specification model populated during expansion.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, ScanLevel, StrategySpec};

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
        let id = format!(
            "{}:{}:{suffix}",
            self.proto
                .as_str(),
            self.ipv
                .as_str()
        );
        if self
            .seen
            .insert(id.clone())
        {
            self.out
                .push(StrategySpec { id, family, weight, proto: self.proto, ipv: self.ipv, actions });
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
            act.args
                .insert(k.to_owned(), v.to_owned());
        }
        else
        {
            act.args
                .insert(trimmed.to_owned(), String::new());
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

/// Appends TCP split, disorder, seqovl, OOB, and syndata strategies.
fn add_tcp_split_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    let (proto, payload, blob) = (
        b.proto,
        b.proto
            .l7_payload(),
        b.proto
            .default_fake_blob(),
    );
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
}

/// Appends TTL, auto-TTL, fooled fake, and TLS-modified fake TCP strategies.
fn add_tcp_fake_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    let (proto, ipv, payload, blob) = (
        b.proto,
        b.ipv,
        b.proto
            .l7_payload(),
        b.proto
            .default_fake_blob(),
    );
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
}

/// Appends fakedsplit, fakeddisorder, hostfakesplit, tcpseg, and combined fake+split TCP strategies.
fn add_tcp_combo_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    let (proto, ipv, payload, blob) = (
        b.proto,
        b.ipv,
        b.proto
            .l7_payload(),
        b.proto
            .default_fake_blob(),
    );
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

/// Appends TCP split, disorder, seqovl, OOB, syndata, fake, faked, hostfake, and combo strategies.
fn add_tcp_strategies(b: &mut CatalogBuilder, level: ScanLevel)
{
    add_tcp_split_strategies(b, level);
    add_tcp_fake_strategies(b, level);
    add_tcp_combo_strategies(b, level);
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
pub(super) fn build_catalog_entries(
    proto: ProbeProtocol,
    level: ScanLevel,
    ipv: IpFamily,
) -> Vec<StrategySpec>
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
    builder
        .out
        .sort_by(|a, b| {
            a.weight
                .cmp(&b.weight)
                .then_with(|| {
                    a.id.cmp(&b.id)
                })
        });
    builder.out
}
