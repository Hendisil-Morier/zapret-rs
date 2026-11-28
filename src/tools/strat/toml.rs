//! Strategy ranking, cross-domain minimal set cover, and `nfqws2.toml` rendering.

/// Ordered maps and sets used for deterministic bucket grouping and set cover.
use std::collections::{BTreeMap, BTreeSet};
/// String formatting helper for writing TOML output without intermediate allocations.
use std::fmt::Write as _;
/// Symlink-safe config file creation (`O_NOFOLLOW`) and writing.
use std::fs::OpenOptions;
/// Standard I/O errors and byte writing for TOML config files.
use std::io::{self, Write as _};
/// Unix open flag extension enabling `O_NOFOLLOW` on generated config writes.
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt as _;
/// Filesystem paths for `lua_init` entries and generated `nfqws2.toml` destinations.
use std::path::{Path, PathBuf};

/// Core config models serialized back into `nfqws2.toml`.
use crate::config::{DesyncAction, L7Payload, PacketPos, PacketPosMode, PacketRange};
/// Strategy catalog types ranked, covered, and rendered into TOML profiles.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol, StrategySpec};

/// One successful probe pairing a [`StrategySpec`] with its observed round-trip latency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyMatch
{
    /// Candidate strategy that passed the probe.
    pub strategy: StrategySpec,
    /// Measured request latency in milliseconds.
    pub latency_ms: u64,
}

/// Passing strategies recorded for a single `(domain, proto, ipv)` target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainStrategies
{
    /// Domain name tested (e.g., `"example.com"`).
    pub domain: String,
    /// Protocol tested for this domain.
    pub proto: ProbeProtocol,
    /// IP address family tested for this domain.
    pub ipv: IpFamily,
    /// Passing strategies for this target (order may be unsorted before ranking).
    pub matches: Vec<StrategyMatch>,
}

/// One selected profile emitted into `nfqws2.toml`, covering one or more domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoveredProfile
{
    /// Selected strategy shared by all `domains`.
    pub strategy: StrategySpec,
    /// Sorted list of domains covered by this profile.
    pub domains: Vec<String>,
    /// Mean observed latency across `domains` in milliseconds.
    pub avg_latency_ms: u64,
}

/// Global header options rendered at the top of a generated `nfqws2.toml`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TomlRenderOptions
{
    /// Netfilter queue number (`qnum`).
    pub qnum: u16,
    /// Desync firewall mark (`fwmark`).
    pub fwmark: u32,
    /// Ordered Lua startup script paths written to `lua_init`.
    pub lua_init: Vec<PathBuf>,
}

impl Default for TomlRenderOptions
{
    /// Returns standard `nfqws2` queue/fwmark defaults with empty `lua_init`.
    fn default() -> Self
    {
        Self {
            qnum: crate::intercepter::DEFAULT_QUEUE_NUM,
            fwmark: crate::intercepter::DEFAULT_DESYNC_FWMARK,
            lua_init: Vec::new(),
        }
    }
}

/// Ranks passing strategies in-place by lowest complexity weight, then lowest latency, then ID.
pub fn rank_matches(matches: &mut [StrategyMatch])
{
    matches.sort_by(|a, b| {
        a.strategy
            .weight
            .cmp(
                &b.strategy
                    .weight,
            )
            .then_with(|| {
                a.latency_ms
                    .cmp(&b.latency_ms)
            })
            .then_with(|| {
                a.strategy
                    .id
                    .cmp(
                        &b.strategy
                            .id,
                    )
            })
    });
}

/// Maps [`ProbeProtocol`] to its runtime `nfqws2` profile bucket (`tls12` and `tls13` share TLS).
const fn runtime_bucket_key(proto: ProbeProtocol) -> u8
{
    match proto
    {
        ProbeProtocol::Http => 0,
        ProbeProtocol::Tls12 | ProbeProtocol::Tls13 => 1,
        ProbeProtocol::Http3 => 2,
    }
}

/// Extracts the protocol-agnostic strategy suffix (after the first `':'`, e.g. `"ipv4:multisplit:2"`).
fn strategy_runtime_key(spec: &StrategySpec) -> &str
{
    spec.id
        .split_once(':')
        .map_or(
            spec.id
                .as_str(),
            |(_, rest)| rest,
        )
}

/// Merges per-domain matches that share one runtime `nfqws2` filter bucket (such as `tls12` + `tls13`).
///
/// When both TLS 1.2 and TLS 1.3 succeeded for a domain, keeps strategies that passed both (with
/// mean latency) so one profile serves both versions; if disjoint, prefers TLS 1.3 over TLS 1.2 so
/// a TLS 1.2 profile never shadows TLS 1.3 on identical `filter_l7 = ["tls"]` rules.
fn merge_domain_bucket_matches(entries: &[&DomainStrategies]) -> Vec<StrategyMatch>
{
    if entries.len() == 1
    {
        return entries[0]
            .matches
            .clone();
    }
    let mut per_entry: Vec<BTreeMap<&str, (&StrategySpec, u64)>> = Vec::with_capacity(entries.len());
    for entry in entries
    {
        let mut map: BTreeMap<&str, (&StrategySpec, u64)> = BTreeMap::new();
        for m in &entry.matches
        {
            let key = strategy_runtime_key(&m.strategy);
            map.entry(key)
                .and_modify(|(_, lat)| *lat = (*lat).min(m.latency_ms))
                .or_insert((&m.strategy, m.latency_ms));
        }
        per_entry.push(map);
    }

    let mut shared = Vec::new();
    for (&key, &(first_spec, first_lat)) in &per_entry[0]
    {
        let mut lat_sum = first_lat;
        let mut best_spec = first_spec;
        let mut all_hit = true;
        for other in &per_entry[1..]
        {
            if let Some(&(spec, lat)) = other.get(key)
            {
                lat_sum = lat_sum.saturating_add(lat);
                if spec.proto == ProbeProtocol::Tls13
                {
                    best_spec = spec;
                }
            }
            else
            {
                all_hit = false;
                break;
            }
        }
        if all_hit
        {
            shared.push(StrategyMatch {
                strategy: best_spec.clone(),
                latency_ms: lat_sum / (per_entry.len() as u64),
            });
        }
    }
    if !shared.is_empty()
    {
        return shared;
    }

    entries
        .iter()
        .find(|e| e.proto == ProbeProtocol::Tls13)
        .unwrap_or(&entries[0])
        .matches
        .clone()
}

/// Selects a minimal set of [`CoveredProfile`] entries covering all domains with passing strategies.
///
/// Domains are grouped by runtime `(L7Proto, ipv)` bucket so TCP HTTP, TLS, and QUIC UDP profiles
/// remain separated while TLS 1.2 and TLS 1.3 merge into one non-shadowing TLS profile per domain.
/// Within each bucket, a greedy set cover repeatedly chooses the strategy covering the most
/// uncovered domains, breaking ties by lowest complexity weight, then lowest mean latency, then
/// lexicographic runtime strategy key.
pub fn select_minimal_cover(results: &[DomainStrategies]) -> Vec<CoveredProfile>
{
    let mut buckets: BTreeMap<(u8, IpFamily), BTreeMap<String, Vec<&DomainStrategies>>> = BTreeMap::new();
    for entry in results
    {
        if !entry
            .matches
            .is_empty()
        {
            buckets
                .entry((runtime_bucket_key(entry.proto), entry.ipv))
                .or_default()
                .entry(
                    entry
                        .domain
                        .clone(),
                )
                .or_default()
                .push(entry);
        }
    }

    let mut covered = Vec::new();
    for ((_bucket, _ipv), by_domain) in buckets
    {
        let mut uncovered: BTreeSet<String> = by_domain
            .keys()
            .cloned()
            .collect();
        // Map runtime key -> (StrategySpec, domain -> best latency_ms).
        let mut candidates: BTreeMap<String, (StrategySpec, BTreeMap<String, u64>)> = BTreeMap::new();
        for (domain, entries) in &by_domain
        {
            for m in merge_domain_bucket_matches(entries)
            {
                let key = strategy_runtime_key(&m.strategy).to_owned();
                let (spec_slot, dom_map) = candidates
                    .entry(key)
                    .or_insert_with(|| {
                        (
                            m.strategy
                                .clone(),
                            BTreeMap::new(),
                        )
                    });
                if m.strategy
                    .proto
                    == ProbeProtocol::Tls13
                    && spec_slot.proto != ProbeProtocol::Tls13
                {
                    *spec_slot = m.strategy;
                }
                dom_map
                    .entry(domain.clone())
                    .and_modify(|lat| *lat = (*lat).min(m.latency_ms))
                    .or_insert(m.latency_ms);
            }
        }

        while !uncovered.is_empty()
        {
            let Some((avg_latency_ms, best_key, domains)) = pick_best_candidate(&candidates, &uncovered)
            else
            {
                break;
            };
            for dom in &domains
            {
                uncovered.remove(dom);
            }
            if let Some((strategy, _)) = candidates.get(&best_key)
            {
                covered.push(CoveredProfile { strategy: strategy.clone(), domains, avg_latency_ms });
            }
        }
    }

    covered
}

/// Selects the candidate covering the most `uncovered` domains, breaking ties by weight, latency, and key.
fn pick_best_candidate(
    candidates: &BTreeMap<String, (StrategySpec, BTreeMap<String, u64>)>,
    uncovered: &BTreeSet<String>,
) -> Option<(u64, String, Vec<String>)>
{
    let mut best_pick: Option<(usize, u32, u64, String, Vec<String>)> = None;
    for (key, (spec, dom_map)) in candidates
    {
        let mut hits = Vec::new();
        let mut lat_sum = 0u64;
        for dom in uncovered
        {
            if let Some(&lat) = dom_map.get(dom)
            {
                hits.push(dom.clone());
                lat_sum = lat_sum.saturating_add(lat);
            }
        }
        if hits.is_empty()
        {
            continue;
        }
        let count = hits.len();
        let avg_lat = lat_sum / (count as u64);
        let is_better = match &best_pick
        {
            None => true,
            Some((b_cnt, b_w, b_lat, b_key, _)) =>
            {
                count > *b_cnt
                    || (count == *b_cnt
                        && (spec.weight, avg_lat, key.as_str()) < (*b_w, *b_lat, b_key.as_str()))
            }
        };
        if is_better
        {
            best_pick = Some((count, spec.weight, avg_lat, key.clone(), hits));
        }
    }
    best_pick.map(|(_, _, avg_lat, key, hits)| (avg_lat, key, hits))
}

/// Escapes `raw` as a TOML basic double-quoted string literal.
fn toml_quote(raw: &str) -> String
{
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars()
    {
        match ch
        {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() =>
            {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Formats one [`PacketPos`] token (`a`, `x`, or `<mode><pos>`).
fn format_packet_pos(pos: PacketPos) -> String
{
    match pos.mode
    {
        PacketPosMode::Always => "a".to_owned(),
        PacketPosMode::Never => "x".to_owned(),
        mode => format!("{}{}", mode.as_char(), pos.pos),
    }
}

/// Formats a [`PacketRange`] into canonical `nfqws2` range syntax parseable by [`PacketRange::parse`].
fn format_packet_range(range: PacketRange) -> String
{
    if range == PacketRange::NEVER
    {
        return "x".to_owned();
    }
    if range == PacketRange::ALWAYS
    {
        return "a".to_owned();
    }
    let sep = if range.upper_cutoff { '<' } else { '-' };
    if range.from == PacketPos::ALWAYS
    {
        return format!("{sep}{}", format_packet_pos(range.to));
    }
    if range.to == PacketPos::ALWAYS
    {
        return format!("{}{sep}", format_packet_pos(range.from));
    }
    format!("{}{sep}{}", format_packet_pos(range.from), format_packet_pos(range.to))
}

/// Known `L7Payload` variants inspected when converting a `payload_mask` back into TOML strings.
const KNOWN_PAYLOADS: &[L7Payload] = &[
    L7Payload::Empty,
    L7Payload::HttpReq,
    L7Payload::HttpReply,
    L7Payload::TlsClientHello,
    L7Payload::TlsServerHello,
    L7Payload::QuicInitial,
    L7Payload::DnsQuery,
    L7Payload::DnsResponse,
];

/// Converts an action's `payload_mask` into TOML payload names (`empty` slice means `"all"`).
fn payload_names(mask: u64) -> Vec<&'static str>
{
    if mask == 0
    {
        return Vec::new();
    }
    KNOWN_PAYLOADS
        .iter()
        .copied()
        .filter(|p| (mask & p.bit()) != 0)
        .map(L7Payload::as_str)
        .collect()
}

/// Appends one `[[profiles.actions]]` block to `out`.
fn write_action_toml(out: &mut String, action: &DesyncAction)
{
    out.push_str("[[profiles.actions]]\n");
    let _ = writeln!(out, "func = {}", toml_quote(&action.func));
    let payloads = payload_names(action.payload_mask);
    if !payloads.is_empty()
    {
        let joined: Vec<String> = payloads
            .iter()
            .map(|p| toml_quote(p))
            .collect();
        let _ = writeln!(out, "payload = [{}]", joined.join(", "));
    }
    if action.in_range != PacketRange::NEVER
    {
        let _ = writeln!(out, "in_range = {}", toml_quote(&format_packet_range(action.in_range)));
    }
    if action.out_range != PacketRange::ALWAYS
    {
        let _ = writeln!(out, "out_range = {}", toml_quote(&format_packet_range(action.out_range)));
    }
    if !action
        .args
        .is_empty()
    {
        out.push_str("[profiles.actions.args]\n");
        for (key, val) in &action.args
        {
            if val.is_empty()
            {
                let _ = writeln!(out, "{key} = true");
            }
            else
            {
                let _ = writeln!(out, "{key} = {}", toml_quote(val));
            }
        }
    }
    out.push('\n');
}

/// Renders `profiles` and `opts` into a complete, `AppConfig::from_toml_str`-valid `nfqws2.toml`.
pub fn render_nfqws2_toml(profiles: &[CoveredProfile], opts: &TomlRenderOptions) -> String
{
    let mut out = String::new();
    out.push_str("# Generated by strat_finder (zapret-rs)\n");
    let _ = writeln!(out, "qnum = {}", opts.qnum);
    let _ = writeln!(out, "fwmark = 0x{:08x}", opts.fwmark);
    if !opts
        .lua_init
        .is_empty()
    {
        out.push_str("lua_init = [\n");
        for path in &opts.lua_init
        {
            let _ = writeln!(out, "  {},", toml_quote(&path.to_string_lossy()));
        }
        out.push_str("]\n");
    }
    out.push('\n');

    for covered in profiles
    {
        let spec = &covered.strategy;
        let _ = writeln!(
            out,
            "# strategy: {} (weight {}, avg {} ms)",
            spec.id, spec.weight, covered.avg_latency_ms
        );
        out.push_str("[[profiles]]\n");
        let _ = writeln!(out, "name = {}", toml_quote(&spec.id));
        let _ = writeln!(
            out,
            "filter_l3 = [{}]",
            toml_quote(
                spec.ipv
                    .as_str()
            )
        );
        let port = spec
            .proto
            .default_port()
            .to_string();
        if spec
            .proto
            .is_udp()
        {
            let _ = writeln!(out, "filter_udp = [{}]", toml_quote(&port));
        }
        else
        {
            let _ = writeln!(out, "filter_tcp = [{}]", toml_quote(&port));
        }
        let _ = writeln!(
            out,
            "filter_l7 = [{}]",
            toml_quote(
                spec.proto
                    .l7_proto()
                    .as_str()
            )
        );
        if !covered
            .domains
            .is_empty()
        {
            let doms: Vec<String> = covered
                .domains
                .iter()
                .map(|d| toml_quote(d))
                .collect();
            let _ = writeln!(out, "hostlist_domains = [{}]", doms.join(", "));
        }
        out.push('\n');
        for action in &spec.actions
        {
            write_action_toml(&mut out, action);
        }
    }

    out
}

/// Writes `content` to `path` with `O_NOFOLLOW`, creating missing parent directories automatically.
pub fn write_config_nofollow(path: &Path, content: &str) -> io::Result<()>
{
    if let Some(parent) = path.parent()
        && !parent
            .as_os_str()
            .is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut opts = OpenOptions::new();
    opts.write(true)
        .create(true)
        .truncate(true);
    #[cfg(unix)]
    opts.custom_flags(libc::O_NOFOLLOW);
    let mut file = opts.open(path)?;
    file.write_all(content.as_bytes())
}
