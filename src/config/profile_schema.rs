//! TOML `[[profiles]]` and `[[profiles.actions]]` schema parsing into validated profiles.

/// Ordered key-value maps for Lua desync action arguments.
use std::collections::BTreeMap;
/// Filesystem paths for profile-scoped hostlist and ipset files.
use std::path::{Path, PathBuf};

/// Serde `Deserialize` macro for strict per-profile TOML parsing.
use serde::Deserialize;

/// Typed configuration parsing and validation errors.
use crate::config::error::ConfigError;
/// Packet and profile filter primitives (`PortFilter`, `IcmpFilter`, etc.).
use crate::config::filter::{IcmpFilter, IppFilter, MarkFilter, PortFilter};
/// L7 protocol and payload bitmask parsers.
use crate::config::l7::{parse_l7_payload_mask, parse_l7_proto_mask};
/// Validated runtime profile and action structs.
use crate::config::model::{DesyncAction, DesyncProfile};
/// Packet position range parser for action `in_range` and `out_range` filters.
use crate::config::range::PacketRange;
/// Validated per-profile hostlist/ipset configuration model.
use crate::config::runtime_cfg::ProfileListsConfig;
/// Relative config path resolver shared with top-level TOML parsing.
use crate::config::schema::resolve_path;
/// Per-profile autohostlist thresholds structure.
use crate::lists::AutoHostlistSettings;

/// Raw TOML scalar argument value forwarded into Lua's `desync.arg` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub(super) enum RawActionArg {
    /// Boolean flag (`true` becomes `""` matching C flag presence; `false` is omitted).
    Bool(bool),
    /// Signed 64-bit integer encoded as decimal string for Lua compatibility.
    Int(i64),
    /// String parameter copied verbatim.
    Str(String),
}

/// Raw TOML `[[profiles.actions]]` block describing a Lua desync invocation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawAction {
    /// Target Lua function name (e.g., `"fake"`, `"multisplit"`).
    func: String,
    /// Allowed L7 payload names (`"all"` when empty).
    #[serde(default)]
    payload: Vec<String>,
    /// Incoming packet position range filter (`"x"` when omitted).
    in_range: Option<String>,
    /// Outgoing packet position range filter (`"a"` when omitted).
    out_range: Option<String>,
    /// Named scalar parameters passed in `desync.arg`.
    #[serde(default)]
    args: BTreeMap<String, RawActionArg>,
}

/// Raw TOML `[[profiles]]` block defining matching criteria, lists, and action pipeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawProfile {
    /// Optional human-readable profile name.
    name: Option<String>,
    /// Optional profile-bound string exposed to Lua via `desync.cookie`.
    cookie: Option<String>,
    /// Skip this profile entirely when `true`.
    #[serde(default)]
    pub(super) skip: bool,
    /// L3 filter list (`"ipv4"`, `"ipv6"`, or empty for both).
    #[serde(default)]
    filter_l3: Vec<String>,
    /// TCP port filter list (`[~]p1[-p2]|*`).
    #[serde(default)]
    filter_tcp: Vec<String>,
    /// UDP port filter list (`[~]p1[-p2]|*`).
    #[serde(default)]
    filter_udp: Vec<String>,
    /// ICMP type[:code] filter list (`*|-|type[:code]`).
    #[serde(default)]
    filter_icmp: Vec<String>,
    /// IP protocol number filter list (`*|-|proto`).
    #[serde(default)]
    filter_ipp: Vec<String>,
    /// L7 protocol filter list (`all`, `http`, `tls`, `quic`, etc.).
    #[serde(default)]
    filter_l7: Vec<String>,
    /// Optional firewall mark filter (`mark[/mask]`).
    filter_mark: Option<String>,
    /// Include hostlist files (`--hostlist`).
    #[serde(default)]
    hostlist: Vec<PathBuf>,
    /// Inline include domains (`--hostlist-domains`).
    #[serde(default)]
    hostlist_domains: Vec<String>,
    /// Exclude hostlist files (`--hostlist-exclude`).
    #[serde(default)]
    hostlist_exclude: Vec<PathBuf>,
    /// Inline exclude domains (`--hostlist-exclude-domains`).
    #[serde(default)]
    hostlist_exclude_domains: Vec<String>,
    /// Writable autohostlist file (`--hostlist-auto`).
    hostlist_auto: Option<PathBuf>,
    /// Autohostlist failure count threshold (`1..=20`).
    hostlist_auto_fail_threshold: Option<u32>,
    /// Autohostlist sliding window duration in seconds (`>= 1`).
    hostlist_auto_fail_time: Option<i64>,
    /// Autohostlist TCP retransmission threshold (`2..=10`).
    hostlist_auto_retrans_threshold: Option<u8>,
    /// Autohostlist maximum relative TCP sequence for retrans detection.
    hostlist_auto_retrans_maxseq: Option<u32>,
    /// Autohostlist synthetic RST toggle on retransmission limit.
    hostlist_auto_retrans_reset: Option<bool>,
    /// Autohostlist maximum relative server TCP sequence for failure/success checks.
    hostlist_auto_incoming_maxseq: Option<u32>,
    /// Autohostlist minimum outgoing UDP packet count for failure detection (`0` disables).
    hostlist_auto_udp_out: Option<u64>,
    /// Autohostlist maximum incoming UDP packet count still considered stalled.
    hostlist_auto_udp_in: Option<u64>,
    /// Cooldown in seconds between counted failures on the same host (`0` disables burst coalescing).
    hostlist_auto_fail_cooldown: Option<i64>,
    /// Distinct failing subdomains inside `fail_time_sec` required to promote their safe parent (`0` disables).
    hostlist_auto_sibling_threshold: Option<u32>,
    /// Enable non-blocking background TCP/TLS/HTTP confirmation probes for failing hosts.
    hostlist_auto_confirm: Option<bool>,
    /// Include CIDR ipset files (`--ipset`).
    #[serde(default)]
    ipset: Vec<PathBuf>,
    /// Inline include CIDR strings (`--ipset-ip`).
    #[serde(default)]
    ipset_ip: Vec<String>,
    /// Exclude CIDR ipset files (`--ipset-exclude`).
    #[serde(default)]
    ipset_exclude: Vec<PathBuf>,
    /// Inline exclude CIDR strings (`--ipset-exclude-ip`).
    #[serde(default)]
    ipset_exclude_ip: Vec<String>,
    /// Ordered Lua desync actions invoked when this profile matches.
    #[serde(default)]
    actions: Vec<RawAction>,
}

/// Parses comma-separated or array-element filter items using `parse_one`.
fn parse_comma_list<T>(
    items: &[String],
    parse_one: impl Fn(&str) -> Result<T, ConfigError>,
) -> Result<Vec<T>, ConfigError> {
    let mut out = Vec::new();
    for entry in items {
        for token in entry.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            out.push(parse_one(trimmed)?);
        }
    }
    Ok(out)
}

/// Maps relative filesystem paths inside list fields against `base_dir`.
fn resolve_paths(paths: Vec<PathBuf>, base_dir: Option<&Path>) -> Vec<PathBuf> {
    paths
        .into_iter()
        .map(|path| resolve_path(path, base_dir))
        .collect()
}

/// Converts a raw TOML profile into a validated [`DesyncProfile`] with `filter_defaults` applied.
pub(super) fn build_profile(
    index: u32,
    raw: RawProfile,
    base_dir: Option<&Path>,
) -> Result<DesyncProfile, ConfigError> {
    let (filter_ipv4, filter_ipv6) = parse_l3_filters(&raw.filter_l3)?;
    let mut filter_tcp = parse_comma_list(&raw.filter_tcp, PortFilter::parse)?;
    let mut filter_udp = parse_comma_list(&raw.filter_udp, PortFilter::parse)?;
    let mut filter_icmp = parse_comma_list(&raw.filter_icmp, IcmpFilter::parse)?;
    let mut filter_ipp = parse_comma_list(&raw.filter_ipp, IppFilter::parse)?;

    // Mirror `zapret2`'s `filter_defaults`: if any L4 filter is set, deny unset L4 protocol families.
    let any_l4 = !filter_tcp.is_empty()
        || !filter_udp.is_empty()
        || !filter_icmp.is_empty()
        || !filter_ipp.is_empty();
    if any_l4 {
        if filter_tcp.is_empty() {
            filter_tcp.push(PortFilter::deny_all());
        }
        if filter_udp.is_empty() {
            filter_udp.push(PortFilter::deny_all());
        }
        if filter_icmp.is_empty() {
            filter_icmp.push(IcmpFilter::skip());
        }
        if filter_ipp.is_empty() {
            filter_ipp.push(IppFilter::skip());
        }
    }

    let filter_l7 = parse_l7_proto_mask(&raw.filter_l7)?;
    let filter_mark = match raw.filter_mark.as_deref() {
        Some(raw_mark) => MarkFilter::parse(raw_mark)?,
        None => MarkFilter::default(),
    };
    let lists = build_profile_lists(&raw, base_dir)?;

    let mut actions = Vec::with_capacity(raw.actions.len());
    for raw_action in raw.actions {
        actions.push(build_action(raw_action)?);
    }

    Ok(DesyncProfile {
        index,
        name: raw.name,
        cookie: raw.cookie,
        filter_ipv4,
        filter_ipv6,
        filter_tcp,
        filter_udp,
        filter_icmp,
        filter_ipp,
        filter_l7,
        filter_mark,
        lists,
        actions,
    })
}

/// Validates and populates hostlist, autohostlist, and ipset settings for one profile.
fn build_profile_lists(
    raw: &RawProfile,
    base_dir: Option<&Path>,
) -> Result<ProfileListsConfig, ConfigError> {
    let mut settings = AutoHostlistSettings::default();
    if let Some(v) = raw.hostlist_auto_fail_threshold {
        settings.fail_threshold = v;
    }
    if let Some(v) = raw.hostlist_auto_fail_time {
        settings.fail_time_sec = v;
    }
    if let Some(v) = raw.hostlist_auto_retrans_threshold {
        settings.retrans_threshold = v;
    }
    if let Some(v) = raw.hostlist_auto_retrans_maxseq {
        settings.retrans_maxseq = v;
    }
    if let Some(v) = raw.hostlist_auto_retrans_reset {
        settings.retrans_reset = v;
    }
    if let Some(v) = raw.hostlist_auto_incoming_maxseq {
        settings.incoming_maxseq = v;
    }
    if let Some(v) = raw.hostlist_auto_udp_out {
        settings.udp_out = v;
    }
    if let Some(v) = raw.hostlist_auto_udp_in {
        settings.udp_in = v;
    }
    if let Some(v) = raw.hostlist_auto_fail_cooldown {
        settings.fail_cooldown_sec = v;
    }
    if let Some(v) = raw.hostlist_auto_sibling_threshold {
        settings.sibling_threshold = v;
    }
    if let Some(v) = raw.hostlist_auto_confirm {
        settings.confirm_block = v;
    }
    if let Err(msg) = settings.validate() {
        return Err(ConfigError::Validation(msg.to_owned()));
    }

    let split_tokens = |items: &[String]| -> Result<Vec<String>, ConfigError> {
        parse_comma_list(items, |token| Ok(token.to_owned()))
    };

    Ok(ProfileListsConfig {
        hostlist: resolve_paths(raw.hostlist.clone(), base_dir),
        hostlist_domains: split_tokens(&raw.hostlist_domains)?,
        hostlist_exclude: resolve_paths(raw.hostlist_exclude.clone(), base_dir),
        hostlist_exclude_domains: split_tokens(&raw.hostlist_exclude_domains)?,
        hostlist_auto: raw
            .hostlist_auto
            .clone()
            .map(|p| resolve_path(p, base_dir)),
        hostlist_auto_settings: settings,
        ipset: resolve_paths(raw.ipset.clone(), base_dir),
        ipset_ip: split_tokens(&raw.ipset_ip)?,
        ipset_exclude: resolve_paths(raw.ipset_exclude.clone(), base_dir),
        ipset_exclude_ip: split_tokens(&raw.ipset_exclude_ip)?,
    })
}

/// Parses `filter_l3` items (`ipv4`/`ipv6`), defaulting to both enabled when empty.
fn parse_l3_filters(items: &[String]) -> Result<(bool, bool), ConfigError> {
    let mut saw_any = false;
    let mut ipv4 = false;
    let mut ipv6 = false;
    for entry in items {
        for token in entry.split(',') {
            let trimmed = token.trim();
            if trimmed.is_empty() {
                continue;
            }
            saw_any = true;
            match trimmed {
                "ipv4" => ipv4 = true,
                "ipv6" => ipv6 = true,
                _ => return Err(ConfigError::InvalidL3Filter(trimmed.to_owned())),
            }
        }
    }
    if !saw_any {
        return Ok((true, true));
    }
    Ok((ipv4, ipv6))
}

/// Converts a raw TOML action block into a validated [`DesyncAction`].
fn build_action(raw: RawAction) -> Result<DesyncAction, ConfigError> {
    let func = raw.func.trim().to_owned();
    if func.is_empty() {
        return Err(ConfigError::Validation(
            "action `func` name cannot be empty".to_owned(),
        ));
    }
    let payload_mask = parse_l7_payload_mask(&raw.payload)?;
    let in_range = match raw.in_range.as_deref() {
        Some(expr) => PacketRange::parse(expr)?,
        None => PacketRange::NEVER,
    };
    let out_range = match raw.out_range.as_deref() {
        Some(expr) => PacketRange::parse(expr)?,
        None => PacketRange::ALWAYS,
    };

    let mut args = BTreeMap::new();
    for (key, val) in raw.args {
        match val {
            RawActionArg::Bool(true) => {
                // In `zapret2`, boolean flags like `tcp_md5` are empty strings (`""`), which are truthy in Lua.
                args.insert(key, String::new());
            }
            RawActionArg::Bool(false) => {}
            RawActionArg::Int(n) => {
                args.insert(key, n.to_string());
            }
            RawActionArg::Str(s) => {
                args.insert(key, s);
            }
        }
    }

    Ok(DesyncAction {
        func,
        payload_mask,
        in_range,
        out_range,
        args,
    })
}
