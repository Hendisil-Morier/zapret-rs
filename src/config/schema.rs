//! TOML configuration deserialization, profile matching, and validated runtime config conversion.

/// Ordered key-value maps for named blobs and Lua desync function arguments.
use std::collections::BTreeMap;
/// Filesystem reader for TOML config files.
use std::fs;
/// File path and borrowed path types for resolving relative config references.
use std::path::{Path, PathBuf};

/// Serde `Deserialize` macro for strict TOML schema parsing.
use serde::Deserialize;

/// Built-in default blob map and hex/file blob loaders.
use crate::config::blobs::{default_blobs, load_file_blob, parse_hex_blob};
/// Typed configuration parsing and validation errors.
use crate::config::error::ConfigError;
/// Packet and profile filter primitives (`PortFilter`, `IcmpFilter`, etc.).
use crate::config::filter::{
    IcmpFilter, IppFilter, MarkFilter, PacketRange, PortFilter, icmp_filters_match,
    ipp_filters_match, port_filters_match,
};
/// L7 protocol and payload classification enums and bitmask helpers.
use crate::config::l7::{L7Proto, l7_proto_matches, parse_l7_payload_mask, parse_l7_proto_mask};
/// Default NFQUEUE configuration constants and [`QueueConfig`] target struct.
use crate::intercepter::{DEFAULT_DESYNC_FWMARK, DEFAULT_QUEUE_NUM, QueueConfig};
/// Lua runtime configuration struct populated from [`AppConfig`].
use crate::lua::LuaConfig;
/// IP protocol constants for routing L4 filter evaluation.
use crate::packet::constants::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};

/// Default forced Lua garbage collection interval in seconds (`LUA_GC_INTERVAL` in `params.h`).
pub const DEFAULT_LUA_GC_INTERVAL: u64 = 60;

/// Raw TOML `lua_init` item supporting a script path or an inline chunk table (`{ inline = "..." }`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawLuaInit {
    /// Path to a Lua script file loaded at startup.
    File(PathBuf),
    /// Inline Lua source snippet (`{ inline = "..." }`).
    Inline {
        /// Lua source code executed directly at startup.
        inline: String,
    },
}

/// Raw TOML `[blobs]` entry supporting inline hex (`"0x..."`) or file slice (`{ file = "...", offset = 0 }`).
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawBlobSpec {
    /// Hex-encoded byte sequence.
    Hex(String),
    /// Disk file and byte start offset.
    File {
        /// Path to the binary blob file.
        file: PathBuf,
        /// Optional starting byte offset within `file`.
        #[serde(default)]
        offset: u64,
    },
}

/// Raw TOML scalar argument value forwarded into Lua's `desync.arg` table.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawActionArg {
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
struct RawAction {
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

/// Raw TOML `[[profiles]]` block defining matching criteria and action pipeline.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProfile {
    /// Optional human-readable profile name.
    name: Option<String>,
    /// Optional profile-bound string exposed to Lua via `desync.cookie`.
    cookie: Option<String>,
    /// Skip this profile entirely when `true`.
    #[serde(default)]
    skip: bool,
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
    /// Ordered Lua desync actions invoked when this profile matches.
    #[serde(default)]
    actions: Vec<RawAction>,
}

/// Top-level TOML configuration file structure (`nfqws2.toml`).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    /// Netfilter queue number (`--qnum`).
    qnum: Option<u16>,
    /// Desync firewall mark bitmask (`--fwmark`).
    fwmark: Option<u32>,
    /// Enable IPv4 `SO_BINDTODEVICE` routing fixup (`--bind-fix4`).
    bind_fix4: Option<bool>,
    /// Enable IPv6 `SO_BINDTODEVICE` routing fixup (`--bind-fix6`).
    bind_fix6: Option<bool>,
    /// Enable verbose debug logging (`--debug`).
    debug: Option<bool>,
    /// Enable NFQUEUE interception (`--intercept`).
    intercept: Option<bool>,
    /// Fork into background daemon mode (`--daemon`).
    daemon: Option<bool>,
    /// PID file path (`--pidfile`).
    pidfile: Option<PathBuf>,
    /// Working directory set on startup (`--chdir`).
    chdir: Option<PathBuf>,
    /// Target username for privilege drop (`--user`).
    user: Option<String>,
    /// Explicit numeric UID[:GID,...] specification for privilege drop (`--uid`).
    uid: Option<String>,
    /// Forced Lua GC interval in seconds (`--lua-gc`).
    lua_gc: Option<u64>,
    /// Ordered list of startup Lua scripts or inline chunks.
    #[serde(default)]
    lua_init: Vec<RawLuaInit>,
    /// Custom Lua binary blobs merged over built-in defaults.
    #[serde(default)]
    blobs: BTreeMap<String, RawBlobSpec>,
    /// Ordered strategy profiles evaluated per packet.
    #[serde(default)]
    profiles: Vec<RawProfile>,
}

/// Resolved startup Lua script source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LuaInitEntry {
    /// Path to a Lua script executed via `LuaRuntime::exec_file`.
    File(PathBuf),
    /// Inline Lua code executed via `LuaRuntime::exec_str`.
    Inline(String),
}

/// Validated Lua desync invocation attached to a [`DesyncProfile`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesyncAction {
    /// Lua global function name invoked for matching packets.
    pub func: String,
    /// Bitmask of allowed [`crate::config::L7Payload`] variants (`0` = all).
    pub payload_mask: u64,
    /// Incoming packet position range filter.
    pub in_range: PacketRange,
    /// Outgoing packet position range filter.
    pub out_range: PacketRange,
    /// String-normalized key-value parameters passed in `desync.arg`.
    pub args: BTreeMap<String, String>,
}

/// Packet L3/L4/L7 attributes evaluated against a [`DesyncProfile`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProfileMatchInput {
    /// `true` for IPv6 packets, `false` for IPv4 packets.
    pub is_v6: bool,
    /// Wire transport/next-header protocol number (`IPPROTO_TCP`, `IPPROTO_UDP`, etc.).
    pub l4proto: u8,
    /// Relevant TCP/UDP port number (`0` for non-TCP/UDP protocols).
    pub port: u16,
    /// ICMPv4 or ICMPv6 message type (`0` when not ICMP).
    pub icmp_type: u8,
    /// ICMPv4 or ICMPv6 message code (`0` when not ICMP).
    pub icmp_code: u8,
    /// Kernel firewall mark (`nfmark`) associated with the packet.
    pub fwmark: u32,
    /// Discovered L7 protocol ([`L7Proto::Unknown`] prior to Milestone 3 DPI probes).
    pub l7proto: L7Proto,
}

/// Validated multi-strategy profile with normalized L3/L4/L7 filters and desync actions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesyncProfile {
    /// 1-based active profile index (`dp.n` in `zapret2`).
    pub index: u32,
    /// Optional human-readable profile name.
    pub name: Option<String>,
    /// Optional profile-bound cookie string passed to Lua (`desync.cookie`).
    pub cookie: Option<String>,
    /// Whether IPv4 packets match this profile.
    pub filter_ipv4: bool,
    /// Whether IPv6 packets match this profile.
    pub filter_ipv6: bool,
    /// TCP port filter rules (populated with `deny_all` if another L4 filter is active).
    pub filter_tcp: Vec<PortFilter>,
    /// UDP port filter rules (populated with `deny_all` if another L4 filter is active).
    pub filter_udp: Vec<PortFilter>,
    /// ICMP type/code rules (populated with `skip` if another L4 filter is active).
    pub filter_icmp: Vec<IcmpFilter>,
    /// Non-TCP/UDP/ICMP IP protocol rules (populated with `skip` if another L4 filter is active).
    pub filter_ipp: Vec<IppFilter>,
    /// Allowed L7 protocol bitmask (`0` = all).
    pub filter_l7: u64,
    /// Kernel firewall mark matcher (`mark/mask`).
    pub filter_mark: MarkFilter,
    /// Ordered Lua desync action pipeline for matching packets.
    pub actions: Vec<DesyncAction>,
}

impl DesyncProfile {
    /// Returns `true` if `input` satisfies mark, L3, L7, and L4 filters on this profile.
    pub fn matches(&self, input: &ProfileMatchInput) -> bool {
        if !self.filter_mark.matches(input.fwmark) {
            return false;
        }
        if (!input.is_v6 && !self.filter_ipv4) || (input.is_v6 && !self.filter_ipv6) {
            return false;
        }
        if !l7_proto_matches(input.l7proto, self.filter_l7) {
            return false;
        }
        match input.l4proto {
            IPPROTO_TCP => port_filters_match(&self.filter_tcp, input.port),
            IPPROTO_UDP => port_filters_match(&self.filter_udp, input.port),
            IPPROTO_ICMP | IPPROTO_ICMPV6 => {
                icmp_filters_match(&self.filter_icmp, input.icmp_type, input.icmp_code)
            }
            _ => ipp_filters_match(&self.filter_ipp, input.l4proto),
        }
    }
}

/// Complete validated application configuration merged from TOML and CLI overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppConfig {
    /// Netfilter queue number (`--qnum`).
    pub qnum: u16,
    /// Desync firewall mark applied to injected raw packets (`--fwmark`).
    pub fwmark: u32,
    /// Enable IPv4 `SO_BINDTODEVICE` routing fixup.
    pub bind_fix4: bool,
    /// Enable IPv6 `SO_BINDTODEVICE` routing fixup.
    pub bind_fix6: bool,
    /// Enable verbose debug logging.
    pub debug: bool,
    /// Enable NFQUEUE packet interception (`false` runs timers/init only).
    pub intercept: bool,
    /// Daemonize process after startup initialization.
    pub daemon: bool,
    /// Optional PID file written on startup.
    pub pidfile: Option<PathBuf>,
    /// Optional working directory change on startup.
    pub chdir: Option<PathBuf>,
    /// Optional username to drop privileges to.
    pub user: Option<String>,
    /// Optional explicit numeric `uid[:gid,...]` specification.
    pub uid: Option<String>,
    /// Forced Lua garbage collection interval in seconds (`0` disables periodic GC).
    pub lua_gc: u64,
    /// Ordered Lua startup scripts and inline snippets.
    pub lua_init: Vec<LuaInitEntry>,
    /// Named binary blobs registered into Lua globals (`fake_default_*` plus custom entries).
    pub blobs: BTreeMap<String, Vec<u8>>,
    /// Ordered non-skipped DPI desync profiles.
    pub profiles: Vec<DesyncProfile>,
}

impl Default for AppConfig {
    /// Returns standard `zapret2`-compatible runtime defaults with built-in default blobs.
    fn default() -> Self {
        Self {
            qnum: DEFAULT_QUEUE_NUM,
            fwmark: DEFAULT_DESYNC_FWMARK,
            bind_fix4: false,
            bind_fix6: false,
            debug: false,
            intercept: true,
            daemon: false,
            pidfile: None,
            chdir: None,
            user: None,
            uid: None,
            lua_gc: DEFAULT_LUA_GC_INTERVAL,
            lua_init: Vec::new(),
            blobs: default_blobs(),
            profiles: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Parses and validates an [`AppConfig`] from TOML text, resolving relative paths from `base_dir`.
    pub fn from_toml_str(input: &str, base_dir: Option<&Path>) -> Result<Self, ConfigError> {
        let raw: RawConfig = toml::from_str(input)?;
        let mut cfg = Self::default();
        if let Some(qnum) = raw.qnum {
            cfg.qnum = qnum;
        }
        if let Some(fwmark) = raw.fwmark {
            cfg.fwmark = fwmark;
        }
        if let Some(bind_fix4) = raw.bind_fix4 {
            cfg.bind_fix4 = bind_fix4;
        }
        if let Some(bind_fix6) = raw.bind_fix6 {
            cfg.bind_fix6 = bind_fix6;
        }
        if let Some(debug) = raw.debug {
            cfg.debug = debug;
        }
        if let Some(intercept) = raw.intercept {
            cfg.intercept = intercept;
        }
        if let Some(daemon) = raw.daemon {
            cfg.daemon = daemon;
        }
        cfg.pidfile = raw.pidfile.map(|p| resolve_path(p, base_dir));
        cfg.chdir = raw.chdir.map(|p| resolve_path(p, base_dir));
        cfg.user = raw.user;
        cfg.uid = raw.uid;
        if let Some(lua_gc) = raw.lua_gc {
            cfg.lua_gc = lua_gc;
        }

        cfg.lua_init = raw
            .lua_init
            .into_iter()
            .map(|entry| match entry {
                RawLuaInit::File(path) => LuaInitEntry::File(resolve_path(path, base_dir)),
                RawLuaInit::Inline { inline } => LuaInitEntry::Inline(inline),
            })
            .collect();

        for (name, spec) in raw.blobs {
            let trimmed = name.trim();
            if trimmed.is_empty() {
                return Err(ConfigError::Validation("blob name cannot be empty".to_owned()));
            }
            let data = match spec {
                RawBlobSpec::Hex(hex) => parse_hex_blob(trimmed, &hex)?,
                RawBlobSpec::File { file, offset } => {
                    let resolved = resolve_path(file, base_dir);
                    load_file_blob(trimmed, &resolved, offset)?
                }
            };
            cfg.blobs.insert(trimmed.to_owned(), data);
        }

        let mut next_index = 1u32;
        for raw_profile in raw.profiles {
            if raw_profile.skip {
                continue;
            }
            cfg.profiles.push(build_profile(next_index, raw_profile)?);
            next_index = next_index.saturating_add(1);
        }

        cfg.validate()?;
        Ok(cfg)
    }

    /// Reads, parses, and validates a TOML configuration file from `path`.
    pub fn from_toml_file(path: &Path) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_toml_str(&content, path.parent())
    }

    /// Enforces cross-field invariants that apply after merging TOML and CLI overrides.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.user.is_some() && self.uid.is_some() {
            return Err(ConfigError::Validation(
                "cannot specify both `user` and `uid` for privilege drop".to_owned(),
            ));
        }
        Ok(())
    }

    /// Derives [`QueueConfig`] settings for `QueueCatcher::bind`.
    pub fn to_queue_config(&self) -> QueueConfig {
        QueueConfig {
            queue_num: self.qnum,
            desync_fwmark: self.fwmark,
            ..QueueConfig::default()
        }
    }

    /// Derives [`LuaConfig`] settings for `LuaRuntime::new`.
    pub fn to_lua_config(&self) -> LuaConfig {
        LuaConfig {
            qnum: u32::from(self.qnum),
            desync_fwmark: self.fwmark,
            bind_fix4: self.bind_fix4,
            bind_fix6: self.bind_fix6,
            debug: self.debug,
            daemon: self.daemon,
            ..LuaConfig::default()
        }
    }
}

/// Resolves relative file paths against `base_dir` when present.
fn resolve_path(path: PathBuf, base_dir: Option<&Path>) -> PathBuf {
    if path.is_relative()
        && let Some(dir) = base_dir
    {
        return dir.join(path);
    }
    path
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

/// Converts a raw TOML profile into a validated [`DesyncProfile`] with `filter_defaults` applied.
fn build_profile(index: u32, raw: RawProfile) -> Result<DesyncProfile, ConfigError> {
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
        actions,
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
