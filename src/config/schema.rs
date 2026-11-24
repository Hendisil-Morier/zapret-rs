//! TOML configuration file deserialization into validated [`AppConfig`] structures.

/// Ordered key-value maps for named blobs and Lua desync function arguments.
use std::collections::BTreeMap;
/// Filesystem reader for TOML config files.
use std::fs;
/// File path and borrowed path types for resolving relative config references.
use std::path::{Path, PathBuf};

/// Serde `Deserialize` macro for strict TOML schema parsing.
use serde::Deserialize;

/// Hex and file binary blob loaders.
use crate::config::blobs::{load_file_blob, parse_hex_blob};
/// Typed configuration parsing and validation errors.
use crate::config::error::ConfigError;
/// Packet and profile filter primitives (`PortFilter`, `IcmpFilter`, etc.).
use crate::config::filter::{IcmpFilter, IppFilter, MarkFilter, PortFilter};
/// L7 protocol and payload bitmask parsers.
use crate::config::l7::{parse_l7_payload_mask, parse_l7_proto_mask};
/// Validated runtime configuration types populated by the TOML deserializer.
use crate::config::model::{AppConfig, DesyncAction, DesyncProfile, LuaInitEntry};
/// Packet position range parser for action `in_range` and `out_range` filters.
use crate::config::range::PacketRange;

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
