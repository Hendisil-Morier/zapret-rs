//! Top-level TOML configuration file deserialization into validated [`AppConfig`] structures.

/// Ordered key-value maps for named custom blobs.
use std::collections::BTreeMap;
/// Filesystem reader for TOML config files.
use std::fs;
/// File path and borrowed path types for resolving relative config references.
use std::path::{Path, PathBuf};

/// Serde `Deserialize` macro for strict top-level TOML schema parsing.
use serde::Deserialize;

/// Hex and file binary blob loaders.
use crate::config::blobs::{load_file_blob, parse_hex_blob};
/// Typed configuration parsing and validation errors.
use crate::config::error::ConfigError;
/// L7 payload disable bitmask parser (`--payload-disable`, `--reasm-disable`).
use crate::config::l7::parse_l7_disable_mask;
/// Validated runtime application configuration, startup script variants, and writable directory mode.
use crate::config::model::{AppConfig, LuaInitEntry, WritableDirConfig};
/// Per-profile TOML schema and validated [`crate::config::DesyncProfile`] builder.
use crate::config::profile_schema::{RawProfile, build_profile};
/// Conntrack timeout parser for TOML `ctrack_timeouts`.
use crate::config::runtime_cfg::parse_timeouts;

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

/// Raw TOML `writable` setting accepting boolean enablement or a custom directory path.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawWritable {
    /// Boolean flag (`true` uses `$TMPDIR/zapret-rs` or `/tmp/zapret-rs`, `false` disables).
    Enabled(bool),
    /// Explicit writable directory path string (empty string selects the default path).
    Path(PathBuf),
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
    /// Enable server-side direction semantics (`--server`).
    server: Option<bool>,
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
    /// Colon-delimited conntrack stage timeouts `S:E:F[:U]` (`--ctrack-timeouts`).
    ctrack_timeouts: Option<String>,
    /// Disable internal connection tracking (`--ctrack-disable`).
    ctrack_disable: Option<bool>,
    /// IPCache entry lifetime in seconds (`--ipcache-lifetime`).
    ipcache_lifetime: Option<u32>,
    /// Enable DNS response domain-to-IP caching (`--ipcache-hostname`).
    ipcache_hostname: Option<bool>,
    /// L7 payloads excluded from detection (`--payload-disable`).
    #[serde(default)]
    payload_disable: Vec<String>,
    /// L7 payloads excluded from client-side reassembly (`--reasm-disable`).
    #[serde(default)]
    reasm_disable: Vec<String>,
    /// Autohostlist failure debug log path (`--hostlist-auto-debug`).
    hostlist_auto_debug: Option<PathBuf>,
    /// Optional writable Lua directory specification (`--writable`).
    writable: Option<RawWritable>,
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
        apply_scalar_fields(&mut cfg, &raw, base_dir)?;

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
            cfg.profiles
                .push(build_profile(next_index, raw_profile, base_dir)?);
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

/// Applies top-level scalar, path, conntrack, ipcache, and L7 disable options from `raw`.
fn apply_scalar_fields(
    cfg: &mut AppConfig,
    raw: &RawConfig,
    base_dir: Option<&Path>,
) -> Result<(), ConfigError> {
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
    if let Some(server) = raw.server {
        cfg.server = server;
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
    cfg.pidfile = raw.pidfile.clone().map(|p| resolve_path(p, base_dir));
    cfg.chdir = raw.chdir.clone().map(|p| resolve_path(p, base_dir));
    cfg.user = raw.user.clone();
    cfg.uid = raw.uid.clone();
    if let Some(lua_gc) = raw.lua_gc {
        cfg.lua_gc = lua_gc;
    }
    if let Some(timeouts) = raw.ctrack_timeouts.as_deref() {
        cfg.conntrack.timeouts = parse_timeouts(timeouts)?;
    }
    if let Some(disable) = raw.ctrack_disable {
        cfg.conntrack.disable = disable;
    }
    if let Some(lifetime) = raw.ipcache_lifetime {
        cfg.ipcache.lifetime_sec = lifetime;
    }
    if let Some(hostname) = raw.ipcache_hostname {
        cfg.ipcache.hostname = hostname;
    }
    if !raw.payload_disable.is_empty() {
        cfg.payload_disable = parse_l7_disable_mask(&raw.payload_disable)?;
    }
    if !raw.reasm_disable.is_empty() {
        cfg.reasm_disable = parse_l7_disable_mask(&raw.reasm_disable)?;
    }
    cfg.hostlist_auto_debug = raw
        .hostlist_auto_debug
        .clone()
        .map(|p| resolve_path(p, base_dir));
    cfg.writable = match &raw.writable {
        Some(RawWritable::Enabled(true)) => Some(WritableDirConfig::Default),
        Some(RawWritable::Enabled(false)) | None => None,
        Some(RawWritable::Path(path)) if path.as_os_str().is_empty() => {
            Some(WritableDirConfig::Default)
        }
        Some(RawWritable::Path(path)) => {
            Some(WritableDirConfig::Custom(resolve_path(path.clone(), base_dir)))
        }
    };
    Ok(())
}

/// Resolves relative file paths against `base_dir` when present.
pub(super) fn resolve_path(path: PathBuf, base_dir: Option<&Path>) -> PathBuf {
    if path.is_relative()
        && let Some(dir) = base_dir
    {
        return dir.join(path);
    }
    path
}
