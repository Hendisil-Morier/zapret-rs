//! Validated application runtime configuration, profile matching, and queue/Lua config adapters.

/// Ordered map storing normalized Lua desync action arguments and named binary blobs.
use std::collections::BTreeMap;
/// Owned paths for startup Lua scripts, PID files, and working directories.
use std::path::PathBuf;

/// Built-in `zapret2` default blobs used to seed `AppConfig::blobs`.
use crate::config::blobs::default_blobs;
/// Typed configuration validation errors.
use crate::config::error::ConfigError;
/// Port, ICMP, IP protocol, and firewall mark filter evaluators.
use crate::config::filter::{
    IcmpFilter, IppFilter, MarkFilter, PortFilter, icmp_filters_match, ipp_filters_match,
    port_filters_match,
};
/// L7 protocol enums, bitmask matchers, and default none-disable bitmask constant.
use crate::config::l7::{L7_PAYLOAD_NONE_MASK, L7Proto, l7_proto_matches};
/// Packet position range filters evaluated per action.
use crate::config::range::PacketRange;
/// Milestone 3 conntrack, ipcache, and per-profile list configuration types.
use crate::config::runtime_cfg::{ConntrackConfig, IpCacheConfig, ProfileListsConfig};
/// Default NFQUEUE configuration constants and [`QueueConfig`] target struct.
use crate::intercepter::{DEFAULT_DESYNC_FWMARK, DEFAULT_QUEUE_NUM, QueueConfig};
/// Lua runtime configuration struct populated from [`AppConfig`].
use crate::lua::LuaConfig;
/// IP protocol constants for routing L4 filter evaluation.
use crate::packet::constants::{IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP};

/// Default forced Lua garbage collection interval in seconds (`LUA_GC_INTERVAL` in `params.h`).
pub const DEFAULT_LUA_GC_INTERVAL: u64 = 60;

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
    /// Per-profile include/exclude hostlists, autohostlist, and CIDR ipset configuration.
    pub lists: ProfileListsConfig,
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
    /// Enable server-side direction tracking (`--server`, `b_server`).
    pub server: bool,
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
    /// Global connection tracking disable switch and stage timeouts (`--ctrack-*`).
    pub conntrack: ConntrackConfig,
    /// Global IP-to-hostname and hop-count cache configuration (`--ipcache-*`).
    pub ipcache: IpCacheConfig,
    /// Bitmask of L7 payloads excluded from discovery (`--payload-disable`).
    pub payload_disable: u64,
    /// Bitmask of L7 payloads excluded from client-side reassembly (`--reasm-disable`).
    pub reasm_disable: u64,
    /// Optional autohostlist failure debug log path (`--hostlist-auto-debug`).
    pub hostlist_auto_debug: Option<PathBuf>,
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
            server: false,
            debug: false,
            intercept: true,
            daemon: false,
            pidfile: None,
            chdir: None,
            user: None,
            uid: None,
            lua_gc: DEFAULT_LUA_GC_INTERVAL,
            conntrack: ConntrackConfig::default(),
            ipcache: IpCacheConfig::default(),
            payload_disable: L7_PAYLOAD_NONE_MASK,
            reasm_disable: L7_PAYLOAD_NONE_MASK,
            hostlist_auto_debug: None,
            lua_init: Vec::new(),
            blobs: default_blobs(),
            profiles: Vec::new(),
        }
    }
}

impl AppConfig {
    /// Enforces cross-field invariants that apply after merging TOML and CLI overrides.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.user.is_some() && self.uid.is_some() {
            return Err(ConfigError::Validation(
                "cannot specify both `user` and `uid` for privilege drop".to_owned(),
            ));
        }
        for profile in &self.profiles {
            if let Err(msg) = profile.lists.hostlist_auto_settings.validate() {
                return Err(ConfigError::Validation(msg.to_owned()));
            }
            if profile.lists.hostlist_auto.is_some() {
                if self.server {
                    return Err(ConfigError::Validation(
                        "autohostlist is not supported in server mode".to_owned(),
                    ));
                }
                if self.conntrack.disable {
                    return Err(ConfigError::Validation(
                        "autohostlist is not supported when conntrack is disabled".to_owned(),
                    ));
                }
            }
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
            server: self.server,
            cache_hostname: self.ipcache.hostname,
            ctrack_disable: self.conntrack.disable,
            ctrack_timeouts: self.conntrack.timeouts,
            lua_gc_sec: self.lua_gc,
            ..LuaConfig::default()
        }
    }
}
