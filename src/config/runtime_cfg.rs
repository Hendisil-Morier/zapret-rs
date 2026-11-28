//! Milestone 3 connection tracking, IP cache, and per-profile list configuration types.

/// Filesystem path type used for per-profile hostlist and ipset file lists.
use std::path::PathBuf;

/// Typed configuration error returned when parsing malformed `--ctrack-timeouts` strings.
use crate::config::error::ConfigError;
/// Conntrack expiration thresholds (`syn`, `established`, `fin`, `udp`, `purge_interval`).
use crate::conntrack::ConntrackTimeouts;
/// Default IP/hostname cache lifetime (`IPCACHE_LIFETIME`) and autohostlist thresholds.
use crate::lists::{AutoHostlistSettings, DEFAULT_IPCACHE_LIFETIME_SEC};

/// Global connection tracking toggle and idle timeout configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConntrackConfig
{
    /// Disable internal connection tracking (`--ctrack-disable`).
    pub disable: bool,
    /// Per-stage idle expiration thresholds (`syn`, `established`, `fin`, `udp`).
    pub timeouts: ConntrackTimeouts,
}

impl Default for ConntrackConfig
{
    /// Returns enabled conntrack tracking with `zapret2` default `60:300:60:60` timeouts.
    fn default() -> Self
    {
        Self { disable: false, timeouts: ConntrackTimeouts::default() }
    }
}

/// Parses `--ctrack-timeouts` in `S:E:F[:U]` colon-delimited seconds format.
pub fn parse_timeouts(raw: &str) -> Result<ConntrackTimeouts, ConfigError>
{
    let parts: Vec<&str> = raw
        .trim()
        .split(':')
        .collect();
    if !(3..=4).contains(&parts.len())
    {
        return Err(ConfigError::Validation(format!(
            "invalid ctrack timeouts '{raw}' (expected syn:est:fin[:udp])"
        )));
    }
    let parse_sec = |s: &str| -> Result<u32, ConfigError> {
        let trimmed = s.trim();
        if trimmed.is_empty()
        {
            return Err(ConfigError::Validation(format!(
                "invalid ctrack timeouts '{raw}' (empty timeout component)"
            )));
        }
        trimmed
            .parse::<u32>()
            .map_err(|_| {
                ConfigError::Validation(format!(
                    "invalid ctrack timeouts '{raw}' (non-integer component '{trimmed}')"
                ))
            })
    };

    Ok(ConntrackTimeouts {
        syn: parse_sec(parts[0])?,
        established: parse_sec(parts[1])?,
        fin: parse_sec(parts[2])?,
        udp: match parts.get(3)
        {
            Some(udp) => parse_sec(udp)?,
            None => ConntrackTimeouts::default().udp,
        },
        ..ConntrackTimeouts::default()
    })
}

/// Global IP-to-hostname and hop-count cache configuration (`--ipcache-*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCacheConfig
{
    /// Entry time-to-live in seconds (`0` disables expiration).
    pub lifetime_sec: u32,
    /// Enable DNS response domain-to-IP learning (`--ipcache-hostname`).
    pub hostname: bool,
}

impl Default for IpCacheConfig
{
    /// Returns `zapret2` default IPCache settings (`7200s` lifetime, hostname learning off).
    fn default() -> Self
    {
        Self { lifetime_sec: DEFAULT_IPCACHE_LIFETIME_SEC as u32, hostname: false }
    }
}

/// Per-profile hostlist, exclusion list, autohostlist, and CIDR ipset configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileListsConfig
{
    /// Include domain list files (`--hostlist`, plain or gzip).
    pub hostlist: Vec<PathBuf>,
    /// Inline include domain tokens (`--hostlist-domains`).
    pub hostlist_domains: Vec<String>,
    /// Exclude domain list files (`--hostlist-exclude`, plain or gzip).
    pub hostlist_exclude: Vec<PathBuf>,
    /// Inline exclude domain tokens (`--hostlist-exclude-domains`).
    pub hostlist_exclude_domains: Vec<String>,
    /// Writable plaintext autohostlist file (`--hostlist-auto`, max one per profile).
    pub hostlist_auto: Option<PathBuf>,
    /// Per-profile autohostlist failure detection thresholds.
    pub hostlist_auto_settings: AutoHostlistSettings,
    /// Include IP/CIDR list files (`--ipset`, plain or gzip).
    pub ipset: Vec<PathBuf>,
    /// Inline include IP/CIDR tokens (`--ipset-ip`).
    pub ipset_ip: Vec<String>,
    /// Exclude IP/CIDR list files (`--ipset-exclude`, plain or gzip).
    pub ipset_exclude: Vec<PathBuf>,
    /// Inline exclude IP/CIDR tokens (`--ipset-exclude-ip`).
    pub ipset_exclude_ip: Vec<String>,
}
