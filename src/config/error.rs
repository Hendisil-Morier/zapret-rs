//! Typed configuration parsing, validation, and I/O errors for `src/config`.

/// File path attached to configuration and blob I/O failures.
use std::path::PathBuf;

/// Errors produced when parsing filters, loading blobs, or validating TOML/CLI config.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Port filter syntax or bounds failure (`[~]p1[-p2]|*`).
    #[error("invalid port filter '{0}'")]
    InvalidPortFilter(String),
    /// ICMP filter syntax or bounds failure (`*|-|type[:code]`).
    #[error("invalid ICMP filter '{0}'")]
    InvalidIcmpFilter(String),
    /// IP protocol filter syntax or bounds failure (`*|-|proto`).
    #[error("invalid IP protocol filter '{0}'")]
    InvalidIppFilter(String),
    /// Packet range expression syntax failure (`from-to`, `from<to`, `x`, `a`).
    #[error("invalid packet range '{0}'")]
    InvalidPacketRange(String),
    /// Firewall mark filter syntax failure (`mark[/mask]`).
    #[error("invalid firewall mark filter '{0}'")]
    InvalidMarkFilter(String),
    /// L3 protocol filter value was neither `ipv4` nor `ipv6`.
    #[error("invalid L3 filter '{0}' (expected 'ipv4' or 'ipv6')")]
    InvalidL3Filter(String),
    /// Unknown L7 protocol identifier in `filter_l7`.
    #[error("invalid L7 protocol name '{0}'")]
    InvalidL7Proto(String),
    /// Unknown L7 payload identifier in `payload`.
    #[error("invalid L7 payload name '{0}'")]
    InvalidL7Payload(String),
    /// Invalid hex or empty/oversized blob definition.
    #[error("invalid blob '{name}': {detail}")]
    InvalidBlob {
        /// Lua blob global name.
        name: String,
        /// Specific validation failure reason.
        detail: String,
    },
    /// Filesystem read or seek error when loading config, blob, or script files.
    #[error("failed reading configuration file '{}': {source}", path.display())]
    Io {
        /// Path that failed to open, seek, or read.
        path: PathBuf,
        /// Underlying OS I/O error.
        source: std::io::Error,
    },
    /// TOML syntax, type, or unknown-field deserialization failure.
    #[error("invalid TOML configuration: {0}")]
    TomlParse(#[from] toml::de::Error),
    /// Semantic configuration validation error across CLI flags or TOML fields.
    #[error("configuration validation error: {0}")]
    Validation(String),
}
