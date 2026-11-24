//! Configuration filters, built-in blobs, TOML schema, and CLI configuration modules.

/// Default `zapret2` fake blobs and bounded hex/file blob loaders.
pub mod blobs;
/// Top-level `clap` CLI definition and override resolution.
pub mod cli;
/// Typed configuration and filter parsing errors.
pub mod error;
/// Port, ICMP, IP protocol, and firewall mark filters.
pub mod filter;
/// L7 protocol and payload bitmask classifications.
pub mod l7;
/// Validated runtime application, profile, and action models.
pub mod model;
/// Packet position counter and range expression filters.
pub mod range;
/// TOML configuration file deserialization.
pub mod schema;

/// Re-exported default and custom blob helpers.
pub use blobs::{
    FAKE_HTTP_REQUEST_DEFAULT, FAKE_QUIC_DEFAULT_LEN, FAKE_TLS_CLIENTHELLO_DEFAULT, MAX_BLOB_SIZE,
    default_blobs, load_file_blob, parse_hex_blob,
};
/// Re-exported CLI argument parser and config override resolver.
pub use cli::{CliArgs, resolve_config};
/// Re-exported configuration error enum.
pub use error::ConfigError;
/// Re-exported packet and profile filter primitives.
pub use filter::{
    FilterMode, IcmpFilter, IppFilter, MarkFilter, PortFilter, icmp_filters_match,
    ipp_filters_match, parse_u32_radix, port_filters_match,
};
/// Re-exported L7 protocol/payload enums and mask matchers.
pub use l7::{
    ALL_L7_PAYLOADS, L7Payload, L7Proto, l7_payload_matches, l7_payload_names,
    l7_payload_str_list, l7_proto_matches, parse_l7_payload_mask, parse_l7_proto_mask,
};
/// Re-exported validated runtime configuration and profile/action structs.
pub use model::{
    AppConfig, DEFAULT_LUA_GC_INTERVAL, DesyncAction, DesyncProfile, LuaInitEntry,
    ProfileMatchInput,
};
/// Re-exported packet position and range filter primitives.
pub use range::{PacketPos, PacketPosMode, PacketRange};
