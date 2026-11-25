//! Core stateful DPI desync profile routing, reassembly, hostlist matching, and Lua orchestration.

/// Autohostlist failure detection, retrans RST injection, and self-append helpers.
pub mod autohost;
/// DNS IN A/AAAA response parsing populating the hostname/IP cache.
pub mod dns_cache;
/// Profile filter matching, Lua action execution, and verdict reconstruction engine.
pub mod engine;
/// ICMPv4/ICMPv6 related flow tracking and raw non-TCP/UDP/ICMP packet handlers.
pub mod icmp_ip;
/// Packet dispatch prolog and initial IPCache/conntrack/profile resolution.
pub mod play;
/// L7 protocol probe tables and TCP/UDP payload classifiers.
pub mod probe;
/// Deduplicated file list registry, autohostlist/ipset initialization, and full `dp_match` selection.
pub mod profile_state;
/// Client-side payload stream reassembly, delayed packet queuing, and replay orchestration.
pub mod reasm_replay;
/// Dynamic L7/hostname profile rediscovery and autohostlist gating.
pub mod rediscovery;
/// Stateful TCP packet desync pipeline with TLS reassembly, replay, and RST handling.
pub mod tcp;
/// Stateful UDP packet desync pipeline with QUIC decrypt/reassembly and DNS caching.
pub mod udp;
/// Verdict aggregation, Lua verdict validation, postnat drop workaround, and baseline helpers.
pub mod verdict;

/// Re-exported stateful desync execution engine.
pub use engine::DesyncEngine;
/// Re-exported list/autohostlist startup and `--dry-run` validation helper.
pub use profile_state::verify_config_list_files;
/// Re-exported verdict aggregator and baseline L7 payload classifier.
pub use verdict::{aggregate_verdict, classify_baseline_payload};
