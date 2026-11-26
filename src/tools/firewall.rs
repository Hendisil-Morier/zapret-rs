//! OS-agnostic firewall rule backend contract and target port collector.

/// Ordered deduplication when collecting configured TCP and UDP target ports.
use std::collections::BTreeSet;
/// Standard I/O result type returned by firewall rule installation.
use std::io;

/// Validated runtime configuration inspected for profile ports.
use crate::config::AppConfig;

/// Opaque RAII handle representing installed temporary firewall rules cleaned up on drop.
pub trait FirewallHandle: Send {
    /// Returns `true` if tearing down this guard is likely to trigger an interactive `sudo` prompt.
    fn needs_interactive_drop(&self) -> bool {
        false
    }
}

/// Injectable firewall rule backend allowing live OS rule setup and offline mock tests.
pub trait FirewallBackend {
    /// Installs temporary packet-interception rules for `qnum`, `fwmark`, and target TCP/UDP ports.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>;
}

/// Collects deduplicated TCP and UDP ports referenced by `cfg.profiles` (defaults to `80`/`443`).
pub fn collect_config_ports(cfg: &AppConfig) -> (Vec<u16>, Vec<u16>) {
    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();
    for p in &cfg.profiles {
        for pf in &p.filter_tcp {
            if !pf.neg && pf.from > 0 && pf.from == pf.to {
                tcp.insert(pf.from);
            }
        }
        for pf in &p.filter_udp {
            if !pf.neg && pf.from > 0 && pf.from == pf.to {
                udp.insert(pf.from);
            }
        }
    }
    if tcp.is_empty() && udp.is_empty() {
        tcp.insert(80);
        tcp.insert(443);
        udp.insert(443);
    }
    (tcp.into_iter().collect(), udp.into_iter().collect())
}
