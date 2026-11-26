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

    /// Returns the TUI panel border title describing filters produced by this backend.
    fn preview_title(&self) -> &'static str {
        " Packet Filter Preview "
    }

    /// Renders a human-readable preview of the filter rules or expressions this backend applies.
    fn preview_filter(
        &self,
        _qnum: u16,
        _fwmark: u32,
        _tcp_ports: &[u16],
        _udp_ports: &[u16],
    ) -> String {
        String::new()
    }
}

/// Fallback [`FirewallBackend`] used on OS targets without a packet-interception implementation yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedFirewallBackend;

impl FirewallBackend for UnsupportedFirewallBackend {
    /// Returns [`io::ErrorKind::Unsupported`] explaining that this OS lacks packet-interception support.
    fn install(
        &self,
        _qnum: u16,
        _fwmark: u32,
        _tcp_ports: &[u16],
        _udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("packet interception is not implemented for OS '{}'", std::env::consts::OS),
        ))
    }

    /// Returns the panel title shown on unsupported operating systems.
    fn preview_title(&self) -> &'static str {
        " Packet Filter Preview "
    }

    /// Returns an explanatory notice instead of Linux `nftables` or Windows `WinDivert` rules.
    fn preview_filter(
        &self,
        _qnum: u16,
        _fwmark: u32,
        _tcp_ports: &[u16],
        _udp_ports: &[u16],
    ) -> String {
        format!(
            "# Packet interception is not implemented for OS '{}' yet.\n",
            std::env::consts::OS
        )
    }
}

/// Returns the active compile-time OS [`FirewallBackend`] for installing and previewing filters.
pub fn active_firewall_backend() -> Box<dyn FirewallBackend> {
    #[cfg(windows)]
    {
        Box::new(crate::tools::strat::WinDivertFirewallBackend)
    }
    #[cfg(target_os = "linux")]
    {
        Box::new(crate::tools::strat::NftFirewallBackend::default())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Box::new(UnsupportedFirewallBackend)
    }
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
