//! OS-agnostic firewall rule backend contract and target port collector.

/// Ordered deduplication when collecting configured TCP and UDP target ports.
use std::collections::BTreeSet;
/// Standard I/O result type returned by firewall rule installation.
use std::io;

/// Validated runtime configuration inspected for profile ports.
use crate::config::AppConfig;

/// Opaque RAII handle representing installed temporary firewall rules cleaned up on drop.
pub trait FirewallHandle: Send
{
    /// Returns `true` if tearing down this guard is likely to trigger an interactive `sudo` prompt.
    fn needs_interactive_drop(&self) -> bool
    {
        false
    }

    /// Disarms automatic rule deletion on drop (used when handing off ownership to a replacement guard).
    fn disarm(&mut self) {}
}

/// Injectable firewall rule backend allowing live OS rule setup and offline mock tests.
pub trait FirewallBackend
{
    /// Installs temporary packet-interception rules for `qnum`, `fwmark`, and target TCP/UDP ports.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>;

    /// Returns the TUI panel border title describing filters produced by this backend.
    fn preview_title(&self) -> &'static str
    {
        " Packet Filter Preview "
    }

    /// Renders a human-readable preview of the filter rules or expressions this backend applies.
    fn preview_filter(&self, _qnum: u16, _fwmark: u32, _tcp_ports: &[u16], _udp_ports: &[u16]) -> String
    {
        String::new()
    }
}

/// Fallback [`FirewallBackend`] used on OS targets without a packet-interception implementation yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedFirewallBackend;

impl FirewallBackend for UnsupportedFirewallBackend
{
    /// Returns [`io::ErrorKind::Unsupported`] explaining that this OS lacks packet-interception support.
    fn install(
        &self,
        _qnum: u16,
        _fwmark: u32,
        _tcp_ports: &[u16],
        _udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("packet interception is not implemented for OS '{}'", std::env::consts::OS),
        ))
    }

    /// Returns the panel title shown on unsupported operating systems.
    fn preview_title(&self) -> &'static str
    {
        " Packet Filter Preview "
    }

    /// Returns an explanatory notice instead of Linux `nftables` or Windows `WinDivert` rules.
    fn preview_filter(&self, _qnum: u16, _fwmark: u32, _tcp_ports: &[u16], _udp_ports: &[u16]) -> String
    {
        format!("# Packet interception is not implemented for OS '{}' yet.\n", std::env::consts::OS)
    }
}

/// Returns the active compile-time OS [`FirewallBackend`] for installing and previewing filters.
pub fn active_firewall_backend() -> Box<dyn FirewallBackend>
{
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

/// Inclusive port interval `(from, to)` collected for TCP/UDP firewall queues.
pub type PortInterval = (u16, u16);
/// Deduplicated `(tcp_ranges, udp_ranges)` port interval pair extracted from [`AppConfig`].
pub type PortRangePair = (Vec<PortInterval>, Vec<PortInterval>);

/// Maximum span of a port range expanded into individual `Vec<u16>` entries by [`collect_config_ports`].
const MAX_EXPANDED_PORT_SPAN: u16 = 256;

/// Inserts one non-negative, non-wildcard `(from, to)` port filter interval into `out`.
fn push_port_interval(out: &mut BTreeSet<(u16, u16)>, pf: &crate::config::PortFilter)
{
    if pf.neg || pf.to == 0
    {
        return;
    }
    let from = pf.from.max(1);
    if from > pf.to || (from == 1 && pf.to == u16::MAX)
    {
        return;
    }
    out.insert((from, pf.to));
}

/// Merges overlapping or adjacent inclusive `(from, to)` port intervals into canonical ascending form.
fn merge_port_intervals(intervals: BTreeSet<(u16, u16)>) -> Vec<(u16, u16)>
{
    let mut merged: Vec<(u16, u16)> = Vec::with_capacity(intervals.len());
    for (from, to) in intervals
    {
        if let Some(last) = merged.last_mut()
            && from <= last.1.saturating_add(1)
        {
            last.1 = last.1.max(to);
        }
        else
        {
            merged.push((from, to));
        }
    }
    merged
}

/// Collects merged inclusive TCP and UDP port intervals `(from, to)` referenced by `cfg.profiles`
/// (defaults to `(80, 80)`/`(443, 443)` and UDP `(443, 443)` when empty).
pub fn collect_config_port_ranges(cfg: &AppConfig) -> PortRangePair
{
    let mut tcp = BTreeSet::new();
    let mut udp = BTreeSet::new();
    for p in &cfg.profiles
    {
        for pf in &p.filter_tcp
        {
            push_port_interval(&mut tcp, pf);
        }
        for pf in &p.filter_udp
        {
            push_port_interval(&mut udp, pf);
        }
    }
    if tcp.is_empty() && udp.is_empty()
    {
        tcp.insert((80, 80));
        tcp.insert((443, 443));
        udp.insert((443, 443));
    }
    (merge_port_intervals(tcp), merge_port_intervals(udp))
}

/// Expands bounded port intervals into a sorted, deduplicated `Vec<u16>`.
fn expand_intervals(intervals: Vec<(u16, u16)>) -> Vec<u16>
{
    let mut ports = BTreeSet::new();
    for (from, to) in intervals
    {
        let span = to.saturating_sub(from);
        if span <= MAX_EXPANDED_PORT_SPAN
        {
            for port in from..=to
            {
                ports.insert(port);
            }
        }
    }
    ports.into_iter().collect()
}

/// Collects deduplicated TCP and UDP ports referenced by `cfg.profiles` (defaults to `80`/`443`).
pub fn collect_config_ports(cfg: &AppConfig) -> (Vec<u16>, Vec<u16>)
{
    let (tcp_ranges, udp_ranges) = collect_config_port_ranges(cfg);
    let mut tcp = expand_intervals(tcp_ranges);
    let mut udp = expand_intervals(udp_ranges);
    if tcp.is_empty() && udp.is_empty()
    {
        tcp = vec![80, 443];
        udp = vec![443];
    }
    (tcp, udp)
}
