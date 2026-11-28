//! Windows WinDivert filter-expression builder implementing [`FirewallBackend`].

/// Standard I/O result type required by [`FirewallBackend`].
use std::io;

/// OS-agnostic firewall backend traits implemented here.
use crate::tools::strat::firewall::{FirewallBackend, FirewallHandle};

/// No-op RAII handle returned by [`WinDivertFirewallBackend`] (filtering happens inside WinDivert).
pub struct WinDivertFilterGuard
{
    /// Generated WinDivert capture filter string for diagnostics.
    pub filter: String,
}

impl FirewallHandle for WinDivertFilterGuard
{
    /// Returns `false` since WinDivert filter strings require no external `sudo` teardown.
    fn needs_interactive_drop(&self) -> bool
    {
        false
    }
}

/// Builds a WinDivert `NETWORK`-layer filter expression targeting inclusive TCP/UDP port ranges.
pub fn build_windivert_filter_ranges(tcp_ranges: &[(u16, u16)], udp_ranges: &[(u16, u16)]) -> String
{
    let mut clauses = Vec::new();
    let fmt_proto = |proto: &str, ranges: &[(u16, u16)]| -> Option<String> {
        if ranges.is_empty()
        {
            return None;
        }
        let terms: Vec<String> = ranges
            .iter()
            .map(|&(from, to)| {
                if from == to
                {
                    format!("{proto}.DstPort == {from}")
                }
                else
                {
                    format!("({proto}.DstPort >= {from} and {proto}.DstPort <= {to})")
                }
            })
            .collect();
        Some(format!("({proto} and ({}))", terms.join(" or ")))
    };
    if let Some(tcp_clause) = fmt_proto("tcp", tcp_ranges)
    {
        clauses.push(tcp_clause);
    }
    if let Some(udp_clause) = fmt_proto("udp", udp_ranges)
    {
        clauses.push(udp_clause);
    }
    if clauses.is_empty()
    {
        "outbound and (tcp or udp) and !impostor".to_owned()
    }
    else
    {
        format!("outbound and !impostor and ({})", clauses.join(" or "))
    }
}

/// Builds a WinDivert `NETWORK`-layer filter expression targeting `tcp_ports` and `udp_ports`.
pub fn build_windivert_filter(tcp_ports: &[u16], udp_ports: &[u16]) -> String
{
    let tcp_ranges: Vec<(u16, u16)> = tcp_ports.iter().map(|&p| (p, p)).collect();
    let udp_ranges: Vec<(u16, u16)> = udp_ports.iter().map(|&p| (p, p)).collect();
    build_windivert_filter_ranges(&tcp_ranges, &udp_ranges)
}

/// Windows [`FirewallBackend`] producing WinDivert filter expressions without external firewall rules.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinDivertFirewallBackend;

impl FirewallBackend for WinDivertFirewallBackend
{
    /// Returns a [`WinDivertFilterGuard`] holding the generated WinDivert filter expression.
    fn install(
        &self,
        _qnum: u16,
        _fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        Ok(Box::new(WinDivertFilterGuard { filter: build_windivert_filter(tcp_ports, udp_ports) }))
    }

    /// Returns the Windows WinDivert filter preview panel title shown on Tab 3.
    fn preview_title(&self) -> &'static str
    {
        " WinDivert Filter "
    }

    /// Renders the WinDivert `NETWORK`-layer capture filter expression preview.
    fn preview_filter(&self, _qnum: u16, _fwmark: u32, tcp_ports: &[u16], udp_ports: &[u16]) -> String
    {
        build_windivert_filter(tcp_ports, udp_ports)
    }
}
