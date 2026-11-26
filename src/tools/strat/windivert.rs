//! Windows WinDivert filter-expression builder implementing [`FirewallBackend`].

/// Standard I/O result type required by [`FirewallBackend`].
use std::io;

/// OS-agnostic firewall backend traits implemented here.
use crate::tools::strat::firewall::{FirewallBackend, FirewallHandle};

/// No-op RAII handle returned by [`WinDivertFirewallBackend`] (filtering happens inside WinDivert).
pub struct WinDivertFilterGuard {
    /// Generated WinDivert capture filter string for diagnostics.
    pub filter: String,
}

impl FirewallHandle for WinDivertFilterGuard {
    /// Returns `false` since WinDivert filter strings require no external `sudo` teardown.
    fn needs_interactive_drop(&self) -> bool {
        false
    }
}

/// Builds a WinDivert `NETWORK`-layer filter expression targeting `tcp_ports` and `udp_ports`.
pub fn build_windivert_filter(tcp_ports: &[u16], udp_ports: &[u16]) -> String {
    let mut clauses = Vec::new();
    if !tcp_ports.is_empty() {
        let ports: Vec<String> = tcp_ports.iter().map(|p| format!("tcp.DstPort == {p}")).collect();
        clauses.push(format!("(tcp and ({}))", ports.join(" or ")));
    }
    if !udp_ports.is_empty() {
        let ports: Vec<String> = udp_ports.iter().map(|p| format!("udp.DstPort == {p}")).collect();
        clauses.push(format!("(udp and ({}))", ports.join(" or ")));
    }
    if clauses.is_empty() {
        "outbound and (tcp or udp) and !impostor".to_owned()
    } else {
        format!("outbound and !impostor and ({})", clauses.join(" or "))
    }
}

/// Windows [`FirewallBackend`] producing WinDivert filter expressions without external firewall rules.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinDivertFirewallBackend;

impl FirewallBackend for WinDivertFirewallBackend {
    /// Returns a [`WinDivertFilterGuard`] holding the generated WinDivert filter expression.
    fn install(
        &self,
        _qnum: u16,
        _fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>> {
        Ok(Box::new(WinDivertFilterGuard {
            filter: build_windivert_filter(tcp_ports, udp_ports),
        }))
    }

    /// Returns the Windows WinDivert filter preview panel title shown on Tab 3.
    fn preview_title(&self) -> &'static str {
        " WinDivert Filter "
    }

    /// Renders the WinDivert `NETWORK`-layer capture filter expression preview.
    fn preview_filter(
        &self,
        _qnum: u16,
        _fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> String {
        build_windivert_filter(tcp_ports, udp_ports)
    }
}
