//! Pure `nftables` script rendering for `table inet zapret_strat_finder` NFQUEUE rules.

/// Formatting helper for building multi-line `nft -f -` rule scripts.
use std::fmt::Write as _;

/// Dedicated `nftables` table name managed for strategy finder and `--nft` daemon sessions.
pub const STRAT_FINDER_NFT_TABLE: &str = "zapret_strat_finder";

/// Formats singleton ports as `{ p1, p2, ... }` and non-singleton intervals as `from-to` clauses.
fn fmt_port_exprs(ranges: &[(u16, u16)]) -> Vec<String>
{
    let mut exprs = Vec::new();
    let singles: Vec<String> =
        ranges.iter().filter(|(from, to)| from == to).map(|(from, _)| from.to_string()).collect();
    if !singles.is_empty()
    {
        exprs.push(format!("{{ {} }}", singles.join(", ")));
    }
    for (from, to) in ranges.iter().copied().filter(|(from, to)| from < to)
    {
        exprs.push(format!("{from}-{to}"));
    }
    exprs
}

/// Appends `queue num {qnum} bypass` NFQUEUE rules for `tcp_ranges` and `udp_ranges`.
fn write_dport_queue_rules(
    script: &mut String,
    prefix: &str,
    qnum: u16,
    tcp_ranges: &[(u16, u16)],
    udp_ranges: &[(u16, u16)],
)
{
    for expr in fmt_port_exprs(tcp_ranges)
    {
        let _ = writeln!(script, "    {prefix}tcp dport {expr} queue num {qnum} bypass");
    }
    for expr in fmt_port_exprs(udp_ranges)
    {
        let _ = writeln!(script, "    {prefix}udp dport {expr} queue num {qnum} bypass");
    }
}

/// Appends an early server-reply conntrack queue rule (`ct original packets 1-6`) to `script`.
fn write_sport_reply_rule(script: &mut String, prefix: &str, qnum: u16, tcp_ranges: &[(u16, u16)])
{
    for expr in fmt_port_exprs(tcp_ranges)
    {
        let _ =
            writeln!(script, "    {prefix}tcp sport {expr} ct original packets 1-6 queue num {qnum} bypass");
    }
}

/// Formats a multi-line `nft -f -` script from inclusive `(from, to)` TCP/UDP port ranges.
pub(crate) fn render_nft_script_ranges(
    qnum: u16,
    fwmark: u32,
    tcp_ranges: &[(u16, u16)],
    udp_ranges: &[(u16, u16)],
) -> String
{
    let mut script = String::new();
    let _ = writeln!(script, "table inet {STRAT_FINDER_NFT_TABLE} {{");

    // Locally-originated outbound packets.
    script.push_str("  chain output {\n");
    script.push_str("    type filter hook output priority mangle; policy accept;\n");
    let _ = writeln!(script, "    meta mark & 0x{fwmark:x} != 0 accept");
    write_dport_queue_rules(&mut script, "", qnum, tcp_ranges, udp_ranges);
    script.push_str("  }\n");

    // Forwarded exit-node traffic: desync outbound WAN requests (excluding packets re-entering
    // tailscale0) and capture early WAN server replies returning to Tailscale clients.
    script.push_str("  chain forward {\n");
    script.push_str("    type filter hook forward priority mangle; policy accept;\n");
    let _ = writeln!(script, "    meta mark & 0x{fwmark:x} != 0 accept");
    write_dport_queue_rules(&mut script, "oifname != \"tailscale0\" ", qnum, tcp_ranges, udp_ranges);
    write_sport_reply_rule(&mut script, "iifname != \"tailscale0\" ", qnum, tcp_ranges);
    script.push_str("  }\n");

    // Early inbound response packets: conntrack match on the first few packets of local
    // reply streams so nfqws2 inspects server hellos and RSTs without full bulk capture.
    script.push_str("  chain input {\n");
    script.push_str("    type filter hook input priority mangle; policy accept;\n");
    write_sport_reply_rule(&mut script, "", qnum, tcp_ranges);
    script.push_str("  }\n");

    script.push_str("}\n");
    script
}
