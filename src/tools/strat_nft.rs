//! Temporary `nftables` NFQUEUE rule management with RAII teardown (`zapret_strat_finder`).

/// Formatting helper for building multi-line `nft -f -` rule scripts.
use std::fmt::Write as _;
/// Standard I/O errors and stdin pipe writing for `nft`.
use std::io::{self, Write as _};
/// Filesystem paths for `nft` and optional `sudo` elevation.
use std::path::{Path, PathBuf};
/// Subprocess spawning for `nft` rule installation and cleanup.
use std::process::{Command, Stdio};

/// OS-agnostic firewall backend traits implemented by [`NftFirewallBackend`] and [`NftQueueGuard`].
use crate::tools::firewall::{FirewallBackend, FirewallHandle};

/// Dedicated `nftables` table name created and deleted by [`NftFirewallBackend`].
pub const STRAT_FINDER_NFT_TABLE: &str = "zapret_strat_finder";

/// Returns `true` when `nft` stderr indicates insufficient privileges (`EPERM`/`EACCES`).
pub fn is_nft_perm_denied(stderr: &str) -> bool {
    let low = stderr.to_ascii_lowercase();
    low.contains("operation not permitted")
        || low.contains("permission denied")
        || low.contains("must be root")
}

/// Returns the one-line cleanup command removing `table inet zapret_strat_finder`.
pub fn build_nft_cleanup_cmd() -> String {
    format!("nft delete table inet {STRAT_FINDER_NFT_TABLE}")
}

/// Returns `true` if invoking `sudo` currently requires an interactive password prompt.
pub fn sudo_needs_password() -> bool {
    !Command::new("sudo")
        .args(["-n", "true"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Elevation mode used when spawning `nft`.
#[derive(Clone, Copy)]
enum SudoMode {
    /// Invoke `nft` directly without `sudo`.
    None,
    /// Invoke `sudo -n -- nft` (fails immediately instead of prompting on `/dev/tty`).
    NonInteractive,
    /// Invoke `sudo -- nft` (may prompt for a password on `/dev/tty`).
    Interactive,
}

/// Builds a `Command` invoking `nft_bin` directly or via `sudo` according to `mode`.
fn build_nft_command(nft_bin: &Path, mode: SudoMode) -> Command {
    match mode {
        SudoMode::None => Command::new(nft_bin),
        SudoMode::NonInteractive => {
            let mut cmd = Command::new("sudo");
            cmd.args(["-n", "--"]).arg(nft_bin);
            cmd
        }
        SudoMode::Interactive => {
            let mut cmd = Command::new("sudo");
            cmd.arg("--").arg(nft_bin);
            cmd
        }
    }
}

/// Runs `nft -f -` feeding `script` on stdin and returning `Ok(())` or the captured stderr text.
fn run_nft_script(nft_bin: &Path, mode: SudoMode, script: &str) -> Result<(), (io::ErrorKind, String)> {
    let mut child = build_nft_command(nft_bin, mode)
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| (err.kind(), err.to_string()))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(script.as_bytes())
            .map_err(|err| (err.kind(), err.to_string()))?;
    }
    let output = child
        .wait_with_output()
        .map_err(|err| (err.kind(), err.to_string()))?;
    if output.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err((io::ErrorKind::Other, err))
    }
}

/// Best-effort deletion of `table inet <table_name>` using direct or `sudo`-elevated `nft`.
fn delete_nft_table_best_effort(nft_bin: &Path, table_name: &str, mode: SudoMode) {
    let _ = build_nft_command(nft_bin, mode)
        .args(["delete", "table", "inet", table_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// RAII guard that removes `table inet zapret_strat_finder` when dropped.
pub struct NftQueueGuard {
    /// Path to the `nft` binary used for teardown.
    nft_bin: PathBuf,
    /// Table name deleted on drop.
    table_name: String,
    /// Whether `sudo` was used to install the table (so teardown uses `sudo` as well).
    used_sudo: bool,
}

impl FirewallHandle for NftQueueGuard {
    /// Returns `true` only when `sudo` teardown would require a fresh interactive password prompt.
    fn needs_interactive_drop(&self) -> bool {
        self.used_sudo && sudo_needs_password()
    }
}

impl Drop for NftQueueGuard {
    /// Deletes the temporary `nftables` table on exit (tries non-interactive `sudo -n` first).
    fn drop(&mut self) {
        if !self.used_sudo {
            delete_nft_table_best_effort(&self.nft_bin, &self.table_name, SudoMode::None);
            return;
        }
        let mode = if sudo_needs_password() {
            SudoMode::Interactive
        } else {
            SudoMode::NonInteractive
        };
        delete_nft_table_best_effort(&self.nft_bin, &self.table_name, mode);
    }
}

/// Live [`FirewallBackend`] managing a dedicated `inet zapret_strat_finder` `nftables` table.
#[derive(Debug, Clone)]
pub struct NftFirewallBackend {
    /// Path or executable name of `nft` (defaults to `"nft"`).
    nft_bin: PathBuf,
}

impl Default for NftFirewallBackend {
    /// Constructs an [`NftFirewallBackend`] using `"nft"` from `PATH`.
    fn default() -> Self {
        Self { nft_bin: PathBuf::from("nft") }
    }
}

impl NftFirewallBackend {
    /// Constructs an [`NftFirewallBackend`] pointing at an explicit `nft` binary path.
    pub fn new(nft_bin: PathBuf) -> Self {
        Self { nft_bin }
    }

    /// Formats a comma-separated `{ p1, p2, ... }` port set literal for use in `nft` rule lines.
    fn fmt_port_set(ports: &[u16]) -> String {
        let joined = ports.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
        format!("{{ {joined} }}")
    }

    /// Appends `queue num {qnum} bypass` NFQUEUE rules for `tcp dport` and `udp dport` to `script`.
    ///
    /// `prefix` holds an optional leading match expression (e.g., `oifname != "tailscale0" `).
    fn write_dport_queue_rules(
        script: &mut String,
        prefix: &str,
        qnum: u16,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) {
        if !tcp_ports.is_empty() {
            let _ = writeln!(script, "    {prefix}tcp dport {} queue num {qnum} bypass", Self::fmt_port_set(tcp_ports));
        }
        if !udp_ports.is_empty() {
            let _ = writeln!(script, "    {prefix}udp dport {} queue num {qnum} bypass", Self::fmt_port_set(udp_ports));
        }
    }

    /// Appends an early server-reply conntrack queue rule (`ct original packets 1-6`) to `script`.
    fn write_sport_reply_rule(script: &mut String, prefix: &str, qnum: u16, tcp_ports: &[u16]) {
        if !tcp_ports.is_empty() {
            let _ = writeln!(
                script,
                "    {prefix}tcp sport {} ct original packets 1-6 queue num {qnum} bypass",
                Self::fmt_port_set(tcp_ports)
            );
        }
    }

    /// Formats a multi-line `nft -f -` script installing `bypass` NFQUEUE rules and `fwmark` guard.
    ///
    /// Three chains are installed:
    /// - `output`: locally-originated packets leaving this machine.
    /// - `forward`: outbound client traffic (`oifname != "tailscale0"`) and early inbound server
    ///   replies (`iifname != "tailscale0"`) routed through this exit node.
    /// - `input`: early inbound responses for locally-terminated connections.
    ///
    /// Outbound hooks skip packets already marked with `fwmark` to prevent re-injected packets
    /// from looping back through NFQUEUE.
    pub fn build_nft_script(qnum: u16, fwmark: u32, tcp_ports: &[u16], udp_ports: &[u16]) -> String {
        let mut script = String::new();
        let _ = writeln!(script, "table inet {STRAT_FINDER_NFT_TABLE} {{");

        // Locally-originated outbound packets.
        script.push_str("  chain output {\n");
        script.push_str("    type filter hook output priority mangle; policy accept;\n");
        let _ = writeln!(script, "    meta mark & 0x{fwmark:x} != 0 accept");
        Self::write_dport_queue_rules(&mut script, "", qnum, tcp_ports, udp_ports);
        script.push_str("  }\n");

        // Forwarded exit-node traffic: desync outbound WAN requests (excluding packets re-entering
        // tailscale0) and capture early WAN server replies returning to Tailscale clients.
        script.push_str("  chain forward {\n");
        script.push_str("    type filter hook forward priority mangle; policy accept;\n");
        let _ = writeln!(script, "    meta mark & 0x{fwmark:x} != 0 accept");
        Self::write_dport_queue_rules(
            &mut script,
            "oifname != \"tailscale0\" ",
            qnum,
            tcp_ports,
            udp_ports,
        );
        Self::write_sport_reply_rule(&mut script, "iifname != \"tailscale0\" ", qnum, tcp_ports);
        script.push_str("  }\n");

        // Early inbound response packets: conntrack match on the first few packets of local
        // reply streams so nfqws2 inspects server hellos and RSTs without full bulk capture.
        script.push_str("  chain input {\n");
        script.push_str("    type filter hook input priority mangle; policy accept;\n");
        Self::write_sport_reply_rule(&mut script, "", qnum, tcp_ports);
        script.push_str("  }\n");

        script.push_str("}\n");
        script
    }
    /// Tries to install `nftables` rules silently (direct `nft`, then non-interactive `sudo -n`).
    ///
    /// Returns `Err(PermissionDenied)` without touching `/dev/tty` when an interactive `sudo`
    /// password prompt is required, allowing TUI callers to suspend the alternate screen only
    /// when a prompt is genuinely needed.
    pub fn install_non_interactive(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>> {
        let script = Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports);
        delete_nft_table_best_effort(&self.nft_bin, STRAT_FINDER_NFT_TABLE, SudoMode::None);

        match run_nft_script(&self.nft_bin, SudoMode::None, &script) {
            Ok(()) => Ok(Box::new(NftQueueGuard {
                nft_bin: self.nft_bin.clone(),
                table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                used_sudo: false,
            })),
            Err((_, ref stderr))
                if is_nft_perm_denied(stderr) && crate::runtime::current_uid_or_zero() != 0 =>
            {
                if sudo_needs_password() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "sudo password required for nft",
                    ));
                }
                delete_nft_table_best_effort(&self.nft_bin, STRAT_FINDER_NFT_TABLE, SudoMode::NonInteractive);
                run_nft_script(&self.nft_bin, SudoMode::NonInteractive, &script).map_err(|(kind, msg)| {
                    io::Error::new(kind, format!("sudo nft rule installation failed (or pass --no-nft): {msg}"))
                })?;
                Ok(Box::new(NftQueueGuard {
                    nft_bin: self.nft_bin.clone(),
                    table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                    used_sudo: true,
                }))
            }
            Err((kind, msg)) => Err(io::Error::new(
                kind,
                format!("nft rule installation failed (or pass --no-nft): {msg}"),
            )),
        }
    }
}

impl FirewallBackend for NftFirewallBackend {
    /// Installs fresh `bypass` queue rules, elevating only `nft` via `sudo` when run as a non-root user.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>> {
        match self.install_non_interactive(qnum, fwmark, tcp_ports, udp_ports) {
            Ok(guard) => Ok(guard),
            Err(err)
                if err.kind() == io::ErrorKind::PermissionDenied
                    && crate::runtime::current_uid_or_zero() != 0 =>
            {
                let script = Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports);
                eprintln!(
                    "[nft] elevating only `nft` via sudo to install temporary table inet {STRAT_FINDER_NFT_TABLE}"
                );
                delete_nft_table_best_effort(&self.nft_bin, STRAT_FINDER_NFT_TABLE, SudoMode::Interactive);
                run_nft_script(&self.nft_bin, SudoMode::Interactive, &script).map_err(|(kind, msg)| {
                    io::Error::new(
                        kind,
                        format!("sudo nft rule installation failed (or pass --no-nft): {msg}"),
                    )
                })?;
                Ok(Box::new(NftQueueGuard {
                    nft_bin: self.nft_bin.clone(),
                    table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                    used_sudo: true,
                }))
            }
            Err(err) => Err(err),
        }
    }
}
