//! Temporary `nftables` NFQUEUE rule management with RAII teardown (`zapret_strat_finder`).

/// Formatting helper for building multi-line `nft -f -` rule scripts.
use std::fmt::Write as _;
/// Standard I/O errors and stdin pipe writing for `nft`.
use std::io::{self, Write as _};
/// Filesystem path to the `nft` executable.
use std::path::PathBuf;
/// Subprocess spawning for `nft` rule installation and cleanup.
use std::process::{Command, Stdio};

/// Dedicated `nftables` table name created and deleted by [`NftFirewallBackend`].
pub const STRAT_FINDER_NFT_TABLE: &str = "zapret_strat_finder";

/// Opaque RAII handle representing installed temporary firewall rules cleaned up on drop.
pub trait FirewallHandle: Send {}

/// Injectable firewall rule backend allowing live `nftables` setup and offline mock tests.
pub trait FirewallBackend {
    /// Installs temporary NFQUEUE rules for `qnum`, `fwmark`, and target TCP/UDP ports.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>;
}

/// RAII guard that removes `table inet zapret_strat_finder` when dropped.
pub struct NftQueueGuard {
    /// Path to the `nft` binary used for teardown.
    nft_bin: PathBuf,
    /// Table name deleted on drop.
    table_name: String,
}

impl FirewallHandle for NftQueueGuard {}

impl Drop for NftQueueGuard {
    /// Deletes the temporary `nftables` table on exit (best-effort, ignoring already-deleted errors).
    fn drop(&mut self) {
        let _ = Command::new(&self.nft_bin)
            .args(["delete", "table", "inet", &self.table_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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

    /// Formats a multi-line `nft -f -` script installing `bypass` NFQUEUE rules and `fwmark` guard.
    pub fn build_nft_script(qnum: u16, fwmark: u32, tcp_ports: &[u16], udp_ports: &[u16]) -> String {
        let mut script = String::new();
        let _ = writeln!(script, "table inet {STRAT_FINDER_NFT_TABLE}");
        script.push_str("{\n");
        script.push_str("  chain output\n  {\n");
        script.push_str("    type filter hook output priority mangle; policy accept;\n");
        let _ = writeln!(script, "    meta mark & 0x{fwmark:x} != 0 accept");
        if !tcp_ports.is_empty() {
            let ports: Vec<String> = tcp_ports.iter().map(ToString::to_string).collect();
            let _ = writeln!(script, "    tcp dport {{ {} }} queue num {qnum} bypass", ports.join(", "));
        }
        if !udp_ports.is_empty() {
            let ports: Vec<String> = udp_ports.iter().map(ToString::to_string).collect();
            let _ = writeln!(script, "    udp dport {{ {} }} queue num {qnum} bypass", ports.join(", "));
        }
        script.push_str("  }\n");
        script.push_str("  chain input\n  {\n");
        script.push_str("    type filter hook input priority mangle; policy accept;\n");
        if !tcp_ports.is_empty() {
            let ports: Vec<String> = tcp_ports.iter().map(ToString::to_string).collect();
            let _ = writeln!(
                script,
                "    tcp sport {{ {} }} ct original packets 1-6 queue num {qnum} bypass",
                ports.join(", ")
            );
        }
        script.push_str("  }\n");
        script.push_str("}\n");
        script
    }
}

impl FirewallBackend for NftFirewallBackend {
    /// Replaces any stale `zapret_strat_finder` table and installs fresh `bypass` queue rules.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>> {
        // Best-effort cleanup of any leftover table from an aborted previous run.
        let _ = Command::new(&self.nft_bin)
            .args(["delete", "table", "inet", STRAT_FINDER_NFT_TABLE])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let script = Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports);
        let mut child = Command::new(&self.nft_bin)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(script.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let err = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(io::Error::other(format!("nft rule installation failed: {err}")));
        }

        Ok(Box::new(NftQueueGuard {
            nft_bin: self.nft_bin.clone(),
            table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
        }))
    }
}
