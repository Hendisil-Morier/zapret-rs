//! Temporary `nftables` NFQUEUE rule management with RAII teardown (`zapret_strat_finder`).

/// Standard I/O errors and stdin pipe writing for `nft`.
use std::io::{self, Write as _};
/// Filesystem paths for `nft` and optional `sudo` elevation.
use std::path::{Path, PathBuf};
/// Subprocess spawning for `nft` rule installation and cleanup.
use std::process::{Command, Stdio};

/// Trusted system binary resolution preventing `PATH` hijacking under `CAP_NET_ADMIN` or root.
use crate::runtime::{resolve_trusted_system_bin, validate_trusted_bin_path};
/// OS-agnostic firewall backend traits implemented by [`NftFirewallBackend`] and [`NftQueueGuard`].
use crate::tools::strat::firewall::{FirewallBackend, FirewallHandle};
/// Pure `nftables` table rendering helper and dedicated table name constant.
pub use crate::tools::strat::nft_script::STRAT_FINDER_NFT_TABLE;
/// Range-aware `nftables` table formatter shared with live `--nft` installation.
use crate::tools::strat::nft_script::render_nft_script_ranges;

/// Returns `true` when `nft` stderr indicates insufficient privileges (`EPERM`/`EACCES`).
pub fn is_nft_perm_denied(stderr: &str) -> bool
{
    let low = stderr.to_ascii_lowercase();
    low.contains("operation not permitted")
        || low.contains("permission denied")
        || low.contains("must be root")
}

/// Returns the one-line cleanup command removing `table inet zapret_strat_finder`.
pub fn build_nft_cleanup_cmd() -> String
{
    format!("nft delete table inet {STRAT_FINDER_NFT_TABLE}")
}

/// Returns `true` if invoking `sudo` currently requires an interactive password prompt.
pub fn sudo_needs_password() -> bool
{
    #[cfg(windows)]
    {
        false
    }
    #[cfg(not(windows))]
    {
        let Ok(sudo_bin) = resolve_trusted_system_bin("sudo")
        else
        {
            return true;
        };
        !Command::new(sudo_bin)
            .args(["-n", "true"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }
}

/// Elevation mode used when spawning `nft`.
#[derive(Clone, Copy)]
enum SudoMode
{
    /// Invoke `nft` directly without `sudo`.
    None,
    /// Invoke `sudo -n -- nft` (fails immediately instead of prompting on `/dev/tty`).
    NonInteractive,
    /// Invoke `sudo -- nft` (may prompt for a password on `/dev/tty`).
    Interactive,
}

/// Builds a `Command` invoking trusted `nft_bin` directly or via trusted `sudo` according to `mode`.
fn build_nft_command(nft_bin: &Path, mode: SudoMode) -> io::Result<Command>
{
    let trusted_nft = validate_trusted_bin_path(nft_bin)?;
    match mode
    {
        SudoMode::None => Ok(Command::new(trusted_nft)),
        SudoMode::NonInteractive =>
        {
            let sudo_bin = resolve_trusted_system_bin("sudo")?;
            let mut cmd = Command::new(sudo_bin);
            cmd.args(["-n", "--"]).arg(trusted_nft);
            Ok(cmd)
        }
        SudoMode::Interactive =>
        {
            let sudo_bin = resolve_trusted_system_bin("sudo")?;
            let mut cmd = Command::new(sudo_bin);
            cmd.arg("--").arg(trusted_nft);
            Ok(cmd)
        }
    }
}

/// Runs `nft -f -` feeding `script` on stdin and returning `Ok(())` or the captured stderr text.
fn run_nft_script(nft_bin: &Path, mode: SudoMode, script: &str) -> Result<(), (io::ErrorKind, String)>
{
    let mut cmd = build_nft_command(nft_bin, mode).map_err(|err| (err.kind(), err.to_string()))?;
    let mut child = cmd
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| (err.kind(), err.to_string()))?;

    if let Some(mut stdin) = child.stdin.take()
    {
        stdin.write_all(script.as_bytes()).map_err(|err| (err.kind(), err.to_string()))?;
    }
    let output = child.wait_with_output().map_err(|err| (err.kind(), err.to_string()))?;
    if output.status.success()
    {
        Ok(())
    }
    else
    {
        let err = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err((io::ErrorKind::Other, err))
    }
}

/// Best-effort deletion of `table inet <table_name>` using direct or `sudo`-elevated trusted `nft`.
fn delete_nft_table_best_effort(nft_bin: &Path, table_name: &str, mode: SudoMode)
{
    let Ok(mut cmd) = build_nft_command(nft_bin, mode)
    else
    {
        return;
    };
    let _ = cmd
        .args(["delete", "table", "inet", table_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// RAII guard that removes `table inet zapret_strat_finder` when dropped unless disarmed.
pub struct NftQueueGuard
{
    /// Path to the `nft` binary used for teardown.
    nft_bin: PathBuf,
    /// Table name deleted on drop.
    table_name: String,
    /// Whether `sudo` was used to install the table (so teardown uses `sudo` as well).
    used_sudo: bool,
    /// When `false`, drop becomes a no-op (e.g., replaced live during `reload_config`).
    armed: bool,
}

impl FirewallHandle for NftQueueGuard
{
    /// Returns `true` only when armed and `sudo` teardown would require an interactive password prompt.
    fn needs_interactive_drop(&self) -> bool
    {
        self.armed && self.used_sudo && sudo_needs_password()
    }

    /// Disarms automatic `nft delete table` on drop when a replacement table has taken over.
    fn disarm(&mut self)
    {
        self.armed = false;
    }
}

impl Drop for NftQueueGuard
{
    /// Deletes the temporary `nftables` table on exit when still armed.
    fn drop(&mut self)
    {
        if !self.armed
        {
            return;
        }
        if !self.used_sudo
        {
            delete_nft_table_best_effort(&self.nft_bin, &self.table_name, SudoMode::None);
            return;
        }
        let mode = if sudo_needs_password() { SudoMode::Interactive } else { SudoMode::NonInteractive };
        delete_nft_table_best_effort(&self.nft_bin, &self.table_name, mode);
    }
}

/// Live [`FirewallBackend`] managing a dedicated `inet zapret_strat_finder` `nftables` table.
#[derive(Debug, Clone)]
pub struct NftFirewallBackend
{
    /// Path or executable name of `nft` (defaults to `"nft"`).
    nft_bin: PathBuf,
}

impl Default for NftFirewallBackend
{
    /// Constructs an [`NftFirewallBackend`] using `"nft"` from `PATH`.
    fn default() -> Self
    {
        Self { nft_bin: PathBuf::from("nft") }
    }
}

impl NftFirewallBackend
{
    /// Constructs an [`NftFirewallBackend`] pointing at an explicit `nft` binary path.
    pub fn new(nft_bin: PathBuf) -> Self
    {
        Self { nft_bin }
    }

    /// Formats a multi-line `nft -f -` script installing `bypass` NFQUEUE rules and `fwmark` guard.
    pub fn build_nft_script(qnum: u16, fwmark: u32, tcp_ports: &[u16], udp_ports: &[u16]) -> String
    {
        let tcp_ranges: Vec<(u16, u16)> = tcp_ports.iter().map(|&p| (p, p)).collect();
        let udp_ranges: Vec<(u16, u16)> = udp_ports.iter().map(|&p| (p, p)).collect();
        Self::build_nft_script_ranges(qnum, fwmark, &tcp_ranges, &udp_ranges)
    }

    /// Formats a multi-line `nft -f -` script from inclusive `(from, to)` TCP/UDP port ranges.
    pub fn build_nft_script_ranges(
        qnum: u16,
        fwmark: u32,
        tcp_ranges: &[(u16, u16)],
        udp_ranges: &[(u16, u16)],
    ) -> String
    {
        render_nft_script_ranges(qnum, fwmark, tcp_ranges, udp_ranges)
    }

    /// Installs temporary `nftables` rules for inclusive `(from, to)` port ranges silently.
    pub fn install_ranges_non_interactive(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ranges: &[(u16, u16)],
        udp_ranges: &[(u16, u16)],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        let script = Self::build_nft_script_ranges(qnum, fwmark, tcp_ranges, udp_ranges);
        self.install_script_non_interactive(&script)
    }

    /// Tries to install `nftables` rules silently (direct `nft`, then non-interactive `sudo -n`).
    pub fn install_non_interactive(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        let script = Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports);
        self.install_script_non_interactive(&script)
    }

    /// Executes an already-rendered `nft` table script directly or via non-interactive `sudo -n`.
    fn install_script_non_interactive(&self, script: &str) -> io::Result<Box<dyn FirewallHandle>>
    {
        let trusted_nft = validate_trusted_bin_path(&self.nft_bin)?;
        delete_nft_table_best_effort(&trusted_nft, STRAT_FINDER_NFT_TABLE, SudoMode::None);

        match run_nft_script(&trusted_nft, SudoMode::None, script)
        {
            Ok(()) => Ok(Box::new(NftQueueGuard {
                nft_bin: trusted_nft,
                table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                used_sudo: false,
                armed: true,
            })),
            Err((_, ref stderr))
                if is_nft_perm_denied(stderr) && crate::runtime::current_uid_or_zero() != 0 =>
            {
                if crate::runtime::has_no_new_privs()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "direct nft failed under NoNewPrivileges (ensure CAP_NET_ADMIN ambient or pass --no-nft)",
                    ));
                }
                if sudo_needs_password()
                {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "sudo password required for nft",
                    ));
                }
                delete_nft_table_best_effort(&trusted_nft, STRAT_FINDER_NFT_TABLE, SudoMode::NonInteractive);
                run_nft_script(&trusted_nft, SudoMode::NonInteractive, script).map_err(|(kind, msg)| {
                    io::Error::new(
                        kind,
                        format!("sudo nft rule installation failed (or pass --no-nft): {msg}"),
                    )
                })?;
                Ok(Box::new(NftQueueGuard {
                    nft_bin: trusted_nft,
                    table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                    used_sudo: true,
                    armed: true,
                }))
            }
            Err((kind, msg)) =>
            {
                Err(io::Error::new(kind, format!("nft rule installation failed (or pass --no-nft): {msg}")))
            }
        }
    }

    /// Installs temporary `nftables` rules for inclusive `(from, to)` port ranges, prompting via `sudo` if needed.
    pub fn install_ranges(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ranges: &[(u16, u16)],
        udp_ranges: &[(u16, u16)],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        let script = Self::build_nft_script_ranges(qnum, fwmark, tcp_ranges, udp_ranges);
        self.install_script_interactive(&script)
    }

    /// Executes an already-rendered `nft` table script, falling back to interactive `sudo` on `EPERM`.
    fn install_script_interactive(&self, script: &str) -> io::Result<Box<dyn FirewallHandle>>
    {
        let trusted_nft = validate_trusted_bin_path(&self.nft_bin)?;
        match self.install_script_non_interactive(script)
        {
            Ok(guard) => Ok(guard),
            Err(err)
                if err.kind() == io::ErrorKind::PermissionDenied
                    && crate::runtime::current_uid_or_zero() != 0
                    && !crate::runtime::has_no_new_privs() =>
            {
                eprintln!(
                    "[nft] elevating only `nft` via sudo to install temporary table inet {STRAT_FINDER_NFT_TABLE}"
                );
                delete_nft_table_best_effort(&trusted_nft, STRAT_FINDER_NFT_TABLE, SudoMode::Interactive);
                run_nft_script(&trusted_nft, SudoMode::Interactive, script).map_err(|(kind, msg)| {
                    io::Error::new(
                        kind,
                        format!("sudo nft rule installation failed (or pass --no-nft): {msg}"),
                    )
                })?;
                Ok(Box::new(NftQueueGuard {
                    nft_bin: trusted_nft,
                    table_name: STRAT_FINDER_NFT_TABLE.to_owned(),
                    used_sudo: true,
                    armed: true,
                }))
            }
            Err(err) => Err(err),
        }
    }
}

impl FirewallBackend for NftFirewallBackend
{
    /// Installs fresh `bypass` queue rules, elevating only `nft` via `sudo` when run as a non-root user.
    fn install(
        &self,
        qnum: u16,
        fwmark: u32,
        tcp_ports: &[u16],
        udp_ports: &[u16],
    ) -> io::Result<Box<dyn FirewallHandle>>
    {
        let script = Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports);
        self.install_script_interactive(&script)
    }

    /// Returns the Linux `nftables` preview panel title shown on Tab 3.
    fn preview_title(&self) -> &'static str
    {
        " Temporary nftables Script "
    }

    /// Renders the temporary `table inet zapret_strat_finder` script preview.
    fn preview_filter(&self, qnum: u16, fwmark: u32, tcp_ports: &[u16], udp_ports: &[u16]) -> String
    {
        Self::build_nft_script(qnum, fwmark, tcp_ports, udp_ports)
    }
}
