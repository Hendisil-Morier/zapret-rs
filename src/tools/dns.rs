//! OS-level DNS and encrypted DNS (DoH on Windows, DoT on Linux) preset management and CLI.

/// CLI argument iteration for `zapret-rs dns`.
use std::ffi::OsString;
/// Filesystem reads for `/proc/net/route` and `/etc/resolv.conf` on Linux.
#[cfg(target_os = "linux")]
use std::fs;
/// Subprocess execution for `netsh`/`ipconfig` (Windows) and `resolvectl` (Linux).
use std::process::{Command, ExitCode, Stdio};

/// Built-in DNS / encrypted DNS presets selectable from CLI or Tab 5 (`Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPreset
{
    /// Cloudflare public DNS (`1.1.1.1` / `1.0.0.1`) with DoH/DoT.
    Cloudflare,
    /// Google public DNS (`8.8.8.8` / `8.8.4.4`) with DoH/DoT.
    Google,
    /// Quad9 filtering DNS (`9.9.9.9` / `149.112.112.112`) with DoH/DoT.
    Quad9,
    /// AdGuard public DNS (`94.140.14.14` / `94.140.15.15`) with DoH/DoT.
    AdGuard,
    /// Revert DNS configuration to system/router DHCP defaults.
    Auto,
}

impl DnsPreset
{
    /// Ordered preset list cycled by `[n]` on Tab 5 (`Status`).
    pub const ALL: [Self; 5] = [Self::Cloudflare, Self::Google, Self::Quad9, Self::AdGuard, Self::Auto];

    /// Human-readable preset display name.
    pub const fn label(self) -> &'static str
    {
        match self
        {
            Self::Cloudflare => "Cloudflare (1.1.1.1, DoH)",
            Self::Google => "Google (8.8.8.8, DoH)",
            Self::Quad9 => "Quad9 (9.9.9.9, DoH)",
            Self::AdGuard => "AdGuard (94.140.14.14, DoH)",
            Self::Auto => "Automatic (DHCP)",
        }
    }

    /// Lowercase CLI token accepted by `zapret-rs dns <preset>`.
    pub const fn cli_name(self) -> &'static str
    {
        match self
        {
            Self::Cloudflare => "cloudflare",
            Self::Google => "google",
            Self::Quad9 => "quad9",
            Self::AdGuard => "adguard",
            Self::Auto => "auto",
        }
    }

    /// Parses a preset name case-insensitively (`cloudflare`, `google`, `quad9`, `adguard`, `auto`).
    pub fn from_name(raw: &str) -> Option<Self>
    {
        match raw
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "cloudflare" | "cf" | "1.1.1.1" => Some(Self::Cloudflare),
            "google" | "8.8.8.8" => Some(Self::Google),
            "quad9" | "9.9.9.9" => Some(Self::Quad9),
            "adguard" => Some(Self::AdGuard),
            "auto" | "dhcp" | "reset" | "default" => Some(Self::Auto),
            _ => None,
        }
    }

    /// Returns `(primary, secondary)` IPv4 DNS servers, or `None` for [`DnsPreset::Auto`].
    pub const fn ipv4_servers(self) -> Option<(&'static str, &'static str)>
    {
        match self
        {
            Self::Cloudflare => Some(("1.1.1.1", "1.0.0.1")),
            Self::Google => Some(("8.8.8.8", "8.8.4.4")),
            Self::Quad9 => Some(("9.9.9.9", "149.112.112.112")),
            Self::AdGuard => Some(("94.140.14.14", "94.140.15.15")),
            Self::Auto => None,
        }
    }

    /// Returns the DNS-over-HTTPS URI template used on Windows 11, or `None` for [`DnsPreset::Auto`].
    pub const fn doh_template(self) -> Option<&'static str>
    {
        match self
        {
            Self::Cloudflare => Some("https://cloudflare-dns.com/dns-query"),
            Self::Google => Some("https://dns.google/dns-query"),
            Self::Quad9 => Some("https://dns.quad9.net/dns-query"),
            Self::AdGuard => Some("https://dns.adguard-dns.com/dns-query"),
            Self::Auto => None,
        }
    }

    /// Advances to the next preset cyclically.
    pub const fn next(self) -> Self
    {
        match self
        {
            Self::Cloudflare => Self::Google,
            Self::Google => Self::Quad9,
            Self::Quad9 => Self::AdGuard,
            Self::AdGuard => Self::Auto,
            Self::Auto => Self::Cloudflare,
        }
    }

    /// Formats a short preview of the OS change shown in the confirmation modal.
    pub fn command_preview(self) -> String
    {
        match (self.ipv4_servers(), self.doh_template())
        {
            (Some((p, s)), Some(tpl)) => format!("set DNS to {p}, {s} ({tpl})"),
            _ => "revert DNS servers to Automatic (DHCP)".to_owned(),
        }
    }
}

/// Snapshot of the currently active OS DNS resolver configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStatus
{
    /// Active network interface name (or `"system"` when read from `/etc/resolv.conf`).
    pub interface: String,
    /// Configured DNS server IP addresses.
    pub servers: Vec<String>,
    /// Optional encryption note (`"DoT: opportunistic"`, `"DoH"`, etc.).
    pub encryption: Option<String>,
}

/// Parses the default-route interface name from Linux `/proc/net/route` table text.
pub fn parse_linux_default_iface(route_table: &str) -> Option<String>
{
    for line in route_table
        .lines()
        .skip(1)
    {
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        if dest == "00000000"
        {
            return Some(iface.to_owned());
        }
    }
    None
}

/// Parses `nameserver <ip>` entries from `/etc/resolv.conf` text.
pub fn parse_resolv_conf_servers(content: &str) -> Vec<String>
{
    content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let rest = trimmed.strip_prefix("nameserver")?;
            let ip = rest
                .split_whitespace()
                .next()?;
            Some(ip.to_owned())
        })
        .collect()
}

/// Parses `Connected` interface names from `netsh interface show interface` stdout on Windows.
pub fn parse_windows_connected_interfaces(stdout: &str) -> Vec<String>
{
    let mut out = Vec::new();
    for line in stdout.lines()
    {
        let trimmed = line.trim();
        let mut cols = trimmed.split_whitespace();
        let Some(_admin) = cols.next()
        else
        {
            continue;
        };
        let Some(state) = cols.next()
        else
        {
            continue;
        };
        let Some(_kind) = cols.next()
        else
        {
            continue;
        };
        if !state.eq_ignore_ascii_case("Connected")
        {
            continue;
        }
        if let Some(pos) = trimmed.find(_kind)
        {
            let rest = trimmed[pos + _kind.len()..].trim();
            if !rest.is_empty()
            {
                out.push(rest.to_owned());
            }
        }
    }
    out
}

/// Runs `program` with `args` silently and returns stdout on exit code 0 or stderr/status on failure.
fn run_cmd_capture(program: &str, args: &[&str]) -> Result<String, String>
{
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|err| format!("failed to run {program}: {err}"))?;
    if out
        .status
        .success()
    {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&out.stderr)
        .trim()
        .to_owned();
    let stdout = String::from_utf8_lossy(&out.stdout)
        .trim()
        .to_owned();
    let msg = if !stderr.is_empty() { stderr } else { stdout };
    Err(format!("{program} failed ({}): {msg}", out.status))
}

/// Detects the active interface and configured DNS servers for the current OS.
pub fn detect_dns_status() -> DnsStatus
{
    #[cfg(target_os = "linux")]
    {
        detect_linux_dns_status()
    }
    #[cfg(windows)]
    {
        detect_windows_dns_status()
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        DnsStatus { interface: "unknown".to_owned(), servers: Vec::new(), encryption: None }
    }
}

/// Linux DNS detection via `/proc/net/route`, `resolvectl`, and `/etc/resolv.conf` fallback.
#[cfg(target_os = "linux")]
fn detect_linux_dns_status() -> DnsStatus
{
    let iface = fs::read_to_string("/proc/net/route")
        .ok()
        .and_then(|s| parse_linux_default_iface(&s))
        .unwrap_or_else(|| "system".to_owned());
    if iface != "system"
        && let Ok(text) = run_cmd_capture("resolvectl", &["dns", &iface])
    {
        let servers: Vec<String> = text
            .split(':')
            .nth(1)
            .map(|rhs| {
                rhs.split_whitespace()
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        let dot = run_cmd_capture("resolvectl", &["dnsovertls", &iface])
            .ok()
            .and_then(|s| {
                s.split(':')
                    .nth(1)
                    .map(|v| format!("DoT: {}", v.trim()))
            });
        if !servers.is_empty()
        {
            return DnsStatus { interface: iface, servers, encryption: dot };
        }
    }
    let servers = fs::read_to_string("/etc/resolv.conf")
        .map(|s| parse_resolv_conf_servers(&s))
        .unwrap_or_default();
    DnsStatus { interface: iface, servers, encryption: None }
}

/// Windows DNS detection via `netsh interface show interface` and `show dnsservers`.
#[cfg(windows)]
fn detect_windows_dns_status() -> DnsStatus
{
    let ifaces = run_cmd_capture("netsh", &["interface", "show", "interface"])
        .map(|s| parse_windows_connected_interfaces(&s))
        .unwrap_or_default();
    let Some(iface) = ifaces
        .into_iter()
        .next()
    else
    {
        return DnsStatus { interface: "none".to_owned(), servers: Vec::new(), encryption: None };
    };
    let mut servers = Vec::new();
    if let Ok(out) = run_cmd_capture("netsh", &["interface", "ipv4", "show", "dnsservers", &iface])
    {
        for line in out.lines()
        {
            for tok in line.split_whitespace()
            {
                if tok
                    .parse::<std::net::Ipv4Addr>()
                    .is_ok()
                {
                    servers.push(tok.to_owned());
                }
            }
        }
    }
    DnsStatus { interface: iface, servers, encryption: None }
}

/// Applies `preset` to the active OS network interface(s).
pub fn apply_dns_preset(preset: DnsPreset) -> Result<String, String>
{
    #[cfg(windows)]
    {
        apply_windows_dns(preset)
    }
    #[cfg(target_os = "linux")]
    {
        apply_linux_dns(preset)
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        let _ = preset;
        Err("OS DNS management is only supported on Linux and Windows".to_owned())
    }
}

/// Applies `preset` on all `Connected` Windows adapters via `netsh` + `ipconfig /flushdns`.
#[cfg(windows)]
fn apply_windows_dns(preset: DnsPreset) -> Result<String, String>
{
    let iface_out = run_cmd_capture("netsh", &["interface", "show", "interface"])?;
    let ifaces = parse_windows_connected_interfaces(&iface_out);
    if ifaces.is_empty()
    {
        return Err("no connected Windows network adapter found".to_owned());
    }
    if let (Some((primary, secondary)), Some(tpl)) = (preset.ipv4_servers(), preset.doh_template())
    {
        for srv in [primary, secondary]
        {
            let srv_arg = format!("server={srv}");
            let tpl_arg = format!("dohtemplate={tpl}");
            let _ = run_cmd_capture(
                "netsh",
                &["dns", "add", "encryption", &srv_arg, &tpl_arg, "autoupgrade=yes", "udpfallback=no"],
            );
        }
    }
    for iface in &ifaces
    {
        let name_arg = format!("name={iface}");
        match preset.ipv4_servers()
        {
            Some((primary, secondary)) =>
            {
                run_cmd_capture(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "set",
                        "dnsservers",
                        &name_arg,
                        "static",
                        primary,
                        "primary",
                        "validate=no",
                    ],
                )?;
                let _ = run_cmd_capture(
                    "netsh",
                    &[
                        "interface",
                        "ipv4",
                        "add",
                        "dnsservers",
                        &name_arg,
                        secondary,
                        "index=2",
                        "validate=no",
                    ],
                );
            }
            None =>
            {
                run_cmd_capture(
                    "netsh",
                    &["interface", "ipv4", "set", "dnsservers", &name_arg, "source=dhcp"],
                )?;
            }
        }
    }
    let _ = run_cmd_capture("ipconfig", &["/flushdns"]);
    Ok(format!("Applied {} on {}", preset.label(), ifaces.join(", ")))
}

/// Applies `preset` on Linux's default-route interface via `resolvectl` (`systemd-resolved`).
#[cfg(target_os = "linux")]
fn apply_linux_dns(preset: DnsPreset) -> Result<String, String>
{
    let route = fs::read_to_string("/proc/net/route")
        .map_err(|err| format!("failed to read /proc/net/route: {err}"))?;
    let iface = parse_linux_default_iface(&route)
        .ok_or_else(|| "no active default-route network interface found".to_owned())?;
    match preset.ipv4_servers()
    {
        Some((primary, secondary)) =>
        {
            run_cmd_capture("resolvectl", &["dns", &iface, primary, secondary])?;
            let _ = run_cmd_capture("resolvectl", &["dnsovertls", &iface, "opportunistic"]);
            let _ = run_cmd_capture("resolvectl", &["flush-caches"]);
            Ok(format!("Applied {} on {iface} (via resolvectl)", preset.label()))
        }
        None =>
        {
            run_cmd_capture("resolvectl", &["revert", &iface])?;
            let _ = run_cmd_capture("resolvectl", &["flush-caches"]);
            Ok(format!("Reverted DNS on {iface} to Automatic (DHCP)"))
        }
    }
}

/// Prints usage help for `zapret-rs dns`.
fn print_dns_usage()
{
    println!(
        "Usage: zapret-rs dns <status|cloudflare|google|quad9|adguard|auto>\n\n\
         Subcommands:\n  \
           status      Show active network interface and DNS servers\n  \
           cloudflare  Set 1.1.1.1 / 1.0.0.1 with DoH (Windows) or DoT (Linux)\n  \
           google      Set 8.8.8.8 / 8.8.4.4 with DoH (Windows) or DoT (Linux)\n  \
           quad9       Set 9.9.9.9 / 149.112.112.112 with DoH/DoT\n  \
           adguard     Set 94.140.14.14 / 94.140.15.15 with DoH/DoT\n  \
           auto        Revert DNS settings to Automatic (DHCP)"
    );
}

/// Entry point for `zapret-rs dns ...`.
pub fn run_dns_cli<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    let argv: Vec<String> = args
        .into_iter()
        .map(|s| {
            s.into()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let Some(cmd) = argv
        .get(1)
        .map(String::as_str)
    else
    {
        print_dns_usage();
        return ExitCode::SUCCESS;
    };
    if matches!(cmd, "-h" | "--help" | "help")
    {
        print_dns_usage();
        return ExitCode::SUCCESS;
    }
    if cmd.eq_ignore_ascii_case("status")
    {
        let st = detect_dns_status();
        let srvs = if st
            .servers
            .is_empty()
        {
            "none".to_owned()
        }
        else
        {
            st.servers
                .join(", ")
        };
        match st.encryption
        {
            Some(enc) => println!("Interface: {}\nDNS: {} ({enc})", st.interface, srvs),
            None => println!("Interface: {}\nDNS: {}", st.interface, srvs),
        }
        return ExitCode::SUCCESS;
    }
    let Some(preset) = DnsPreset::from_name(cmd)
    else
    {
        eprintln!("unknown DNS preset '{cmd}' (try: status, cloudflare, google, quad9, adguard, auto)");
        return ExitCode::from(2);
    };
    match apply_dns_preset(preset)
    {
        Ok(msg) =>
        {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err(err) =>
        {
            eprintln!("dns error: {err}");
            ExitCode::FAILURE
        }
    }
}
