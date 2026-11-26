//! Operational health checks for `zapret-rs` dependencies, drivers, scripts, and daemon IPC.

/// Path resolution for `lua/` script directories.
use std::path::PathBuf;
/// Path checks for `WinDivert64.sys` on Windows.
#[cfg(windows)]
use std::path::Path;
/// Subprocess probes for `curl --version` and `nft --version` / `systemctl is-active`.
use std::process::{Command, Stdio};

/// Windows dynamic `WinDivert.dll` loader probe.
#[cfg(windows)]
use crate::intercepter::windivert_ffi::WinDivertApi;
/// Lua script discovery and `curl` HTTP/3 probe backend.
use crate::tools::{CurlProbeBackend, ProbeBackend, resolve_lua_scripts};
/// Control socket / loopback IPC auto-detection.
use crate::tui::remote::detect_control_socket;
/// Application state inspected during component status collection.
use crate::tui::state::AppState;
/// Live daemon lifecycle state displayed in the Daemon & IPC row.
use crate::tui::types::RunStatus;

/// Three-state operational health level for a `zapret-rs` dependency.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentHealth {
    /// Component is present, loaded/reachable, and ready.
    Ok,
    /// Component is usable with caveats (e.g., missing HTTP/3 or manual `nft` mode).
    Warn,
    /// Component is missing, unprivileged, or misconfigured.
    Err,
}

/// One diagnostic row shown in Tab 5 (`Status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentCheck {
    /// Short component label (`Privileges`, `Packet Driver`, `Lua Scripts`, etc.).
    pub name: &'static str,
    /// Operational health level.
    pub health: ComponentHealth,
    /// Concise single-line status summary rendered in the table.
    pub summary: String,
    /// Extended diagnostic details or remediation instructions for the detail pane.
    pub detail: String,
}

/// Collects live operational status across privileges, driver, Lua, `curl`, config, and daemon IPC.
pub fn collect_component_statuses(state: &AppState) -> Vec<ComponentCheck> {
    vec![
        check_privileges(state),
        check_packet_driver(state),
        check_lua_scripts(state),
        check_curl_probe(),
        check_config(state),
        check_daemon_ipc(state),
    ]
}

/// Checks OS packet-capture privileges (`Administrator` on Windows, `CAP_NET_ADMIN` / `uid` on Linux).
fn check_privileges(state: &AppState) -> ComponentCheck {
    #[cfg(windows)]
    {
        if state.has_net_caps {
            ComponentCheck {
                name: "Privileges",
                health: ComponentHealth::Ok,
                summary: "Administrator (elevated)".to_owned(),
                detail: "Process token is elevated; WinDivert driver loading is permitted."
                    .to_owned(),
            }
        } else {
            ComponentCheck {
                name: "Privileges",
                health: ComponentHealth::Err,
                summary: "Standard user (not elevated)".to_owned(),
                detail: "WinDivert requires Administrator privileges. Right-click zapret-rs.exe and select \"Run as administrator\", or launch from an elevated Windows Terminal."
                    .to_owned(),
            }
        }
    }
    #[cfg(not(windows))]
    {
        if state.has_net_caps {
            ComponentCheck {
                name: "Privileges",
                health: ComponentHealth::Ok,
                summary: format!("UID {} | CAP_NET_ADMIN+RAW active", state.uid),
                detail: "Effective packet capture and raw-socket capabilities are active."
                    .to_owned(),
            }
        } else {
            ComponentCheck {
                name: "Privileges",
                health: ComponentHealth::Err,
                summary: format!("UID {} | missing network caps", state.uid),
                detail: format!(
                    "Missing CAP_NET_ADMIN/CAP_NET_RAW. Press 'g' to grant via: sudo setcap cap_net_admin,cap_net_raw+ep {}",
                    state.exe_path
                ),
            }
        }
    }
}

/// Checks WinDivert (`WinDivert.dll` + `WinDivert64.sys`) on Windows or `nftables` / `NFQUEUE` on Linux.
fn check_packet_driver(state: &AppState) -> ComponentCheck {
    #[cfg(windows)]
    {
        let dll_res = WinDivertApi::load();
        let exe_dir = Path::new(&state.exe_path).parent();
        let sys_beside_exe = exe_dir.is_some_and(|d| d.join("WinDivert64.sys").is_file());
        let sys_in_system = Path::new(r"C:\Windows\System32\drivers\WinDivert64.sys").is_file();
        let sys_ok = sys_beside_exe || sys_in_system;
        match (dll_res, sys_ok) {
            (Ok(_), true) => ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Ok,
                summary: "WinDivert.dll + WinDivert64.sys ready".to_owned(),
                detail: "WinDivert 2.2 DLL loaded cleanly and WinDivert64.sys kernel driver is present."
                    .to_owned(),
            },
            (Ok(_), false) => ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Warn,
                summary: "WinDivert.dll loaded; WinDivert64.sys not beside exe".to_owned(),
                detail: "WinDivert.dll loaded, but WinDivert64.sys was not found next to zapret-rs.exe or in System32\\drivers. Keep WinDivert64.sys in the same folder as zapret-rs.exe."
                    .to_owned(),
            },
            (Err(err), _) => ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Err,
                summary: "WinDivert.dll unavailable".to_owned(),
                detail: format!(
                    "Failed to load WinDivert.dll ({err}). Place WinDivert.dll and WinDivert64.sys from WinDivert-2.2.2-A next to zapret-rs.exe."
                ),
            },
        }
    }
    #[cfg(not(windows))]
    {
        if state.no_nft {
            return ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Warn,
                summary: "NFQUEUE | manual nftables (--no-nft)".to_owned(),
                detail: "Automatic nftables management is disabled (--no-nft); ensure your own NFQUEUE rules are loaded."
                    .to_owned(),
            };
        }
        match Command::new("nft")
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => {
                let ver = String::from_utf8_lossy(&out.stdout).trim().to_owned();
                ComponentCheck {
                    name: "Packet Driver",
                    health: ComponentHealth::Ok,
                    summary: format!("NFQUEUE + {ver}"),
                    detail: format!("Detected {ver} for automatic temporary nftables queue rules."),
                }
            }
            Ok(out) => ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Err,
                summary: format!("nft exited with {}", out.status),
                detail: "nft binary returned non-zero status; pass --no-nft or verify nftables installation."
                    .to_owned(),
            },
            Err(err) => ComponentCheck {
                name: "Packet Driver",
                health: ComponentHealth::Err,
                summary: "nft binary not found".to_owned(),
                detail: format!(
                    "Failed to run nft ({err}). Install nftables or launch with --no-nft."
                ),
            },
        }
    }
}

/// Checks `zapret-lib.lua` and `zapret-antidpi.lua` resolution from the configured Lua directory.
fn check_lua_scripts(state: &AppState) -> ComponentCheck {
    let lua_opt = if state.lua_dir_input.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(state.lua_dir_input.trim()))
    };
    match resolve_lua_scripts(lua_opt.as_deref()) {
        Ok(paths) => {
            let dir = paths
                .first()
                .and_then(|p| p.parent())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| ".".to_owned());
            ComponentCheck {
                name: "Lua Scripts",
                health: ComponentHealth::Ok,
                summary: format!("{} script(s) in {dir}", paths.len()),
                detail: format!(
                    "Resolved Lua scripts: {}",
                    paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", ")
                ),
            }
        }
        Err(err) => ComponentCheck {
            name: "Lua Scripts",
            health: ComponentHealth::Err,
            summary: "Lua scripts missing".to_owned(),
            detail: err,
        },
    }
}

/// Checks `curl` availability, version, and `--http3-only` support.
fn check_curl_probe() -> ComponentCheck {
    let backend = CurlProbeBackend::default();
    let ver_out = Command::new(backend.curl_bin())
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match ver_out {
        Ok(out) if out.status.success() => {
            let text = String::from_utf8_lossy(&out.stdout);
            let first_line = text.lines().next().unwrap_or("curl").trim();
            let short_ver = first_line.split(" (").next().unwrap_or(first_line).trim();
            let h3 = backend.supports_http3();
            if h3 {
                ComponentCheck {
                    name: "Probe (curl)",
                    health: ComponentHealth::Ok,
                    summary: format!("{short_ver} (HTTP/3 ready)"),
                    detail: format!(
                        "{first_line} — HTTP/1.1, TLS 1.2/1.3, and HTTP/3 probes are supported."
                    ),
                }
            } else {
                ComponentCheck {
                    name: "Probe (curl)",
                    health: ComponentHealth::Warn,
                    summary: format!("{short_ver} (no HTTP/3)"),
                    detail: format!(
                        "{first_line} — HTTP/1.1 and TLS 1.2/1.3 work, but HTTP/3 (ngtcp2/quiche) is unavailable and will be skipped."
                    ),
                }
            }
        }
        Ok(out) => ComponentCheck {
            name: "Probe (curl)",
            health: ComponentHealth::Err,
            summary: format!("curl exited with {}", out.status),
            detail: "curl --version failed; Strategy Finder and Speed Test require a working curl binary on PATH."
                .to_owned(),
        },
        Err(err) => ComponentCheck {
            name: "Probe (curl)",
            health: ComponentHealth::Err,
            summary: "curl not found on PATH".to_owned(),
            detail: format!("Failed to execute curl ({err}). Install curl and ensure it is on PATH."),
        },
    }
}

/// Checks the active `nfqws2.toml` parse status and profile count.
fn check_config(state: &AppState) -> ComponentCheck {
    if state.active_toml.trim().is_empty() {
        return ComponentCheck {
            name: "Config",
            health: ComponentHealth::Warn,
            summary: format!("No active config ({})", state.output_path),
            detail: "No nfqws2.toml loaded yet. Run Strategy Finder or press 'l' on Tab 3 to load a file."
                .to_owned(),
        };
    }
    if let Some(err) = &state.toml_error {
        return ComponentCheck {
            name: "Config",
            health: ComponentHealth::Err,
            summary: format!("Invalid TOML ({})", state.output_path),
            detail: err.clone(),
        };
    }
    ComponentCheck {
        name: "Config",
        health: ComponentHealth::Ok,
        summary: format!("Valid ({} profile(s))", state.parsed_profiles.len()),
        detail: format!("Active configuration at {} parsed cleanly.", state.output_path),
    }
}

/// Checks live daemon / control IPC reachability and `systemd` unit state on Linux.
fn check_daemon_ipc(state: &AppState) -> ComponentCheck {
    let detected = detect_control_socket(state.control_socket_override.as_deref());
    let base_summary = match &state.run_status {
        RunStatus::Running => "In-process engine running".to_owned(),
        RunStatus::Attached => "Attached to daemon IPC".to_owned(),
        RunStatus::Error(err) => format!("Error: {err}"),
        RunStatus::Stopped => match &detected {
            Some(sock) => format!("Daemon reachable at {}", sock.display()),
            None => "Idle (no active daemon IPC)".to_owned(),
        },
    };

    #[cfg(target_os = "linux")]
    let svc_note = match Command::new("systemctl")
        .args(["is-active", "zapret-rs.service"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
    {
        Ok(out) => {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
            if s.is_empty() { "not installed".to_owned() } else { s }
        }
        Err(_) => "unavailable".to_owned(),
    };

    #[cfg(target_os = "linux")]
    let detail = format!(
        "Control endpoint: {}. systemd unit (zapret-rs.service): {svc_note}.",
        detected
            .as_ref()
            .map_or_else(|| "none active".to_owned(), |p| p.display().to_string())
    );
    #[cfg(not(target_os = "linux"))]
    let detail = format!(
        "Control IPC endpoint: {}.",
        detected
            .as_ref()
            .map_or_else(|| "none active".to_owned(), |p| p.display().to_string())
    );

    let health = match &state.run_status {
        RunStatus::Error(_) => ComponentHealth::Err,
        _ => ComponentHealth::Ok,
    };
    ComponentCheck { name: "Daemon & IPC", health, summary: base_summary, detail }
}
