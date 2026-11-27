//! TUI side-effect executors for Blacklist (`hostlist_exclude`), Auto Hostlist, and Web UI actions.

/// Standard I/O and terminal detection for OSC 52 clipboard writes.
use std::io::{self, IsTerminal, Write};
/// Bind address parsing and non-sending UDP outbound route discovery for LAN URL display.
use std::net::{SocketAddr, UdpSocket};
/// Child process spawning for `wl-copy`/`xclip`/`xsel`/`xdg-open` desktop helpers.
use std::process::{Command, Stdio};

/// Wire request enum sent to attached background `nfqws2` daemons after list/config updates.
use crate::control::Request;
/// Symlink-safe TOML/hostlist writers, Web UI server primitives, and domain cleaners.
use crate::tools::{
    DEFAULT_WEB_BIND, WebAuth, WebConfig, WebServerHandle, expand_tilde,
    mutate_exclude_domains_toml, mutate_hostlist_file, parse_clean_domain, start_web_server,
    write_config_nofollow,
};
/// Prompt modal variants handled on Tab 3 submission and Web UI launch.
use crate::tui::prompt_modal::PromptKind;
/// Shared TUI state mutated after disk/daemon/Web UI updates.
use crate::tui::state::AppState;
/// Remote daemon session handle used to live-reload modified configs or lists.
use crate::tui::tab2_session::Tab2Session;

/// Wildcard LAN bind address (`0.0.0.0:8787`) exposed when user picks LAN / Phone mode.
pub const LAN_WEB_BIND: &str = "0.0.0.0:8787";

/// Live background HTTP/SSE Web UI handle owned by the TUI runner loop.
pub struct ActiveWebUi {
    /// Running HTTP/SSE listener handle shut down cleanly on toggle or TUI exit.
    pub handle: WebServerHandle,
    /// Reachable display URL (`http://<host>:<port>`) shown in Tab 2, Tab 5, and the banner.
    pub url: String,
    /// Auto-generated pairing passcode displayed when binding non-loopback interfaces.
    pub passcode: String,
}

/// Maps `PromptKind::LaunchWebUi` mode tag (`"local"` vs `"lan"`) to its bind socket string.
pub fn resolve_web_bind(mode: &str) -> &'static str {
    if mode.eq_ignore_ascii_case("local") {
        DEFAULT_WEB_BIND
    } else {
        LAN_WEB_BIND
    }
}

/// Encodes arbitrary bytes into standard RFC 4648 base64 for terminal OSC 52 sequences.
fn encode_base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(*chunk.get(1).unwrap_or(&0));
        let b2 = u32::from(*chunk.get(2).unwrap_or(&0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Pipes `text` to an external clipboard helper command when available.
fn run_clipboard_tool(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(text.as_bytes());
    }
    child.wait().is_ok_and(|st| st.success())
}

/// Copies `text` via terminal OSC 52 and native OS clipboard utilities (`wl-copy`/`xclip`/`xsel`).
pub fn copy_to_clipboard(text: &str) -> Result<&'static str, String> {
    let mut osc52_ok = false;
    if io::stdout().is_terminal() {
        let b64 = encode_base64(text.as_bytes());
        let mut out = io::stdout().lock();
        if write!(out, "\x1b]52;c;{b64}\x07").is_ok() && out.flush().is_ok() {
            osc52_ok = true;
        }
    }
    #[cfg(target_os = "macos")]
    let os_ok = run_clipboard_tool("pbcopy", &[], text);
    #[cfg(windows)]
    let os_ok = run_clipboard_tool("clip", &[], text);
    #[cfg(all(unix, not(target_os = "macos")))]
    let os_ok = (std::env::var_os("WAYLAND_DISPLAY").is_some()
        && run_clipboard_tool("wl-copy", &[], text))
        || run_clipboard_tool("xclip", &["-selection", "clipboard"], text)
        || run_clipboard_tool("xsel", &["--clipboard", "--input"], text);

    match (os_ok, osc52_ok) {
        (true, true) => Ok("clipboard & OSC 52"),
        (true, false) => Ok("clipboard"),
        (false, true) => Ok("terminal OSC 52"),
        (false, false) => Err("no clipboard tool (wl-copy/xclip/xsel) and non-TTY stdout".to_owned()),
    }
}

/// Launches `url` in the system's default browser without blocking the TUI event loop.
pub fn open_url_in_browser(url: &str) -> Result<(), String> {
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("refusing to open non-HTTP URL".to_owned());
    }
    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("open", &[url])];
    #[cfg(windows)]
    let candidates: &[(&str, &[&str])] = &[("cmd", &["/C", "start", "", url])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[(&str, &[&str])] = &[("xdg-open", &[url]), ("gio", &["open", url])];

    for (prog, args) in candidates {
        if let Ok(mut child) = Command::new(prog)
            .args(*args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
            return Ok(());
        }
    }
    Err("could not launch browser (install xdg-open or open URL manually)".to_owned())
}

/// Copies active Web UI passcode (or URL when no passcode) and updates the footer banner.
pub fn copy_web_passcode(state: &mut AppState) {
    let Some((url, passcode)) = state.web_status.as_ref() else {
        return;
    };
    let target = if passcode.starts_with("none") { url } else { passcode };
    state.status_banner = match copy_to_clipboard(target) {
        Ok(method) => format!("Copied '{target}' ({method})"),
        Err(err) => format!("Copy failed ({err}); passcode is {target}"),
    };
}

/// Opens the active Web UI URL in a browser, copies the pairing passcode, and updates the banner.
pub fn open_web_ui(state: &mut AppState) {
    let Some((url, passcode)) = state.web_status.clone() else {
        return;
    };
    let clip = (!passcode.starts_with("none")).then(|| copy_to_clipboard(&passcode).ok()).flatten();
    state.status_banner = match open_url_in_browser(&url) {
        Ok(()) => match clip {
            Some(method) => format!("Opened {url} in browser (passcode copied via {method})"),
            None => format!("Opened {url} in browser (passcode: {passcode})"),
        },
        Err(err) => format!("{err}: {url} (passcode: {passcode})"),
    };
}

/// Resolves the outbound route IP for `0.0.0.0` / `::` so LAN users see a phone-reachable URL.
fn format_web_url(addr: SocketAddr) -> String {
    let port = addr.port();
    if !addr.ip().is_unspecified() {
        return match addr {
            SocketAddr::V4(v4) => format!("http://{}:{port}", v4.ip()),
            SocketAddr::V6(v6) => format!("http://[{}]:{port}", v6.ip()),
        };
    }
    let probed = ["1.1.1.1:80", "192.168.1.1:80", "10.0.0.1:80"]
        .into_iter()
        .find_map(|probe| {
            UdpSocket::bind("0.0.0.0:0")
                .and_then(|sock| {
                    sock.connect(probe)?;
                    sock.local_addr()
                })
                .ok()
                .map(|local| local.ip())
                .filter(|ip| !ip.is_unspecified())
        });
    match probed {
        Some(ip) if ip.is_ipv6() => format!("http://[{ip}]:{port}"),
        Some(ip) => format!("http://{ip}:{port}"),
        None => format!("http://127.0.0.1:{port}"),
    }
}

/// Starts the embedded HTTP/SSE Web UI bound to `bind` and updates `state.web_status`.
pub fn launch_web_ui(state: &mut AppState, bind: SocketAddr) -> Result<ActiveWebUi, String> {
    let (auth, token) = WebAuth::new(bind, None, false)?;
    let cfg_path = (!state.finder.output_path.trim().is_empty()).then(|| expand_tilde(&state.finder.output_path));
    let lua_dir = (!state.finder.lua_dir_input.trim().is_empty()).then(|| expand_tilde(&state.finder.lua_dir_input));
    let control_socket =
        state.run.control_socket_override.clone().or_else(|| state.run.detected_socket.clone());
    let cfg = WebConfig {
        bind,
        auth,
        control_socket,
        config: cfg_path,
        lua_dir,
    };
    let handle = start_web_server(cfg)?;
    let url = format_web_url(handle.addr());
    let passcode = token.unwrap_or_else(|| "none (localhost)".to_owned());
    state.web_status = Some((url.clone(), passcode.clone()));
    state.refresh_status_checks();
    Ok(ActiveWebUi { handle, url, passcode })
}

/// Stops any active [`ActiveWebUi`] listener cleanly and clears [`AppState::web_status`].
pub fn stop_web_ui(state: &mut AppState, web_ui: &mut Option<ActiveWebUi>) {
    let Some(mut active) = web_ui.take() else {
        state.web_status = None;
        return;
    };
    active.handle.shutdown();
    state.web_status = None;
    state.refresh_status_checks();
    state.status_banner = "Stopped Web UI".to_owned();
    state.push_run_log("[web] stopped HTTP dashboard");
}

/// Saves `updated_toml` to disk, updates [`AppState`], and live-reloads any attached daemon.
fn commit_updated_toml(
    state: &mut AppState,
    tab2_session: &Option<Tab2Session>,
    updated_toml: String,
    label: &str,
) -> Result<(), String> {
    let cfg_path = expand_tilde(&state.finder.output_path);
    write_config_nofollow(&cfg_path, &updated_toml)
        .map_err(|err| format!("failed to write {}: {err}", cfg_path.display()))?;
    state.set_active_toml(updated_toml.clone());

    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref() {
        if let Err(err) = remote.send_command(&Request::ReloadConfig { toml: updated_toml }) {
            state.status_banner = format!("{label} (saved; daemon reload failed: {err})");
            return Ok(());
        }
        state.status_banner = format!("{label} (saved & reloaded daemon)");
    } else {
        state.status_banner = format!("{label} (saved to {})", cfg_path.display());
    }
    Ok(())
}

/// Executes [`AppState::prompt_modal`] without a live daemon session (used by offline TUI tests).
pub fn apply_prompt_offline(state: &mut AppState) {
    let mut no_web = None;
    submit_prompt_modal(state, &None, &mut no_web);
}

/// Executes the confirmed Tab 3 domain list or Web UI modal action and closes on success.
pub(crate) fn submit_prompt_modal(
    state: &mut AppState,
    tab2_session: &Option<Tab2Session>,
    web_ui: &mut Option<ActiveWebUi>,
) {
    let Some((kind, raw_input)) = state
        .prompt_modal
        .as_ref()
        .map(|m| (m.kind, m.input.trim().to_owned()))
    else {
        return;
    };

    let outcome: Result<(), String> = match kind {
        PromptKind::BlacklistDomain => {
            let cfg_path = expand_tilde(&state.finder.output_path);
            let source_toml = if !state.config.active_toml.trim().is_empty() {
                state.config.active_toml.clone()
            } else {
                std::fs::read_to_string(&cfg_path).unwrap_or_default()
            };
            mutate_exclude_domains_toml(&source_toml, &raw_input, true, cfg_path.parent())
                .and_then(|updated| {
                    let clean = parse_clean_domain(&raw_input).unwrap_or_else(|| raw_input.clone());
                    commit_updated_toml(state, tab2_session, updated, &format!("Blacklisted {clean}"))
                })
        }
        PromptKind::AddAutoHostlist => {
            if state.config.autohostlist_paths.is_empty() {
                Err("Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first)".to_owned())
            } else {
                let mut res = Ok(());
                for path in state.config.autohostlist_paths.clone() {
                    if let Err(err) = mutate_hostlist_file(&path, &raw_input, true) {
                        res = Err(err);
                        break;
                    }
                }
                res.map(|()| {
                    state.refresh_autohostlist();
                    let clean = parse_clean_domain(&raw_input).unwrap_or_else(|| raw_input.clone());
                    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref()
                        && remote.send_command(&Request::ReloadLists).is_ok()
                    {
                        state.status_banner = format!("Added {clean} to Auto Hostlist & reloaded daemon");
                    } else {
                        state.status_banner = format!("Added {clean} to Auto Hostlist");
                    }
                })
            }
        }
        PromptKind::RemoveListDomain => {
            let Some(clean) = parse_clean_domain(&raw_input) else {
                if let Some(m) = state.prompt_modal.as_mut() {
                    m.error = Some("invalid domain name".to_owned());
                }
                return;
            };
            let mut removed_any = false;
            if state.config.exclude_entries.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                let cfg_path = expand_tilde(&state.finder.output_path);
                if let Ok(updated) =
                    mutate_exclude_domains_toml(&state.config.active_toml, &clean, false, cfg_path.parent())
                {
                    let _ = commit_updated_toml(
                        state,
                        tab2_session,
                        updated,
                        &format!("Removed {clean} from Blacklist"),
                    );
                    removed_any = true;
                }
            }
            for path in state.config.autohostlist_paths.clone() {
                let prev_len = state.config.autohostlist_entries.len();
                if let Ok(after) = mutate_hostlist_file(&path, &clean, false)
                    && after.len() < prev_len
                {
                    removed_any = true;
                }
            }
            if removed_any {
                state.refresh_autohostlist();
                if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref() {
                    let _ = remote.send_command(&Request::ReloadLists);
                }
                if !state.status_banner.contains(&clean) {
                    state.status_banner = format!("Removed {clean} from list(s)");
                }
                Ok(())
            } else {
                Err(format!("{clean} not found in Blacklist or Auto Hostlist"))
            }
        }
        PromptKind::LaunchWebUi => {
            let bind_str = resolve_web_bind(&raw_input);
            let parsed: Result<SocketAddr, String> = bind_str
                .parse()
                .map_err(|err| format!("invalid bind address {bind_str}: {err}"));
            match parsed.and_then(|addr| launch_web_ui(state, addr)) {
                Ok(active) => {
                    let clip_note = if !active.passcode.starts_with("none")
                        && copy_to_clipboard(&active.passcode).is_ok()
                    {
                        "copied"
                    } else {
                        "copy: y"
                    };
                    state.status_banner = format!(
                        "Web UI: {} (passcode: {} [{}]) | [o] Open  [y] Copy  [W] Stop",
                        active.url, active.passcode, clip_note
                    );
                    state.push_run_log(format!(
                        "[web] listening at {} (pairing passcode active; press 'y' to copy)",
                        active.url
                    ));
                    if let Some(mut prev) = web_ui.replace(active) {
                        prev.handle.shutdown();
                    }
                    Ok(())
                }
                Err(err) => Err(err),
            }
        }
    };

    match outcome {
        Ok(()) => state.prompt_modal = None,
        Err(err) => {
            if let Some(modal) = state.prompt_modal.as_mut() {
                modal.error = Some(err);
            }
        }
    }
}
