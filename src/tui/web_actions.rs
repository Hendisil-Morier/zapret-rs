//! TUI side-effect executors for Blacklist (`hostlist_exclude`), Auto Hostlist, and Web UI actions.

/// Bind address parsing and non-sending UDP outbound route discovery for LAN URL display.
use std::net::{SocketAddr, UdpSocket};

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

/// Live background HTTP/SSE Web UI handle owned by the TUI runner loop.
pub struct ActiveWebUi {
    /// Running HTTP/SSE listener handle shut down cleanly on toggle or TUI exit.
    pub handle: WebServerHandle,
    /// Reachable display URL (`http://<host>:<port>`) shown in Tab 2, Tab 5, and the banner.
    pub url: String,
    /// Auto-generated pairing passcode displayed when binding non-loopback interfaces.
    pub passcode: String,
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
    let probed = UdpSocket::bind("0.0.0.0:0")
        .and_then(|sock| {
            sock.connect("1.1.1.1:80")?;
            sock.local_addr()
        })
        .ok()
        .map(|local| local.ip())
        .filter(|ip| !ip.is_unspecified());
    match probed {
        Some(ip) if ip.is_ipv6() => format!("http://[{ip}]:{port}"),
        Some(ip) => format!("http://{ip}:{port}"),
        None => format!("http://127.0.0.1:{port}"),
    }
}

/// Starts the embedded HTTP/SSE Web UI bound to `bind` and updates `state.web_status`.
pub fn launch_web_ui(state: &mut AppState, bind: SocketAddr) -> Result<ActiveWebUi, String> {
    let (auth, token) = WebAuth::new(bind, None, false)?;
    let cfg_path = (!state.output_path.trim().is_empty()).then(|| expand_tilde(&state.output_path));
    let lua_dir = (!state.lua_dir_input.trim().is_empty()).then(|| expand_tilde(&state.lua_dir_input));
    let control_socket =
        state.control_socket_override.clone().or_else(|| state.detected_socket.clone());
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
    let cfg_path = expand_tilde(&state.output_path);
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
            let cfg_path = expand_tilde(&state.output_path);
            let source_toml = if !state.active_toml.trim().is_empty() {
                state.active_toml.clone()
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
            if state.autohostlist_paths.is_empty() {
                Err("Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first)".to_owned())
            } else {
                let mut res = Ok(());
                for path in state.autohostlist_paths.clone() {
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
            if state.exclude_entries.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                let cfg_path = expand_tilde(&state.output_path);
                if let Ok(updated) =
                    mutate_exclude_domains_toml(&state.active_toml, &clean, false, cfg_path.parent())
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
            for path in state.autohostlist_paths.clone() {
                let prev_len = state.autohostlist_entries.len();
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
            let bind_str = if raw_input == "local" {
                "127.0.0.1:8787"
            } else {
                DEFAULT_WEB_BIND
            };
            let parsed: Result<SocketAddr, String> = bind_str
                .parse()
                .map_err(|err| format!("invalid bind address {bind_str}: {err}"));
            match parsed.and_then(|addr| launch_web_ui(state, addr)) {
                Ok(active) => {
                    state.status_banner = format!(
                        "Web UI: {} (passcode: {}), press W to stop",
                        active.url, active.passcode
                    );
                    state.push_run_log(format!(
                        "[web] listening at {} (passcode: {})",
                        active.url, active.passcode
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
