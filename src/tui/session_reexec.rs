//! Serializable TUI form and config snapshot preserved across seamless `exec()` restarts.

/// Filesystem read restoring pre-existing `nfqws2.toml` content when `output_path` changed before restart.
use std::fs;
/// Path storage for preserved centralized `config.toml` destination.
use std::path::PathBuf;

/// Serialization helpers for preserving TUI form state across seamless `setcap` restarts.
use serde::{Deserialize, Serialize};

/// Domain scope, scan level, and tilde path expansion used during snapshot restore.
use crate::tools::{DomainScope, ScanLevel, expand_tilde};
/// Centralized `config.toml` snapshot and keybinding serializer across `exec()` restarts.
use crate::tui::app_config::{parse_app_config_str, render_app_config_toml};
/// Application state updated from restored snapshot payloads.
use crate::tui::state::AppState;
/// Navigation, IP mode, and deferred post-restart action types.
use crate::tui::types::{ActiveTab, IpMode, PostCapsAction};

/// Environment marker set across seamless post-`setcap` `exec()` restarts to avoid screen flash.
pub(crate) const SEAMLESS_REEXEC_ENV: &str = "ZAPRET_RS_SEAMLESS_REEXEC";
/// Environment payload carrying JSON-encoded [`ReexecSnapshot`] across seamless restarts.
pub(crate) const REEXEC_STATE_ENV: &str = "ZAPRET_RS_REEXEC_STATE";

/// Serializable form and navigation snapshot preserved across `setcap` `exec()` restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReexecSnapshot
{
    /// Active tab visible when the restart started.
    pub tab: ActiveTab,
    /// Focused form row index on Tab 1.
    pub focus_idx: usize,
    /// Target domains typed by the user.
    pub domains_input: String,
    /// HTTP (TCP 80) toggle.
    pub proto_http: bool,
    /// TLS 1.2 (TCP 443) toggle.
    pub proto_tls12: bool,
    /// TLS 1.3 (TCP 443) toggle.
    pub proto_tls13: bool,
    /// HTTP/3 QUIC (UDP 443) toggle.
    pub proto_http3: bool,
    /// Selected IP family mode.
    pub ip_mode: IpMode,
    /// Serialized scan thoroughness level (`"quick"`, `"standard"`, `"force"`).
    pub level: String,
    /// Stop-on-first-match toggle.
    pub stop_on_first: bool,
    /// Manual `nftables` toggle.
    pub no_nft: bool,
    /// Lua scripts directory field.
    pub lua_dir_input: String,
    /// Config TOML path field.
    pub output_path: String,
    /// Optional action to launch immediately once capabilities are active.
    pub pending_action: Option<PostCapsAction>,
    /// Active serialized `config.toml` payload (theme + keybinds) preserved across seamless restarts.
    #[serde(default)]
    pub app_config_toml: Option<String>,
    /// Centralized `config.toml` target path preserved across seamless `exec()` restarts.
    #[serde(default)]
    pub app_config_path: Option<PathBuf>,
    /// Selected Tab 1 domain scope preserved across seamless `exec()` restarts.
    #[serde(default)]
    pub domain_scope: DomainScope,
}

impl ReexecSnapshot
{
    /// Captures current form and navigation state from `state`.
    pub(crate) fn capture(state: &AppState) -> Self
    {
        Self {
            tab: state.tab,
            focus_idx: state
                .finder
                .focus_idx,
            domains_input: state
                .finder
                .domains_input
                .clone(),
            proto_http: state
                .finder
                .proto_http,
            proto_tls12: state
                .finder
                .proto_tls12,
            proto_tls13: state
                .finder
                .proto_tls13,
            proto_http3: state
                .finder
                .proto_http3,
            ip_mode: state
                .finder
                .ip_mode,
            level: state
                .finder
                .level
                .as_str()
                .to_owned(),
            stop_on_first: state
                .finder
                .stop_on_first,
            no_nft: state
                .finder
                .no_nft,
            lua_dir_input: state
                .finder
                .lua_dir_input
                .clone(),
            output_path: state
                .finder
                .output_path
                .clone(),
            pending_action: state.pending_caps_action,
            app_config_toml: render_app_config_toml(
                Some(
                    state
                        .finder
                        .output_path
                        .as_str(),
                ),
                Some(
                    state
                        .finder
                        .lua_dir_input
                        .as_str(),
                ),
                state
                    .finder
                    .no_nft,
                state
                    .run
                    .control_socket_override
                    .as_deref(),
                &state.theme,
                &state.keybinds,
            )
            .ok(),
            app_config_path: Some(
                state
                    .app_config_path
                    .clone(),
            ),
            domain_scope: state
                .finder
                .domain_scope,
        }
    }

    /// Encodes the snapshot into JSON for [`REEXEC_STATE_ENV`].
    pub(crate) fn encode(&self) -> Option<String>
    {
        serde_json::to_string(self).ok()
    }

    /// Restores any serialized snapshot from [`REEXEC_STATE_ENV`] when running after `exec()`.
    ///
    /// Returns `(from_reexec, pending_action)`.
    pub(crate) fn restore_from_env(state: &mut AppState) -> (bool, Option<PostCapsAction>)
    {
        if std::env::var_os(SEAMLESS_REEXEC_ENV).is_none()
        {
            return (false, None);
        }
        let Some(raw) = std::env::var_os(REEXEC_STATE_ENV)
        else
        {
            return (true, None);
        };
        let Ok(snap) = serde_json::from_str::<Self>(&raw.to_string_lossy())
        else
        {
            return (true, None);
        };
        state.tab = snap.tab;
        state
            .finder
            .focus_idx = snap.focus_idx;
        state
            .finder
            .domains_input = snap.domains_input;
        state
            .finder
            .proto_http = snap.proto_http;
        state
            .finder
            .proto_tls12 = snap.proto_tls12;
        state
            .finder
            .proto_tls13 = snap.proto_tls13;
        state
            .finder
            .proto_http3 = snap.proto_http3;
        state
            .finder
            .ip_mode = snap.ip_mode;
        state
            .finder
            .level = match snap
            .level
            .as_str()
        {
            "standard" => ScanLevel::Standard,
            "force" => ScanLevel::Force,
            _ => ScanLevel::Quick,
        };
        state
            .finder
            .stop_on_first = snap.stop_on_first;
        state
            .finder
            .no_nft = snap.no_nft;
        state
            .finder
            .lua_dir_input = snap.lua_dir_input;
        state
            .finder
            .domain_scope = snap.domain_scope;
        if snap.output_path
            != state
                .finder
                .output_path
        {
            state
                .finder
                .output_path = snap.output_path;
            let cfg_path = expand_tilde(
                &state
                    .finder
                    .output_path,
            );
            if let Ok(text) = fs::read_to_string(&cfg_path)
            {
                state.set_active_toml(text);
            }
        }
        if let Some(path) = snap.app_config_path
        {
            state.app_config_path = path;
        }
        if let Some(raw_app_cfg) = snap.app_config_toml
            && let Ok((parsed, _)) = parse_app_config_str(
                &raw_app_cfg,
                state
                    .app_config_path
                    .clone(),
                state
                    .app_config_path
                    .parent(),
            )
        {
            state.theme = parsed.theme;
            state.keybinds = parsed.keybinds;
        }
        (true, snap.pending_action)
    }
}
