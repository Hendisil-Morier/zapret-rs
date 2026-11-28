//! Centralized TUI application configuration (`~/.config/zapret-rs/config.toml`).

/// Path resolution for centralized `config.toml` and referenced `nfqws2.toml` files.
use std::path::{Path, PathBuf};

/// Deserialization for centralized `config.toml` sections.
use serde::Deserialize;

/// Shared config directory helper, `~/` expander, and symlink-safe TOML writer.
use crate::tools::{default_output_config_path, expand_tilde, write_config_nofollow};
/// Recursive `import` / `imports` resolution and TOML table merging helper.
use crate::tui::app_config_import::{load_merged_app_table, resolve_import_path};
/// Complete remappable keybinding map across global chrome and all six tabs.
use crate::tui::keybind_schema::Keybinds;
/// Shared theme override schema and preset/color resolver.
use crate::tui::theme_config::{RawThemeFile, Theme, resolve_theme};

/// Keys exclusive to `nfqws2.toml` used to distinguish `--config nfqws2.toml` from `config.toml`.
const NFQWS2_ONLY_KEYS: &[&str] = &[
    "profiles",
    "qnum",
    "fwmark",
    "intercept",
    "daemon",
    "lua_init",
    "blobs",
    "hostlist_auto_debug",
    "writable",
    "auto_nft",
    "payload_disable",
    "reasm_disable",
    "ctrack_timeouts",
    "ctrack_disable",
    "ipcache_lifetime",
    "ipcache_hostname",
    "server",
    "debug",
    "bind_fix4",
    "bind_fix6",
    "pidfile",
    "chdir",
    "user",
    "uid",
    "lua_gc",
    "control_pass_sample",
];

/// Keys exclusive to centralized TUI `config.toml`.
const APP_CONFIG_ONLY_KEYS: &[&str] =
    &["import", "imports", "nfqws2_config", "lua_dir", "no_nft", "theme", "keybinds"];

/// Combined startup settings loaded from `config.toml` and CLI overrides.
#[derive(Debug, Clone)]
pub struct ResolvedAppConfig
{
    /// Centralized app config path where Tab 7 Settings persists changes.
    pub app_config_path: PathBuf,
    /// Explicit or configured `nfqws2.toml` path to load into Finder/Config/Run tabs.
    pub nfqws2_config: Option<PathBuf>,
    /// Optional configured Lua directory override.
    pub lua_dir: Option<PathBuf>,
    /// Optional configured manual `nftables` toggle override.
    pub no_nft: bool,
    /// Optional configured daemon Unix control socket override.
    pub control_socket: Option<PathBuf>,
    /// Active TUI color theme resolved from `--theme` or `[theme]`.
    pub theme: Theme,
    /// Active remappable keymap loaded from `[keybinds.*]` or defaults.
    pub keybinds: Keybinds,
}

impl ResolvedAppConfig
{
    /// Builds default startup settings pointing persistence to `app_config_path`.
    fn default_at(app_config_path: PathBuf) -> Self
    {
        Self {
            app_config_path,
            nfqws2_config: None,
            lua_dir: None,
            no_nft: false,
            control_socket: None,
            theme: Theme::neon(),
            keybinds: Keybinds::default(),
        }
    }
}

/// Raw TOML schema accepted from `~/.config/zapret-rs/config.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawAppConfigFile
{
    /// Path to the managed `nfqws2.toml` daemon/strategy file (`~/` or relative to `config.toml`).
    nfqws2_config: Option<String>,
    /// Default Lua scripts directory (`~/` or relative to `config.toml`).
    lua_dir: Option<String>,
    /// Start with manual `nftables` mode enabled (`--no-nft`).
    no_nft: Option<bool>,
    /// Default Unix control socket override (`--control-socket`).
    control_socket: Option<String>,
    /// Optional `[theme]` preset and palette color overrides.
    theme: Option<RawThemeFile>,
    /// Optional `[keybinds.*]` overrides merged on top of built-in defaults.
    keybinds: Keybinds,
}

/// Returns the default centralized TUI config path (`~/.config/zapret-rs/config.toml`).
pub fn default_app_config_path() -> PathBuf
{
    default_output_config_path().with_file_name("config.toml")
}

/// Returns `true` when `input` at `path` represents a centralized `config.toml` rather than `nfqws2.toml`.
pub fn is_centralized_app_config(input: &str, path: &Path) -> bool
{
    if let Ok(table) = toml::from_str::<toml::Table>(input)
    {
        if NFQWS2_ONLY_KEYS
            .iter()
            .any(|k| table.contains_key(*k))
        {
            return false;
        }
        if APP_CONFIG_ONLY_KEYS
            .iter()
            .any(|k| table.contains_key(*k))
        {
            return true;
        }
    }
    path.file_name()
        .and_then(|n| n.to_str())
        == Some("config.toml")
}

/// Parses a centralized `config.toml` string (resolving `import` / `imports` recursively) into settings.
pub fn parse_app_config_str(
    input: &str,
    config_path: PathBuf,
    base_dir: Option<&Path>,
) -> Result<(ResolvedAppConfig, bool), String>
{
    let mut ancestors = Vec::new();
    let merged = load_merged_app_table(input, base_dir, Some(&config_path), &mut ancestors, expand_tilde)?;
    let raw: RawAppConfigFile = RawAppConfigFile::deserialize(toml::Value::Table(merged))
        .map_err(|err| format!("invalid config.toml: {err}"))?;
    let (theme, has_theme) = match raw
        .theme
        .as_ref()
    {
        Some(raw_theme) => (Theme::from_raw(raw_theme)?, true),
        None => (Theme::neon(), false),
    };
    let resolved = ResolvedAppConfig {
        app_config_path: config_path,
        nfqws2_config: raw
            .nfqws2_config
            .as_deref()
            .and_then(|s| resolve_import_path(s, base_dir, expand_tilde)),
        lua_dir: raw
            .lua_dir
            .as_deref()
            .and_then(|s| resolve_import_path(s, base_dir, expand_tilde)),
        no_nft: raw
            .no_nft
            .unwrap_or(false),
        control_socket: raw
            .control_socket
            .as_deref()
            .and_then(|s| resolve_import_path(s, base_dir, expand_tilde)),
        theme,
        keybinds: raw.keybinds,
    };
    Ok((resolved, has_theme))
}

/// Re-exported sparse diff-only config generator and surgical saver for tests and callers.
pub use crate::tui::app_config_save::{ensure_default_app_config_file, render_sparse_app_config};

/// Serializes active TUI paths, sparse `[theme]`, and custom `[keybinds.*]` into `config.toml`.
pub fn render_app_config_toml(
    nfqws2_config: Option<&str>,
    lua_dir: Option<&str>,
    no_nft: bool,
    control_socket: Option<&Path>,
    theme: &Theme,
    keybinds: &Keybinds,
) -> Result<String, String>
{
    render_sparse_app_config(nfqws2_config, lua_dir, no_nft, control_socket, Some(*theme), None, keybinds)
}

/// Writes `toml` symlink-safely to `path`.
pub fn save_app_config_to_path(path: &Path, toml: &str) -> Result<(), String>
{
    write_config_nofollow(path, toml).map_err(|err| format!("write {}: {err}", path.display()))
}

/// Options accepted by [`resolve_startup_app_config`] after CLI parsing.
#[derive(Debug, Clone, Default)]
pub struct StartupConfigRequest<'a>
{
    /// Raw `--config` CLI path (auto-detected as `config.toml` or `nfqws2.toml`).
    pub cli_config: Option<&'a Path>,
    /// Explicit `--nfqws2-config` CLI override.
    pub cli_nfqws2_config: Option<&'a Path>,
    /// Explicit `--lua-dir` CLI override.
    pub cli_lua_dir: Option<&'a Path>,
    /// Explicit `--no-nft` CLI flag.
    pub cli_no_nft: bool,
    /// Explicit `--control-socket` CLI override.
    pub cli_control_socket: Option<&'a Path>,
    /// Explicit `--theme` CLI preset or path override.
    pub cli_theme: Option<&'a str>,
}

/// Resolves centralized `config.toml`, `nfqws2.toml`, and CLI flags together.
pub fn resolve_startup_app_config(req: StartupConfigRequest<'_>) -> (ResolvedAppConfig, Option<String>)
{
    let default_cfg_path = default_app_config_path();
    let mut direct_nfqws2: Option<PathBuf> = None;
    let mut app_cfg_path = default_cfg_path.clone();
    let mut warning: Option<String> = None;

    if let Some(cli_path) = req.cli_config
    {
        match std::fs::read_to_string(cli_path)
        {
            Ok(text) =>
            {
                if is_centralized_app_config(&text, cli_path)
                {
                    app_cfg_path = cli_path.to_path_buf();
                }
                else
                {
                    direct_nfqws2 = Some(cli_path.to_path_buf());
                }
            }
            Err(_)
                if cli_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    == Some("config.toml") =>
            {
                app_cfg_path = cli_path.to_path_buf();
            }
            Err(_) => direct_nfqws2 = Some(cli_path.to_path_buf()),
        }
    }

    let (mut resolved, _) = match std::fs::read_to_string(&app_cfg_path)
    {
        Ok(text) => match parse_app_config_str(&text, app_cfg_path.clone(), app_cfg_path.parent())
        {
            Ok(parsed) => parsed,
            Err(err) =>
            {
                warning = Some(format!("Config {} error: {err}", app_cfg_path.display()));
                (ResolvedAppConfig::default_at(app_cfg_path), false)
            }
        },
        Err(_) => (ResolvedAppConfig::default_at(app_cfg_path), false),
    };

    if let Some(theme_spec) = req.cli_theme
    {
        let (theme, theme_warn) = resolve_theme(theme_spec);
        resolved.theme = theme;
        if theme_warn.is_some()
        {
            warning = theme_warn;
        }
    }

    if let Some(p) = req.cli_nfqws2_config
    {
        resolved.nfqws2_config = Some(p.to_path_buf());
    }
    else if let Some(p) = direct_nfqws2
    {
        resolved.nfqws2_config = Some(p);
    }
    if let Some(p) = req.cli_lua_dir
    {
        resolved.lua_dir = Some(p.to_path_buf());
    }
    if req.cli_no_nft
    {
        resolved.no_nft = true;
    }
    if let Some(p) = req.cli_control_socket
    {
        resolved.control_socket = Some(p.to_path_buf());
    }

    (resolved, warning)
}
