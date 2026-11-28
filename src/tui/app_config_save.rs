//! Sparse diff-only `config.toml` serialization and comment-preserving surgical updates.

/// Filesystem checks for sibling `theme.toml` imports during surgical saves.
use std::path::Path;

/// Shared `nfqws2.toml` default path, `~/` expander, and auto-detected Lua folder check.
use crate::tools::{default_output_config_path, detect_lua_dir, expand_tilde};
/// Theme and config table constructors for sparse TOML diffing.
use crate::tui::app_config::{ResolvedAppConfig, parse_app_config_str, save_app_config_to_path};
/// Path expansion and imported fragment classification helpers.
use crate::tui::app_config_import::resolve_import_path;
/// Keybinding schema compared against built-in defaults before serializing.
use crate::tui::keybind_schema::Keybinds;
/// Palette slot formatter and built-in baseline preset lookup.
use crate::tui::theme_config::{Theme, format_color};
/// Comment-preserving TOML preamble and section splicing helpers.
use crate::tui::toml_splice::{replace_sections, update_root_scalars};

/// Header written on freshly auto-generated `config.toml` files.
const SPARSE_HEADER: &str = "# zapret-rs TUI configuration (~/.config/zapret-rs/config.toml)\n\
# Manage settings in Tab 7 (Settings) or edit directly. Supports `import = \"./theme.toml\"`.\n\n";

/// Builds a minimal `[theme]` TOML table containing `preset` and only customized color overrides.
pub(crate) fn sparse_theme_table(theme: Theme) -> toml::Table
{
    let base_name = if theme.name == "custom" { "neon" } else { theme.name };
    let base = Theme::from_preset(base_name).unwrap_or_else(Theme::neon);
    let mut tbl = toml::Table::new();
    tbl.insert("preset".to_owned(), toml::Value::String(base_name.to_owned()));
    for (key, cur, def) in [
        ("accent", theme.accent, base.accent),
        ("accent_bright", theme.accent_bright, base.accent_bright),
        ("frame", theme.frame, base.frame),
        ("info", theme.info, base.info),
        ("ok", theme.ok, base.ok),
        ("ok_bright", theme.ok_bright, base.ok_bright),
        ("warn", theme.warn, base.warn),
        ("warn_bright", theme.warn_bright, base.warn_bright),
        ("err", theme.err, base.err),
        ("err_bright", theme.err_bright, base.err_bright),
        ("special", theme.special, base.special),
        ("special_bright", theme.special_bright, base.special_bright),
        ("text", theme.text, base.text),
        ("subtle", theme.subtle, base.subtle),
        ("muted", theme.muted, base.muted),
        ("highlight_bg", theme.highlight_bg, base.highlight_bg),
    ]
    {
        if cur != def
        {
            tbl.insert(key.to_owned(), toml::Value::String(format_color(cur)));
        }
    }
    tbl
}

/// Returns a `[keybinds]` table containing only sections and actions that differ from defaults.
pub(crate) fn sparse_keybinds_table(keybinds: &Keybinds) -> Option<toml::Table>
{
    let cur = toml::Value::try_from(keybinds)
        .ok()?
        .as_table()?
        .clone();
    let def = toml::Value::try_from(Keybinds::default())
        .ok()?
        .as_table()?
        .clone();
    let mut out = toml::Table::new();
    for (sec, val) in cur
    {
        let Some(sec_tbl) = val.as_table()
        else
        {
            continue;
        };
        let def_tbl = def
            .get(&sec)
            .and_then(toml::Value::as_table);
        let mut diff_sec = toml::Table::new();
        for (k, v) in sec_tbl
        {
            let matches_default = def_tbl.and_then(|d| d.get(k)) == Some(v);
            if !matches_default
            {
                diff_sec.insert(k.clone(), v.clone());
            }
        }
        if !diff_sec.is_empty()
        {
            out.insert(sec, toml::Value::Table(diff_sec));
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Formats active settings concisely (omitting defaults and uncustomized keybinds).
pub fn render_sparse_app_config(
    nfqws2_config: Option<&str>,
    lua_dir: Option<&str>,
    no_nft: bool,
    control_socket: Option<&Path>,
    theme: Option<Theme>,
    import_path: Option<&str>,
    keybinds: &Keybinds,
) -> Result<String, String>
{
    let mut root = toml::Table::new();
    if let Some(imp) = import_path.filter(|s| {
        !s.trim()
            .is_empty()
    })
    {
        root.insert("import".to_owned(), toml::Value::String(imp.to_owned()));
    }
    if let Some(cfg) = nfqws2_config
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        root.insert("nfqws2_config".to_owned(), toml::Value::String(cfg.to_owned()));
    }
    if let Some(lua) = explicit_lua_dir(lua_dir)
    {
        root.insert("lua_dir".to_owned(), toml::Value::String(lua.to_owned()));
    }
    if no_nft
    {
        root.insert("no_nft".to_owned(), toml::Value::Boolean(true));
    }
    if let Some(sock) = control_socket
    {
        root.insert(
            "control_socket".to_owned(),
            toml::Value::String(
                sock.display()
                    .to_string(),
            ),
        );
    }
    if let Some(t) = theme
    {
        root.insert("theme".to_owned(), toml::Value::Table(sparse_theme_table(t)));
    }
    if let Some(kb) = sparse_keybinds_table(keybinds)
    {
        root.insert("keybinds".to_owned(), toml::Value::Table(kb));
    }
    let body = toml::to_string_pretty(&root).map_err(|err| format!("serialize config.toml failed: {err}"))?;
    Ok(format!("{SPARSE_HEADER}{body}"))
}

/// Returns `lua_dir` only when set and different from the auto-detected system Lua directory.
fn explicit_lua_dir(lua_dir: Option<&str>) -> Option<&str>
{
    let trimmed = lua_dir
        .map(str::trim)
        .filter(|s| !s.is_empty())?;
    let auto = detect_lua_dir(None).map(|p| {
        p.display()
            .to_string()
    });
    if auto.as_deref() == Some(trimmed) { None } else { Some(trimmed) }
}

/// Creates a lean first-run `config.toml` when missing, importing `./theme.toml` if present.
pub fn ensure_default_app_config_file(resolved: &ResolvedAppConfig, active_lua_dir: &str) -> Option<String>
{
    let path = &resolved.app_config_path;
    if path.exists()
        || path
            .symlink_metadata()
            .is_ok()
    {
        return None;
    }
    let default_nfq = default_output_config_path()
        .display()
        .to_string();
    let import_theme = path
        .with_file_name("theme.toml")
        .exists();
    let rendered = render_sparse_app_config(
        Some(&default_nfq),
        Some(active_lua_dir),
        resolved.no_nft,
        resolved
            .control_socket
            .as_deref(),
        (!import_theme).then_some(resolved.theme),
        import_theme.then_some("./theme.toml"),
        &resolved.keybinds,
    );
    rendered
        .and_then(|toml| save_app_config_to_path(path, &toml))
        .err()
}

/// Saves Tab 7 settings sparsely, preserving comments, `import` lines, and standalone `theme.toml`.
pub fn save_settings_surgically(
    app_cfg_path: &Path,
    nfqws2_config: &str,
    lua_dir: &str,
    no_nft: bool,
    control_socket: Option<&Path>,
    theme: Theme,
    keybinds: &Keybinds,
) -> Result<String, String>
{
    let Ok(existing) = std::fs::read_to_string(app_cfg_path)
    else
    {
        let fresh = render_sparse_app_config(
            Some(nfqws2_config),
            Some(lua_dir),
            no_nft,
            control_socket,
            Some(theme),
            None,
            keybinds,
        )?;
        save_app_config_to_path(app_cfg_path, &fresh)?;
        return Ok(format!("Saved {}", app_cfg_path.display()));
    };

    let mut note = String::new();
    let imported_theme_path = find_imported_theme_path(&existing, app_cfg_path.parent());
    let has_inline_theme = toml::from_str::<toml::Table>(&existing).is_ok_and(|t| t.contains_key("theme"));

    let write_inline_theme = if let Some(ref theme_path) = imported_theme_path
        && !has_inline_theme
    {
        let theme_toml = toml::to_string_pretty(&sparse_theme_table(theme))
            .map_err(|e| format!("serialize theme failed: {e}"))?;
        save_app_config_to_path(theme_path, &theme_toml)?;
        note = format!(
            " (+ {})",
            theme_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("theme.toml")
        );
        false
    }
    else
    {
        true
    };

    let mut updated = update_root_scalars(
        &existing,
        nfqws2_config.trim(),
        explicit_lua_dir(Some(lua_dir)),
        no_nft,
        control_socket,
    );

    if write_inline_theme
    {
        let mut wrap = toml::Table::new();
        wrap.insert("theme".to_owned(), toml::Value::Table(sparse_theme_table(theme)));
        let block = toml::to_string_pretty(&wrap).map_err(|e| format!("serialize [theme] failed: {e}"))?;
        updated = replace_sections(&updated, |h| h == "theme", Some(block.trim_end()));
    }

    let kb_block = match sparse_keybinds_table(keybinds)
    {
        Some(kb_tbl) =>
        {
            let mut wrap = toml::Table::new();
            wrap.insert("keybinds".to_owned(), toml::Value::Table(kb_tbl));
            let s = toml::to_string_pretty(&wrap).map_err(|e| format!("serialize [keybinds] failed: {e}"))?;
            Some(
                s.trim_end()
                    .to_owned(),
            )
        }
        None => None,
    };
    updated =
        replace_sections(&updated, |h| h == "keybinds" || h.starts_with("keybinds."), kb_block.as_deref());

    parse_app_config_str(&updated, app_cfg_path.to_path_buf(), app_cfg_path.parent())?;
    save_app_config_to_path(app_cfg_path, &updated)?;
    Ok(format!("Saved {}{}", app_cfg_path.display(), note))
}

/// Checks whether `existing` imports a standalone theme file directly (`import = "./theme.toml"`).
fn find_imported_theme_path(existing: &str, base_dir: Option<&Path>) -> Option<std::path::PathBuf>
{
    let tbl = toml::from_str::<toml::Table>(existing).ok()?;
    let val = tbl
        .get("import")
        .or_else(|| tbl.get("imports"))?;
    let specs: Vec<&str> = match val
    {
        toml::Value::String(s) => vec![s.as_str()],
        toml::Value::Array(arr) => arr
            .iter()
            .filter_map(toml::Value::as_str)
            .collect(),
        _ => return None,
    };
    for spec in specs
    {
        let path = resolve_import_path(spec, base_dir, expand_tilde)?;
        if let Ok(text) = std::fs::read_to_string(&path)
            && let Ok(sub) = toml::from_str::<toml::Table>(&text)
            && sub.contains_key("preset")
            && !sub.contains_key("keybinds")
        {
            return Some(path);
        }
    }
    None
}
