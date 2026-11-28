//! Recursive `import` / `imports` resolution and TOML table merging for centralized `config.toml`.

/// Canonical cycle tracking and relative import path resolution.
use std::path::{Path, PathBuf};

/// Theme palette field names recognized when importing a standalone `theme.toml` fragment.
const THEME_FILE_KEYS: &[&str] = &[
    "preset",
    "accent",
    "accent_bright",
    "frame",
    "info",
    "ok",
    "ok_bright",
    "warn",
    "warn_bright",
    "err",
    "err_bright",
    "special",
    "special_bright",
    "text",
    "subtle",
    "muted",
    "highlight_bg",
];

/// Keybind section names recognized when importing a standalone `keybinds.toml` fragment.
const KEYBIND_SECTION_KEYS: &[&str] =
    &["global", "nav", "finder", "run", "inspector", "config", "speed", "status", "hostlist"];

/// Maximum nested import depth permitted to prevent runaway recursion.
const MAX_IMPORT_DEPTH: usize = 16;

/// Resolves an `import` path string relative to `base_dir`, expanding `~/`.
pub(crate) fn resolve_import_path(
    spec: &str,
    base_dir: Option<&Path>,
    expand_home: fn(&str) -> PathBuf,
) -> Option<PathBuf>
{
    let trimmed = spec.trim();
    if trimmed.is_empty()
    {
        return None;
    }
    if trimmed.starts_with("~/") || trimmed == "~"
    {
        return Some(expand_home(trimmed));
    }
    let p = PathBuf::from(trimmed);
    if p.is_relative()
        && let Some(dir) = base_dir
    {
        return Some(dir.join(p));
    }
    Some(p)
}

/// Loads `input` and merges any `import`/`imports` fragments underneath local keys.
///
/// Supports importing nested `config.toml` fragments, standalone `theme.toml` files (keys placed
/// under `[theme]`), standalone `keybinds.toml` files (sections placed under `[keybinds]`), and
/// `[theme].import = "./theme.toml"`. Local keys always take precedence over imported values.
pub(crate) fn load_merged_app_table(
    input: &str,
    base_dir: Option<&Path>,
    current_path: Option<&Path>,
    ancestors: &mut Vec<PathBuf>,
    expand_home: fn(&str) -> PathBuf,
) -> Result<toml::Table, String>
{
    if ancestors.len() >= MAX_IMPORT_DEPTH
    {
        return Err(format!("config import depth exceeded ({MAX_IMPORT_DEPTH})"));
    }
    let pushed = if let Some(path) = current_path
    {
        let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        if ancestors.contains(&canon)
        {
            return Err(format!("circular config import detected: {}", path.display()));
        }
        ancestors.push(canon);
        true
    }
    else
    {
        false
    };

    let result = load_merged_inner(input, base_dir, ancestors, expand_home);
    if pushed
    {
        ancestors.pop();
    }
    result
}

/// Inner worker for [`load_merged_app_table`] ensuring `ancestors` pops cleanly on every exit path.
fn load_merged_inner(
    input: &str,
    base_dir: Option<&Path>,
    ancestors: &mut Vec<PathBuf>,
    expand_home: fn(&str) -> PathBuf,
) -> Result<toml::Table, String>
{
    let mut local: toml::Table =
        toml::from_str(input).map_err(|err| format!("invalid config.toml: {err}"))?;
    let top_imports = extract_import_specs(&mut local)?;
    let theme_imports = match local.get_mut("theme")
    {
        Some(toml::Value::Table(theme_tbl)) => extract_import_specs(theme_tbl)?,
        _ => Vec::new(),
    };
    normalize_relative_path_fields(&mut local, base_dir, expand_home);

    let mut merged = toml::Table::new();
    for spec in top_imports
    {
        let frag = load_fragment_from_spec(&spec, base_dir, ancestors, expand_home, false)?;
        deep_merge_table(&mut merged, frag);
    }
    for spec in theme_imports
    {
        let frag = load_fragment_from_spec(&spec, base_dir, ancestors, expand_home, true)?;
        deep_merge_table(&mut merged, frag);
    }
    deep_merge_table(&mut merged, local);
    Ok(merged)
}

/// Reads one imported TOML file and classifies it as app config, standalone theme, or keybinds.
fn load_fragment_from_spec(
    spec: &str,
    base_dir: Option<&Path>,
    ancestors: &mut Vec<PathBuf>,
    expand_home: fn(&str) -> PathBuf,
    force_theme: bool,
) -> Result<toml::Table, String>
{
    let path = resolve_import_path(spec, base_dir, expand_home)
        .ok_or_else(|| "import path cannot be empty".to_owned())?;
    let text = std::fs::read_to_string(&path)
        .map_err(|err| format!("failed to read imported config {}: {err}", path.display()))?;
    let raw_tbl: toml::Table =
        toml::from_str(&text).map_err(|err| format!("invalid TOML in {}: {err}", path.display()))?;

    if force_theme
    {
        return Ok(wrap_if_unwrapped_theme(raw_tbl));
    }

    if !raw_tbl.is_empty()
        && raw_tbl
            .keys()
            .all(|k| THEME_FILE_KEYS.contains(&k.as_str()))
    {
        let mut wrapper = toml::Table::new();
        wrapper.insert("theme".to_owned(), toml::Value::Table(raw_tbl));
        return Ok(wrapper);
    }
    if !raw_tbl.is_empty()
        && raw_tbl
            .keys()
            .all(|k| KEYBIND_SECTION_KEYS.contains(&k.as_str()))
    {
        let mut wrapper = toml::Table::new();
        wrapper.insert("keybinds".to_owned(), toml::Value::Table(raw_tbl));
        return Ok(wrapper);
    }

    load_merged_app_table(&text, path.parent(), Some(&path), ancestors, expand_home)
}

/// Wraps top-level theme keys into `[theme]`, or passes through a file that already uses `[theme]`.
fn wrap_if_unwrapped_theme(mut tbl: toml::Table) -> toml::Table
{
    if tbl.contains_key("theme") && tbl.len() == 1
    {
        return tbl;
    }
    let mut wrapper = toml::Table::new();
    let inner = match tbl.remove("theme")
    {
        Some(v) => v,
        None => toml::Value::Table(tbl),
    };
    wrapper.insert("theme".to_owned(), inner);
    wrapper
}

/// Removes and parses `"import"` and `"imports"` string/array values from `table`.
fn extract_import_specs(table: &mut toml::Table) -> Result<Vec<String>, String>
{
    let mut specs = Vec::new();
    for key in ["import", "imports"]
    {
        if let Some(val) = table.remove(key)
        {
            match val
            {
                toml::Value::String(s) => specs.push(s),
                toml::Value::Array(items) =>
                {
                    for item in items
                    {
                        match item
                        {
                            toml::Value::String(s) => specs.push(s),
                            _ =>
                            {
                                return Err(format!("'{key}' entries must be file path strings"));
                            }
                        }
                    }
                }
                _ => return Err(format!("'{key}' must be a path string or array of path strings")),
            }
        }
    }
    Ok(specs)
}

/// Resolves relative path scalars inside `table` against `base_dir` before merging upwards.
fn normalize_relative_path_fields(
    table: &mut toml::Table,
    base_dir: Option<&Path>,
    expand_home: fn(&str) -> PathBuf,
)
{
    for key in ["nfqws2_config", "lua_dir", "control_socket"]
    {
        if let Some(toml::Value::String(raw)) = table.get_mut(key)
            && let Some(resolved) = resolve_import_path(raw, base_dir, expand_home)
        {
            *raw = resolved
                .display()
                .to_string();
        }
    }
}

/// Recursively merges `overlay` into `base`, overriding matching leaf keys and merging sub-tables.
fn deep_merge_table(base: &mut toml::Table, overlay: toml::Table)
{
    for (key, val) in overlay
    {
        match (base.get_mut(&key), val)
        {
            (Some(toml::Value::Table(base_sub)), toml::Value::Table(over_sub)) =>
            {
                deep_merge_table(base_sub, over_sub);
            }
            (_, over_val) =>
            {
                base.insert(key, over_val);
            }
        }
    }
}
