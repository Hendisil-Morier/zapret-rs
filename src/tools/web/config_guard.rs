//! Path confinement checks preventing Web UI config uploads from reading/writing host files.

/// Filesystem canonicalization and symlink metadata checks along relative subpaths.
use std::fs;
/// Path normalization, component checks, and parent anchoring.
use std::path::{Component, Path, PathBuf};

/// Official XDG/user bundled Lua directory lookup for allowlisted `zapret-*.lua` paths.
use crate::tools::lua_bundle::default_user_lua_dir;

/// Resolves the deepest existing ancestor of `path` cleanly and re-attaches remaining tail parts.
fn resolve_with_existing_ancestor(path: &Path) -> Result<PathBuf, String>
{
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cursor = path;
    while !cursor.exists()
    {
        let Some(name) = cursor.file_name()
        else
        {
            return Err(format!("cannot anchor path '{}'", path.display()));
        };
        tail.push(name.to_owned());
        let Some(parent) = cursor.parent()
        else
        {
            return Err(format!("missing existing root for '{}'", path.display()));
        };
        cursor = parent;
    }
    let mut resolved = fs::canonicalize(cursor)
        .map_err(|err| format!("cannot canonicalize '{}': {err}", cursor.display()))?;
    for part in tail
        .into_iter()
        .rev()
    {
        resolved.push(part);
    }
    Ok(resolved)
}

/// Returns `Ok(())` only if `raw` stays strictly inside `config_dir` without `..` or symlinks.
pub(crate) fn check_confined_path(raw: &Path, config_dir: &Path) -> Result<PathBuf, String>
{
    if raw
        .as_os_str()
        .is_empty()
    {
        return Err("empty path is not permitted".to_owned());
    }
    if raw
        .components()
        .any(|c| matches!(c, Component::ParentDir | Component::Prefix(_)))
    {
        return Err(format!("path traversal '..' is not permitted: '{}'", raw.display()));
    }

    if let Ok(meta) = fs::symlink_metadata(config_dir)
        && meta
            .file_type()
            .is_symlink()
    {
        return Err(format!("config directory '{}' must not be a symlink", config_dir.display()));
    }
    let root_canon = if config_dir.exists()
    {
        fs::canonicalize(config_dir)
            .map_err(|err| format!("invalid config directory '{}': {err}", config_dir.display()))?
    }
    else
    {
        resolve_with_existing_ancestor(config_dir)?
    };

    let candidate = if raw.is_relative() { config_dir.join(raw) } else { raw.to_path_buf() };
    let mut scan = root_canon.clone();
    if raw.is_relative()
    {
        for comp in raw.components()
        {
            if let Component::Normal(seg) = comp
            {
                scan.push(seg);
                if let Ok(meta) = fs::symlink_metadata(&scan)
                    && meta
                        .file_type()
                        .is_symlink()
                {
                    return Err(format!("symlink component not permitted: '{}'", scan.display()));
                }
            }
        }
    }
    else if fs::symlink_metadata(&candidate).is_ok_and(|m| {
        m.file_type()
            .is_symlink()
    })
    {
        return Err(format!("symlink path not permitted: '{}'", candidate.display()));
    }

    let resolved = resolve_with_existing_ancestor(&candidate)?;
    if !resolved.starts_with(&root_canon)
    {
        return Err(format!(
            "path '{}' escapes managed config directory '{}'",
            raw.display(),
            config_dir.display()
        ));
    }
    Ok(resolved)
}

/// Returns `true` when `path` is confined inside `config_dir` (for `/api/domains` R/W validation).
pub(crate) fn is_confined_to_config_dir(path: &Path, config_dir: &Path) -> bool
{
    check_confined_path(path, config_dir).is_ok()
}

/// Validates a `lua_init` entry: confined inside `config_dir` or an official `zapret-*.lua` file.
fn check_lua_init_entry(
    val: &toml::Value,
    config_dir: &Path,
    extra_lua_dir: Option<&Path>,
) -> Result<(), String>
{
    let raw_str = match val
    {
        toml::Value::String(s) => Some(s.as_str()),
        toml::Value::Table(t) =>
        {
            if t.contains_key("inline")
            {
                return Err("inline Lua scripts cannot be configured via Web UI".to_owned());
            }
            t.get("file")
                .and_then(toml::Value::as_str)
        }
        _ => None,
    };
    let Some(path_str) = raw_str
    else
    {
        return Ok(());
    };
    let p = Path::new(path_str);
    if check_confined_path(p, config_dir).is_ok()
    {
        return Ok(());
    }
    let Some(fname) = p
        .file_name()
        .and_then(|n| n.to_str())
    else
    {
        return Err(format!("invalid lua_init path '{path_str}'"));
    };
    if !fname.starts_with("zapret-") || !fname.ends_with(".lua") || !p.is_file()
    {
        return Err(format!(
            "lua_init script '{path_str}' must reside in config dir or bundled Lua directory"
        ));
    }
    let Ok(canon) = fs::canonicalize(p)
    else
    {
        return Err(format!("cannot canonicalize lua_init '{path_str}'"));
    };
    let mut allowed_dirs: Vec<PathBuf> =
        vec![PathBuf::from("/usr/local/share/zapret-rs/lua"), PathBuf::from("/usr/share/zapret-rs/lua")];
    if let Some(d) = default_user_lua_dir()
    {
        allowed_dirs.push(d);
    }
    if let Some(d) = extra_lua_dir
    {
        allowed_dirs.push(d.to_path_buf());
    }
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        allowed_dirs.push(parent.join("lua"));
        if let Some(pref) = parent.parent()
        {
            allowed_dirs.push(pref.join("share/zapret-rs/lua"));
        }
        if let Some(grand) = parent
            .parent()
            .and_then(Path::parent)
        {
            allowed_dirs.push(grand.join("lua"));
        }
    }
    if allowed_dirs
        .iter()
        .filter_map(|d| fs::canonicalize(d).ok())
        .any(|d| canon.starts_with(&d))
    {
        Ok(())
    }
    else
    {
        Err(format!("lua_init script '{path_str}' is outside allowed directories"))
    }
}

/// Checks an optional array of path strings in `table[key]` against `config_dir`.
fn check_path_array(table: &toml::Table, key: &str, config_dir: &Path) -> Result<(), String>
{
    let Some(toml::Value::Array(items)) = table.get(key)
    else
    {
        return Ok(());
    };
    for item in items
    {
        if let Some(s) = item.as_str()
        {
            check_confined_path(Path::new(s), config_dir)?;
        }
    }
    Ok(())
}

/// Validates every filesystem path in raw `nfqws2.toml` before `AppConfig::from_toml_str` reads disk.
pub(crate) fn validate_web_toml_paths(
    toml_text: &str,
    config_dir: &Path,
    extra_lua_dir: Option<&Path>,
) -> Result<(), String>
{
    let root: toml::Table = toml::from_str(toml_text).map_err(|err| format!("invalid config TOML: {err}"))?;

    for key in ["pidfile", "chdir", "hostlist_auto_debug", "writable"]
    {
        if let Some(s) = root
            .get(key)
            .and_then(toml::Value::as_str)
        {
            check_confined_path(Path::new(s), config_dir)?;
        }
    }
    if let Some(sock) = root
        .get("control_socket")
        .and_then(toml::Value::as_str)
        && sock != "off"
        && sock != "default"
    {
        check_confined_path(Path::new(sock), config_dir)?;
    }
    if let Some(toml::Value::Table(blobs)) = root.get("blobs")
    {
        for (name, spec) in blobs
        {
            if let Some(file_str) = spec
                .as_table()
                .and_then(|t| t.get("file"))
                .and_then(toml::Value::as_str)
            {
                check_confined_path(Path::new(file_str), config_dir)
                    .map_err(|e| format!("blob '{name}': {e}"))?;
            }
        }
    }
    if let Some(toml::Value::Array(lua_items)) = root.get("lua_init")
    {
        for item in lua_items
        {
            check_lua_init_entry(item, config_dir, extra_lua_dir)?;
        }
    }
    if let Some(toml::Value::Array(profiles)) = root.get("profiles")
    {
        for item in profiles
        {
            let Some(prof) = item.as_table()
            else
            {
                continue;
            };
            if let Some(auto_str) = prof
                .get("hostlist_auto")
                .and_then(toml::Value::as_str)
            {
                check_confined_path(Path::new(auto_str), config_dir)?;
            }
            for arr_key in ["hostlist", "hostlist_exclude", "ipset", "ipset_exclude"]
            {
                check_path_array(prof, arr_key, config_dir)?;
            }
        }
    }
    Ok(())
}
