//! Shared domain normalization, `hostlist_exclude` TOML mutation, and hostlist file editors.

/// Ordered deduplication when collecting domains across inline arrays and list files.
use std::collections::BTreeSet;
/// Filesystem reads for `hostlist_exclude` and `hostlist_auto` files.
use std::fs;
/// File paths resolved relative to `nfqws2.toml`.
use std::path::{Path, PathBuf};

/// Validated `nfqws2.toml` configuration model checked after every mutation.
use crate::config::AppConfig;
/// Domain normalization and symlink-safe atomic config file writer.
use crate::tools::strat::interactive::normalize_domain;
use crate::tools::strat::toml::write_config_nofollow;

/// Normalizes `raw` and rejects malformed labels, spaces, or newlines before writing lists/TOML.
pub fn parse_clean_domain(raw: &str) -> Option<String> {
    let domain = normalize_domain(raw)?;
    let valid_chars = domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !valid_chars || !domain.contains('.') || domain.contains("..") {
        return None;
    }
    Some(domain)
}

/// Reads non-empty, non-comment domain entries from a hostlist file.
pub fn read_hostlist_lines(path: &Path) -> Vec<String> {
    let Ok(raw) = fs::read_to_string(path) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                Some(trimmed.to_owned())
            }
        })
        .collect()
}

/// Appends or removes `raw_domain` in `path`, preserving existing entries and returning the updated list.
pub fn mutate_hostlist_file(path: &Path, raw_domain: &str, add: bool) -> Result<Vec<String>, String> {
    let Some(domain) = parse_clean_domain(raw_domain) else {
        return Err("invalid domain name (expected hostname like example.com)".to_owned());
    };
    let mut domains = read_hostlist_lines(path);
    if add {
        if !domains.iter().any(|d| d.eq_ignore_ascii_case(&domain)) {
            domains.push(domain);
        }
    } else {
        domains.retain(|d| !d.eq_ignore_ascii_case(&domain));
    }
    let mut rendered = domains.join("\n");
    if !rendered.is_empty() {
        rendered.push('\n');
    }
    write_config_nofollow(path, &rendered)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    Ok(domains)
}

/// Returns all unique configured `hostlist_auto` file paths referenced by `cfg`.
pub fn configured_autohostlist_paths(cfg: &AppConfig) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    for prof in &cfg.profiles {
        if let Some(path) = &prof.lists.hostlist_auto
            && !paths.contains(path)
        {
            paths.push(path.clone());
        }
    }
    paths
}

/// Extracts unique excluded (blacklisted) domains across `hostlist_exclude_domains` and `hostlist_exclude` files.
pub fn extract_exclude_domains(cfg: &AppConfig) -> Vec<String> {
    let mut domains = BTreeSet::new();
    for prof in &cfg.profiles {
        for raw in &prof.lists.hostlist_exclude_domains {
            let trimmed = raw.trim();
            if !trimmed.is_empty() {
                domains.insert(trimmed.to_ascii_lowercase());
            }
        }
        for path in &prof.lists.hostlist_exclude {
            for line in read_hostlist_lines(path) {
                domains.insert(line.to_ascii_lowercase());
            }
        }
    }
    domains.into_iter().collect()
}

/// Adds or removes `raw_domain` in `hostlist_exclude_domains` across all `[[profiles]]` tables.
///
/// Validates the resulting TOML with [`AppConfig::from_toml_str`] before returning so malformed
/// configurations can never be saved or pushed to a running daemon.
pub fn mutate_exclude_domains_toml(
    toml_text: &str,
    raw_domain: &str,
    add: bool,
    base_dir: Option<&Path>,
) -> Result<String, String> {
    let Some(domain) = parse_clean_domain(raw_domain) else {
        return Err("invalid domain name (expected hostname like bank.com)".to_owned());
    };
    let mut root: toml::Table =
        toml::from_str(toml_text).map_err(|err| format!("invalid config TOML: {err}"))?;
    let Some(toml::Value::Array(profiles)) = root.get_mut("profiles") else {
        return Err("no [[profiles]] configured in nfqws2.toml yet".to_owned());
    };
    if profiles.is_empty() {
        return Err("no [[profiles]] configured in nfqws2.toml yet".to_owned());
    }

    for item in profiles.iter_mut() {
        let Some(prof) = item.as_table_mut() else {
            continue;
        };
        if add {
            let arr = match prof.entry("hostlist_exclude_domains") {
                toml::map::Entry::Occupied(e) => match e.into_mut() {
                    toml::Value::Array(a) => Some(a),
                    _ => None,
                },
                toml::map::Entry::Vacant(v) => match v.insert(toml::Value::Array(Vec::new())) {
                    toml::Value::Array(a) => Some(a),
                    _ => None,
                },
            };
            if let Some(arr) = arr
                && !arr.iter().any(|v| v.as_str().is_some_and(|s| s.eq_ignore_ascii_case(&domain)))
            {
                arr.push(toml::Value::String(domain.clone()));
            }
        } else if let Some(toml::Value::Array(arr)) = prof.get_mut("hostlist_exclude_domains") {
            arr.retain(|v| v.as_str().is_none_or(|s| !s.eq_ignore_ascii_case(&domain)));
            if arr.is_empty() {
                prof.remove("hostlist_exclude_domains");
            }
        }
    }

    let rendered =
        toml::to_string_pretty(&root).map_err(|err| format!("failed to serialize TOML: {err}"))?;
    AppConfig::from_toml_str(&rendered, base_dir)
        .map_err(|err| format!("updated config failed validation: {err}"))?;
    Ok(rendered)
}
