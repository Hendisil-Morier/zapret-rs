//! TOML profile merging and hostlist-domain extraction helpers for preserving existing rules.

/// Case-insensitive duplicate filtering while merging profile domain arrays.
use std::collections::HashSet;
/// Writing scoped profile directives into rendered TOML strings cleanly.
use std::fmt::Write as _;

/// Serialization support so Tab 1's domain scope survives `setcap` `exec()` restarts.
use serde::{Deserialize, Serialize};

/// Parsed configuration model validated before returning merged TOML.
use crate::config::AppConfig;
/// Base strategy TOML renderer wrapped by [`render_nfqws2_toml_scoped`].
use crate::tools::strat_toml::{CoveredProfile, TomlRenderOptions, render_nfqws2_toml};

/// Default relative autohostlist file placed beside `nfqws2.toml`.
pub const DEFAULT_AUTOHOSTLIST_FILE: &str = "autohostlist.txt";

/// Controls whether generated profiles affect only scanned domains, all domains, or use autohostlist.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum DomainScope {
    /// Restrict generated profiles to the scanned domains via `hostlist_domains`.
    #[default]
    ScannedOnly,
    /// Omit `hostlist_domains` so generated profiles apply across all domains on that port/protocol.
    AllDomains,
    /// Emit `hostlist_auto` alongside `hostlist_domains` so failing domains are added dynamically.
    AutoHostlist,
}

impl DomainScope {
    /// Cycles `ScannedOnly -> AllDomains -> AutoHostlist -> ScannedOnly`.
    pub const fn next(self) -> Self {
        match self {
            Self::ScannedOnly => Self::AllDomains,
            Self::AllDomains => Self::AutoHostlist,
            Self::AutoHostlist => Self::ScannedOnly,
        }
    }

    /// Returns a compact display label for Tab 1's `Domain Scope` row.
    pub const fn label(self) -> &'static str {
        match self {
            Self::ScannedOnly => "Scanned Only",
            Self::AllDomains => "All Domains (catch-all)",
            Self::AutoHostlist => "Auto Hostlist",
        }
    }
}

/// Renders `profiles` with [`render_nfqws2_toml`] and rewrites per-profile domain scoping for `scope`.
pub fn render_nfqws2_toml_scoped(
    profiles: &[CoveredProfile],
    opts: &TomlRenderOptions,
    scope: DomainScope,
) -> String {
    let base = render_nfqws2_toml(profiles, opts);
    match scope {
        DomainScope::ScannedOnly => base,
        DomainScope::AllDomains => {
            let mut out = String::with_capacity(base.len());
            for line in base.lines() {
                if !line.starts_with("hostlist_domains = ") {
                    let _ = writeln!(out, "{line}");
                }
            }
            out
        }
        DomainScope::AutoHostlist => {
            let mut out = String::with_capacity(base.len() + 64);
            for line in base.lines() {
                let _ = writeln!(out, "{line}");
                if line.starts_with("filter_l7 = ") {
                    let _ = writeln!(out, "hostlist_auto = \"{DEFAULT_AUTOHOSTLIST_FILE}\"");
                }
            }
            out
        }
    }
}

/// Extracts unique, trimmed inline `hostlist_domains` entries across every profile in `cfg`.
pub fn extract_hostlist_domains(cfg: &AppConfig) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for prof in &cfg.profiles {
        for raw in &prof.lists.hostlist_domains {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let key = trimmed.to_ascii_lowercase();
            if seen.insert(key) {
                out.push(trimmed.to_owned());
            }
        }
    }
    out
}

/// Reads an array of strings from `table[key]`, returning empty when absent or non-array.
fn read_str_array(table: &toml::Table, key: &str) -> Vec<String> {
    table
        .get(key)
        .and_then(toml::Value::as_array)
        .map(|arr| arr.iter().filter_map(toml::Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Canonical `(filter_l3, filter_tcp, filter_udp, filter_l7)` signature for comparing profile slots.
fn filter_signature(prof: &toml::Table) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
    (
        read_str_array(prof, "filter_l3"),
        read_str_array(prof, "filter_tcp"),
        read_str_array(prof, "filter_udp"),
        read_str_array(prof, "filter_l7"),
    )
}

/// Returns `true` when `prof` acts as a catch-all without hostlist or ipset scoping.
fn is_catch_all(prof: &toml::Table) -> bool {
    !prof.contains_key("hostlist_domains")
        && !prof.contains_key("hostlist")
        && !prof.contains_key("ipset")
        && !prof.contains_key("ipset_domains")
}

/// Returns `true` if `prof` still references list/ipset sources after inline domains are removed.
fn has_other_lists(prof: &toml::Table) -> bool {
    prof.contains_key("hostlist")
        || prof.contains_key("hostlist_auto")
        || prof.contains_key("ipset")
        || prof.contains_key("ipset_domains")
}

/// Appends unique string items from `extra` into `target` case-insensitively.
fn merge_unique_strings(target: &mut Vec<toml::Value>, extra: &[String]) {
    let mut seen: HashSet<String> = target
        .iter()
        .filter_map(toml::Value::as_str)
        .map(str::to_ascii_lowercase)
        .collect();
    for item in extra {
        let key = item.to_ascii_lowercase();
        if seen.insert(key) {
            target.push(toml::Value::String(item.clone()));
        }
    }
}

/// Removes `domains` (case-insensitively) from `prof["hostlist_domains"]`.
///
/// Returns `true` when `prof` originally scoped via `hostlist_domains`, has no remaining domains,
/// and has no other list/ipset directives keeping it meaningful.
fn strip_domains(prof: &mut toml::Table, domains: &HashSet<String>) -> bool {
    let became_empty = {
        let Some(toml::Value::Array(arr)) = prof.get_mut("hostlist_domains") else {
            return false;
        };
        arr.retain(|v| v.as_str().is_none_or(|s| !domains.contains(&s.to_ascii_lowercase())));
        arr.is_empty()
    };
    if !became_empty {
        return false;
    }
    if !has_other_lists(prof) {
        return true;
    }
    prof.remove("hostlist_domains");
    false
}

/// Merges generated `[[profiles]]` from `new_toml` into `existing_toml` without wiping prior rules.
///
/// Preserves existing top-level daemon settings (`qnum`, `fwmark`, `control_socket`, `ipcache`),
/// unions any missing `lua_init` entries, updates/deduplicates overlapping domain profiles cleanly,
/// inserts new domain-scoped profiles before catch-all fallbacks, and validates the output with
/// [`AppConfig::from_toml_str`].
pub fn merge_nfqws2_toml(existing_toml: &str, new_toml: &str) -> Result<String, String> {
    if existing_toml.trim().is_empty() {
        return Ok(new_toml.to_owned());
    }
    if new_toml.trim().is_empty() {
        return Ok(existing_toml.to_owned());
    }
    let mut base: toml::Table =
        toml::from_str(existing_toml).map_err(|err| format!("invalid existing TOML: {err}"))?;
    let incoming: toml::Table =
        toml::from_str(new_toml).map_err(|err| format!("invalid scan TOML: {err}"))?;

    // Union any new `lua_init` script paths required by newly scanned strategies.
    let new_lua = read_str_array(&incoming, "lua_init");
    if !new_lua.is_empty() {
        let arr = match base.entry("lua_init") {
            toml::map::Entry::Occupied(e) => match e.into_mut() {
                toml::Value::Array(a) => Some(a),
                _ => None,
            },
            toml::map::Entry::Vacant(v) => match v.insert(toml::Value::Array(Vec::new())) {
                toml::Value::Array(a) => Some(a),
                _ => None,
            },
        };
        if let Some(a) = arr {
            merge_unique_strings(a, &new_lua);
        }
    }

    let mut merged_profiles: Vec<toml::Table> = base
        .get("profiles")
        .and_then(toml::Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_table().cloned()).collect())
        .unwrap_or_default();

    let incoming_profiles: Vec<toml::Table> = incoming
        .get("profiles")
        .and_then(toml::Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_table().cloned()).collect())
        .unwrap_or_default();

    for new_prof in incoming_profiles {
        let sig = filter_signature(&new_prof);
        let new_name = new_prof.get("name").and_then(toml::Value::as_str);
        let new_actions = new_prof.get("actions");
        let new_domains = read_str_array(&new_prof, "hostlist_domains");
        let new_set: HashSet<String> = new_domains.iter().map(|d| d.to_ascii_lowercase()).collect();

        // Remove overwritten domains from older conflicting profiles in the same protocol slot.
        if !new_set.is_empty() {
            merged_profiles.retain_mut(|old_prof| {
                let same_slot = filter_signature(old_prof) == sig;
                let same_strat = old_prof.get("name").and_then(toml::Value::as_str) == new_name
                    && old_prof.get("actions") == new_actions;
                if same_slot && !same_strat {
                    return !strip_domains(old_prof, &new_set);
                }
                true
            });
        }

        // Reuse an identical profile in the same slot by extending its `hostlist_domains`.
        if let Some(existing) = merged_profiles.iter_mut().find(|p| {
            filter_signature(p) == sig
                && p.get("name").and_then(toml::Value::as_str) == new_name
                && p.get("actions") == new_actions
        }) {
            if !new_domains.is_empty()
                && !is_catch_all(existing)
                && let Some(toml::Value::Array(arr)) = existing.get_mut("hostlist_domains")
            {
                merge_unique_strings(arr, &new_domains);
            }
            continue;
        }

        // Insert new domain-scoped profiles ahead of trailing catch-all profiles.
        let insert_idx = merged_profiles
            .iter()
            .position(is_catch_all)
            .unwrap_or(merged_profiles.len());
        merged_profiles.insert(insert_idx, new_prof);
    }

    base.insert(
        "profiles".to_owned(),
        toml::Value::Array(merged_profiles.into_iter().map(toml::Value::Table).collect()),
    );
    let rendered =
        toml::to_string_pretty(&base).map_err(|err| format!("failed to serialize merged TOML: {err}"))?;
    AppConfig::from_toml_str(&rendered, None)
        .map_err(|err| format!("merged config failed validation: {err}"))?;
    Ok(rendered)
}
