//! Interactive terminal setup wizard for `strat_finder` (`nfqws2 --strat-finder`).

/// Filesystem canonicalization when resolving `zapret2/lua` scripts.
use std::fs;
/// Line-buffered input reading and prompt writing traits enabling deterministic offline tests.
use std::io::{BufRead, Write};
/// Path normalization for `~/` expansion and default `nfqws2.toml` paths.
use std::path::{Path, PathBuf};

/// Strategy finder protocol, IP family, and scan level types selected by the wizard.
use crate::tools::strat_catalog::{IpFamily, ProbeProtocol, ScanLevel};

/// Pre-filled defaults passed into [`prompt_interactive_wizard`].
#[derive(Debug, Clone)]
pub struct InteractiveDefaults {
    /// Domains already provided on the command line, if any.
    pub domains: Vec<String>,
    /// Default protocols shown in the prompt.
    pub protos: Vec<ProbeProtocol>,
    /// Default IP families shown in the prompt.
    pub families: Vec<IpFamily>,
    /// Default scan thoroughness level.
    pub level: ScanLevel,
    /// Default `--stop-on-first` choice.
    pub stop_on_first: bool,
    /// Explicit or auto-detected Lua scripts directory shown as default.
    pub lua_dir: Option<PathBuf>,
    /// Explicit `--write-config` path (or `None` to suggest default `~/nfqws2.toml`).
    pub write_config: Option<PathBuf>,
}

/// Resolved options produced by [`prompt_interactive_wizard`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InteractiveSelections {
    /// Normalized target hostnames (guaranteed non-empty).
    pub domains: Vec<String>,
    /// Protocols selected for probing (guaranteed non-empty).
    pub protos: Vec<ProbeProtocol>,
    /// IP families selected (`[V4]`, `[V6]`, or `[V4, V6]`).
    pub families: Vec<IpFamily>,
    /// Selected scan thoroughness level.
    pub level: ScanLevel,
    /// Whether to stop probing each target after the first working strategy.
    pub stop_on_first: bool,
    /// Selected Lua scripts directory, if any.
    pub lua_dir: Option<PathBuf>,
    /// Destination path for generated `nfqws2.toml`, or `None` to skip writing.
    pub write_config: Option<PathBuf>,
}

/// Normalizes a domain token by stripping any URL scheme, path, port, and surrounding whitespace.
pub fn normalize_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let host = no_scheme.split(['/', '?', '#']).next().unwrap_or("").trim();
    let host = host.split(':').next().unwrap_or("").trim().trim_end_matches('.');
    if host.is_empty() { None } else { Some(host.to_ascii_lowercase()) }
}

/// Expands a leading `~` or `~/` path prefix using the `HOME` environment variable.
pub fn expand_tilde(raw: &str) -> PathBuf {
    let trimmed = raw.trim();
    if trimmed == "~" {
        return std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("~"));
    }
    if let Some(rest) = trimmed.strip_prefix("~/")
        && let Some(home) = std::env::var_os("HOME")
    {
        return PathBuf::from(home).join(rest);
    }
    PathBuf::from(trimmed)
}

/// Suggests a default writable `nfqws2.toml` path (`$HOME/nfqws2.toml`, falling back to `./nfqws2.toml`).
pub fn default_output_config_path() -> PathBuf {
    std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("nfqws2.toml"))
        .unwrap_or_else(|| PathBuf::from("nfqws2.toml"))
}

/// Returns candidate directories searched for `zapret-lib.lua` and `zapret-antidpi.lua`.
fn candidate_lua_dirs(explicit_dir: Option<&Path>) -> Vec<PathBuf> {
    if let Some(dir) = explicit_dir {
        return vec![expand_tilde(&dir.to_string_lossy())];
    }
    let mut dirs = vec![PathBuf::from("lua"), PathBuf::from("../zapret2/lua")];
    if let Ok(exe) = std::env::current_exe()
        && let Some(parent) = exe.parent()
    {
        dirs.push(parent.join("lua"));
        if let Some(grand) = parent.parent().and_then(Path::parent) {
            dirs.push(grand.join("../zapret2/lua"));
        }
    }
    dirs.push(PathBuf::from("/opt/zapret2/lua"));
    dirs.push(PathBuf::from("/usr/share/zapret2/lua"));
    dirs
}

/// Auto-detects the first directory containing both `zapret-lib.lua` and `zapret-antidpi.lua`.
pub fn detect_lua_dir(explicit_dir: Option<&Path>) -> Option<PathBuf> {
    candidate_lua_dirs(explicit_dir).into_iter().find(|dir| {
        dir.join("zapret-lib.lua").is_file() && dir.join("zapret-antidpi.lua").is_file()
    })
}

/// Resolves canonical paths to `zapret-lib.lua` and `zapret-antidpi.lua`.
pub fn resolve_lua_scripts(explicit_dir: Option<&Path>) -> Result<Vec<PathBuf>, String> {
    if let Some(dir) = detect_lua_dir(explicit_dir) {
        let lib = dir.join("zapret-lib.lua");
        let anti = dir.join("zapret-antidpi.lua");
        return Ok(vec![
            fs::canonicalize(&lib).unwrap_or(lib),
            fs::canonicalize(&anti).unwrap_or(anti),
        ]);
    }
    let checked = candidate_lua_dirs(explicit_dir)
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "could not locate zapret-lib.lua and zapret-antidpi.lua (checked: {checked}); pass --lua-dir <PATH>"
    ))
}

/// Reads one trimmed line from `reader` after printing `prompt` to `writer`.
fn read_prompt_line<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
) -> Result<String, String> {
    write!(writer, "{prompt}").map_err(|err| format!("failed to write prompt: {err}"))?;
    writer.flush().map_err(|err| format!("failed to flush prompt: {err}"))?;
    let mut line = String::new();
    let n = reader
        .read_line(&mut line)
        .map_err(|err| format!("failed to read input: {err}"))?;
    if n == 0 {
        return Err("interactive input ended unexpectedly (EOF)".to_owned());
    }
    Ok(line.trim().to_owned())
}

/// Parses comma- or space-separated protocol tokens into a deduplicated list.
fn parse_proto_list(raw: &str) -> Result<Vec<ProbeProtocol>, String> {
    let mut out = Vec::new();
    for tok in raw.split(|c: char| c.is_whitespace() || c == ',') {
        if tok.is_empty() {
            continue;
        }
        let p: ProbeProtocol = tok.parse()?;
        if !out.contains(&p) {
            out.push(p);
        }
    }
    if out.is_empty() {
        return Err("please enter at least one protocol (http, tls12, tls13, http3)".to_owned());
    }
    Ok(out)
}

/// Parses an IP version answer (`4`, `6`, `46`, `ipv4`, `ipv6`, `both`).
fn parse_ip_families(raw: &str) -> Result<Vec<IpFamily>, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "4" | "v4" | "ipv4" => Ok(vec![IpFamily::V4]),
        "6" | "v6" | "ipv6" => Ok(vec![IpFamily::V6]),
        "46" | "64" | "both" | "all" => Ok(vec![IpFamily::V4, IpFamily::V6]),
        other => Err(format!("invalid IP version '{other}' (expected 4, 6, or 46)")),
    }
}

/// Parses a yes/no response, returning `default` when `raw` is empty.
fn parse_yes_no(raw: &str, default: bool) -> Result<bool, String> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" => Ok(default),
        "y" | "yes" | "1" | "true" => Ok(true),
        "n" | "no" | "0" | "false" => Ok(false),
        other => Err(format!("invalid answer '{other}' (expected y or n)")),
    }
}

/// Formats `families` compactly as `"4"`, `"6"`, or `"46"`.
fn format_families(families: &[IpFamily]) -> &'static str {
    let v4 = families.contains(&IpFamily::V4);
    let v6 = families.contains(&IpFamily::V6);
    match (v4, v6) {
        (true, true) => "46",
        (false, true) => "6",
        _ => "4",
    }
}

/// Prompts for target domains until at least one valid domain is supplied.
fn prompt_domains<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    default_domains: &[String],
) -> Result<Vec<String>, String> {
    let hint = if default_domains.is_empty() {
        String::new()
    } else {
        format!(" [{}]", default_domains.join(", "))
    };
    loop {
        let line = read_prompt_line(
            reader,
            writer,
            &format!("Target domain(s) (comma/space separated){hint}: "),
        )?;
        if line.is_empty() && !default_domains.is_empty() {
            return Ok(default_domains.to_vec());
        }
        let parsed: Vec<String> = line
            .split(|c: char| c.is_whitespace() || c == ',')
            .filter_map(normalize_domain)
            .collect();
        if !parsed.is_empty() {
            return Ok(parsed);
        }
        let _ = writeln!(writer, "  Please enter at least one domain (e.g., youtube.com).");
    }
}

/// Runs the interactive configuration wizard over `reader` and `writer` using `defaults`.
pub fn prompt_interactive_wizard<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    defaults: &InteractiveDefaults,
) -> Result<InteractiveSelections, String> {
    let _ = writeln!(writer, "\n=== strat_finder interactive setup (press Enter for defaults) ===");

    let domains = prompt_domains(reader, writer, &defaults.domains)?;

    let proto_default: String = defaults
        .protos
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let protos = loop {
        let line = read_prompt_line(
            reader,
            writer,
            &format!("Protocols (http,tls12,tls13,http3) [{proto_default}]: "),
        )?;
        if line.is_empty() {
            break defaults.protos.clone();
        }
        match parse_proto_list(&line) {
            Ok(list) => break list,
            Err(msg) => {
                let _ = writeln!(writer, "  {msg}");
            }
        }
    };

    let fam_default = format_families(&defaults.families);
    let families = loop {
        let line = read_prompt_line(
            reader,
            writer,
            &format!("IP version (4, 6, or 46) [{fam_default}]: "),
        )?;
        if line.is_empty() {
            break defaults.families.clone();
        }
        match parse_ip_families(&line) {
            Ok(list) => break list,
            Err(msg) => {
                let _ = writeln!(writer, "  {msg}");
            }
        }
    };

    let level = loop {
        let line = read_prompt_line(
            reader,
            writer,
            &format!("Scan level (quick, standard, force) [{}]: ", defaults.level),
        )?;
        if line.is_empty() {
            break defaults.level;
        }
        match line.parse::<ScanLevel>() {
            Ok(lvl) => break lvl,
            Err(msg) => {
                let _ = writeln!(writer, "  {msg}");
            }
        }
    };

    let stop_hint = if defaults.stop_on_first { "Y/n" } else { "y/N" };
    let stop_on_first = loop {
        let line = read_prompt_line(
            reader,
            writer,
            &format!("Stop on first working strategy per domain? [{stop_hint}]: "),
        )?;
        match parse_yes_no(&line, defaults.stop_on_first) {
            Ok(val) => break val,
            Err(msg) => {
                let _ = writeln!(writer, "  {msg}");
            }
        }
    };

    let lua_hint = defaults
        .lua_dir
        .as_deref()
        .map(Path::display)
        .map_or_else(|| "auto".to_owned(), |d| d.to_string());
    let lua_line = read_prompt_line(
        reader,
        writer,
        &format!("Lua scripts directory [{lua_hint}]: "),
    )?;
    let lua_dir = if lua_line.is_empty() {
        defaults.lua_dir.clone()
    } else {
        Some(expand_tilde(&lua_line))
    };

    let default_cfg = defaults
        .write_config
        .clone()
        .unwrap_or_else(default_output_config_path);
    let cfg_line = read_prompt_line(
        reader,
        writer,
        &format!("Write nfqws2.toml to path ('none' to skip) [{}]: ", default_cfg.display()),
    )?;
    let write_config = if cfg_line.is_empty() {
        Some(default_cfg)
    } else if matches!(cfg_line.to_ascii_lowercase().as_str(), "none" | "-" | "skip") {
        None
    } else {
        Some(expand_tilde(&cfg_line))
    };

    let _ = writeln!(
        writer,
        "\nStarting scan: domains=[{}], protos=[{}], ip={}, level={}, stop_on_first={}, output={}\n",
        domains.join(", "),
        protos.iter().map(|p| p.as_str()).collect::<Vec<_>>().join(","),
        format_families(&families),
        level,
        stop_on_first,
        write_config.as_deref().map_or_else(|| "none".to_owned(), |p| p.display().to_string()),
    );

    Ok(InteractiveSelections {
        domains,
        protos,
        families,
        level,
        stop_on_first,
        lua_dir,
        write_config,
    })
}
