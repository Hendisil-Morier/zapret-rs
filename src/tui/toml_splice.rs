//! Comment-preserving TOML preamble scalar and section splicing helpers.

/// File path formatting for root `control_socket` / `nfqws2_config` / `lua_dir` scalars.
use std::path::Path;

/// Updates `nfqws2_config`, `lua_dir`, `no_nft`, and `control_socket` in the root TOML preamble.
pub(crate) fn update_root_scalars(
    doc: &str,
    nfqws2_config: &str,
    lua_dir: Option<&str>,
    no_nft: bool,
    control_socket: Option<&Path>,
) -> String
{
    let lines: Vec<&str> = doc.lines().collect();
    let first_hdr = first_header_line(&lines).unwrap_or(lines.len());
    let desired: [(&str, Option<String>); 4] = [
        ("nfqws2_config", (!nfqws2_config.is_empty()).then(|| toml_str(nfqws2_config))),
        ("lua_dir", lua_dir.map(toml_str)),
        ("no_nft", no_nft.then(|| "true".to_owned())),
        ("control_socket", control_socket.map(|p| toml_str(&p.display().to_string()))),
    ];

    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len() + 4);
    let mut seen = [false; 4];
    for &line in &lines[..first_hdr]
    {
        let mut handled = false;
        for (idx, (key, val)) in desired.iter().enumerate()
        {
            if matches_root_assignment(line, key)
            {
                seen[idx] = true;
                handled = true;
                if let Some(rendered_val) = val
                {
                    out_lines.push(format!("{key} = {rendered_val}"));
                }
                break;
            }
        }
        if !handled
        {
            out_lines.push(line.to_owned());
        }
    }
    for (idx, (key, val)) in desired.iter().enumerate()
    {
        if !seen[idx]
            && let Some(rendered_val) = val
        {
            let insert_at =
                out_lines.iter().rposition(|l| !l.trim().is_empty()).map_or(out_lines.len(), |i| i + 1);
            out_lines.insert(insert_at, format!("{key} = {rendered_val}"));
        }
    }
    for &line in &lines[first_hdr..]
    {
        out_lines.push(line.to_owned());
    }
    let mut joined = out_lines.join("\n");
    if doc.ends_with('\n') || !joined.is_empty()
    {
        joined.push('\n');
    }
    joined
}

/// Replaces all `[header]` / `[[header]]` sections matching `pred` with `replacement` in place.
pub(crate) fn replace_sections<F: Fn(&str) -> bool>(doc: &str, pred: F, replacement: Option<&str>) -> String
{
    let lines: Vec<&str> = doc.lines().collect();
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let (mut ml_dq, mut ml_sq) = (false, false);
    let mut active_start: Option<usize> = None;

    for (idx, &line) in lines.iter().enumerate()
    {
        if !ml_dq
            && !ml_sq
            && let Some(hdr) = parse_header_name(line)
        {
            if let Some(start) = active_start.take()
            {
                let end = trim_trailing_header_comments(&lines, start, idx);
                spans.push((start, end));
            }
            if pred(&hdr)
            {
                active_start = Some(idx);
            }
        }
        advance_multiline_state(line, &mut ml_dq, &mut ml_sq);
    }
    if let Some(start) = active_start
    {
        spans.push((start, lines.len()));
    }

    if spans.is_empty()
    {
        let Some(block) = replacement
        else
        {
            return doc.to_owned();
        };
        let mut out = doc.trim_end().to_owned();
        if !out.is_empty()
        {
            out.push_str("\n\n");
        }
        out.push_str(block);
        out.push('\n');
        return out;
    }

    let first_start = spans[0].0;
    let mut out_lines: Vec<String> = Vec::with_capacity(lines.len());
    for (idx, &line) in lines.iter().enumerate()
    {
        if idx == first_start
            && let Some(block) = replacement
        {
            for b_line in block.lines()
            {
                out_lines.push(b_line.to_owned());
            }
        }
        if spans.iter().any(|&(s, e)| idx >= s && idx < e)
        {
            continue;
        }
        out_lines.push(line.to_owned());
    }
    let mut out = out_lines.join("\n");
    while out.contains("\n\n\n")
    {
        out = out.replace("\n\n\n", "\n\n");
    }
    let out = out.trim_end().to_owned();
    if out.is_empty() { String::new() } else { format!("{out}\n") }
}

/// Formats a TOML quoted string literal cleanly using `toml::Value::String`.
fn toml_str(val: &str) -> String
{
    toml::Value::String(val.to_owned()).to_string()
}

/// Returns `true` when `line` assigns top-level scalar `key = ...` outside comments.
fn matches_root_assignment(line: &str, key: &str) -> bool
{
    let trimmed = line.trim_start();
    let Some(rest) = trimmed.strip_prefix(key)
    else
    {
        return false;
    };
    rest.trim_start().starts_with('=')
}

/// Finds the first top-level `[section]` header line index outside multiline TOML strings.
fn first_header_line(lines: &[&str]) -> Option<usize>
{
    let (mut ml_dq, mut ml_sq) = (false, false);
    for (idx, &line) in lines.iter().enumerate()
    {
        if !ml_dq && !ml_sq && parse_header_name(line).is_some()
        {
            return Some(idx);
        }
        advance_multiline_state(line, &mut ml_dq, &mut ml_sq);
    }
    None
}

/// Preserves blank lines and comments attached immediately above the next unrelated section header.
fn trim_trailing_header_comments(lines: &[&str], start: usize, end: usize) -> usize
{
    let mut cur = end;
    while cur > start + 1
    {
        let t = lines[cur - 1].trim();
        if t.is_empty() || t.starts_with('#')
        {
            cur -= 1;
        }
        else
        {
            break;
        }
    }
    cur
}

/// Extracts `[name]` / `[[name]]` header name when `line` starts a TOML table header.
fn parse_header_name(line: &str) -> Option<String>
{
    let trimmed = line.trim_start();
    if !trimmed.starts_with('[')
    {
        return None;
    }
    let inner = if let Some(s) = trimmed.strip_prefix("[[")
    {
        s.split("]]").next()?.trim()
    }
    else
    {
        trimmed.strip_prefix('[')?.split(']').next()?.trim()
    };
    (!inner.is_empty()).then(|| inner.to_owned())
}

/// Tracks unescaped multiline TOML string delimiters across lines.
fn advance_multiline_state(line: &str, ml_dq: &mut bool, ml_sq: &mut bool)
{
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len()
    {
        if *ml_dq
        {
            if bytes[i..].starts_with(b"\"\"\"")
            {
                *ml_dq = false;
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        if *ml_sq
        {
            if bytes[i..].starts_with(b"'''")
            {
                *ml_sq = false;
                i += 3;
                continue;
            }
            i += 1;
            continue;
        }
        match bytes[i]
        {
            b'#' => break,
            b'"' if bytes[i..].starts_with(b"\"\"\"") =>
            {
                *ml_dq = true;
                i += 3;
            }
            b'\'' if bytes[i..].starts_with(b"'''") =>
            {
                *ml_sq = true;
                i += 3;
            }
            _ => i += 1,
        }
    }
}
