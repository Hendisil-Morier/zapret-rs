//! Repository structural hygiene checks enforced on every `cargo nextest` run.

/// OS file name comparison when locating `mod.rs` facades under `src/`.
use std::ffi::OsStr;
/// Filesystem directory traversal and UTF-8 source file reading.
use std::fs;
/// Path normalization for computing repository-relative file paths.
use std::path::{Path, PathBuf};

/// Maximum logical code lines (excluding blanks, comments, and lone `{`/`}` lines) under `src/`.
const MAX_SRC_CODE_LINES: usize = 450;
/// Maximum logical code lines allowed for integration test files under `tests/`.
const MAX_TEST_CODE_LINES: usize = 500;

/// Binary payloads exempted from `MAX_SRC_CODE_LINES`.
const DECLARATIVE_EXEMPTIONS: &[(&str, &str)] =
    &[("src/config/blobs.rs", "static built-in FakeTLS/FakeQUIC binary payloads")];

/// Forbidden inline-test or panic-prone macros/calls inside `src/`.
const FORBIDDEN_IN_SRC: &[&str] = &["#[cfg(test)]", "#[test]", ".unwrap(", ".expect("];

/// Recursively collects sorted `.rs` file paths under `dir`.
fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>)
{
    let Ok(entries) = fs::read_dir(dir)
    else
    {
        panic!("failed to read directory {}", dir.display());
    };
    let mut paths: Vec<PathBuf> = entries.map(|res| res.expect("readable dir entry").path()).collect();
    paths.sort();

    for path in paths
    {
        if path.is_dir()
        {
            collect_rs_files(&path, out);
        }
        else if path.extension() == Some(OsStr::new("rs"))
        {
            out.push(path);
        }
    }
}

/// Converts `path` inside `root` into a forward-slash repository-relative string.
fn rel_path(root: &Path, path: &Path) -> String
{
    path.strip_prefix(root)
        .expect("path must live inside CARGO_MANIFEST_DIR")
        .to_string_lossy()
        .replace('\\', "/")
}

/// Counts non-empty lines excluding `//` comments and standalone Allman `{` / `}` lines.
fn count_logical_lines(content: &str) -> usize
{
    content
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("//") && *line != "{" && *line != "}" && *line != "};"
        })
        .count()
}

/// Checks one source directory against `limit`, appending formatted violations to `violations`.
fn check_line_limits(
    root: &Path,
    subdir: &str,
    limit: usize,
    exemptions: &[(&str, &str)],
    violations: &mut Vec<String>,
)
{
    let mut files = Vec::new();
    collect_rs_files(&root.join(subdir), &mut files);

    for path in files
    {
        let rel = rel_path(root, &path);
        if exemptions.iter().any(|&(exempt, _)| exempt == rel)
        {
            continue;
        }
        let content = fs::read_to_string(&path).expect("UTF-8 Rust source file");
        let lines = count_logical_lines(&content);
        if lines > limit
        {
            violations.push(format!("{rel}: {lines} code lines (limit {limit})"));
        }
    }
}

/// Enforces logical line-count thresholds across `src/` (`<= 450`) and `tests/` (`<= 500`).
#[test]
fn no_monolithic_rust_files()
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));

    for &(rel, reason) in DECLARATIVE_EXEMPTIONS
    {
        assert!(root.join(rel).is_file(), "stale declarative exemption '{rel}' ({reason}) no longer exists");
    }

    let mut violations = Vec::new();
    check_line_limits(root, "src", MAX_SRC_CODE_LINES, DECLARATIVE_EXEMPTIONS, &mut violations);
    check_line_limits(root, "tests", MAX_TEST_CODE_LINES, DECLARATIVE_EXEMPTIONS, &mut violations);

    assert!(
        violations.is_empty(),
        "monolithic Rust file(s) exceeded logical code line limits:\n{}",
        violations.join("\n")
    );
}

/// Verifies every `src/**/mod.rs` contains only `pub mod` declarations, `pub use` re-exports, and comments.
#[test]
fn mod_rs_files_are_pure_facades()
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut src_files = Vec::new();
    collect_rs_files(&root.join("src"), &mut src_files);

    let mut violations = Vec::new();
    for path in src_files
    {
        if path.file_name() != Some(OsStr::new("mod.rs"))
        {
            continue;
        }
        let rel = rel_path(root, &path);
        let content = fs::read_to_string(&path).expect("UTF-8 mod.rs file");
        let mut in_pub_use = false;

        for (idx, raw_line) in content.lines().enumerate()
        {
            let trimmed = raw_line.trim();
            if trimmed.is_empty()
                || trimmed.starts_with("//")
                || (trimmed.starts_with("#[cfg(") && trimmed.ends_with(']'))
            {
                continue;
            }
            if in_pub_use
            {
                if trimmed.ends_with(';')
                {
                    in_pub_use = false;
                }
                continue;
            }
            if (trimmed.starts_with("pub mod ")
                || trimmed.starts_with("pub(crate) mod ")
                || trimmed.starts_with("mod "))
                && trimmed.ends_with(';')
            {
                continue;
            }
            if trimmed.starts_with("pub use ")
            {
                if !trimmed.ends_with(';')
                {
                    in_pub_use = true;
                }
                continue;
            }
            violations.push(format!("{rel}:{}: disallowed item `{trimmed}` inside mod.rs facade", idx + 1));
        }
        if in_pub_use
        {
            violations.push(format!("{rel}: unclosed multi-line `pub use` statement"));
        }
    }

    assert!(
        violations.is_empty(),
        "mod.rs files must contain only `pub mod` and `pub use`:\n{}",
        violations.join("\n")
    );
}

/// Verifies `src/` contains zero inline test modules/functions and zero `.unwrap()` or `.expect()` calls.
#[test]
fn src_contains_no_inline_tests_or_unwrap_expect()
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut src_files = Vec::new();
    collect_rs_files(&root.join("src"), &mut src_files);

    let mut violations = Vec::new();
    for path in src_files
    {
        let rel = rel_path(root, &path);
        let content = fs::read_to_string(&path).expect("UTF-8 Rust source file");
        for (idx, raw_line) in content.lines().enumerate()
        {
            let code = raw_line.split("//").next().unwrap_or("");
            for token in FORBIDDEN_IN_SRC
            {
                if code.contains(token)
                {
                    violations.push(format!("{rel}:{}: forbidden `{token}`", idx + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "forbidden inline test or panic-prone construct(s) found under src/:\n{}",
        violations.join("\n")
    );
}

/// Ensures tab panel renderers do not duplicate keybind bars (keybindings belong in `[?] Keys`).
#[test]
fn no_inline_keybind_bars_in_tab_panels()
{
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let checked = [
        "src/tui/render_config.rs",
        "src/tui/render_status.rs",
        "src/tui/render_hostlist.rs",
        "src/tui/render_settings.rs",
        "src/tui/inspect_ui.rs",
    ];
    let mut violations = Vec::new();
    for rel in checked
    {
        let content = fs::read_to_string(root.join(rel)).expect("UTF-8 Rust source file");
        for (idx, line) in content.lines().enumerate()
        {
            let code = line.split("//").next().unwrap_or("");
            if code.contains("styled_key_hints(") || code.contains("styled_key_hints_owned(")
            {
                violations
                    .push(format!("{rel}:{}: inline styled_key_hints rendering inside tab panel", idx + 1));
            }
        }
    }
    assert!(
        violations.is_empty(),
        "tab panels must not render inline keybind rows:\n{}",
        violations.join("\n")
    );
}
