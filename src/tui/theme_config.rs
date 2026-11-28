//! Configurable `zapret-rs` TUI color themes: hex/named parsing and `--theme` resolution.

/// `ratatui` 24-bit RGB and standard 16-color terminal palette types.
use ratatui::style::Color;
/// Deserialization for user theme override TOML files (`theme.toml` fragments and `[theme]`).
use serde::Deserialize;

/// `~/` path expansion helper for explicit `--theme <path>` files.
use crate::tools::expand_tilde;

/// Re-exported palette struct and preset catalog so existing `theme_config` callers stay intact.
pub use crate::tui::theme_presets::{PRESET_NAMES, Theme};

impl Theme
{
    /// Parses a TOML theme configuration string, starting from `preset` (or `neon`) and applying overrides.
    pub fn from_toml_str(input: &str) -> Result<Self, String>
    {
        let raw: RawThemeFile = toml::from_str(input).map_err(|err| format!("invalid theme.toml: {err}"))?;
        Self::from_raw(&raw)
    }

    /// Builds a [`Theme`] from a parsed [`RawThemeFile`] override block.
    pub(crate) fn from_raw(raw: &RawThemeFile) -> Result<Self, String>
    {
        let mut theme = match raw
            .preset
            .as_deref()
        {
            Some(name) => Self::from_preset(name).ok_or_else(|| {
                format!("unknown theme preset '{name}' (expected one of: {})", PRESET_NAMES.join(", "))
            })?,
            None => Self::neon(),
        };
        let mut overridden = false;
        for (slot, val) in [
            (
                &mut theme.accent,
                raw.accent
                    .as_deref(),
            ),
            (
                &mut theme.accent_bright,
                raw.accent_bright
                    .as_deref(),
            ),
            (
                &mut theme.frame,
                raw.frame
                    .as_deref(),
            ),
            (
                &mut theme.info,
                raw.info
                    .as_deref(),
            ),
            (
                &mut theme.ok,
                raw.ok
                    .as_deref(),
            ),
            (
                &mut theme.ok_bright,
                raw.ok_bright
                    .as_deref(),
            ),
            (
                &mut theme.warn,
                raw.warn
                    .as_deref(),
            ),
            (
                &mut theme.warn_bright,
                raw.warn_bright
                    .as_deref(),
            ),
            (
                &mut theme.err,
                raw.err
                    .as_deref(),
            ),
            (
                &mut theme.err_bright,
                raw.err_bright
                    .as_deref(),
            ),
            (
                &mut theme.special,
                raw.special
                    .as_deref(),
            ),
            (
                &mut theme.special_bright,
                raw.special_bright
                    .as_deref(),
            ),
            (
                &mut theme.text,
                raw.text
                    .as_deref(),
            ),
            (
                &mut theme.subtle,
                raw.subtle
                    .as_deref(),
            ),
            (
                &mut theme.muted,
                raw.muted
                    .as_deref(),
            ),
            (
                &mut theme.highlight_bg,
                raw.highlight_bg
                    .as_deref(),
            ),
        ]
        {
            if let Some(spec) = val
            {
                *slot = parse_color(spec)?;
                overridden = true;
            }
        }
        if overridden
        {
            theme.name = "custom";
        }
        Ok(theme)
    }
}

/// Raw TOML schema accepted from imported `theme.toml` fragments, `[theme]` in `config.toml`, or `--theme`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RawThemeFile
{
    /// Optional base preset name (`neon`, `tokyo`, `dracula`, `gruvbox`, `ansi`).
    preset: Option<String>,
    /// Override for primary accent.
    accent: Option<String>,
    /// Override for bright accent.
    accent_bright: Option<String>,
    /// Override for panel border color.
    frame: Option<String>,
    /// Override for informational label color.
    info: Option<String>,
    /// Override for success accent.
    ok: Option<String>,
    /// Override for bright success accent.
    ok_bright: Option<String>,
    /// Override for warning accent.
    warn: Option<String>,
    /// Override for bright warning/keycap accent.
    warn_bright: Option<String>,
    /// Override for error accent.
    err: Option<String>,
    /// Override for bright error accent.
    err_bright: Option<String>,
    /// Override for special/desync accent.
    special: Option<String>,
    /// Override for bright magenta/profile accent.
    special_bright: Option<String>,
    /// Override for primary body text.
    text: Option<String>,
    /// Override for secondary labels.
    subtle: Option<String>,
    /// Override for dimmed text and comments.
    muted: Option<String>,
    /// Override for active header/row highlight background.
    highlight_bg: Option<String>,
}

/// Canonical ANSI color names mapped cleanly for both parsing and serialization.
const NAMED_COLORS: &[(&str, Color)] = &[
    ("black", Color::Black),
    ("red", Color::Red),
    ("green", Color::Green),
    ("yellow", Color::Yellow),
    ("blue", Color::Blue),
    ("magenta", Color::Magenta),
    ("cyan", Color::Cyan),
    ("gray", Color::Gray),
    ("dark-gray", Color::DarkGray),
    ("light-red", Color::LightRed),
    ("light-green", Color::LightGreen),
    ("light-yellow", Color::LightYellow),
    ("light-blue", Color::LightBlue),
    ("light-magenta", Color::LightMagenta),
    ("light-cyan", Color::LightCyan),
    ("white", Color::White),
];

/// Parses `#RRGGBB` / `RRGGBB` hex colors or standard ANSI color names into a [`Color`].
pub fn parse_color(spec: &str) -> Result<Color, String>
{
    let trimmed = spec.trim();
    let hex = trimmed
        .strip_prefix('#')
        .unwrap_or(trimmed);
    if hex.len() == 6
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        return Ok(Color::Rgb(r, g, b));
    }
    let norm = trimmed
        .to_ascii_lowercase()
        .replace('_', "-");
    let canonical = match norm.as_str()
    {
        "grey" => "gray",
        "dark-grey" => "dark-gray",
        other => other,
    };
    NAMED_COLORS
        .iter()
        .find_map(|&(name, col)| (name == canonical).then_some(col))
        .ok_or_else(|| format!("invalid color '{spec}' (use #RRGGBB hex or ANSI color name)"))
}

/// Formats a [`Color`] back into a `#RRGGBB` hex string or canonical ANSI name.
pub fn format_color(color: Color) -> String
{
    if let Color::Rgb(r, g, b) = color
    {
        return format!("#{r:02x}{g:02x}{b:02x}");
    }
    NAMED_COLORS
        .iter()
        .find_map(|&(name, col)| (col == color).then(|| name.to_owned()))
        .unwrap_or_else(|| "#ffffff".to_owned())
}

/// Resolves a CLI `--theme <preset|path>` override into a [`Theme`].
///
/// Returns `(theme, optional_warning)` without aborting startup on malformed custom files.
pub fn resolve_theme(cli_spec: &str) -> (Theme, Option<String>)
{
    let spec = cli_spec.trim();
    if spec.is_empty()
    {
        return (Theme::neon(), None);
    }
    if let Some(preset) = Theme::from_preset(spec)
    {
        return (preset, None);
    }
    let path = expand_tilde(spec);
    match std::fs::read_to_string(&path)
    {
        Ok(text) => match Theme::from_toml_str(&text)
        {
            Ok(t) => (t, None),
            Err(err) => (Theme::neon(), Some(format!("Theme {} error: {err}", path.display()))),
        },
        Err(err) =>
        {
            (Theme::neon(), Some(format!("Unknown theme or unreadable file {}: {err}", path.display())))
        }
    }
}
