//! Configurable `zapret-rs` TUI color themes: built-in vivid presets, hex/named parsing, and TOML I/O.

/// Filesystem loading and `PathBuf` handling for `~/.config/zapret-rs/theme.toml`.
use std::path::PathBuf;

/// `ratatui` 24-bit RGB and standard 16-color terminal palette types.
use ratatui::style::Color;
/// Serde deserialization for user theme override TOML files.
use serde::Deserialize;

/// Config path helper, `~/` expansion, and symlink-safe TOML writer shared across the app.
use crate::tools::{default_output_config_path, expand_tilde, write_config_nofollow};

/// Ordered names of all built-in TUI theme presets selectable with `t` or `--theme`.
pub const PRESET_NAMES: &[&str] = &["neon", "tokyo", "dracula", "gruvbox", "ansi"];

/// Complete 16-slot color palette driving borders, highlights, telemetry badges, and syntax colors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    /// Active preset identifier or `"custom"` when individual slots were overridden.
    pub name: &'static str,
    /// Primary accent color for gauges, protocol tags, and live focus highlights.
    pub accent: Color,
    /// High-contrast cyan accent for focused borders, TOML keys, and active tab highlights.
    pub accent_bright: Color,
    /// Structural panel border color (bright enough to stay clear on translucent dark terminals).
    pub frame: Color,
    /// Informational accent for titles, outgoing direction badges, and config paths.
    pub info: Color,
    /// Success accent for passing statuses and positive log bodies.
    pub ok: Color,
    /// High-contrast green for active running state, `[x]` checkboxes, and TOML strings.
    pub ok_bright: Color,
    /// Warning accent for paused capture, edits, and modified counters.
    pub warn: Color,
    /// High-contrast yellow/gold for `[key]` keycaps, numbers, RTTs, and focus markers.
    pub warn_bright: Color,
    /// Error accent for invalid TOML borders and error log bodies.
    pub err: Color,
    /// High-contrast red/coral for error badges and root UID warnings.
    pub err_bright: Color,
    /// Special accent for desync counters and strategy tags.
    pub special: Color,
    /// High-contrast magenta/pink for profile badges, TOML/`nftables` keywords, and UDP rows.
    pub special_bright: Color,
    /// Primary bright body text color.
    pub text: Color,
    /// Secondary descriptive label color.
    pub subtle: Color,
    /// Dimmed comment, placeholder, and delimiter color (kept legible over dark backgrounds).
    pub muted: Color,
    /// Background highlight color for active table headers and selected list/table rows.
    pub highlight_bg: Color,
}

impl Default for Theme {
    /// Returns the vivid high-contrast `"neon"` preset by default.
    fn default() -> Self {
        Self::neon()
    }
}

impl Theme {
    /// Vivid high-contrast default preset tuned for dark and translucent terminals.
    pub const fn neon() -> Self {
        Self {
            name: "neon",
            accent: Color::Rgb(0, 230, 255),
            accent_bright: Color::Rgb(130, 255, 255),
            frame: Color::Rgb(95, 165, 255),
            info: Color::Rgb(135, 200, 255),
            ok: Color::Rgb(55, 225, 125),
            ok_bright: Color::Rgb(135, 255, 175),
            warn: Color::Rgb(255, 195, 45),
            warn_bright: Color::Rgb(255, 235, 110),
            err: Color::Rgb(255, 90, 110),
            err_bright: Color::Rgb(255, 150, 165),
            special: Color::Rgb(205, 115, 255),
            special_bright: Color::Rgb(250, 155, 255),
            text: Color::Rgb(245, 248, 255),
            subtle: Color::Rgb(195, 210, 235),
            muted: Color::Rgb(135, 155, 195),
            highlight_bg: Color::Rgb(42, 68, 120),
        }
    }

    /// Tokyo Night inspired palette with crisp indigo, teal, coral, and warm amber tones.
    pub const fn tokyo() -> Self {
        Self {
            name: "tokyo",
            accent: Color::Rgb(42, 195, 222),
            accent_bright: Color::Rgb(125, 207, 255),
            frame: Color::Rgb(122, 162, 247),
            info: Color::Rgb(137, 221, 255),
            ok: Color::Rgb(115, 218, 202),
            ok_bright: Color::Rgb(158, 206, 106),
            warn: Color::Rgb(224, 175, 104),
            warn_bright: Color::Rgb(255, 158, 100),
            err: Color::Rgb(247, 118, 142),
            err_bright: Color::Rgb(255, 137, 157),
            special: Color::Rgb(187, 154, 247),
            special_bright: Color::Rgb(215, 175, 255),
            text: Color::Rgb(230, 236, 255),
            subtle: Color::Rgb(176, 186, 224),
            muted: Color::Rgb(126, 138, 180),
            highlight_bg: Color::Rgb(46, 60, 100),
        }
    }

    /// Dracula palette featuring saturated purple, pink, cyan, and lime highlights.
    pub const fn dracula() -> Self {
        Self {
            name: "dracula",
            accent: Color::Rgb(139, 233, 253),
            accent_bright: Color::Rgb(180, 250, 255),
            frame: Color::Rgb(189, 147, 249),
            info: Color::Rgb(139, 233, 253),
            ok: Color::Rgb(80, 250, 123),
            ok_bright: Color::Rgb(145, 255, 170),
            warn: Color::Rgb(255, 184, 108),
            warn_bright: Color::Rgb(241, 250, 140),
            err: Color::Rgb(255, 85, 85),
            err_bright: Color::Rgb(255, 121, 198),
            special: Color::Rgb(189, 147, 249),
            special_bright: Color::Rgb(255, 121, 198),
            text: Color::Rgb(248, 248, 242),
            subtle: Color::Rgb(205, 212, 232),
            muted: Color::Rgb(139, 150, 189),
            highlight_bg: Color::Rgb(68, 71, 90),
        }
    }

    /// Warm Gruvbox Bright palette with retro orange, aqua, olive green, and gold accents.
    pub const fn gruvbox() -> Self {
        Self {
            name: "gruvbox",
            accent: Color::Rgb(142, 192, 124),
            accent_bright: Color::Rgb(184, 233, 148),
            frame: Color::Rgb(131, 165, 152),
            info: Color::Rgb(254, 128, 25),
            ok: Color::Rgb(152, 187, 38),
            ok_bright: Color::Rgb(184, 219, 60),
            warn: Color::Rgb(250, 189, 47),
            warn_bright: Color::Rgb(255, 216, 102),
            err: Color::Rgb(251, 73, 52),
            err_bright: Color::Rgb(255, 118, 102),
            special: Color::Rgb(211, 134, 155),
            special_bright: Color::Rgb(244, 164, 192),
            text: Color::Rgb(251, 241, 199),
            subtle: Color::Rgb(235, 219, 178),
            muted: Color::Rgb(168, 153, 132),
            highlight_bg: Color::Rgb(80, 73, 69),
        }
    }

    /// Classic 16-color bright ANSI palette for minimal terminals without truecolor support.
    pub const fn ansi() -> Self {
        Self {
            name: "ansi",
            accent: Color::Cyan,
            accent_bright: Color::LightCyan,
            frame: Color::LightBlue,
            info: Color::LightBlue,
            ok: Color::Green,
            ok_bright: Color::LightGreen,
            warn: Color::Yellow,
            warn_bright: Color::LightYellow,
            err: Color::Red,
            err_bright: Color::LightRed,
            special: Color::Magenta,
            special_bright: Color::LightMagenta,
            text: Color::White,
            subtle: Color::Gray,
            muted: Color::Gray,
            highlight_bg: Color::DarkGray,
        }
    }

    /// Looks up a built-in preset by case-insensitive name.
    pub fn from_preset(name: &str) -> Option<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "neon" => Some(Self::neon()),
            "tokyo" | "tokyonight" | "tokyo-night" => Some(Self::tokyo()),
            "dracula" => Some(Self::dracula()),
            "gruvbox" => Some(Self::gruvbox()),
            "ansi" => Some(Self::ansi()),
            _ => None,
        }
    }

    /// Cycles cleanly to the next built-in preset after `self.name`.
    pub fn next_preset(self) -> Self {
        let idx = PRESET_NAMES.iter().position(|&n| n == self.name).unwrap_or(PRESET_NAMES.len() - 1);
        let next = PRESET_NAMES[(idx + 1) % PRESET_NAMES.len()];
        Self::from_preset(next).unwrap_or_else(Self::neon)
    }

    /// Parses a TOML theme configuration string, starting from `preset` (or `neon`) and applying overrides.
    pub fn from_toml_str(input: &str) -> Result<Self, String> {
        let raw: RawThemeFile = toml::from_str(input).map_err(|err| format!("invalid theme.toml: {err}"))?;
        let mut theme = match raw.preset.as_deref() {
            Some(name) => Self::from_preset(name)
                .ok_or_else(|| format!("unknown theme preset '{name}' (expected one of: {})", PRESET_NAMES.join(", ")))?,
            None => Self::neon(),
        };
        let mut overridden = false;
        for (slot, val) in [
            (&mut theme.accent, raw.accent.as_deref()), (&mut theme.accent_bright, raw.accent_bright.as_deref()),
            (&mut theme.frame, raw.frame.as_deref()), (&mut theme.info, raw.info.as_deref()),
            (&mut theme.ok, raw.ok.as_deref()), (&mut theme.ok_bright, raw.ok_bright.as_deref()),
            (&mut theme.warn, raw.warn.as_deref()), (&mut theme.warn_bright, raw.warn_bright.as_deref()),
            (&mut theme.err, raw.err.as_deref()), (&mut theme.err_bright, raw.err_bright.as_deref()),
            (&mut theme.special, raw.special.as_deref()), (&mut theme.special_bright, raw.special_bright.as_deref()),
            (&mut theme.text, raw.text.as_deref()), (&mut theme.subtle, raw.subtle.as_deref()),
            (&mut theme.muted, raw.muted.as_deref()), (&mut theme.highlight_bg, raw.highlight_bg.as_deref()),
        ] {
            if let Some(spec) = val {
                *slot = parse_color(spec)?;
                overridden = true;
            }
        }
        if overridden {
            theme.name = "custom";
        }
        Ok(theme)
    }

    /// Serializes all active palette slots into a commented `theme.toml` template.
    pub fn to_toml(&self) -> String {
        let base = if self.name == "custom" { "neon" } else { self.name };
        format!(
            "# zapret-rs TUI color theme (~/.config/zapret-rs/theme.toml)\n\
             # Presets: neon, tokyo, dracula, gruvbox, ansi\n\
             # Any key below overrides the preset using #RRGGBB hex or named terminal colors.\n\
             preset = \"{base}\"\n\
             accent = \"{}\"\n\
             accent_bright = \"{}\"\n\
             frame = \"{}\"\n\
             info = \"{}\"\n\
             ok = \"{}\"\n\
             ok_bright = \"{}\"\n\
             warn = \"{}\"\n\
             warn_bright = \"{}\"\n\
             err = \"{}\"\n\
             err_bright = \"{}\"\n\
             special = \"{}\"\n\
             special_bright = \"{}\"\n\
             text = \"{}\"\n\
             subtle = \"{}\"\n\
             muted = \"{}\"\n\
             highlight_bg = \"{}\"\n",
            format_color(self.accent),
            format_color(self.accent_bright),
            format_color(self.frame),
            format_color(self.info),
            format_color(self.ok),
            format_color(self.ok_bright),
            format_color(self.warn),
            format_color(self.warn_bright),
            format_color(self.err),
            format_color(self.err_bright),
            format_color(self.special),
            format_color(self.special_bright),
            format_color(self.text),
            format_color(self.subtle),
            format_color(self.muted),
            format_color(self.highlight_bg),
        )
    }
}

/// Raw TOML schema accepted from `~/.config/zapret-rs/theme.toml` or `--theme <file>`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawThemeFile {
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
    ("black", Color::Black), ("red", Color::Red), ("green", Color::Green),
    ("yellow", Color::Yellow), ("blue", Color::Blue), ("magenta", Color::Magenta),
    ("cyan", Color::Cyan), ("gray", Color::Gray), ("dark-gray", Color::DarkGray),
    ("light-red", Color::LightRed), ("light-green", Color::LightGreen),
    ("light-yellow", Color::LightYellow), ("light-blue", Color::LightBlue),
    ("light-magenta", Color::LightMagenta), ("light-cyan", Color::LightCyan),
    ("white", Color::White),
];

/// Parses `#RRGGBB` / `RRGGBB` hex colors or standard ANSI color names into a [`Color`].
pub fn parse_color(spec: &str) -> Result<Color, String> {
    let trimmed = spec.trim();
    let hex = trimmed.strip_prefix('#').unwrap_or(trimmed);
    if hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        let r = u8::from_str_radix(&hex[0..2], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        let g = u8::from_str_radix(&hex[2..4], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        let b = u8::from_str_radix(&hex[4..6], 16).map_err(|_| format!("invalid hex color '{spec}'"))?;
        return Ok(Color::Rgb(r, g, b));
    }
    let norm = trimmed.to_ascii_lowercase().replace('_', "-");
    let canonical = match norm.as_str() {
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
pub fn format_color(color: Color) -> String {
    if let Color::Rgb(r, g, b) = color {
        return format!("#{r:02x}{g:02x}{b:02x}");
    }
    NAMED_COLORS
        .iter()
        .find_map(|&(name, col)| (col == color).then(|| name.to_owned()))
        .unwrap_or_else(|| "#ffffff".to_owned())
}

/// Returns the default user theme config path (`~/.config/zapret-rs/theme.toml`).
pub fn default_theme_config_path() -> PathBuf {
    default_output_config_path().with_file_name("theme.toml")
}

/// Resolves startup [`Theme`] from `--theme <preset|path>` or `~/.config/zapret-rs/theme.toml`.
///
/// Returns `(theme, optional_warning)` without aborting startup on malformed custom files.
pub fn resolve_theme(cli_spec: Option<&str>) -> (Theme, Option<String>) {
    if let Some(spec) = cli_spec.map(str::trim).filter(|s| !s.is_empty()) {
        if let Some(preset) = Theme::from_preset(spec) {
            return (preset, None);
        }
        let path = expand_tilde(spec);
        return match std::fs::read_to_string(&path) {
            Ok(text) => match Theme::from_toml_str(&text) {
                Ok(t) => (t, None),
                Err(err) => (Theme::neon(), Some(format!("Theme {} error: {err}", path.display()))),
            },
            Err(err) => (
                Theme::neon(),
                Some(format!("Unknown theme or unreadable file {}: {err}", path.display())),
            ),
        };
    }
    let path = default_theme_config_path();
    let Ok(text) = std::fs::read_to_string(&path) else {
        return (Theme::neon(), None);
    };
    match Theme::from_toml_str(&text) {
        Ok(t) => (t, None),
        Err(err) => (Theme::neon(), Some(format!("Theme {} error: {err}", path.display()))),
    }
}

/// Saves `theme` to `~/.config/zapret-rs/theme.toml` without following symlinks.
pub fn save_theme_to_default_path(theme: &Theme) -> Result<PathBuf, String> {
    let path = default_theme_config_path();
    write_config_nofollow(&path, &theme.to_toml()).map_err(|err| err.to_string())?;
    Ok(path)
}
