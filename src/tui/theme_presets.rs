//! Built-in `zapret-rs` TUI color theme struct and vivid palette presets.

/// `ratatui` 24-bit RGB and standard 16-color terminal palette types.
use ratatui::style::Color;

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
}
