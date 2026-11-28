//! Keybinding primitive parsing, matching, and multi-key TOML representation.

/// Ordered formatter primitives for serialization into TOML strings and arrays.
use std::fmt;

/// Keyboard key codes and modifier bitmasks matched against terminal input events.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// Custom TOML serde support accepting either a single key string or an array of key strings.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// Single keyboard binding pairing a [`KeyCode`] with optional `Ctrl`/`Alt`/`Shift` modifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBind
{
    /// Target key code matched against incoming terminal key events.
    pub code: KeyCode,
    /// Modifier bitmask required alongside `code` (`CONTROL`, `ALT`, or `SHIFT`).
    pub modifiers: KeyModifiers,
}

impl KeyBind
{
    /// Parses a key specification string such as `"q"`, `"H"`, `"Ctrl+c"`, `"Shift+Tab"`, or `"Del"`.
    pub fn parse(spec: &str) -> Result<Self, String>
    {
        let trimmed = spec.trim();
        if trimmed.is_empty()
        {
            return Err("keybinding cannot be empty".to_owned());
        }
        let mut modifiers = KeyModifiers::NONE;
        let mut rest = trimmed;
        while let Some(pos) = rest.find('+')
        {
            let prefix = rest[..pos].trim();
            if prefix.is_empty()
            {
                break;
            }
            match prefix.to_ascii_lowercase().as_str()
            {
                "ctrl" | "control" | "c" => modifiers |= KeyModifiers::CONTROL,
                "alt" | "meta" | "m" => modifiers |= KeyModifiers::ALT,
                "shift" | "s" => modifiers |= KeyModifiers::SHIFT,
                other => return Err(format!("unknown key modifier '{other}' in '{spec}'")),
            }
            rest = rest[pos + 1..].trim_start();
        }
        let key_token = rest.trim();
        let code =
            parse_key_token(key_token).ok_or_else(|| format!("unknown key '{key_token}' in '{spec}'"))?;
        if matches!(code, KeyCode::Tab) && modifiers.contains(KeyModifiers::SHIFT)
        {
            return Ok(Self { code: KeyCode::BackTab, modifiers: KeyModifiers::NONE });
        }
        Ok(Self { code, modifiers })
    }

    /// Returns `true` when `event` matches this binding.
    ///
    /// Printable characters compare their exact character value without failing when a terminal
    /// reports `SHIFT` alongside uppercase letters (`'H'`, `'?'`, etc.), whereas `BackTab` matches
    /// both `KeyCode::BackTab` and `Shift+Tab`.
    pub fn matches(self, event: KeyEvent) -> bool
    {
        if self.code == KeyCode::BackTab
        {
            let clean = !event.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
            return clean
                && (event.code == KeyCode::BackTab
                    || (event.code == KeyCode::Tab && event.modifiers.contains(KeyModifiers::SHIFT)));
        }
        let ctrl_match =
            event.modifiers.contains(KeyModifiers::CONTROL) == self.modifiers.contains(KeyModifiers::CONTROL);
        let alt_match =
            event.modifiers.contains(KeyModifiers::ALT) == self.modifiers.contains(KeyModifiers::ALT);
        if !ctrl_match || !alt_match
        {
            return false;
        }
        match (self.code, event.code)
        {
            (KeyCode::Char(expected), KeyCode::Char(actual)) =>
            {
                if self.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                {
                    expected.eq_ignore_ascii_case(&actual)
                }
                else
                {
                    expected == actual
                }
            }
            (expected, actual) => expected == actual,
        }
    }

    /// Formats this binding back into a readable keycap label (for example `"Shift+Tab"` or `"Del"`).
    pub fn format_label(self) -> String
    {
        if self.code == KeyCode::BackTab
        {
            return "Shift+Tab".to_owned();
        }
        let mut out = String::new();
        if self.modifiers.contains(KeyModifiers::CONTROL)
        {
            out.push_str("Ctrl+");
        }
        if self.modifiers.contains(KeyModifiers::ALT)
        {
            out.push_str("Alt+");
        }
        if self.modifiers.contains(KeyModifiers::SHIFT)
        {
            out.push_str("Shift+");
        }
        out.push_str(&format_key_code(self.code));
        out
    }
}

/// Collection of equivalent [`KeyBind`] alternatives bound to one TUI action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyList(pub Vec<KeyBind>);

impl KeyList
{
    /// Builds a [`KeyList`] from canonical key specification strings (ignoring invalid entries only if unreachable).
    pub(crate) fn from_specs(specs: &[&str]) -> Self
    {
        Self(specs.iter().filter_map(|s| KeyBind::parse(s).ok()).collect())
    }

    /// Returns `true` when any configured key in this list matches `event`.
    pub fn contains(&self, event: KeyEvent) -> bool
    {
        self.0.iter().any(|k| k.matches(event))
    }

    /// Formats all bound keys separated by `'/'` (`"unbound"` when empty).
    pub fn joined_label(&self) -> String
    {
        if self.0.is_empty()
        {
            return "unbound".to_owned();
        }
        self.0.iter().map(|k| k.format_label()).collect::<Vec<_>>().join("/")
    }

    /// Returns only the primary (first) key label, or `"unbound"` when empty.
    pub fn primary_label(&self) -> String
    {
        self.0.first().map_or_else(|| "unbound".to_owned(), |k| k.format_label())
    }

    /// Formats distinct labels from `self` followed by `other`, joined with `'/'`.
    pub fn combine_labels(&self, other: &Self) -> String
    {
        let mut labels: Vec<String> = Vec::new();
        for kb in self.0.iter().chain(other.0.iter())
        {
            let lbl = kb.format_label();
            if !labels.contains(&lbl)
            {
                labels.push(lbl);
            }
        }
        if labels.is_empty() { "unbound".to_owned() } else { labels.join("/") }
    }
}

impl Serialize for KeyList
{
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error>
    {
        if self.0.len() == 1
        {
            serializer.serialize_str(&self.0[0].format_label())
        }
        else
        {
            let items: Vec<String> = self.0.iter().map(|k| k.format_label()).collect();
            items.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for KeyList
{
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        /// Visitor accepting either a single key spec string or a TOML array of key spec strings.
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum OneOrMany
        {
            /// Single key string (`quit = "q"`).
            One(String),
            /// Multiple equivalent keys (`up = ["Up", "k"]`).
            Many(Vec<String>),
        }
        let parsed = match OneOrMany::deserialize(deserializer)?
        {
            OneOrMany::One(single) => vec![KeyBind::parse(&single).map_err(de::Error::custom)?],
            OneOrMany::Many(many) => many
                .iter()
                .map(|item| KeyBind::parse(item).map_err(de::Error::custom))
                .collect::<Result<Vec<_>, _>>()?,
        };
        Ok(Self(parsed))
    }
}

impl fmt::Display for KeyList
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result
    {
        f.write_str(&self.joined_label())
    }
}

/// Resolves a key name token or single printable Unicode scalar into a [`KeyCode`].
fn parse_key_token(token: &str) -> Option<KeyCode>
{
    if token.chars().count() == 1
    {
        let ch = token.chars().next()?;
        return Some(if ch == ' ' { KeyCode::Char(' ') } else { KeyCode::Char(ch) });
    }
    let lower = token.to_ascii_lowercase();
    if let Some(num) = lower.strip_prefix('f').and_then(|s| s.parse::<u8>().ok())
        && (1..=12).contains(&num)
    {
        return Some(KeyCode::F(num));
    }
    Some(match lower.as_str()
    {
        "space" => KeyCode::Char(' '),
        "enter" | "return" | "cr" => KeyCode::Enter,
        "esc" | "escape" => KeyCode::Esc,
        "tab" => KeyCode::Tab,
        "backtab" => KeyCode::BackTab,
        "backspace" | "bs" => KeyCode::Backspace,
        "del" | "delete" => KeyCode::Delete,
        "up" => KeyCode::Up,
        "down" => KeyCode::Down,
        "left" => KeyCode::Left,
        "right" => KeyCode::Right,
        "pgup" | "pageup" | "page_up" => KeyCode::PageUp,
        "pgdn" | "pagedown" | "page_down" => KeyCode::PageDown,
        "home" => KeyCode::Home,
        "end" => KeyCode::End,
        _ => return None,
    })
}

/// Converts a [`KeyCode`] back into its canonical config/hint string representation.
fn format_key_code(code: KeyCode) -> String
{
    match code
    {
        KeyCode::Char(' ') => "Space".to_owned(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Enter => "Enter".to_owned(),
        KeyCode::Esc => "Esc".to_owned(),
        KeyCode::Tab => "Tab".to_owned(),
        KeyCode::BackTab => "Shift+Tab".to_owned(),
        KeyCode::Backspace => "Backspace".to_owned(),
        KeyCode::Delete => "Del".to_owned(),
        KeyCode::Up => "Up".to_owned(),
        KeyCode::Down => "Down".to_owned(),
        KeyCode::Left => "Left".to_owned(),
        KeyCode::Right => "Right".to_owned(),
        KeyCode::PageUp => "PgUp".to_owned(),
        KeyCode::PageDown => "PgDn".to_owned(),
        KeyCode::Home => "Home".to_owned(),
        KeyCode::End => "End".to_owned(),
        KeyCode::F(n) => format!("F{n}"),
        other => format!("{other:?}"),
    }
}
