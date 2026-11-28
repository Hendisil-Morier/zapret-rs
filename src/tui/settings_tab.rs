//! Tab 7 (`Settings`) interactive `config.toml`, theme preset, and live keybinding manager.

/// Keyboard events, codes, and modifiers captured during live keybind remapping.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

/// `nfqws2.toml` default path, Lua directory auto-detection, and `~/` path helper.
use crate::tools::{default_output_config_path, detect_lua_dir, expand_tilde};
/// Complete remappable keybinding table updated live from Tab 7.
use crate::tui::keybind_schema::Keybinds;
/// Single key binding chord constructed from live terminal [`KeyEvent`] capture.
use crate::tui::keybind_spec::{KeyBind, KeyList};
/// Top-level mutable TUI state updated by Tab 7 interactions.
use crate::tui::state::AppState;
/// Side-effect actions, inline text editing, and clamped cursor-stepping helpers for Tab 7.
use crate::tui::types::{AppAction, TextInputOutcome, handle_inline_text_key, step_selection};

/// Focused column on Tab 7 (`Settings`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsFocus
{
    /// Left column listing `config.toml` scalar options and Theme preset.
    #[default]
    Options,
    /// Right scrollable keybindings table (`Scope.Action` -> `Keys`).
    Keybinds,
}

/// Option row selectable inside Tab 7's left `Options` column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingRow
{
    /// Built-in color palette preset (`neon`, `tokyo`, `dracula`, `gruvbox`, `ansi`).
    ThemePreset,
    /// Path to managed `nfqws2.toml` loaded into Finder/Config/Run tabs.
    Nfqws2Config,
    /// Optional explicit directory containing `zapret-lib.lua` and `zapret-antidpi.lua`.
    LuaDir,
    /// Manual `nftables` / firewall management flag (`--no-nft`).
    NoNft,
    /// Optional Unix control socket override for daemon attach mode.
    ControlSocket,
}

impl SettingRow
{
    /// Ordered option rows rendered in Tab 7's left pane.
    pub const ALL: [Self; 5] =
        [Self::ThemePreset, Self::Nfqws2Config, Self::LuaDir, Self::NoNft, Self::ControlSocket];
}

/// Descriptor binding one named `"section.field"` entry in [`Keybinds`] to read/write accessors.
pub(crate) struct KeybindEntrySpec
{
    /// Human-readable `"section.field"` identifier matching TOML `[keybinds.<section>].<field>`.
    pub id: &'static str,
    /// Accessor returning the current binding list from `keybinds`.
    pub get: fn(&Keybinds) -> &KeyList,
    /// Mutable accessor replacing the binding list inside `keybinds`.
    pub set: fn(&mut Keybinds, KeyList),
}

/// Generates static read/write descriptors across every field of [`Keybinds`].
macro_rules! kb_specs {
    ( $( $sec:ident . $field:ident ),+ $(,)? ) => {
        &[
            $(
                KeybindEntrySpec {
                    id: concat!(stringify!($sec), ".", stringify!($field)),
                    get: |kb| &kb.$sec.$field,
                    set: |kb, val| kb.$sec.$field = val,
                },
            )+
        ]
    };
}

/// Ordered keybinding rows displayed and interactively remapped in Tab 7.
pub(crate) const KEYBIND_ENTRIES: &[KeybindEntrySpec] = kb_specs!(
    global.help,
    global.quit,
    global.caps_modal,
    global.tab_1,
    global.tab_2,
    global.tab_3,
    global.tab_4,
    global.tab_5,
    global.tab_6,
    global.tab_7,
    global.prev_tab,
    global.next_tab,
    global.next_panel,
    global.prev_panel,
    global.web_ui,
    global.copy_web_passcode,
    global.open_web_ui,
    nav.up,
    nav.down,
    nav.left,
    nav.right,
    nav.page_up,
    nav.page_down,
    nav.home,
    nav.end,
    finder.activate,
    finder.start_scan,
    finder.stop_scan,
    finder.save_toml,
    finder.open_run_tab,
    finder.dismiss_hover,
    run.start_stop,
    run.stop_or_detach,
    run.restart,
    run.reload,
    run.stop_attached,
    run.clear,
    inspector.filter_cycle,
    inspector.filter_edit,
    inspector.pause,
    inspector.detail,
    inspector.close_detail,
    config.edit,
    config.push,
    config.save,
    config.reload,
    speed.start,
    speed.cancel,
    speed.clear,
    status.refresh,
    status.export_debug,
    status.next_dns,
    status.apply_dns,
    hostlist.filter,
    hostlist.clear_filter,
    hostlist.add_auto,
    hostlist.add_blacklist,
    hostlist.delete,
    hostlist.move_entry,
    hostlist.reload,
    settings.save,
    settings.reload,
    settings.edit,
    settings.rebind,
    settings.reset,
);

/// Interactive state for Tab 7 (`Settings`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SettingsTabState
{
    /// Currently focused column (`Options` or `Keybinds`).
    pub focus: SettingsFocus,
    /// Selected row inside `SettingRow::ALL`.
    pub option_sel: usize,
    /// Selected row inside [`KEYBIND_ENTRIES`].
    pub keybind_sel: usize,
    /// Inline text editing active for a path row in `Options`.
    pub editing_option: bool,
    /// Draft buffer edited while `editing_option` is `true`.
    pub edit_buf: String,
    /// Waiting for the next raw [`KeyEvent`] to bind to `KEYBIND_ENTRIES[keybind_sel]`.
    pub capturing_rebind: bool,
    /// `true` when memory holds unsaved changes compared to `config.toml` on disk.
    pub dirty: bool,
}

impl SettingsTabState
{
    /// Alternates focus between `Options` and `Keybinds` columns.
    pub fn toggle_focus(&mut self)
    {
        self.focus = match self.focus
        {
            SettingsFocus::Options => SettingsFocus::Keybinds,
            SettingsFocus::Keybinds => SettingsFocus::Options,
        };
    }

    /// Moves row cursor inside the focused Tab 7 column cleanly within bounds.
    pub fn move_selection(&mut self, delta: isize)
    {
        let (len, target) = match self.focus
        {
            SettingsFocus::Options => (SettingRow::ALL.len(), &mut self.option_sel),
            SettingsFocus::Keybinds => (KEYBIND_ENTRIES.len(), &mut self.keybind_sel),
        };
        *target = step_selection(*target, len, delta);
    }
}

/// Converts a captured terminal [`KeyEvent`] into a canonical [`KeyBind`].
fn normalize_captured_key(event: KeyEvent) -> KeyBind
{
    if event.code == KeyCode::BackTab
        || (event.code == KeyCode::Tab && event.modifiers.contains(KeyModifiers::SHIFT))
    {
        return KeyBind { code: KeyCode::BackTab, modifiers: KeyModifiers::NONE };
    }
    let modifiers = match event.code
    {
        KeyCode::Char(_) => event.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT),
        _ => event.modifiers & (KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SHIFT),
    };
    KeyBind { code: event.code, modifiers }
}

impl AppState
{
    /// Handles Tab 7 (`Settings`) navigation, live rebinding, path edits, save, reload, and `$EDITOR`.
    pub(crate) fn handle_settings_key(&mut self, key: KeyEvent) -> AppAction
    {
        if self.settings.capturing_rebind
        {
            if key.code == KeyCode::Esc
                && !key.modifiers.intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            {
                self.settings.capturing_rebind = false;
                self.status_banner = "Cancelled keybind capture.".to_owned();
                return AppAction::None;
            }
            if let Some(spec) = KEYBIND_ENTRIES.get(self.settings.keybind_sel)
            {
                let bound = normalize_captured_key(key);
                let label = bound.format_label();
                (spec.set)(&mut self.keybinds, KeyList(vec![bound]));
                self.settings.capturing_rebind = false;
                self.settings.dirty = true;
                let save_key = self.keybinds.settings.save.primary_label();
                self.status_banner =
                    format!("Bound '{}' to [{label}] (press '{save_key}' to save).", spec.id);
            }
            return AppAction::None;
        }

        if self.settings.editing_option
        {
            match handle_inline_text_key(&mut self.settings.edit_buf, key)
            {
                TextInputOutcome::Cancelled =>
                {
                    self.settings.editing_option = false;
                    self.status_banner = "Cancelled option edit.".to_owned();
                }
                TextInputOutcome::Submitted => self.apply_edited_setting_row(),
                TextInputOutcome::Edited | TextInputOutcome::Ignored =>
                {}
            }
            return AppAction::None;
        }

        let nav = &self.keybinds.nav;
        let sk = &self.keybinds.settings;
        if nav.left.contains(key) || nav.right.contains(key)
        {
            self.settings.toggle_focus();
        }
        else if let Some(delta) = nav.vertical_delta(key, 10)
        {
            self.settings.move_selection(delta);
        }
        else if sk.save.contains(key)
        {
            return AppAction::SaveAppConfig;
        }
        else if sk.reload.contains(key)
        {
            return AppAction::ReloadAppConfig;
        }
        else if sk.edit.contains(key)
        {
            return AppAction::EditAppConfig;
        }
        else if sk.rebind.contains(key)
        {
            self.activate_selected_setting_or_keybind();
        }
        else if sk.reset.contains(key)
        {
            self.reset_selected_setting_or_keybind();
        }
        AppAction::None
    }

    /// Activates the focused setting row (`Options`) or enters capture mode (`Keybinds`).
    pub(crate) fn activate_selected_setting_or_keybind(&mut self)
    {
        if self.settings.focus == SettingsFocus::Keybinds
        {
            if let Some(spec) = KEYBIND_ENTRIES.get(self.settings.keybind_sel)
            {
                self.settings.capturing_rebind = true;
                self.status_banner = format!("Press new key for '{}' (Esc cancel)...", spec.id);
            }
            return;
        }
        match SettingRow::ALL.get(self.settings.option_sel).copied()
        {
            Some(SettingRow::ThemePreset) =>
            {
                self.theme = self.theme.next_preset();
                self.settings.dirty = true;
                let save_key = self.keybinds.settings.save.primary_label();
                self.status_banner =
                    format!("Selected theme '{}' (press '{save_key}' to save).", self.theme.name);
            }
            Some(SettingRow::NoNft) =>
            {
                self.finder.no_nft = !self.finder.no_nft;
                self.settings.dirty = true;
            }
            Some(SettingRow::Nfqws2Config) =>
            {
                self.settings.edit_buf = self.finder.output_path.clone();
                self.settings.editing_option = true;
            }
            Some(SettingRow::LuaDir) =>
            {
                self.settings.edit_buf = self.finder.lua_dir_input.clone();
                self.settings.editing_option = true;
            }
            Some(SettingRow::ControlSocket) =>
            {
                self.settings.edit_buf = self
                    .run
                    .control_socket_override
                    .as_ref()
                    .map_or_else(String::new, |p| p.display().to_string());
                self.settings.editing_option = true;
            }
            None =>
            {}
        }
    }

    /// Commits `self.settings.edit_buf` into the currently selected `Options` path field.
    fn apply_edited_setting_row(&mut self)
    {
        let val = self.settings.edit_buf.trim().to_owned();
        self.settings.editing_option = false;
        self.settings.edit_buf.clear();
        match SettingRow::ALL.get(self.settings.option_sel).copied()
        {
            Some(SettingRow::Nfqws2Config) =>
            {
                self.finder.output_path =
                    if val.is_empty() { default_output_config_path().display().to_string() } else { val };
                let expanded = expand_tilde(&self.finder.output_path);
                if let Ok(text) = std::fs::read_to_string(&expanded)
                {
                    self.set_active_toml(text);
                }
                self.settings.dirty = true;
            }
            Some(SettingRow::LuaDir) =>
            {
                self.finder.lua_dir_input = val;
                self.settings.dirty = true;
            }
            Some(SettingRow::ControlSocket) =>
            {
                self.run.control_socket_override = (!val.is_empty()).then(|| expand_tilde(&val));
                self.settings.dirty = true;
            }
            _ =>
            {}
        }
    }

    /// Resets the highlighted `SettingRow` or `KeybindEntrySpec` back to its built-in default.
    fn reset_selected_setting_or_keybind(&mut self)
    {
        if self.settings.focus == SettingsFocus::Keybinds
        {
            if let Some(spec) = KEYBIND_ENTRIES.get(self.settings.keybind_sel)
            {
                let defaults = Keybinds::default();
                let def_val = (spec.get)(&defaults).clone();
                let lbl = def_val.joined_label();
                (spec.set)(&mut self.keybinds, def_val);
                self.settings.dirty = true;
                self.status_banner = format!("Reset '{}' to [{lbl}].", spec.id);
            }
            return;
        }
        match SettingRow::ALL.get(self.settings.option_sel).copied()
        {
            Some(SettingRow::ThemePreset) =>
            {
                self.theme = crate::tui::Theme::neon();
                self.settings.dirty = true;
            }
            Some(SettingRow::Nfqws2Config) =>
            {
                self.finder.output_path = default_output_config_path().display().to_string();
                self.settings.dirty = true;
            }
            Some(SettingRow::LuaDir) =>
            {
                self.finder.lua_dir_input =
                    detect_lua_dir(None).map_or_else(String::new, |p| p.display().to_string());
                self.settings.dirty = true;
            }
            Some(SettingRow::NoNft) =>
            {
                self.finder.no_nft = false;
                self.settings.dirty = true;
            }
            Some(SettingRow::ControlSocket) =>
            {
                self.run.control_socket_override = None;
                self.settings.dirty = true;
            }
            None =>
            {}
        }
    }
}
