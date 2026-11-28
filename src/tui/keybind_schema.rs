//! Complete remappable keybinding table spanning global chrome, navigation, and all six tabs.

/// Terminal key event type matched against configured directional bindings.
use crossterm::event::KeyEvent;
/// Serialization/deserialization helpers for partial `[keybinds.*]` overrides in `config.toml`.
use serde::{Deserialize, Serialize};

/// Multi-key binding list type supporting single string or string array syntax in TOML.
use crate::tui::keybind_spec::KeyList;

/// Declares a keybind section struct with `#[serde(default)]`, `#[serde(deny_unknown_fields)]`,
/// per-field docstrings, and matching `Default` key specifications.
macro_rules! keybind_section {
    (
        $(#[$struct_doc:meta])*
        pub struct $Name:ident {
            $(
                $(#[$field_doc:meta])*
                $field:ident : $default_fn:ident = $specs:expr
            ),+ $(,)?
        }
    ) => {
        $(#[$struct_doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(default, deny_unknown_fields)]
        pub struct $Name {
            $(
                $(#[$field_doc])*
                pub $field: KeyList,
            )+
        }

        impl Default for $Name {
            fn default() -> Self {
                Self {
                    $(
                        $field: KeyList::from_specs(&$specs),
                    )+
                }
            }
        }
    };
}

/// Complete configurable TUI keymap grouped by scope (`global`, `nav`, per-tab, and `inspector`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Keybinds
{
    /// Keys honored on every tab outside modal prompts and inline text-editing fields.
    pub global: GlobalKeybinds,
    /// Directional cursor and viewport scrolling keys shared across tables, lists, and logs.
    pub nav: NavKeybinds,
    /// Keys specific to Tab 1 (`Strategy Finder`).
    pub finder: FinderKeybinds,
    /// Keys specific to Tab 2 (`Run nfqws2` / `Run WinDivert`).
    pub run: RunKeybinds,
    /// Keys specific to Tab 2's live Packet Inspector panel and detail modal.
    pub inspector: InspectorKeybinds,
    /// Keys specific to Tab 3 (`Config & Diagnostics`).
    pub config: ConfigKeybinds,
    /// Keys specific to Tab 4 (`Speed Test`).
    pub speed: SpeedKeybinds,
    /// Keys specific to Tab 5 (`Status`).
    pub status: StatusKeybinds,
    /// Keys specific to Tab 6 (`Auto Hostlist & Blacklist`).
    pub hostlist: HostlistKeybinds,
    /// Keys specific to Tab 7 (`Settings`).
    pub settings: SettingsKeybinds,
}

keybind_section! {
    /// Global navigation, help, theme, and Web UI keybindings.
    pub struct GlobalKeybinds {
        /// Opens or closes the contextual `?` keybindings popup.
        help: help = ["?"],
        /// Exits the TUI cleanly (or dismisses the help overlay).
        quit: quit = ["q", "Ctrl+c"],
        /// Opens the capability/administrator setup prompt when capture privileges are missing.
        caps_modal: caps_modal = ["g"],
        /// Switches directly to Tab 1 (`Strategy Finder`).
        tab_1: tab_1 = ["1"],
        /// Switches directly to Tab 2 (`Run`).
        tab_2: tab_2 = ["2"],
        /// Switches directly to Tab 3 (`Config`).
        tab_3: tab_3 = ["3"],
        /// Switches directly to Tab 4 (`Speed Test`).
        tab_4: tab_4 = ["4"],
        /// Switches directly to Tab 5 (`Status`).
        tab_5: tab_5 = ["5"],
        /// Switches directly to Tab 6 (`Hostlist`).
        tab_6: tab_6 = ["6"],
        /// Switches directly to Tab 7 (`Settings`).
        tab_7: tab_7 = ["7"],
        /// Cycles backward to the previous top-level tab.
        prev_tab: prev_tab = ["H"],
        /// Cycles forward to the next top-level tab.
        next_tab: next_tab = ["L"],
        /// Moves focus forward to the next pane inside the current tab.
        next_panel: next_panel = ["Tab"],
        /// Moves focus backward to the previous pane inside the current tab.
        prev_panel: prev_panel = ["Shift+Tab"],
        /// Starts or stops the embedded Web UI dashboard.
        web_ui: web_ui = ["W"],
        /// Copies the active Web UI pairing passcode to the system clipboard.
        copy_web_passcode: copy_web_passcode = ["y"],
        /// Opens the active Web UI URL in the default desktop browser.
        open_web_ui: open_web_ui = ["o"],
    }
}

keybind_section! {
    /// Directional movement and scrolling keybindings shared across tabs.
    pub struct NavKeybinds {
        /// Moves selection up or scrolls upward one line.
        up: up = ["Up", "k"],
        /// Moves selection down or scrolls downward one line.
        down: down = ["Down", "j"],
        /// Switches column focus left or scrolls left horizontally.
        left: left = ["Left", "h"],
        /// Switches column focus right or scrolls right horizontally.
        right: right = ["Right", "l"],
        /// Scrolls or steps backward by a page.
        page_up: page_up = ["PgUp"],
        /// Scrolls or steps forward by a page.
        page_down: page_down = ["PgDn"],
        /// Jumps to the top or beginning of the list/pane.
        home: home = ["Home"],
        /// Jumps to the bottom or live log tail.
        end: end = ["End"],
    }
}

impl NavKeybinds
{
    /// Maps vertical movement bindings (`up`, `down`, `page_up`, `page_down`, `home`, `end`) into a
    /// signed row step using `page_step` for page jumps, or `None` if `key` is not vertical navigation.
    pub fn vertical_delta(&self, key: KeyEvent, page_step: isize) -> Option<isize>
    {
        if self
            .up
            .contains(key)
        {
            Some(-1)
        }
        else if self
            .down
            .contains(key)
        {
            Some(1)
        }
        else if self
            .page_up
            .contains(key)
        {
            Some(-page_step)
        }
        else if self
            .page_down
            .contains(key)
        {
            Some(page_step)
        }
        else if self
            .home
            .contains(key)
        {
            Some(isize::MIN / 2)
        }
        else if self
            .end
            .contains(key)
        {
            Some(isize::MAX / 2)
        }
        else
        {
            None
        }
    }
}

keybind_section! {
    /// Tab 1 (`Strategy Finder`) keybindings.
    pub struct FinderKeybinds {
        /// Toggles focused options or enters inline text edit mode on the Setup form.
        activate: activate = ["Enter", "Space"],
        /// Starts an asynchronous strategy discovery scan.
        start_scan: start_scan = ["r"],
        /// Stops an active strategy discovery scan.
        stop_scan: stop_scan = ["x", "Esc"],
        /// Saves the generated `nfqws2.toml` to disk.
        save_toml: save_toml = ["s"],
        /// Jumps to Tab 2 (`Run`) with the active configuration ready.
        open_run_tab: open_run_tab = ["a"],
        /// Dismisses the floating Strategy Finder option tooltip.
        dismiss_hover: dismiss_hover = ["Esc"],
    }
}

keybind_section! {
    /// Tab 2 (`Run nfqws2` / `Run WinDivert`) daemon control keybindings.
    pub struct RunKeybinds {
        /// Starts, stops, or attaches to the packet engine daemon.
        start_stop: start_stop = ["r", "Enter"],
        /// Stops a locally spawned daemon or detaches from an external daemon.
        stop_or_detach: stop_or_detach = ["x"],
        /// Restarts the active local or external daemon.
        restart: restart = ["R"],
        /// Reloads `nfqws2.toml` or remote hostlists from disk.
        reload: reload = ["l"],
        /// Opens confirmation prompt to stop an attached external daemon.
        stop_attached: stop_attached = ["S"],
        /// Clears visible packet counters and inspector ring buffer entries.
        clear: clear = ["c"],
    }
}

keybind_section! {
    /// Tab 2 live Packet Inspector panel and packet detail popup keybindings.
    pub struct InspectorKeybinds {
        /// Cycles verdict filter (`All` -> `Desync` -> `Pass` -> `Fail`).
        filter_cycle: filter_cycle = ["f"],
        /// Enters live packet filter query input mode (`/`).
        filter_edit: filter_edit = ["/"],
        /// Pauses or resumes live packet inspector table updates.
        pause: pause = ["p"],
        /// Opens full hex/layer detail popup for the highlighted packet.
        detail: detail = ["d"],
        /// Closes the open packet detail popup.
        close_detail: close_detail = ["Esc", "d", "Enter"],
    }
}

keybind_section! {
    /// Tab 3 (`Config & Diagnostics`) keybindings.
    pub struct ConfigKeybinds {
        /// Opens `nfqws2.toml` in external `$VISUAL` / `$EDITOR`.
        edit: edit = ["e", "Enter"],
        /// Pushes edited `nfqws2.toml` to an attached daemon via control socket.
        push: push = ["p"],
        /// Saves active `nfqws2.toml` to disk.
        save: save = ["s"],
        /// Reloads `nfqws2.toml` from disk.
        reload: reload = ["l"],
    }
}

keybind_section! {
    /// Tab 4 (`Speed Test`) keybindings.
    pub struct SpeedKeybinds {
        /// Starts the before/after speed test workflow (with confirmation modal).
        start: start = ["r", "Enter"],
        /// Cancels an active speed test run.
        cancel: cancel = ["x", "Esc"],
        /// Clears stored speed comparison measurements.
        clear: clear = ["c"],
    }
}

keybind_section! {
    /// Tab 5 (`Status`) diagnostics keybindings.
    pub struct StatusKeybinds {
        /// Refreshes all operational component status checks.
        refresh: refresh = ["r", "Enter"],
        /// Exports a redacted diagnostic report text file.
        export_debug: export_debug = ["d"],
        /// Cycles through selectable OS DNS / DoH presets.
        next_dns: next_dns = ["n"],
        /// Opens confirmation modal to apply the selected DNS preset.
        apply_dns: apply_dns = ["a"],
    }
}

keybind_section! {
    /// Tab 6 (`Auto Hostlist & Blacklist`) keybindings.
    pub struct HostlistKeybinds {
        /// Enters interactive substring filter mode across Auto Hostlist and Blacklist.
        filter: filter = ["/"],
        /// Clears the active hostlist filter when not typing.
        clear_filter: clear_filter = ["Esc"],
        /// Prompts to add a domain or IP directly to Auto Hostlist.
        add_auto: add_auto = ["a"],
        /// Prompts to add a domain or IP to Blacklist (`hostlist_exclude`).
        add_blacklist: add_blacklist = ["b"],
        /// Deletes the currently highlighted Auto Hostlist or Blacklist entry directly.
        delete: delete = ["d", "Del", "Backspace"],
        /// Moves the highlighted entry between Auto Hostlist and Blacklist.
        move_entry: move_entry = ["x", "m"],
        /// Reloads Auto Hostlist and Blacklist entries from disk.
        reload: reload = ["r"],
    }
}

keybind_section! {
    /// Tab 7 (`Settings`) configuration, theme, and live keybinding manager keys.
    pub struct SettingsKeybinds {
        /// Saves active settings, theme overrides, and modified keybinds to `config.toml`.
        save: save = ["s"],
        /// Reloads `config.toml` from disk, discarding unsaved edits.
        reload: reload = ["l"],
        /// Opens `config.toml` in external `$VISUAL` / `$EDITOR`.
        edit: edit = ["e"],
        /// Toggles an option, edits a path field, or captures a new keybind for the highlighted action.
        rebind: rebind = ["Enter", "Space"],
        /// Resets the selected keybind or setting back to its built-in default.
        reset: reset = ["r", "Del"],
    }
}
