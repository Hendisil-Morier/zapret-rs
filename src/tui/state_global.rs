//! Global hotkeys shared by every tab: help popup, quit, tab switching, panel focus, and themes.

/// Keyboard event primitive carrying key code and modifier bits.
use crossterm::event::KeyEvent;

/// Domain and Web UI launcher modal state opened from global (`W`) or Tab 3 (`b`/`a`/`d`).
use crate::tui::prompt_modal::{PromptKind, PromptModal};
/// Attached background `nfqws2` daemon metadata stored when attaching from Tab 2.
use crate::tui::remote::RemoteDaemonMeta;
/// Mutable application state receiving global hotkey effects.
use crate::tui::state::AppState;
/// Navigation enums and the side-effect action returned to the runner.
use crate::tui::types::{ActiveTab, AppAction, RunStatus};

impl AppState
{
    /// Handles a key that means the same on every tab; returns `None` when `key` is not global.
    ///
    /// Theme/help/Web UI global keys are suppressed while the packet detail popup is open so
    /// tab-local close bindings (or plain characters) cannot trigger underneath the popup.
    pub(crate) fn handle_global_key(&mut self, key: KeyEvent) -> Option<AppAction>
    {
        let detail_open = self.inspector.detail_open;
        let g = &self.keybinds.global;
        if !detail_open && g.help.contains(key)
        {
            self.help_open = true;
            self.dismiss_finder_hover();
            return Some(AppAction::None);
        }
        if g.quit.contains(key)
        {
            return Some(AppAction::Quit);
        }
        if !self.status.has_net_caps && g.caps_modal.contains(key)
        {
            self.open_caps_modal();
            return Some(AppAction::None);
        }
        let tab_target = [
            (&g.tab_1, ActiveTab::Finder),
            (&g.tab_2, ActiveTab::Run),
            (&g.tab_3, ActiveTab::Config),
            (&g.tab_4, ActiveTab::Speed),
            (&g.tab_5, ActiveTab::Status),
            (&g.tab_6, ActiveTab::Hostlist),
            (&g.tab_7, ActiveTab::Settings),
        ]
        .into_iter()
        .find_map(|(keys, tab)| keys.contains(key).then_some(tab));
        if let Some(tab) = tab_target
        {
            return Some(self.switch_tab(tab));
        }
        if g.prev_tab.contains(key)
        {
            return Some(self.switch_tab(self.tab.prev()));
        }
        if g.next_tab.contains(key)
        {
            return Some(self.switch_tab(self.tab.next()));
        }
        if g.next_panel.contains(key)
        {
            return Some(self.cycle_panel_focus(true));
        }
        if g.prev_panel.contains(key)
        {
            return Some(self.cycle_panel_focus(false));
        }
        if !detail_open && g.cycle_theme.contains(key)
        {
            let settings_tab = self.keybinds.global.tab_7.primary_label();
            let save_key = self.keybinds.settings.save.primary_label();
            self.theme = self.theme.next_preset();
            self.settings.dirty = true;
            self.status_banner = format!(
                "Theme preview: {} (Tab {settings_tab} Settings -> '{save_key}' to save)",
                self.theme.name
            );
            return Some(AppAction::None);
        }
        if !detail_open && g.web_ui.contains(key)
        {
            if self.web_status.is_some()
            {
                return Some(AppAction::StopWebUi);
            }
            self.prompt_modal = Some(PromptModal::open(PromptKind::LaunchWebUi));
            self.dismiss_finder_hover();
            return Some(AppAction::None);
        }
        if !detail_open && self.web_status.is_some() && g.copy_web_passcode.contains(key)
        {
            return Some(AppAction::CopyWebPasscode);
        }
        if !detail_open && self.web_status.is_some() && g.open_web_ui.contains(key)
        {
            return Some(AppAction::OpenWebUi);
        }
        None
    }

    /// Switches top-level tab, refreshing Tab 5/6 state and resetting tooltips cleanly.
    fn switch_tab(&mut self, tab: ActiveTab) -> AppAction
    {
        self.tab = tab;
        if tab == ActiveTab::Status
        {
            self.refresh_status_checks();
        }
        else if tab == ActiveTab::Hostlist
        {
            self.refresh_autohostlist();
        }
        self.reset_finder_hover();
        AppAction::None
    }

    /// Cycles focused panel inside the active tab (`Tab` / `Shift+Tab`) and updates tooltip state.
    fn cycle_panel_focus(&mut self, forward: bool) -> AppAction
    {
        if self.tab == ActiveTab::Hostlist
        {
            self.hostlist.toggle_focus();
        }
        else if self.tab == ActiveTab::Settings
        {
            self.settings.toggle_focus();
        }
        else
        {
            self.focus.cycle(self.tab, forward);
        }
        self.reset_finder_hover();
        AppAction::None
    }

    /// Transitions Tab 2 into [`RunStatus::Attached`] with `meta` and logs attachment.
    pub fn set_attached(&mut self, meta: RemoteDaemonMeta)
    {
        let log_line = format!(
            "[attach] connected to PID {} on queue {} ({}, {} profiles)",
            meta.pid,
            meta.qnum,
            meta.socket_path.display(),
            meta.profile_names.len()
        );
        self.status_banner =
            "Attached to nfqws2. Press 'x' to detach, 'l' to reload lists, 'S' to stop daemon.".to_owned();
        self.run.detected_socket = Some(meta.socket_path.clone());
        self.run.remote_meta = Some(meta);
        self.run.status = RunStatus::Attached;
        self.run.auto_reattach = true;
        self.run.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
    }

    /// Transitions Tab 2 back from [`RunStatus::Attached`] to [`RunStatus::Stopped`].
    pub fn set_detached(&mut self, log_line: String, banner: String)
    {
        self.run.remote_meta = None;
        self.run.status = RunStatus::Stopped;
        self.run.counter_baseline = (0, 0, 0, 0, 0);
        self.push_run_log(log_line);
        self.status_banner = banner;
    }

    /// Returns `(total, passed, reassembled, modified, desynced)` minus [`Self::counter_baseline`].
    pub fn visible_counters(&self) -> (u64, u64, u64, u64, u64)
    {
        let (s0, s1, s2, s3, s4) = self.run.counters.snapshot();
        let (b0, b1, b2, b3, b4) = self.run.counter_baseline;
        if s0 < b0 || s1 < b1 || s2 < b2 || s3 < b3 || s4 < b4
        {
            return (s0, s1, s2, s3, s4);
        }
        (s0 - b0, s1 - b1, s2 - b2, s3 - b3, s4 - b4)
    }
}
