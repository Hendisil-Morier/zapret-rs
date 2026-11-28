//! Tab 7 side-effectful `config.toml` save/reload/$EDITOR and mouse interaction helpers.

/// Shared `ratatui` layout splitters aligned identically with `draw_settings_tab`.
use ratatui::layout::{Constraint, Direction, Layout, Position, Rect};

/// Expansion of `~/` paths when preparing fallback startup settings.
use crate::tools::expand_tilde;
/// Centralized `config.toml` parser, default generator, and surgical saver.
use crate::tui::app_config::{ResolvedAppConfig, parse_app_config_str};
use crate::tui::app_config_save::{ensure_default_app_config_file, save_settings_surgically};
/// Unprivileged `$VISUAL` / `$EDITOR` launcher reused for editing `config.toml`.
use crate::tui::editor::{resolve_editor_command, spawn_unprivileged_editor};
/// Terminal alternate-screen session wrapper suspended cleanly while `$EDITOR` runs.
use crate::tui::session::TerminalSession;
/// Tab 7 table metrics and selectable option/keybind descriptors.
use crate::tui::settings_tab::{KEYBIND_ENTRIES, SettingRow, SettingsFocus};
/// Mutable top-level TUI state updated by Tab 7 actions.
use crate::tui::state::AppState;
/// Shared visible-window slice helper aligned with `draw_settings_tab`.
use crate::tui::types::visible_window;

/// Saves active Tab 7 settings, theme, and customized keybinds sparsely into `state.app_config_path`.
pub(crate) fn save_app_config_from_settings(state: &mut AppState)
{
    match save_settings_surgically(
        &state.app_config_path,
        &state.finder.output_path,
        &state.finder.lua_dir_input,
        state.finder.no_nft,
        state.run.control_socket_override.as_deref(),
        state.theme,
        &state.keybinds,
    )
    {
        Ok(msg) =>
        {
            state.settings.dirty = false;
            state.status_banner = msg;
        }
        Err(err) => state.status_banner = format!("Save config.toml failed: {err}"),
    }
}

/// Reloads `state.app_config_path` from disk and applies theme, keybinds, and path defaults live.
pub(crate) fn reload_app_config_from_disk(state: &mut AppState)
{
    let path = state.app_config_path.clone();
    let text = match std::fs::read_to_string(&path)
    {
        Ok(t) => t,
        Err(err) =>
        {
            state.status_banner = format!("Reload {} failed: {err}", path.display());
            return;
        }
    };
    match parse_app_config_str(&text, path.clone(), path.parent())
    {
        Ok((resolved, has_theme)) =>
        {
            state.theme =
                if has_theme { resolved.theme } else { crate::tui::theme_config::resolve_theme(None).0 };
            state.keybinds = resolved.keybinds;
            if let Some(p) = resolved.nfqws2_config
            {
                state.finder.output_path = p.display().to_string();
                if let Ok(nfq) = std::fs::read_to_string(&p)
                {
                    state.set_active_toml(nfq);
                }
            }
            if let Some(lua) = resolved.lua_dir
            {
                state.finder.lua_dir_input = lua.display().to_string();
            }
            state.finder.no_nft = resolved.no_nft;
            state.run.control_socket_override = resolved.control_socket;
            state.settings.dirty = false;
            state.status_banner = format!("Reloaded {}", path.display());
        }
        Err(err) => state.status_banner = format!("Reload failed: {err}"),
    }
}

/// Suspends the TUI to open `state.app_config_path` in `$VISUAL`/`$EDITOR` and reloads on return.
pub(crate) fn edit_app_config_in_editor(state: &mut AppState, session: &mut TerminalSession)
{
    let resolved = ResolvedAppConfig {
        app_config_path: state.app_config_path.clone(),
        nfqws2_config: Some(expand_tilde(&state.finder.output_path)),
        lua_dir: (!state.finder.lua_dir_input.is_empty()).then(|| expand_tilde(&state.finder.lua_dir_input)),
        no_nft: state.finder.no_nft,
        control_socket: state.run.control_socket_override.clone(),
        theme: state.theme,
        keybinds: state.keybinds.clone(),
    };
    if let Some(err) = ensure_default_app_config_file(&resolved, &state.finder.lua_dir_input)
    {
        state.status_banner = err;
        return;
    }
    let path = state.app_config_path.clone();
    let editor_cmd = resolve_editor_command();
    match session.suspend_for(|| spawn_unprivileged_editor(&editor_cmd, &path))
    {
        Ok(_) => reload_app_config_from_disk(state),
        Err(err) => state.status_banner = err,
    }
}

/// Handles left mouse clicks and scroll wheel events inside Tab 7 (`Settings`).
pub(crate) fn handle_settings_mouse(
    state: &mut AppState,
    pos: Position,
    is_left: bool,
    scroll_dir: Option<isize>,
    body: Rect,
)
{
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(body);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(rows[1]);

    if cols[0].contains(pos)
    {
        state.settings.focus = SettingsFocus::Options;
        if let Some(dir) = scroll_dir
        {
            state.settings.move_selection(if dir < 0 { -1 } else { 1 });
        }
        else if is_left && pos.y > cols[0].y && pos.y + 1 < cols[0].bottom()
        {
            let row = usize::from(pos.y - (cols[0].y + 1));
            if row < SettingRow::ALL.len()
            {
                state.settings.option_sel = row;
            }
        }
    }
    else if cols[1].contains(pos)
    {
        state.settings.focus = SettingsFocus::Keybinds;
        if let Some(dir) = scroll_dir
        {
            state.settings.move_selection(if dir < 0 { -3 } else { 3 });
        }
        else if is_left && pos.y > cols[1].y + 1 && pos.y + 1 < cols[1].bottom()
        {
            let cap = usize::from(cols[1].height.saturating_sub(3)).max(1);
            let (start, end) = visible_window(KEYBIND_ENTRIES.len(), state.settings.keybind_sel, cap);
            let idx = start + usize::from(pos.y - (cols[1].y + 2));
            if idx < end
            {
                state.settings.keybind_sel = idx;
            }
        }
    }
}
