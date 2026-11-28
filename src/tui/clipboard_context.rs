//! Context-aware TUI copy selection extraction and active-input paste dispatch.

/// System clipboard / OSC 52 I/O primitives and single-line text sanitizer.
use crate::tui::clipboard::{copy_to_clipboard, paste_from_clipboard, sanitize_paste_text};
/// Byte-sliced hex + ASCII formatter reused when copying packet details from Tab 2.
use crate::tui::inspect_ui::format_hex_dump;
/// Interactive prompt kind distinguishing plain-text domain entry from Web UI launch.
use crate::tui::prompt_modal::PromptKind;
/// Remappable keybinding action labels copied when Tab 7 focus sits in Keybinds.
use crate::tui::settings_tab::{KEYBIND_ENTRIES, SettingRow, SettingsFocus};
/// Speed comparison formatting helpers for Tab 4 selection copy.
use crate::tui::speed::describe_sample;
/// Top-level mutable TUI application state inspected and updated by copy/paste helpers.
use crate::tui::state::AppState;
/// Navigation, tab, field, and panel focus enums for context-aware selection resolution.
use crate::tui::types::{ActiveTab, ConfigFocus, FinderField, FinderFocus, RunFocus};

/// Extracts copyable text from Tab 1 (`Setup` text buffer, `Results` row, or `Live Scan Log`).
fn copyable_finder_text(state: &AppState) -> Option<(&'static str, String)>
{
    match state
        .focus
        .finder
    {
        FinderFocus::Setup =>
        {
            let text = match state.focused_field()
            {
                FinderField::Domains =>
                {
                    &state
                        .finder
                        .domains_input
                }
                FinderField::LuaDir =>
                {
                    &state
                        .finder
                        .lua_dir_input
                }
                FinderField::OutputPath =>
                {
                    &state
                        .finder
                        .output_path
                }
                _ => return None,
            };
            (!text.is_empty()).then(|| ("field value", text.clone()))
        }
        FinderFocus::Results => state
            .finder
            .targets
            .get(
                state
                    .focus
                    .finder_results_sel,
            )
            .map(|t| {
                let best = t
                    .matches
                    .first()
                    .map_or_else(
                        || {
                            t.baseline
                                .summary()
                        },
                        |m| {
                            format!(
                                "{} ({}ms)",
                                m.strategy
                                    .id,
                                m.latency_ms
                            )
                        },
                    );
                (
                    "scan result",
                    format!(
                        "{} ({}/{}): {best}",
                        t.domain,
                        t.proto
                            .as_str(),
                        t.ipv
                            .as_str()
                    ),
                )
            }),
        FinderFocus::Log => (!state
            .finder
            .logs
            .is_empty())
        .then(|| {
            let lines: Vec<&str> = state
                .finder
                .logs
                .iter()
                .map(String::as_str)
                .collect();
            ("scan log", lines.join("\n"))
        }),
    }
}

/// Extracts copyable text from Tab 2 (`Packet Inspector` row/detail modal or `Daemon Log`).
fn copyable_run_text(state: &AppState) -> Option<(&'static str, String)>
{
    if state
        .inspector
        .detail_open
        || state
            .focus
            .run
            == RunFocus::Inspector
    {
        if let Some(pkt) = state
            .inspector
            .selected_record()
        {
            let prof = pkt
                .profile
                .as_deref()
                .unwrap_or("-");
            let mut body = format!(
                "#{} [{}] {} {} -> {} | prof={prof} | {}",
                pkt.seq,
                pkt.verdict
                    .label(),
                pkt.proto,
                pkt.src,
                pkt.dst,
                pkt.info
            );
            if state
                .inspector
                .detail_open
                && !pkt
                    .payload_preview
                    .is_empty()
            {
                body.push('\n');
                body.push_str(&format_hex_dump(&pkt.payload_preview).join("\n"));
            }
            return Some(("packet details", body));
        }
        if !state
            .inspector
            .detail_open
        {
            return None;
        }
    }
    (!state
        .run
        .logs
        .is_empty())
    .then(|| {
        let lines: Vec<&str> = state
            .run
            .logs
            .iter()
            .map(String::as_str)
            .collect();
        ("daemon log", lines.join("\n"))
    })
}

/// Extracts copyable text from Tab 7 (`Settings` option value or selected keybind row).
fn copyable_settings_text(state: &AppState) -> Option<(&'static str, String)>
{
    match state
        .settings
        .focus
    {
        SettingsFocus::Options => match SettingRow::ALL.get(
            state
                .settings
                .option_sel,
        )
        {
            Some(SettingRow::ThemePreset) => Some((
                "theme preset",
                state
                    .theme
                    .name
                    .to_owned(),
            )),
            Some(SettingRow::Nfqws2Config) => Some((
                "nfqws2_config path",
                state
                    .finder
                    .output_path
                    .clone(),
            )),
            Some(SettingRow::LuaDir) => Some((
                "lua_dir path",
                state
                    .finder
                    .lua_dir_input
                    .clone(),
            )),
            Some(SettingRow::ControlSocket) => state
                .run
                .control_socket_override
                .as_ref()
                .map(|p| {
                    (
                        "control_socket path",
                        p.display()
                            .to_string(),
                    )
                }),
            Some(SettingRow::NoNft) | None => None,
        },
        SettingsFocus::Keybinds => KEYBIND_ENTRIES
            .get(
                state
                    .settings
                    .keybind_sel,
            )
            .map(|spec| {
                let lbl = (spec.get)(&state.keybinds).joined_label();
                ("keybind", format!("{} = {lbl}", spec.id))
            }),
    }
}

/// Returns `(label, text)` representing the currently selected or focused TUI item/pane.
pub fn copyable_selection_text(state: &AppState) -> Option<(&'static str, String)>
{
    match state.tab
    {
        ActiveTab::Finder => copyable_finder_text(state),
        ActiveTab::Run => copyable_run_text(state),
        ActiveTab::Config => match state
            .focus
            .config
        {
            ConfigFocus::Toml
                if !state
                    .config
                    .active_toml
                    .is_empty() =>
            {
                Some((
                    "nfqws2.toml",
                    state
                        .config
                        .active_toml
                        .clone(),
                ))
            }
            ConfigFocus::Toml => None,
            ConfigFocus::Nft => Some((
                "filter preview",
                state
                    .filter_preview()
                    .1,
            )),
        },
        ActiveTab::Speed => state
            .speed
            .rows
            .get(
                state
                    .speed
                    .selected,
            )
            .map(|r| {
                let b = r
                    .before
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), describe_sample);
                let a = r
                    .after
                    .as_ref()
                    .map_or_else(|| "-".to_owned(), describe_sample);
                ("speed row", format!("{}: without={b} | with={a}", r.label))
            }),
        ActiveTab::Status => state
            .status
            .checks
            .get(
                state
                    .status
                    .selected,
            )
            .map(|c| ("status check", format!("{}: {} | {}", c.name, c.summary, c.detail))),
        ActiveTab::Hostlist => state
            .hostlist
            .selected_domain(&state.config)
            .map(|d| ("domain", d)),
        ActiveTab::Settings => copyable_settings_text(state),
    }
}

/// Copies the active contextual TUI selection into the OS clipboard / OSC 52 and reports it in the banner.
pub fn copy_context_selection(state: &mut AppState)
{
    let Some((label, text)) = copyable_selection_text(state)
    else
    {
        state.status_banner = "Nothing selected to copy here.".to_owned();
        return;
    };
    state.status_banner = match copy_to_clipboard(&text)
    {
        Ok(method) => format!("Copied {label} ({method})."),
        Err(err) => format!("Copy {label} failed: {err}"),
    };
}

/// Returns `true` when any modal input box, inline filter, option editor, or Tab 1 text field accepts paste.
pub fn has_paste_target(state: &AppState) -> bool
{
    if let Some(m) = &state.modal
    {
        return m.needs_password;
    }
    if let Some(p) = &state.prompt_modal
    {
        return p.kind != PromptKind::LaunchWebUi;
    }
    state
        .finder
        .editing_text
        || state
            .inspector
            .filter_editing
        || state
            .hostlist
            .filter_editing
        || state
            .settings
            .editing_option
        || (state.tab == ActiveTab::Finder
            && state
                .focus
                .finder
                == FinderFocus::Setup
            && state
                .focused_field()
                .is_text())
}

/// Inserts sanitized `clean` text into the currently focused Tab 1 text buffer at its cursor.
fn paste_into_finder(state: &mut AppState, clean: &str) -> bool
{
    let editing = state
        .finder
        .editing_text;
    let cur_pos = state
        .finder
        .text_cursor;
    let new_cursor = {
        let Some(buf) = state.focused_text_buf_mut()
        else
        {
            return false;
        };
        let pos = if editing { cur_pos.min(buf.len()) } else { buf.len() };
        buf.insert_str(pos, clean);
        pos + clean.len()
    };
    state
        .finder
        .editing_text = true;
    state
        .finder
        .text_cursor = new_cursor;
    state.dismiss_finder_hover();
    state.status_banner = "Pasted into field.".to_owned();
    true
}

/// Inserts sanitized clipboard or bracketed-paste text into whichever TUI text input currently has focus.
pub fn apply_paste_to_state(state: &mut AppState, raw: &str) -> bool
{
    let clean = sanitize_paste_text(raw);
    if clean.is_empty()
    {
        return false;
    }
    if let Some(modal) = state
        .modal
        .as_mut()
    {
        if modal.needs_password
        {
            modal.append_password(&clean);
            return true;
        }
        return false;
    }
    if let Some(prompt) = state
        .prompt_modal
        .as_mut()
    {
        if prompt.kind != PromptKind::LaunchWebUi
        {
            prompt
                .input
                .push_str(&clean);
            prompt.error = None;
            return true;
        }
        return false;
    }
    if state
        .inspector
        .filter_editing
    {
        state
            .inspector
            .filter_query
            .push_str(&clean);
        state
            .inspector
            .selected = 0;
        return true;
    }
    if state
        .hostlist
        .filter_editing
    {
        state
            .hostlist
            .filter
            .push_str(&clean);
        state
            .hostlist
            .clamp_selection(&state.config);
        return true;
    }
    if state
        .settings
        .editing_option
    {
        state
            .settings
            .edit_buf
            .push_str(&clean);
        return true;
    }
    if state
        .finder
        .editing_text
        || (state.tab == ActiveTab::Finder
            && state
                .focus
                .finder
                == FinderFocus::Setup
            && state
                .focused_field()
                .is_text())
    {
        return paste_into_finder(state, &clean);
    }
    false
}

/// Reads the OS clipboard (`Ctrl+v`) and pastes into the active TUI text input, updating the status banner.
pub fn paste_clipboard_into_state(state: &mut AppState)
{
    if !has_paste_target(state)
    {
        return;
    }
    match paste_from_clipboard()
    {
        Ok(text) if !apply_paste_to_state(state, &text) =>
        {
            state.status_banner = "Clipboard is empty.".to_owned();
        }
        Ok(_) =>
        {}
        Err(err) => state.status_banner = err,
    }
}
