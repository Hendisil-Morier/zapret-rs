//! TUI side-effect executors for Blacklist (`hostlist_exclude`), Auto Hostlist, and Web UI actions.

/// Symlink-safe TOML/hostlist disk writers and path resolvers.
use crate::control::Request;
use crate::tools::{
    expand_tilde, mutate_exclude_domains_toml, mutate_hostlist_file, parse_clean_domain,
    write_config_nofollow,
};
/// Prompt modal variants handled on Tab 3 submission.
use crate::tui::prompt_modal::PromptKind;
/// Shared TUI state mutated after disk/daemon updates.
use crate::tui::state::AppState;
/// Remote daemon session handle used to live-reload modified configs or lists.
use crate::tui::tab2_session::Tab2Session;

/// Saves `updated_toml` to disk, updates [`AppState`], and live-reloads any attached daemon.
fn commit_updated_toml(
    state: &mut AppState,
    tab2_session: &Option<Tab2Session>,
    updated_toml: String,
    label: &str,
) -> Result<(), String> {
    let cfg_path = expand_tilde(&state.output_path);
    write_config_nofollow(&cfg_path, &updated_toml)
        .map_err(|err| format!("failed to write {}: {err}", cfg_path.display()))?;
    state.set_active_toml(updated_toml.clone());

    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref() {
        if let Err(err) = remote.send_command(&Request::ReloadConfig { toml: updated_toml }) {
            state.status_banner = format!("{label} (saved; daemon reload failed: {err})");
            return Ok(());
        }
        state.status_banner = format!("{label} (saved & reloaded daemon)");
    } else {
        state.status_banner = format!("{label} (saved to {})", cfg_path.display());
    }
    Ok(())
}

/// Executes [`AppState::prompt_modal`] without a live daemon session (used by offline TUI tests).
pub fn apply_prompt_offline(state: &mut AppState) {
    submit_prompt_modal(state, &None);
}

/// Executes the confirmed Tab 3 domain list action and closes [`AppState::prompt_modal`] on success.
pub(crate) fn submit_prompt_modal(state: &mut AppState, tab2_session: &Option<Tab2Session>) {
    let Some((kind, raw_input)) = state
        .prompt_modal
        .as_ref()
        .map(|m| (m.kind, m.input.trim().to_owned()))
    else {
        return;
    };

    let outcome: Result<(), String> = match kind {
        PromptKind::BlacklistDomain => {
            let cfg_path = expand_tilde(&state.output_path);
            let source_toml = if !state.active_toml.trim().is_empty() {
                state.active_toml.clone()
            } else {
                std::fs::read_to_string(&cfg_path).unwrap_or_default()
            };
            mutate_exclude_domains_toml(&source_toml, &raw_input, true, cfg_path.parent())
                .and_then(|updated| {
                    let clean = parse_clean_domain(&raw_input).unwrap_or_else(|| raw_input.clone());
                    commit_updated_toml(state, tab2_session, updated, &format!("Blacklisted {clean}"))
                })
        }
        PromptKind::AddAutoHostlist => {
            if state.autohostlist_paths.is_empty() {
                Err("Auto Hostlist is off (set Tab 1 Domain Scope to Auto Hostlist first)".to_owned())
            } else {
                let mut res = Ok(());
                for path in state.autohostlist_paths.clone() {
                    if let Err(err) = mutate_hostlist_file(&path, &raw_input, true) {
                        res = Err(err);
                        break;
                    }
                }
                res.map(|()| {
                    state.refresh_autohostlist();
                    let clean = parse_clean_domain(&raw_input).unwrap_or_else(|| raw_input.clone());
                    if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref()
                        && remote.send_command(&Request::ReloadLists).is_ok()
                    {
                        state.status_banner = format!("Added {clean} to Auto Hostlist & reloaded daemon");
                    } else {
                        state.status_banner = format!("Added {clean} to Auto Hostlist");
                    }
                })
            }
        }
        PromptKind::RemoveListDomain => {
            let Some(clean) = parse_clean_domain(&raw_input) else {
                if let Some(m) = state.prompt_modal.as_mut() {
                    m.error = Some("invalid domain name".to_owned());
                }
                return;
            };
            let mut removed_any = false;
            if state.exclude_entries.iter().any(|d| d.eq_ignore_ascii_case(&clean)) {
                let cfg_path = expand_tilde(&state.output_path);
                if let Ok(updated) =
                    mutate_exclude_domains_toml(&state.active_toml, &clean, false, cfg_path.parent())
                {
                    let _ = commit_updated_toml(
                        state,
                        tab2_session,
                        updated,
                        &format!("Removed {clean} from Blacklist"),
                    );
                    removed_any = true;
                }
            }
            for path in state.autohostlist_paths.clone() {
                let prev_len = state.autohostlist_entries.len();
                if let Ok(after) = mutate_hostlist_file(&path, &clean, false)
                    && after.len() < prev_len
                {
                    removed_any = true;
                }
            }
            if removed_any {
                state.refresh_autohostlist();
                if let Some(Tab2Session::Remote(remote)) = tab2_session.as_ref() {
                    let _ = remote.send_command(&Request::ReloadLists);
                }
                if !state.status_banner.contains(&clean) {
                    state.status_banner = format!("Removed {clean} from list(s)");
                }
                Ok(())
            } else {
                Err(format!("{clean} not found in Blacklist or Auto Hostlist"))
            }
        }
    };

    match outcome {
        Ok(()) => state.prompt_modal = None,
        Err(err) => {
            if let Some(modal) = state.prompt_modal.as_mut() {
                modal.error = Some(err);
            }
        }
    }
}
