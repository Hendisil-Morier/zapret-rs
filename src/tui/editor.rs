//! Unprivileged `$VISUAL`/`$EDITOR` launcher and starter `nfqws2.toml` generator for Tab 3.

/// Unix `pre_exec` hook clearing capabilities before spawning an external text editor.
use std::os::unix::process::CommandExt as _;
/// Filesystem path inspection for locating fallback editors in `PATH`.
use std::path::{Path, PathBuf};
/// Subprocess execution for launching the user's editor inside a suspended terminal.
use std::process::{Command, ExitStatus};

/// Least-privilege helper stripping `CAP_NET_ADMIN`/`CAP_NET_RAW` from child processes.
use crate::runtime::clear_child_privileges;
/// Lua script discovery helper for populating `lua_init` in newly seeded starter configs.
use crate::tools::resolve_lua_scripts;

/// Fallback editors checked in order on `PATH` when neither `$VISUAL` nor `$EDITOR` is set.
const FALLBACK_EDITORS: &[&str] = &["nvim", "vim", "nano", "vi"];

/// Returns `true` when `bin` resolves to an existing file on the current `PATH`.
fn binary_in_path(bin: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|dir| dir.join(bin).is_file())
}

/// Resolves the user's preferred editor command (`$VISUAL`, `$EDITOR`, then `nvim`/`vim`/`nano`/`vi`).
pub fn resolve_editor_command() -> Vec<String> {
    for var in ["VISUAL", "EDITOR"] {
        if let Ok(val) = std::env::var(var) {
            let parts: Vec<String> = val.split_whitespace().map(str::to_owned).collect();
            if !parts.is_empty() {
                return parts;
            }
        }
    }
    for &bin in FALLBACK_EDITORS {
        if binary_in_path(bin) {
            return vec![bin.to_owned()];
        }
    }
    vec!["vi".to_owned()]
}

/// Builds a minimal, valid starter `nfqws2.toml` used when opening a non-existent config path.
pub fn build_starter_toml(qnum: u16, fwmark: u32, lua_dir_hint: &str) -> String {
    let hint = (!lua_dir_hint.trim().is_empty()).then(|| PathBuf::from(lua_dir_hint.trim()));
    let scripts = resolve_lua_scripts(hint.as_deref()).unwrap_or_default();
    let mut out = format!(
        "# zapret-rs nfqws2.toml configuration\nqnum = {qnum}\nfwmark = 0x{fwmark:08x}\n"
    );
    if !scripts.is_empty() {
        out.push_str("lua_init = [\n");
        for path in scripts {
            let escaped = path.to_string_lossy().replace('\\', "\\\\").replace('"', "\\\"");
            out.push_str(&format!("  \"{escaped}\",\n"));
        }
        out.push_str("]\n");
    }
    out.push_str(
        "\n# Example profile (uncomment and adjust domains/strategy):\n\
         # [[profiles]]\n\
         # name = \"tls-split\"\n\
         # filter_l3 = [\"ipv4\"]\n\
         # filter_tcp = [\"443\"]\n\
         # filter_l7 = [\"tls\"]\n\
         # hostlist_domains = [\"example.com\"]\n\
         #\n\
         # [[profiles.actions]]\n\
         # func = \"multisplit\"\n\
         # payload = [\"tls_client_hello\"]\n\
         # [profiles.actions.args]\n\
         # pos = \"2\"\n",
    );
    out
}

/// Spawns `cmd_parts` targeting `path` with all network capabilities stripped via `pre_exec`.
pub fn spawn_unprivileged_editor(cmd_parts: &[String], path: &Path) -> Result<ExitStatus, String> {
    let Some((prog, args)) = cmd_parts.split_first() else {
        return Err("no editor command configured".to_owned());
    };
    let mut cmd = Command::new(prog);
    cmd.args(args).arg(path);
    // SAFETY: `clear_child_privileges` invokes only async-signal-safe `prctl`/`capset` syscalls.
    unsafe {
        cmd.pre_exec(clear_child_privileges);
    }
    cmd.status()
        .map_err(|err| format!("failed to launch editor '{prog}': {err}"))
}
