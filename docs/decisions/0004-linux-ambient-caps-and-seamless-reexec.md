# ADR-0004: Linux Ambient Capabilities & Seamless `setcap` TUI Re-Exec

## Status

Accepted

## Date

2026-11-27

## Context

Intercepting NFQUEUE packets and sending forged L3 packets requires `CAP_NET_ADMIN` and `CAP_NET_RAW`. Running the entire TUI, Web UI, `$EDITOR`, or `systemd` service permanently as UID `0` expands privilege risk unnecessarily (for example spawning `$EDITOR` or opening browser links as root), while dropping capabilities naively breaks packet capture on non-root daemons and prompts inside `NoNewPrivileges` sandboxes deadlock. Additionally, granting file capabilities (`setcap`) mid-session inside the TUI requires restarting the process image for the kernel to grant effective capabilities to the running PID.

## Decision

1. Drop root UID cleanly on TUI startup when launched under `sudo` (`drop_elevated_root_if_needed`), invoke `$EDITOR` strictly unprivileged (`spawn_unprivileged_editor` in [src/tui/editor.rs](../../src/tui/editor.rs)), and run `systemd` units under the user's account with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`.
2. In the headless `nfqws2` daemon ([src/tools/daemon/linux.rs](../../src/tools/daemon/linux.rs), [src/runtime/caps.rs](../../src/runtime/caps.rs)), retain `CAP_NET_ADMIN|CAP_NET_RAW` across `--user`/`--uid` privilege drops while validating external helper binaries (`nft`, `sudo`, `setcap`, `systemctl`) against verified root-owned directories ([src/runtime/trusted_bin.rs](../../src/runtime/trusted_bin.rs)) and checking `has_no_new_privs` before attempting `sudo`.
3. When capabilities are granted via `setcap` inside the TUI, serialize active UI state (`tab`, Strategy Finder inputs, `app_config_path`, sparse `app_config_toml`, and `PostCapsAction`) into `ReexecSnapshot` (`ZAPRET_RS_REEXEC_STATE` / `ZAPRET_RS_SEAMLESS_REEXEC` in [src/tui/session.rs](../../src/tui/session.rs)) and seamlessly `exec()` without tearing down or flashing the alternate screen.

## Alternatives Considered

### Require users to run the entire `zapret-rs` TUI under `sudo`
- **Pros:** Avoids `setcap`, `AmbientCapabilities`, and `ReexecSnapshot` complexity.
- **Cons:** Leaves XDG configs (`~/.config/zapret-rs/`) owned by `root:root`, runs `$EDITOR` and desktop browser openers as root, and requires root for every launch.
- **Rejected:** Unprivileged TUI execution paired with narrow file/ambient packet capabilities minimizes attack surface and file-ownership friction.

### Spawn a separate privileged background worker on every launch
- **Pros:** Keeps UI unprivileged even without `setcap`.
- **Cons:** Breaks direct Strategy Finder self-contained runs when unprivileged and still requires repeated `sudo` prompts.
- **Rejected:** `setcap` on the installed binary + `systemd` ambient capabilities provide zero-prompt operation after initial setup, while `ReexecSnapshot` keeps the first-run transition transparent.

## Consequences

- `zapret-rs` supports zero-root `systemd` services and unprivileged TUI `$EDITOR` sessions cleanly.
- File operations inside `prepare_writable_dir`, `PidFileGuard`, and `write_config_nofollow` enforce `O_NOFOLLOW` and leaf-only ownership checks to prevent symlink privilege escalation.
- Seamless re-exec requires keeping `ReexecSnapshot` updated whenever persistent startup state changes (e.g., `app_config_toml`, `domain_scope`, `PostCapsAction`).
