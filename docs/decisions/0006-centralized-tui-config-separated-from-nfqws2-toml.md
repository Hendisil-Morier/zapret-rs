# ADR-0006: Centralized TUI `config.toml` Separated from `nfqws2.toml`

## Status

Accepted

## Date

2026-11-28

## Context

Adding fully remappable TUI keybindings alongside custom color themes and startup overrides (`nfqws2_config`, `lua_dir`, `no_nft`, `control_socket`) raised two structural questions:

1. Whether UI configuration should be merged into `nfqws2.toml` (under top-level keys or an inline `[nfqws]` namespace) or live in its own centralized `~/.config/zapret-rs/config.toml`.
2. How saving changes from inside the TUI should avoid bloating `config.toml` with unchanged defaults or clobbering user comments and modular `import` files (`import = "./theme.toml"`).

## Decision

1. Store TUI preferences in centralized `~/.config/zapret-rs/config.toml` ([src/tui/app_config.rs](../../src/tui/app_config.rs)) while leaving generated/daemon profiles standalone in `nfqws2.toml` (referenced via `nfqws2_config`).
2. Support `--config` auto-detection between centralized `config.toml` and direct `nfqws2.toml`, plus explicit `--nfqws2-config` override and recursive `import`/`imports` resolution with cycle guards ([src/tui/app_config_import.rs](../../src/tui/app_config_import.rs)).
3. Place interactive configuration, theme preset selection, live `KeyEvent` keybind capture, and explicit sparse saving (`s`) inside dedicated **Tab 7 (`7: Settings`)** ([src/tui/settings_tab.rs](../../src/tui/settings_tab.rs), [src/tui/app_config_save.rs](../../src/tui/app_config_save.rs)), removing the old global `T` save hotkey:
   - First-run creation writes a minimal `config.toml` (`nfqws2_config` + inline `[theme]` or `import = "./theme.toml"` when a sibling `theme.toml` exists), omitting default keybinds.
   - Explicit saves write only keybinds and colors differing from defaults while preserving header comments, `import` entries, and updating imported standalone `theme.toml` files in place.

## Alternatives Considered

### Embed `[nfqws]` inside `config.toml` and rewrite it with an in-place splicer
- **Pros:** Single file containing both DPI strategy profiles and UI settings.
- **Cons:** Strategy Finder (`render_nfqws2_toml_scoped`), Tab 6 Blacklist edits (`mutate_exclude_domains_toml`), Tab 3 `$EDITOR`, Web UI (`POST /api/config`), `systemd` units, and `--no-default-features` headless daemons all read/rewrite standalone `nfqws2.toml` (`#[serde(deny_unknown_fields)]`). Embedding `[nfqws]` couples generated machine rules tightly to hand-edited UI preferences.
- **Rejected:** Keeping `config.toml` as a lean hub that references `nfqws2_config` and `import`ed files cleanly separates generated network rules from personal TUI customization.

### Keep global `T` overwriting full `config.toml` inline
- **Pros:** No 7th tab or surgical TOML splicer needed.
- **Cons:** Dumping all 10 `[keybinds.*]` tables creates a ~120-line file even with zero changes, overwrites user `import = "./theme.toml"` directives and comments, and gives no in-TUI way to rebind keys or reload `config.toml`.
- **Rejected:** Tab 7 (`Settings`) plus sparse comment-preserving saves make UI customization discoverable and non-destructive.

## Consequences

- Headless builds (`--no-default-features`), `daemon`, `web`, and `systemd` remain unchanged and continue using `nfqws2.toml` directly.
- Adding a 7th top-level tab (`7: Settings`) required switching the header `Tabs` divider to `"|"` and Status badge width to `30` cols ([src/tui/tabs.rs](../../src/tui/tabs.rs), [src/tui/render.rs](../../src/tui/render.rs)) so all seven full tab titles remain unclipped inside standard 120-column terminals.
- Legacy standalone `~/.config/zapret-rs/theme.toml` files continue working automatically via first-run `import = "./theme.toml"` and `resolve_theme(None)` fallback.
