# ADR-0002: Acyclic Module DAG & Automated Repository Hygiene Constraints

## Status

Accepted

## Date

2026-11-27

## Context

As `zapret-rs` expanded from a CLI packet daemon into a multi-applet binary containing Strategy Finder, WinDivert, Control IPC, Web UI, and a 7-tab TUI, subsystems began mixing unrelated domains (UI, IPC, config mutation, and firewall calls) into multi-hundred-line files and `mod.rs` files. Both human maintainers and AI coding agents need fast feedback when a change blurs module boundaries, creates circular module edges, leaves inline `#[cfg(test)]` clutter in `src/`, or hides panicking `.unwrap()` calls in packet/daemon paths.

## Decision

1. Structure all 18 modules in [src/lib.rs](../../src/lib.rs) as a strict layered acyclic DAG (detailed in [docs/architecture/README.md](../architecture/README.md)).
2. Enforce structural invariants automatically in [tests/repo_hygiene.rs](../../tests/repo_hygiene.rs) on every `cargo nextest` run:
   - Non-exempt production files under `src/` stay at or below `450` logical code lines (`MAX_SRC_CODE_LINES`), and integration tests under `tests/` stay at or below `500` (`MAX_TEST_CODE_LINES`), excluding blank lines, comments, and lone `{`/`}` brace lines (exempting `src/config/blobs.rs`).
   - Every `src/**/mod.rs` file must be a pure facade containing only `pub mod`, `pub use`, `#[cfg(...)]` gates, and comments.
   - Zero `#[cfg(test)]`, `#[test]`, `.unwrap(`, or `.expect(` calls are permitted inside `src/`.

## Alternatives Considered

### Rely solely on manual code review and PR conventions
- **Pros:** Zero upfront splitting boilerplate when adding small helpers.
- **Cons:** Conventions drift rapidly under rapid feature work and agent edits, reintroducing monolithic files and panic paths in daemon threads.
- **Rejected:** Automated failure during `cargo nextest run` guarantees architectural hygiene before any change is considered verified.

### Split `zapret-rs` into multiple Cargo workspace crates
- **Pros:** Compiler enforces dependency DAG at the crate boundary.
- **Cons:** Slows incremental compilation, duplicates build metadata/error conversions, and complicates single-binary multicall packaging (`--no-default-features`).
- **Rejected:** Enforcing single-responsibility modules and pure `mod.rs` facades inside one crate yields fast builds and clean static guarantees without workspace overhead.

## Consequences

- Every subsystem exposes explicit error variants aggregated into `ZapretError` ([src/error.rs](../../src/error.rs)) using `?` propagation rather than `.unwrap()`/`.expect()`.
- Non-trivial additions that push a file near `450` logical code lines naturally decompose along domain seams (for example, separating `toml_splice.rs`, `app_config_import.rs`, `app_config_save.rs`, `settings_tab.rs`, and `settings_actions.rs`).
- All unit and integration tests reside cleanly under `tests/` against public or `pub(crate)` APIs.
