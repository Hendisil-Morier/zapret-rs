# Implementation Plan: Milestone 7, Daemon Control Socket and TUI Attach Mode

## Overview

Let a long-running `nfqws2` (for example under systemd) expose a local Unix control socket, and let the `zapret-rs` TUI attach to it to show live counters and packets, reload lists, and stop the daemon. When no daemon socket is found, Tab 2 keeps today's behavior of running an in-process engine. Version bump is MINOR (1.1.0): everything is additive and opt-in.

Decisions confirmed with the user:
- Plan lives in `tasks/plan-ipc.md` and `tasks/todo-ipc.md`; the Milestone 6 files are untouched.
- Access: same user as the daemon only. Socket mode 0600 plus an `SO_PEERCRED` uid check.
- TUI Tab 2 auto-detects a daemon and attaches; otherwise it falls back to the in-process engine.

## Architecture Decisions

- **Control server runs in its own thread, not in the packet loop.** `DesyncEngine` holds `Rc`/`RefCell` and Lua state, so it is `!Send`. The thread talks to the packet loop only through atomics (counters), bounded `sync_channel`s (packet records, same pattern as `tui/workers.rs`) and a command channel that the loop drains inside its existing `next_timeout` closure. The loop timeout is capped at 50 ms when control is enabled, so commands are handled within 50 ms.
- **Shared telemetry module.** `PacketCounters`, `PacketVerdict`, `PacketRecord` and `build_packet_record` currently live under the feature-gated `src/tui/`. `nfqws2` must build with `--no-default-features`, so they move to `src/telemetry/` and the TUI re-exports them. This is a pure refactor and lands first and alone.
- **Wire protocol:** newline-delimited JSON over `SOCK_STREAM`, with a `hello` handshake carrying a protocol version. `serde_json 1.0.154` is already in the local cargo registry (not yet in `Cargo.lock`), so no network fetch is needed.
- **Zero cost when nobody is attached.** Counters are always atomic increments. `build_packet_record` runs only while at least one client has subscribed.
- **Flood control.** `DESYNC`, `MODIFY` and `REASM` records are always forwarded. `PASS` records are sampled (1 in N, N chosen by the server). Each client has a bounded outbound queue; a slow client is disconnected, never allowed to block the packet loop.
- **Default path, safe binding.** A default socket path is used and created when absent (see Decisions), overridable with `--control-socket PATH` or TOML `control_socket`. Bind with umask 0177, refuse a symlink at the path, remove a stale socket only if connect returns `ECONNREFUSED`, unlink on clean exit.
- **Attach mode never touches nftables.** The daemon owner manages firewall rules. The TUI in attach mode only reads telemetry and sends commands.
- **TUI reuses its existing plumbing.** The remote client thread fills the same `Arc<PacketCounters>` and the same `pkt_rx`/`desync_rx` channels as `ActiveDaemon`, so rendering and the inspector need no changes.

## Dependency Graph

```
7.1 telemetry extraction (refactor)
 ├── 7.2 protocol codec
 │    ├── 7.3 control server (thread, socket, peercred)
 │    │    └── 7.4 nfqws2 integration (flag, hub, commands)  ── Checkpoint A
 │    └── 7.5 remote client + TUI attach (needs 7.3 for tests)
 │                                                          ── Checkpoint B
 └── 7.6 reload-config command (needs 7.4 and 7.5)
7.7 docs, changelog, 1.1.0 release (needs all)
```

## Task List

See `tasks/todo-ipc.md` for acceptance criteria and verification steps.

### Phase 1: Foundation
- [x] Task 7.1: Extract shared telemetry model into `src/telemetry/`
- [x] Task 7.2: Control protocol and line codec

### Phase 2: Daemon side
- [ ] Task 7.3: Control server (Unix socket, peer-uid check, subscriptions)
- [ ] Task 7.4: `nfqws2` integration (`--control-socket`, hub, stop and reload-lists commands)

### Checkpoint A: Daemon exposes status and stop over a real socket

### Phase 3: TUI side
- [ ] Task 7.5: Remote client and TUI attach mode on Tab 2
- [ ] Task 7.6: `reload-config` command (hot-swap profiles from TOML)

### Checkpoint B: TUI attaches to a running `nfqws2`, shows live packets, detaches and stops it

### Phase 4: Release
- [ ] Task 7.7: README systemd example, CHANGELOG, 1.1.0 bump and tag

## Git Workflow

- Branch `feature/daemon-ipc` from `main`; one atomic Conventional Commit per task (task 7.1 is a separate `refactor:` commit, never mixed with features).
- Each commit leaves `cargo clippy --all-targets --offline -- -D warnings`, `cargo nextest run --offline`, and `cargo check --no-default-features --offline` green.
- CHANGELOG entry is written in the same commit as each user-visible change; 7.7 only finalizes the version heading.
- Tag `v1.1.0` on `main` after merge. Nothing is pushed to a remote unless asked.

## Repo Constraints (enforced by `tests/repo_hygiene.rs`)

- `src/**` files at most 400 lines, `tests/**` at most 450; `mod.rs` files contain only `pub mod` / `pub use`.
- No `#[cfg(test)]`, `#[test]`, `.unwrap(` or `.expect(` in `src/`; all tests in `tests/`.
- Doc comment on every function, struct, enum and import.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Control thread stalls or floods the packet loop | High | Bounded channels with `try_send`; the loop never blocks on the control path; slow clients are dropped |
| Hot-path cost of building records for PASS traffic | Med | Build records only with at least one subscriber; sample PASS |
| Another local user connecting to the socket | High | 0600 socket, `SO_PEERCRED` uid check, reject and close otherwise |
| Stale socket after a crash blocks restart | Med | Probe with connect; unlink only on `ECONNREFUSED`; refuse non-socket or symlink paths |
| Daemon drops root after `preinit`, so the socket directory may be unwritable | Med | Create the socket after privilege drop, in a path the target user owns; document `RuntimeDirectory=` for systemd |
| TUI and daemon version skew | Low | `hello` handshake with protocol version; TUI shows a clear mismatch message |
| Telemetry move breaks `--no-default-features` build | Med | Task 7.1 gate includes `cargo check --no-default-features` |

## Decisions on Former Open Questions

- `S` in the TUI opens a confirm popup before stopping the daemon.
- PASS sampling is configurable (`--control-pass-sample N`, TOML `control_pass_sample`), default 1 in 20, 0 disables PASS records.
- A default socket path exists. Resolution order: `--control-socket PATH` / TOML `control_socket`, else `$XDG_RUNTIME_DIR/zapret-rs/control.sock`, else `/run/zapret-rs/control.sock`. The parent directory is created (mode 0700) when missing, before the privilege drop when needed and then chowned to the daemon user. `--control-socket=off` disables the feature.
