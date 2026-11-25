# Task Breakdown: Milestone 7 (Daemon Control Socket and TUI Attach Mode)

Plan: `tasks/plan-ipc.md`. Verification commands used throughout:
- Lint: `cargo clippy --all-targets --offline -- -D warnings`
- Tests: `cargo nextest run --offline --show-progress none --no-pager`
- No-TUI build: `cargo check --no-default-features --offline`
- Release build: `cargo build --release --offline`

## Task 7.1: Extract shared telemetry model into `src/telemetry/`

**Description:** Move `PacketCounters`, `PacketVerdict`, `PacketRecord` and `build_packet_record` out of the feature-gated `src/tui/` into a new always-built `src/telemetry/` module, and make `tui` re-export them. No behavior change.

**Acceptance criteria:**
- [x] `crate::telemetry` is available without the `tui` feature
- [x] `zapret_rs::tui::{PacketCounters, PacketRecord, PacketVerdict, build_packet_record}` still resolve (re-exports)
- [x] `PacketRecord` derives `serde::Serialize` and `Deserialize`

**Verification:**
- [x] Tests pass (existing `tui_app` and `desync_m3_e2e` unchanged)
- [x] `cargo check --no-default-features --offline` succeeds
- [x] Lint clean

**Dependencies:** None
**Files likely touched:** `src/telemetry/{mod,counters,record}.rs`, `src/tui/{inspect,types,mod}.rs`, `src/lib.rs`
**Estimated scope:** Medium. Commit type: `refactor`.

## Task 7.2: Control protocol and line codec

**Description:** Define `Request` (`hello`, `status`, `subscribe`, `unsubscribe`, `reload_lists`, `stop`) and `Response`/`Event` (`hello_ok`, `status`, `counters`, `packet`, `error`) with a version field, plus a newline-delimited JSON codec that bounds line length.

**Acceptance criteria:**
- [x] Round-trip encode/decode for every message
- [x] Oversized line (over 64 KiB) and malformed JSON return a typed error, not a panic
- [x] Unknown protocol version is reported distinctly

**Verification:**
- [x] `tests/control_protocol.rs` passes
- [x] No-TUI build and lint clean

**Dependencies:** 7.1
**Files likely touched:** `src/control/{mod,protocol,codec}.rs`, `Cargo.toml` (`serde_json`), `tests/control_protocol.rs`
**Estimated scope:** Medium. Commit type: `feat`.

## Task 7.3: Control server (Unix socket, peer-uid check, subscriptions)

**Description:** A server thread that binds the socket (umask 0177, refuses symlinks, probes and removes stale sockets), accepts clients, rejects any peer whose `SO_PEERCRED` uid differs from the daemon's, and serves `hello`, `status`, `subscribe`. Packet records and counters come from a `TelemetryHub` handed in by the caller; commands go out on a channel.

**Acceptance criteria:**
- [x] Socket file is mode 0600 and is removed on shutdown
- [x] Stale socket is replaced; a live socket makes startup fail with a clear error
- [x] A client with a different uid is closed before any reply (unit-tested through an injectable uid check)
- [x] A client that stops reading is disconnected without blocking other clients

**Verification:**
- [x] `tests/control_server.rs` passes using a temp-dir socket
- [x] Lint clean, no-TUI build clean

**Dependencies:** 7.2
**Files likely touched:** `src/control/{server,hub,peer}.rs`, `tests/control_server.rs`
**Estimated scope:** Medium. Commit type: `feat`.

## Task 7.4: `nfqws2` integration

**Description:** Add `--control-socket <PATH|off|default>` (`control_socket` in TOML, auto-resolving `$XDG_RUNTIME_DIR/zapret-rs/control.sock` else `/run/zapret-rs/control.sock` for live intercepting daemons) and `--control-pass-sample N` (`control_pass_sample` in TOML, default 20). In `nfqws2.rs`, create parent dir (`0700`, chowned before privilege drop), start the server after privilege drop and daemonize, update counters and publish records from the packet closure (records built only when subscribed, PASS sampled), drain commands in `next_loop_timeout` (cap 50 ms), and implement `stop` (set quit flag) and `reload_lists`.

**Acceptance criteria:**
- [x] Default control socket path binds automatically in intercept mode (`--control-socket=off` leaves hot path untouched)
- [x] `--intercept=0` daemon with a control socket answers `hello` and `status`, reloads lists, and exits cleanly on `stop` with no socket or pidfile left behind
- [x] Packet closure cost without subscribers is only atomic counter increments

**Verification:**
- [x] `tests/nfqws2_control.rs` (spawns the real binary with `--intercept=0`) passes
- [x] Lint clean, release build succeeds

**Dependencies:** 7.3
**Files likely touched:** `src/bin/nfqws2.rs`, `src/config/{cli,mod,model,schema}.rs`, `src/control/{client_session,mod,socket}.rs`, `src/telemetry/counters.rs`, `src/tui/workers.rs`, `tests/nfqws2_control.rs`, `tests/config_toml.rs`
**Estimated scope:** Medium. Commit type: `feat`.

### Checkpoint A: After Tasks 7.1-7.4
- [x] All tests pass, lint and both builds clean
- [x] `nfqws2 --intercept=0 --control-socket <path>` answers status and stops cleanly via a client
- [ ] Review with human before the TUI work

## Task 7.5: Remote client and TUI attach mode on Tab 2

**Description:** A client thread that connects, does the handshake, subscribes, and feeds the existing `Arc<PacketCounters>` and `pkt_rx`/`desync_rx` channels. Tab 2 auto-detects a socket (configured path, then `$XDG_RUNTIME_DIR/zapret-rs/control.sock`, then `/run/zapret-rs/control.sock`) and shows `ATTACHED` status. Keys: `x` detaches, `S` stops the daemon after a confirm popup, `l` asks the daemon to reload lists. In attach mode the TUI never installs nftables rules.

**Acceptance criteria:**
- [ ] With a daemon socket present, `r` attaches instead of starting an in-process engine
- [ ] Without one, behavior is identical to today
- [ ] Connection loss shows an error in the daemon log pane and returns to `STOPPED` without a crash
- [ ] Version mismatch is shown as a readable message

**Verification:**
- [ ] `tests/tui_attach.rs` passes against a fake server on a temp socket, including headless render of `ATTACHED`
- [ ] Existing `tui_app` tests unchanged and green
- [ ] Manual: run a real daemon, attach, see REASM and DESYNC rows, detach, daemon keeps running

**Dependencies:** 7.3 (7.4 for the manual check)
**Files likely touched:** `src/tui/{remote,workers,runner,state,render}.rs`, `tests/tui_attach.rs`
**Estimated scope:** Large, so split if `runner.rs` or `state.rs` would pass 400 lines (put attach logic in `remote.rs`). Commit type: `feat`.

## Task 7.6: `reload-config` command

**Description:** `reload_config` request carrying TOML text; the daemon parses it with `AppConfig::from_toml_str` and applies it with `DesyncEngine::replace_profiles`, returning the profile count or a parse error. TUI Tab 3 gets `p` to push the validated config to an attached daemon.

**Acceptance criteria:**
- [ ] Invalid TOML returns an error and leaves the running profiles untouched
- [ ] Valid TOML swaps profiles and clears conntrack, as `replace_profiles` already does
- [ ] Only profiles are swapped; changing `qnum` or `fwmark` is rejected with a message asking for a daemon restart

**Verification:**
- [ ] `tests/control_server.rs` and `tests/tui_attach.rs` extended and green

**Dependencies:** 7.4, 7.5
**Files likely touched:** `src/control/{protocol,server}.rs`, `src/bin/nfqws2.rs`, `src/tui/{state,runner}.rs`
**Estimated scope:** Medium. Commit type: `feat`.

### Checkpoint B: After Tasks 7.5-7.6
- [ ] All tests pass, lint and both builds clean
- [ ] End-to-end manual run against a real queue: attach, view packets, reload config, stop
- [ ] Review with human before release

## Task 7.7: Docs, changelog, 1.1.0 release

**Description:** README section for the control socket with a sample systemd unit (`RuntimeDirectory=zapret-rs`, `User=`, `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`), CHANGELOG `1.1.0` heading consolidating entries written in earlier commits, version bump, annotated tag.

**Acceptance criteria:**
- [ ] `Cargo.toml` version is 1.1.0 and the changelog has Added/Changed entries
- [ ] Tag `v1.1.0` created on `main` after merge (not pushed unless asked)

**Verification:**
- [ ] Full test suite, lint, both builds, and `tests/repo_hygiene.rs` green

**Dependencies:** 7.1-7.6
**Files likely touched:** `README.md`, `CHANGELOG.md`, `Cargo.toml`, `Cargo.lock`
**Estimated scope:** Small. Commit type: `chore`.

### Checkpoint C: Milestone 7 Complete
- [ ] All acceptance criteria met
- [ ] Ready for review and merge
