# Task Breakdown: Milestone 2 (`nfqws2` Interception, CLI, Desync Loop, and Timers)

Target verification commands used across tasks:
- Lint: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- Tests: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`

---

## Task 2.1: Upgrade NFQUEUE intercepter with queue tuning, persistent `SIOCGIFNAME`, fwmark guard, and `poll()` loop

**Description:** Harden `src/intercepter` to match `zapret2/nfq2/nfqws.c` Linux NFQUEUE setup: configure queue max length (`4096`), socket receive buffer (`1 MiB`), best-effort fail-open, persistent `AF_INET` `SOCK_DGRAM` FD for `SIOCGIFNAME` index-to-name resolution, `desync_fwmark` loop-prevention guard, and `libc::poll` wakeup with clean shutdown flag support.

**Acceptance criteria:**
- [x] `QueueCatcher` configures `set_queue_max_len(qnum, 4096)`, `SO_RCVBUF = 1 MiB` (best-effort), `set_fail_open(qnum, true)` (best-effort), and unbinds on drop/exit.
- [x] Interface indices resolve via a single persistent `SOCK_DGRAM` `OwnedFd` using `SIOCGIFNAME`, and packets matching `(mark & desync_fwmark) != 0` return `Decision::Pass` without invoking the desync handler.
- [x] Dispatch helper, verdict mapping (`Pass`, `Drop`, `Replace(Vec<u8>)`), and poll timeout clamping are unit-tested without requiring root privileges.

**Verification:**
- [x] Tests pass: `cargo test --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --test intercepter_dispatch --offline`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline`
- [x] Manual check: confirm `src/intercepter/mod.rs` contains only `pub mod` and `pub use`, and `src/intercepter/` has zero `unwrap()`/`expect()` or `#[test]`.

**Dependencies:** None

**Files likely touched:**
- `src/intercepter/mod.rs`
- `src/intercepter/error.rs`
- `src/intercepter/ifname.rs`
- `src/intercepter/types.rs`
- `src/intercepter/nfqueue.rs`
- `tests/intercepter_dispatch.rs`

**Estimated scope:** Medium (6 files)

---

## Task 2.2: Implement profile filters, blobs, TOML config schema, and `clap` CLI

**Description:** Add `src/config` implementing `zapret2` filter primitives (`port_filter`, `icmp_filter`, `ipp_filter`, `packet_range`, `filter_mark`), built-in default blobs (`fake_default_tls`, `fake_default_http`, `fake_default_quic`) plus file/hex blobs, a `serde` + `toml` configuration file schema (`qnum`, `fwmark`, `bind_fix4`, `bind_fix6`, `debug`, `lua_init`, `[blobs]`, `[[profiles]]`, `[[profiles.actions]]`), and a `clap` derive CLI (`--config`, `--qnum`, `--fwmark`, `--debug`, `--dry-run`, `--intercept`, `--version`, `--pidfile`, `--daemon`, `--user`/`--uid`, `--chdir`) with CLI-over-config overrides.

**Acceptance criteria:**
- [x] Port (`[~]p1[-p2]|*`), ICMP (`type[:code]|*`), IP protocol, fwmark (`mark[/mask]`), and packet-range parsers match `zapret2/nfq2/filter.c` behavior including negation and invalid-input errors.
- [x] TOML config files with global settings, blobs, profiles, filters, and actions deserialize cleanly and merge with `clap` CLI overrides.
- [x] Workspace compiles with zero warnings under `cargo clippy --all-targets --offline -- -D warnings`.

**Verification:**
- [x] Tests pass: `cargo test --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --test config_toml --offline`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: confirm `--version`, `--dry-run`, and malformed flags or TOML files return deterministic typed errors without panicking.

**Dependencies:** None (can run immediately after Task 2.1)

**Files likely touched:**
- `Cargo.toml`
- `Cargo.lock`
- `src/lib.rs`
- `src/config/mod.rs`
- `src/config/error.rs`
- `src/config/filter.rs`
- `src/config/l7.rs`
- `src/config/blobs.rs`
- `src/config/schema.rs`
- `src/config/cli.rs`
- `tests/config_filters.rs`
- `tests/config_toml.rs`

**Estimated scope:** Medium (split Task 2.2 into Commit 2.2a `filter.rs` + Commit 2.2b `schema.rs` + `cli.rs` + tests to stay <= 5 files per commit)

---

## Task 2.3: Implement core `desync` pipeline and Lua desync-context bridge

**Description:** Build `src/desync` and `src/lua/desync_api.rs` to route dissected packets through matching `DesyncProfile` rules and execute configured Lua `--lua-desync` functions with the `zapret2` `(ctx, desync)` contract (`desync.dis`, `desync.arg`, `desync.func`, `desync.func_n`, `desync.func_instance`, `desync.profile_n`, `desync.profile_name`, `desync.cookie`, `desync.outgoing`, `desync.ifin`, `desync.ifout`, `desync.l7payload`, `desync.raw_packet`), plus C-API helpers `raw_packet`, `execution_plan`, `execution_plan_cancel`, `instance_cutoff`, and `lua_cutoff`.

**Acceptance criteria:**
- [x] Packets dissect once, match the first eligible `DesyncProfile` (L3, TCP/UDP port, ICMP, IPP, mark), and invoke each matching `lua_desync` action in order.
- [x] Lua actions returning `VERDICT_PASS`, `VERDICT_DROP`, or `VERDICT_MODIFY` (with optional `VERDICT_PRESERVE_NEXT` and modified `desync.dis`) produce the exact `Decision` and reconstructed wire bytes, and can invoke `rawsend` / `rawsend_dissect` safely during execution.
- [x] `execution_plan` / `execution_plan_cancel` and `raw_packet` work with `zapret2/lua/zapret-lib.lua` helpers.

**Verification:**
- [x] Tests pass: `cargo test --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --test desync_pipeline --offline`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: verify `VERDICT_MODIFY` updates IP/L4 checksums accurately and bad Lua return values fail gracefully to `Pass` with error logging.

**Dependencies:** Task 2.1, Task 2.2

**Files likely touched:**
- `src/lib.rs`
- `src/desync/mod.rs`
- `src/desync/engine.rs`
- `src/lua/desync_api.rs`
- `src/lua/mod.rs`
- `src/lua/runtime.rs`
- `tests/desync_pipeline.rs`

**Estimated scope:** Medium (split into Commit 2.3a `lua/desync_api.rs` + Commit 2.3b `desync/engine.rs` + tests)

---

## Checkpoint 2A: After Tasks 2.1-2.3
- [x] All tests (including `repo_hygiene`) pass (`cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`)
- [x] Clippy passes cleanly with `-D warnings`
- [x] Synthetic packet -> profile filter -> Lua desync -> `Pass`/`Drop`/`Replace` + `rawsend_dissect` flow works end-to-end
- [ ] Review with user before proceeding to Tasks 2.4-2.5

---

## Task 2.4: Implement timer pool, Lua `timer_*` bindings, and `poll()` timeout integration

**Description:** Port `zapret2/nfq2/timer.c` into `src/timer` using `CLOCK_BOOTTIME` monotonic milliseconds, expose `timer_set`, `timer_del`, `timer_info`, and `timer_enum` in `src/lua/timer_api.rs`, integrate next-deadline calculation into the NFQUEUE `poll()` loop and periodic `lua_gc`, and implement the `--intercept=0` timer-only loop (`NoInterceptLoop`).

**Acceptance criteria:**
- [x] Repeating and oneshot timers fire on schedule, honor deletion during callback (`dirty` flag), and return accurate `timer_info` / `timer_enum` metadata to Lua.
- [x] `--intercept=0` runs `lua_init` scripts, executes scheduled timers until none remain or shutdown is signaled, and exits with code 0.
- [x] NFQUEUE `poll()` sleeps until the earliest timer deadline without busy-looping.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml -E 'binary(timer_lua) or binary(repo_hygiene)' --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: verify bounded test completes in < 1s with zero busy-wait CPU spin.

**Dependencies:** Task 2.1, Task 2.3

**Files likely touched:**
- `src/lib.rs`
- `src/timer/mod.rs`
- `src/timer/pool.rs`
- `src/lua/timer_api.rs`
- `src/lua/mod.rs`
- `src/lua/runtime.rs`
- `src/intercepter/nfqueue.rs`
- `tests/timer_lua.rs`

**Estimated scope:** Medium (split into Commit 2.4a `src/timer/` + Commit 2.4b `lua/timer_api.rs` + poll hook + tests)

---

## Task 2.5: Wire `nfqws2` binary, process lifecycle, and live namespace smoke test

**Description:** Replace the placeholder `src/main.rs` with `src/bin/nfqws2.rs` (plus `src/runtime/process.rs` for pidfile, daemonize, `--chdir`, `--user`/`--uid` privilege drop, capability retention for `CAP_NET_RAW`/`CAP_NET_ADMIN`, and `SIGINT`/`SIGTERM`/`SIGHUP` signal flags). Connect CLI parsing, `RawSender::preinit`, Lua init/blobs, `--dry-run`, `--intercept=0`, and the NFQUEUE event loop.

**Acceptance criteria:**
- [ ] `nfqws2 --version`, `nfqws2 --dry-run ...`, and `nfqws2 --intercept=0 --lua-init=...` exit 0 with expected output and clean signal shutdown.
- [ ] Startup initializes `RawSender::preinit` before dropping privileges and handles `SIGINT`/`SIGTERM` cleanly without hanging or leaking pidfiles.
- [ ] End-to-end CLI smoke test passes offline, and live `unshare -r -n` NFQUEUE test runs if kernel `nfnetlink_queue` is accessible (or reports clearly if blocked by kernel config).

**Verification:**
- [ ] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [ ] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [ ] Manual check: run `nfqws2 --intercept=0 --lua-init=@../zapret2/lua/zapret-lib.lua --lua-init='DLOG_CONDUP("ok")'` and confirm clean exit 0.

**Dependencies:** Task 2.1, Task 2.2, Task 2.3, Task 2.4

**Files likely touched:**
- `Cargo.toml`
- `src/bin/nfqws2.rs` (replaces `src/main.rs`)
- `src/runtime/mod.rs`
- `src/runtime/process.rs`
- `tests/nfqws2_cli.rs`

**Estimated scope:** Medium (5 files)

---

## Checkpoint 2B: Milestone 2 Complete
- [ ] All tasks 2.1 through 2.5 checked off with individual atomic commits
- [ ] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [ ] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored suites (including `repo_hygiene`) and `rawsend_live` passes in `unshare -r -n`
- [ ] Review with user and plan Milestone 3
