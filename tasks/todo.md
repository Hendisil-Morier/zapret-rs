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
- [x] Review with user before proceeding to Tasks 2.4-2.5

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
- [x] `nfqws2 --version`, `nfqws2 --dry-run ...`, and `nfqws2 --intercept=0 --lua-init=...` exit 0 with expected output and clean signal shutdown.
- [x] Startup initializes `RawSender::preinit` before dropping privileges and handles `SIGINT`/`SIGTERM` cleanly without hanging or leaking pidfiles.
- [x] End-to-end CLI smoke test passes offline, and live `unshare -r -n` NFQUEUE test (`live_nfqueue_daemon_starts_and_exits_on_sigterm`) passes alongside `rawsend_live`.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: run `nfqws2 --intercept=0 --lua-init=@../zapret2/lua/zapret-lib.lua --lua-init='DLOG_CONDUP("ok")'` and confirm clean exit 0.

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
- [x] All tasks 2.1 through 2.5 checked off with individual atomic commits
- [x] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [x] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored suites (including `repo_hygiene`) and all 3 live tests (`rawsend_live` + `live_nfqueue_daemon_starts_and_exits_on_sigterm`) pass in `unshare -r -n`
- [x] Review with user and plan Milestone 3

---

# Task Breakdown: Milestone 3 (Conntrack, L7 Detectors, Hostlists, IPsets, and IPCache)

## Task 3.1: Conntrack, TCP stream reassembly, `PacketRange`, `desync.track`, `conntrack_feed`, and cutoffs

**Description:** Port `zapret2/nfq2/conntrack.c` into `src/conntrack` (`types.rs`, `reasm.rs`, `pool.rs`, `mod.rs`) with 5-tuple IPv4/IPv6 TCP and UDP tracking, SYN/SYN-ACK/ESTABLISHED/FIN transitions, `scale <= 14` window shifting, wrapping sequence positions, `rseq_over_2g`, `bReverse`/`bReverseFixed` direction resolution, timeout purging via monotonic `CLOCK_BOOTTIME` seconds, FIFO delayed-packet replay snapshots, and continuous `ReasmFeed` reassembly. Implement `check_pos_from`, `check_pos_to`, `check_pos_range`, and `check_pos_cutoff` in `src/config/range.rs`, encode `desync.track` (with persistent `lua_state` table, `pos.direct`/`pos.reverse` aliases, relative TCP fields, and `replay*`/`reasm_offset`/`reasm_data` fields) in `src/lua/ctrack_encode.rs` + `src/lua/desync_encode.rs`, and wire `conntrack_feed`, `instance_cutoff`, and `lua_cutoff` in `src/lua/desync_api.rs` + `src/lua/runtime.rs`.

**Acceptance criteria:**
- [x] `ConntrackPool::feed` tracks client/server bidirectional TCP and UDP flows (`SYN-ACK` creates swapped key preserving client/server orientation), updates `pcounter`/`pdcounter`/`pbcounter`/`pos`/`uppos`/`uppos_prev`/`winsize_calc`/`mss`, latches `rseq_over_2g`, and evicts expired entries at rate-limited intervals.
- [x] `ReasmState` rejects forward gaps and overflow (`0x100000` window), overwrites overlapping retransmissions consistently, and buffers up to 64 delayed packets for replay on completion.
- [x] `PacketRange` enforces `n`/`d`/`b`/`s`/`p`/`a`/`x` bounds and cutoff semantics cleanly on both tracked and untracked flows.
- [x] Lua `desync.track` preserves `lua_state` across packets of the same flow, `conntrack_feed` injects synthetic/dissected packets and propagates `ctx.ctrack` to subsequent actions, and `instance_cutoff` / `lua_cutoff` suppress further execution on matching directions.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml -E 'binary(conntrack_reasm) or binary(conntrack_lua) or binary(config_filters) or binary(desync_lua_bridge) or binary(repo_hygiene)' --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: verify `LuaRuntime` drops `ConntrackPool` registry keys cleanly before shutdown and `tests/repo_hygiene.rs` passes (`src/` <= 400 lines, `tests/` <= 450 lines).

**Dependencies:** Milestone 2

**Files likely touched:**
- `src/lib.rs`
- `src/timer/clock.rs` & `src/timer/mod.rs`
- `src/conntrack/{mod.rs,types.rs,reasm.rs,entry.rs,pool.rs}`
- `src/config/range.rs`
- `src/lua/{mod.rs,ctrack_encode.rs,desync_encode.rs,desync_api.rs,runtime.rs}`
- `src/desync/{engine.rs,verdict.rs}`
- `tests/conntrack_reasm.rs`
- `tests/conntrack_lua.rs`
- `tests/config_filters.rs`
- `tests/desync_lua_bridge.rs`

**Estimated scope:** Large — Commit 3.1a (`src/timer/clock.rs`, `src/conntrack/`, `src/config/range.rs`) + Commit 3.1b (`src/lua/ctrack_encode.rs`, `desync_api.rs`, `desync_encode.rs`, `runtime.rs`, tests).

---

## Task 3.2: L7 protocol/payload detectors, QUIC Initial decryption, `tls_mod`, and position markers

**Description:** Port `zapret2/nfq2/protocol.c` into `src/protocol` (`http.rs`, `tls.rs`, `tls_mod.rs`, `aes_block.rs`, `quic.rs`, `datagram.rs`, `markers.rs`, `mod.rs`) covering HTTP (`IsHttp`, `HttpExtractHost`, `IsHttpReply`, `HttpReplyLooksLikeDPIRedirect`), TLS (`IsTLS*`, `TLSFindExt*`, `TLSHelloExtractHost*`, `TLSMod` `rnd`/`rndsni`/`sni`/`dupsid`/`padencap`), QUIC Initial validation + offline `ring` HKDF-SHA256/AES-128-GCM/HP decryption (`QUICDecryptInitial`) + `QUICDefragCrypto`, MTProto AES-256 single-block ECB check, XMPP (4), DNS (2), WireGuard (5), DHT, Discord IP discovery, STUN, DTLS (3), BitTorrent, and uTP-BT. Implement position markers (`abs`, `host`, `endhost`, `sld`, `midsld`, `endsld`, `method`, `extlen`, `sniext`) and expose `resolve_pos`, `resolve_multi_pos`, `resolve_range`, and `tls_mod` in `src/lua/protocol_api.rs`.

**Acceptance criteria:**
- [x] All L7 probes classify `L7Proto` and `L7Payload` matching `protocol.c`, extract lowercase hostnames from HTTP `Host:` and TLS/QUIC SNI extensions, and detect HTTP `302`/`307` off-SLD/off-IP DPI redirects.
- [x] `QUICDecryptInitial` + `QUICDefragCrypto` decrypt QUIC draft/v1/v2 Initial packets via offline `ring` and extract TLS ClientHello handshakes without requiring Milestone 4 Lua crypto bindings.
- [x] `tls_mod` supports `rnd`, `rndsni`, `sni=<host>`, `dupsid`, `padencap`, and `none`, adjusting all 6 TLS length headers accurately when SNI or padding grows/shrinks.
- [x] `resolve_pos`, `resolve_multi_pos`, and `resolve_range` enforce strict string types, 1-based default indexing (plus optional `zero_based_pos`), and `strict` range semantics cleanly in Lua.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml -E 'binary(protocol_detect) or binary(protocol_markers_lua) or binary(repo_hygiene)' --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: verify `cargo check --offline` builds with `ring = "0.17.14"` without touching network.

**Dependencies:** Milestone 2

**Files likely touched:**
- `Cargo.toml`
- `Cargo.lock`
- `src/lib.rs`
- `src/protocol/{mod.rs,http.rs,tls.rs,tls_mod.rs,aes_block.rs,quic.rs,quic_crypto.rs,datagram.rs,markers.rs}`
- `src/lua/{mod.rs,protocol_api.rs,runtime.rs}`
- `tests/protocol_detect.rs`
- `tests/protocol_markers_lua.rs`

**Estimated scope:** Large — Commit 3.2a (`Cargo.toml` `ring` + `src/protocol/{http,tls,tls_mod,aes_block,quic,quic_crypto,datagram,markers}.rs`) + Commit 3.2b (`src/lua/protocol_api.rs`, `tests/protocol_*.rs`).

---

## Checkpoint 3A: After Tasks 3.1-3.2
- [x] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [x] `cargo nextest run --offline --show-progress none --no-pager` passes all suites including `conntrack_reasm`, `conntrack_lua`, `protocol_detect`, `protocol_markers_lua`, and `repo_hygiene`
- [x] Review with user before proceeding to Tasks 3.3-3.4

---

## Task 3.3: Hostlists, autohostlist failure detector, disjoint CIDR IPsets, gzip loader, and IPCache

**Description:** Add `flate2` (pure-Rust `rust_backend`, offline-cached) to `Cargo.toml` and port `zapret2/nfq2/{hostlist.c,ipset.c,pools.c}` into `src/lists` (`file_loader.rs`, `hostlist.rs`, `autohostlist.rs`, `ipset.rs`, `ipcache.rs`, `mod.rs`). Implement gzip/plain streaming readers with `(mtime_sec, mtime_nsec, size)` signature reload resilience, subdomain suffix matching (`^` strict, `!` exempt, `no_match_subdomains`, exclude-before-include, `"@&()"` empty-autolist sentinel), autohostlist `HostFailPool` non-refreshed failure windows (TCP retransmissions, incoming RST / HTTP 302/307 redirect, UDP in/out heuristic, file self-append + debug log), disjoint IPv4/IPv6 CIDR prefix trees (`parse_cidr4`/`parse_cidr6` with non-fatal bad lines), and rate-limited TTL-based `IpCache` (empty-iface hostnames + iface-keyed client TTLs).

**Acceptance criteria:**
- [x] Plain and `.gz` (`0x1F 0x8B`) hostlists and IPsets parse comments/prefixes/CIDRs cleanly, tolerate transient unreadable reloads by keeping cached sets, and enforce exclude-before-include semantics.
- [x] `HostFailPool` tracks `fail_threshold` hits inside non-refreshed `fail_time` windows from first failure, appends new domains safely without triggering spurious self-reloads, and honors `!` auto-exemptions.
- [x] `IpSet` maintains minimal non-overlapping IPv4 and IPv6 CIDR prefixes and supports dual-IP (`dst` / `src`) checks in O(log N).
- [x] `IpCache` expires entries past `lifetime_sec`, keys hostname entries globally while keying TTL entries per `(ip, iface)` in client mode, and purges rate-limited at <= 1 Hz.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml -E 'binary(lists_and_ipcache) or binary(repo_hygiene)' --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: confirm `.gz` hostlist/ipset decompression works offline with `flate2` `rust_backend` and all files stay <= 400 lines.

**Dependencies:** Task 3.2 (uses `IpAddr` parsing helpers / DPI redirect detection patterns)

**Files likely touched:**
- `Cargo.toml`
- `Cargo.lock`
- `src/lib.rs`
- `src/lists/{mod.rs,file_loader.rs,hostlist.rs,autohostlist.rs,ipset.rs,ipcache.rs}`
- `tests/lists_and_ipcache.rs`

**Estimated scope:** Large — Commit 3.3a (`Cargo.toml` `flate2`, `file_loader.rs`, `hostlist.rs`, `ipset.rs`, `ipcache.rs`) + Commit 3.3b (`autohostlist.rs`, `tests/lists_and_ipcache.rs`).

---

## Task 3.4: Config split, CLI flags, full `DesyncEngine` stateful wiring, `SIGHUP` reload, and E2E tests

**Description:** Split `src/config/schema.rs` (`391` lines -> `schema.rs` + `profile_schema.rs`) and extract `src/config/runtime_cfg.rs` (`ConntrackConfig`, `IpCacheConfig`, `ProfileListsConfig`) before adding Milestone 3 TOML tables and CLI options (`--server`, `--ctrack-timeouts`, `--ctrack-disable`, `--ipcache-lifetime`, `--ipcache-hostname`, `--payload-disable`, `--reasm-disable`, `--hostlist-auto-debug`). Add `L7_PAYLOAD_NONE_MASK` (`1u64 << 31`) disable masks in `src/config/l7.rs`. Refactor `src/desync/` (`autohost.rs`, `dns_cache.rs`, `engine.rs`, `icmp_ip.rs`, `mod.rs`, `play.rs`, `probe.rs`, `profile_state.rs`, `reasm_replay.rs`, `rediscovery.rs`, `tcp.rs`, `udp.rs`, `verdict.rs`) to wire `ConntrackPool`, `IpCache`, L7 probes, DNS A/AAAA hostname learning, TLS/QUIC client-side reassembly + `replay_queue` + `dp_rediscovery`, hostlist/autohostlist/ipset `dp_match`, synthetic TCP RST on retrans fail, and `ct_new_postnat_fix`. Wire `verify_config_list_files` validation and `SIGHUP` reload into `src/bin/nfqws2.rs` and `src/timer/runner.rs`, and add end-to-end tests.

**Acceptance criteria:**
- [x] Every TOML field and CLI override resolves deterministically, rejects `hostlist_auto` when `--server` or `--ctrack-disable` is set, and keeps all `src/` files strictly `<= 400` lines.
- [x] Outgoing multi-segment TLS ClientHello triggers reassembly, buffers packets, replays all pieces with populated `desync.reasm_data`/`desync.reasm_offset`/`desync.replay*`, and preserves `desync.track.lua_state` across packets.
- [x] QUIC Initial packets decrypt cleanly for SNI matching/hostlists and populate `desync.decrypt_data`, while `SIGHUP` reloads modified hostlist/ipset files inside `nfqws2`.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Live check: `unshare -r -n bash -c 'ip link set lo up && cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --run-ignored only --show-progress none --no-pager'` passes all ignored kernel tests.

**Dependencies:** Task 3.1, Task 3.2, Task 3.3

**Files likely touched:**
- `src/config/{mod.rs,l7.rs,runtime_cfg.rs,model.rs,schema.rs,profile_schema.rs,cli.rs}`
- `src/desync/{mod.rs,autohost.rs,dns_cache.rs,engine.rs,icmp_ip.rs,play.rs,probe.rs,profile_state.rs,reasm_replay.rs,rediscovery.rs,tcp.rs,udp.rs,verdict.rs}`
- `src/timer/{mod.rs,runner.rs}`
- `src/bin/nfqws2.rs`
- `tests/config_toml.rs`
- `tests/config_filters.rs`
- `tests/desync_m3_e2e.rs`
- `tests/nfqws2_cli.rs`

**Estimated scope:** Large — Commit 3.4a (`src/config/*` split & M3 schema/CLI) + Commit 3.4b (`src/desync/*`, `src/timer/*`, `src/bin/nfqws2.rs`) + Commit 3.4c (E2E integration & CLI validation tests).

---

## Checkpoint 3B: Milestone 3 Complete
- [x] All tasks 3.1 through 3.4 checked off with individual atomic commits
- [x] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [x] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored suites (including `repo_hygiene`) and ignored kernel tests pass in `unshare -r -n`
- [x] Review with user and plan Milestone 4

---

# Task Breakdown: Milestone 4 (Full Lua API Parity & zapret2 Script Verification)

## Task 4.1: Pure-Rust crypto primitives (SHA-224/256, HKDF, AES-128/192/256 ECB/CTR/GCM) and Lua bindings

**Description:** Create pure-Rust `src/crypto/` (`error.rs`, `sha2.rs`, `aes.rs`, `aes_gcm.rs`, facade `mod.rs`) covering FIPS 180-4 SHA-224/SHA-256, RFC 2104 HMAC, RFC 5869 HKDF, FIPS-197 AES-128/192/256 ECB/CTR with 128-bit big-endian `ctr_add`, and NIST SP 800-38D AES-GCM with arbitrary non-empty IV lengths and unconditional `(out, tag16)` return on decrypt. Deduplicate `src/protocol/aes_block.rs` to delegate to `src/crypto/aes.rs`, add coercing byte/string extractors in `src/lua/helpers.rs`, wire `hash`, `aes`, `aes_gcm`, `aes_ctr`, and `hkdf` in `src/lua/crypto_api.rs`, and verify against unmodified `zapret2/lua/zapret-tests.lua::test_crypto()`, NIST/RFC/FIPS KATs, and `ring` cross-checks.

**Acceptance criteria:**
- [x] `src/crypto/` provides SHA-224/256, HMAC, HKDF (`okm_len == 0` or `> 255 * hash_len` returns `nil` without oversized allocation), AES-128/192/256 ECB/CTR, and AES-GCM (arbitrary IV >= 1 byte, returns `(out, tag16)` on decrypt even on tag mismatch) with zero new Cargo dependencies.
- [x] `src/protocol/aes_block.rs` delegates to `src/crypto/aes.rs` with zero duplicated AES S-boxes or round logic.
- [x] Lua `hash`, `aes`, `aes_gcm`, `aes_ctr`, and `hkdf` pass unmodified `zapret-tests.lua::test_crypto()` alongside NIST SP 800-38D, FIPS-197, FIPS 180-4, and RFC 5869 vectors.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`
- [x] Manual check: confirm `src/` files `<= 400` lines, `tests/lua_crypto.rs` `<= 450` lines, pure `mod.rs` facades, and zero `.unwrap(`/`.expect(`/`#[test]` in `src/`.

**Dependencies:** Checkpoint 3B

**Files likely touched:**
- `src/lib.rs`
- `src/crypto/{mod.rs,error.rs,sha2.rs,aes.rs,aes_gcm.rs}`
- `src/protocol/aes_block.rs`
- `src/lua/{mod.rs,helpers.rs,crypto_api.rs,runtime.rs}`
- `tests/lua_crypto.rs`

---

## Task 4.2: Streaming gzip/gunzip, stat/time Lua bindings, and `--writable` support

**Description:** Implement `src/lua/{gzip_deflate.rs,gzip_inflate.rs,gzip_api.rs}` over `flate2` `rust_backend` (`Compress`, `Decompress`, `Crc`) with an RFC 1952 streaming header/trailer state machine covering raw deflate (`-15..=-8`), zlib (`8..=15`), gzip (`24..=31`), and auto-detect (`40..=47`), handling arbitrary byte-boundary splits and lifecycle invalidation. Implement `src/lua/fs_time_api.rs` exposing `stat`, `localtime`, `gmtime`, `timelocal`, and `timegm` via `libc`. Implement `--writable[=DIR]` and TOML `writable` in `src/runtime/writable.rs` (defaulting to `$TMPDIR/zapret-rs` or `/tmp/zapret-rs`), wiring it into config/CLI and `nfqws2`.

**Acceptance criteria:**
- [x] Streaming gzip/gunzip bindings pass unmodified `zapret-tests.lua::test_gzip()` including byte-by-byte / mid-header splits, invalid handles, and role mismatches.
- [x] `stat`, `localtime`, `gmtime`, `timelocal`, and `timegm` pass `zapret-tests.lua::test_time()` and POSIX metadata/error parity checks.
- [x] `--writable` creates the directory (`$TMPDIR/zapret-rs` or `/tmp/zapret-rs` default) and exports `WRITABLE`.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Task 4.1

---

## Task 4.3: Full unmodified `zapret2/lua/*.lua` E2E verification and parity hardening

**Description:** Add `tests/lua_zapret_scripts_e2e.rs` verifying all non-live suites in `zapret2/lua/zapret-tests.lua` along with unmodified `zapret-antidpi.lua` (`fake`+`tls_mod`, `multisplit`, `multidisorder`, `fakedsplit`, `hostfakesplit`, `syndata`), `zapret-obfs.lua` (`wgobfs` round-trip), `zapret-auto.lua` (`circular` rotation), and `zapret-pcap.lua` (writing under `WRITABLE`), fixing any parity edge cases uncovered.

**Acceptance criteria:**
- [x] Unmodified `zapret2/lua/{zapret-lib,zapret-tests,zapret-antidpi,zapret-auto,zapret-obfs,zapret-pcap}.lua` load cleanly and execute expected test scenarios.
- [x] Any subtle Lua host binding discrepancies uncovered during real-script execution are fixed and regression-tested.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Task 4.2

---

## Checkpoint 4: Milestone 4 Complete
- [x] All tasks 4.1 through 4.3 checked off with individual atomic commits
- [x] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [x] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored suites (including `repo_hygiene`) and ignored kernel tests pass in `unshare -r -n`
- [x] Review with user and plan Milestone 5

---

# Task Breakdown: Milestone 5 (Companion Binaries & v1.0.0 Release)

## Task 5.1: Implement `ip2net` library (`src/tools/ip2net.rs`) and CLI binary (`src/bin/ip2net.rs`)

**Description:** Create `src/tools/{mod.rs,ip2net.rs}`, expose `pub mod tools` in `src/lib.rs`, and wire `src/bin/ip2net.rs` in `Cargo.toml` with zero new dependencies. Implement full flag parity with `zapret2/ip2net/ip2net.c` (`-4`, `-6`, `--prefix-length=min[-max]`, `--v4-threshold=mul/div`, `--v6-threshold=N`, `-h`/`--help`, `--version`), streaming pass-through of valid CIDRs (`< /32` / `< /128`) and ranges, `/32` and `/128` single-IP folding, `u64`-safe IPv4 threshold pruning, IPv6 `u128` aggregation, and the smallest-subnet anti-carpet-bombing tie-breaker. Verify library and subprocess behavior in `tests/ip2net_cli.rs`.

**Acceptance criteria:**
- [x] `-4`, `-6`, `--prefix-length`, `--v4-threshold`, `--v6-threshold`, `--help`, and `--version` parse and validate with last-flag-wins family override and deterministic exit code `1` on invalid parameters.
- [x] Streaming pass-through emits valid CIDRs and ranges before sorted/deduplicated single-IP aggregation, folds `/32` and `/128`, ignores invalid/out-of-range/non-UTF-8 lines, and preserves C threshold and smallest-subnet tie-breaker outputs.
- [x] `tests/ip2net_cli.rs` verifies IPv4/IPv6 grouping, anti-carpet-bombing, fast-prune boundary, pass-through ordering, parameter errors, and `ip2net` subprocess runs.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Checkpoint 4

**Files likely touched:**
- `Cargo.toml`
- `src/lib.rs`
- `src/tools/{mod.rs,ip2net.rs}`
- `src/bin/ip2net.rs`
- `tests/ip2net_cli.rs`

---

## Task 5.2: Implement `mdig` DNS/resolver library and CLI binary (`src/bin/mdig.rs`)

**Description:** Create `src/tools/{mdig_backend.rs,mdig_dns.rs,mdig_resolver.rs}` and `src/bin/mdig.rs` with a `[[bin]]` entry in `Cargo.toml`, sharing RFC 1035 DNS name-skipping and `A`/`AAAA` record decoding helpers in `src/protocol/datagram.rs` with `src/desync/dns_cache.rs`. Implement full CLI and exit-code parity (`--family`, `--threads`, `--eagain`, `--eagain-delay`, `--verbose`, `--stats`, `--log-resolved`, `--log-failed`, `--dns-make-query`, `--dns-parse-query`) over an injectable `DnsResolver` trait backed by `libc::getaddrinfo` in production. Verify offline in `tests/mdig_cli.rs`.

**Acceptance criteria:**
- [x] `--dns-make-query` and `--dns-parse-query` encode/decode RFC 1035 binary DNS packets and compressed answers matching `mdig.c` exit codes (`1`, `10`, `11`).
- [x] Multi-threaded resolution supports `--family`, `--threads=1..=100`, `--eagain` retry delays, transparent IP/CIDR filtering, `--stats=N`, `--verbose`, and `--log-resolved` / `--log-failed` (exit `5` on creation error).
- [x] `tests/mdig_cli.rs` verifies all modes deterministically offline via `DnsResolver` mocks and subprocess runs.

**Verification:**
- [x] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [x] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Task 5.1

**Files likely touched:**
- `Cargo.toml`
- `src/protocol/{mod.rs,datagram.rs}`
- `src/desync/dns_cache.rs`
- `src/tools/{mod.rs,mdig_backend.rs,mdig_dns.rs,mdig_resolver.rs}`
- `src/bin/mdig.rs`
- `tests/mdig_cli.rs`

---

## Task 5.3: Release preparation (`CHANGELOG.md`, `README.md`, `1.0.0` bump, live gates, `v1.0.0` tag)

**Description:** Write `CHANGELOG.md` summarizing Milestones 1 through 5 and a concise `README.md` covering `nfqws2`, `ip2net`, `mdig`, build instructions, and configuration usage. Bump `Cargo.toml` package version to `1.0.0`, run full release builds (`cargo build --release --offline`), offline lint and nextest suites, and `unshare -r -n` live kernel tests, then create an annotated `v1.0.0` git tag.

**Acceptance criteria:**
- [x] `CHANGELOG.md` and `README.md` are accurate and complete, and `Cargo.toml` / `Cargo.lock` record `version = "1.0.0"`.
- [x] `cargo build --release --offline` builds `nfqws2`, `ip2net`, and `mdig` cleanly, and `clippy`, `nextest`, and `unshare -r -n` live kernel tests pass after final edits.
- [x] Annotated git tag `v1.0.0` points to the Checkpoint 5 commit.

**Dependencies:** Task 5.2

---

## Checkpoint 5: Milestone 5 & v1.0.0 Release Complete
- [x] All tasks 5.1 through 5.3 checked off with individual atomic commits
- [x] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [x] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored suites (including `repo_hygiene`) and ignored kernel tests pass in `unshare -r -n`
- [x] `cargo build --release --offline` builds `nfqws2`, `ip2net`, and `mdig`, and `v1.0.0` tag is created

---

# Task Breakdown: Milestone 6 (`strat_finder` Native Strategy Finder)

## Task 6.1: Engine profile hot-swap, `strat_finder` domain model, strategy catalog, and TOML generator

**Description:** Add `DesyncEngine::replace_profiles` (delegated cleanly into `src/desync/profile_state.rs` to respect the 400-line ceiling on `src/desync/engine.rs`), create `src/tools/strat_catalog.rs` and `src/tools/strat_toml.rs` with typed scan levels (`Quick`, `Standard`, `Force`), protocols (`Http`, `Tls12`, `Tls13`, `Http3`), fooling/split/fake/hostfakesplit/QUIC strategy expansion ported from `zapret2/blockcheck2.d/standard`, complexity + latency ranking, minimal cross-domain set cover, and `nfqws2.toml` rendering.

**Acceptance criteria:**
- [ ] `DesyncEngine::replace_profiles` swaps active profiles in memory, validates Lua functions, and clears `conntrack` and `ipcache` state without recreating `LuaRuntime`.
- [ ] Strategy catalog emits distinct deterministic candidate sets for `Quick`, `Standard`, and `Force` levels across HTTP, TLS 1.2/1.3, and HTTP/3 (IPv4 and IPv6).
- [ ] Every generated `nfqws2.toml` config parses cleanly back via `AppConfig::from_toml_str` and selects minimal covering profiles across multiple domains in `tests/strat_finder_toml.rs`.

**Verification:**
- [ ] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [ ] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Checkpoint 5

**Files likely touched:**
- `src/desync/{engine.rs,profile_state.rs}`
- `src/tools/{mod.rs,strat_catalog.rs,strat_toml.rs}`
- `tests/strat_finder_toml.rs`

**Estimated scope:** Medium (5 files, <= 400 lines per `src/` file)

---

## Checkpoint 6A: Strategy Catalog & Engine Profile Swap Verified
- [ ] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [ ] `cargo nextest run --offline --show-progress none --no-pager` passes including `repo_hygiene`

---

## Task 6.2: `nftables` + `QueueCatcher` worker, `ProbeBackend` (`curl` + mock), and scan orchestrator

**Description:** Create `src/tools/strat_probe.rs` and `src/tools/strat_runner.rs` implementing injectable `ProbeBackend` and `FirewallBackend` traits, `CurlProbeBackend` (measuring RTT, classifying timeouts, TCP RSTs, TLS errors, and spoofed HTTP 3xx redirects, plus HTTP/3 capability detection), RAII `NftFirewallBackend` (`table inet zapret_strat_finder` with `bypass` queue rules and `fwmark` loop guard), an in-process NFQUEUE + `DesyncEngine` worker thread communicating via channel ACK swaps, and multi-domain scan orchestration (`baseline -> sweep -> rank -> coverage`).

**Acceptance criteria:**
- [ ] Direct baseline probing classifies unblocked, timed-out, reset, TLS-blocked, and spoof-redirect responses accurately before running desync sweeps.
- [ ] Worker thread handles profile swaps atomically via channel ACK and exits cleanly with `NftQueueGuard` cleanup on completion or shutdown signal.
- [ ] Offline `tests/strat_finder_runner.rs` verifies baseline pruning, `--stop-on-first`, latency ranking, spoof-redirect rejection, and multi-domain set cover over mock backends.

**Verification:**
- [ ] Tests pass: `cargo nextest run --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --offline --show-progress none --no-pager`
- [ ] Build succeeds: `cargo clippy --manifest-path /home/morier/Documents/projects/zapret-rs/Cargo.toml --all-targets --offline -- -D warnings`

**Dependencies:** Task 6.1

**Files likely touched:**
- `src/tools/{mod.rs,strat_probe.rs,strat_runner.rs}`
- `tests/strat_finder_runner.rs`

**Estimated scope:** Medium (4 files)

---

## Task 6.3: `src/bin/strat_finder.rs` CLI, Cargo target, `README.md` docs, and verification

**Description:** Create `src/bin/strat_finder.rs` with `clap` CLI flags (`--domain`, `--proto`, `--level`, `--ipv4`/`--ipv6`, `--qnum`, `--fwmark`, `--timeout`, `--stop-on-first`, `--write-config`, `--json`, `--lua-dir`, `--curl-bin`, `--version`, plus interactive domain prompt on TTY when no `--domain` is passed), add `[[bin]] name = "strat_finder"` to `Cargo.toml`, add `strat_finder` CLI/TOML subprocess checks in `tests/strat_finder_runner.rs`, and document usage in `README.md`.

**Acceptance criteria:**
- [ ] `strat_finder --version`, `--help`, invalid-flag handling, and `--write-config` serialization work deterministically without root.
- [ ] `cargo build --release --offline` produces `target/release/strat_finder` alongside `nfqws2`, `ip2net`, and `mdig`.
- [ ] `clippy`, full `cargo nextest run --offline` (including `repo_hygiene`), and `unshare -r -n` live kernel tests pass after the final edit.

**Dependencies:** Task 6.2

**Files likely touched:**
- `Cargo.toml`
- `src/bin/strat_finder.rs`
- `tests/strat_finder_runner.rs`
- `README.md`

**Estimated scope:** Small-Medium (4 files)

---

## Checkpoint 6B: Milestone 6 Complete
- [ ] All tasks 6.1 through 6.3 checked off with clean atomic commits on `feature/strat-finder` merged to `main` (or clean trunk commits)
- [ ] `cargo clippy --all-targets --offline -- -D warnings` passes with 0 warnings
- [ ] `cargo nextest run --offline --show-progress none --no-pager` passes all non-ignored tests including `repo_hygiene`
- [ ] `cargo build --release --offline` builds all four binaries and `unshare -r -n` live kernel checks pass
