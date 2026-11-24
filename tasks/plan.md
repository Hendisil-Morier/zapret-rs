# Implementation Plan: zapret-rs (Milestone 2 and Roadmap)

## Overview

Milestone 1 delivered the core packet engine (`src/packet`), Linux `SOCK_RAW` packet injector and topology queries (`src/rawsend`), and hardened LuaJIT runtime with `zapret2`-compatible packet and system bindings (`src/lua`). Milestone 2 turns those foundations into a working Linux `nfqws2` daemon in five vertical slices: hardened NFQUEUE packet interception, stateful sequential CLI and profile filters, the core desync pipeline and Lua desync context, timer scheduling, and the `nfqws2` process entry point. Subsequent milestones add conntrack and L7 protocol detection (Milestone 3), remaining Lua crypto/gzip/stat parity (Milestone 4), and the `ip2net` and `mdig` companion binaries (Milestone 5).

## Architecture Decisions

- **Synchronous `poll()` loop over `nfq::Queue` (no async runtime):** `nfq` 0.2.6 implements `AsRawFd` and `AsFd` on `Queue` and already disables `NETLINK_NO_ENOBUFS`. Pairing `nfq::Queue` with `libc::poll` and a single persistent `AF_INET` `SOCK_DGRAM` `OwnedFd` for `SIOCGIFNAME` matches `zapret2/nfq2/nfqws.c` without adding `tokio` or `mio`.
- **Sequential stateful GNU option parser for `nfqws2` CLI:** `nfqws2` options are order-dependent across `--new`, `--template`, `--import`, `--payload`, `--out-range`, `--in-range`, and `--lua-desync`, plus `@<file>`/`$<file>` config files. A small sequential long-option parser directly mirrors `getopt_long` semantics and lets us drop the currently unused `clap` dependency from `Cargo.toml` so `cargo clippy --all-targets --offline -- -D warnings` passes with zero warnings.
- **Minimal Milestone 2 `desync` slice before conntrack/L7 (Ponytail scope):** Milestone 2 executes profile matching (L3, TCP/UDP port, ICMP, IP protocol, fwmark) and Lua desync actions with `ctrack = nil` and baseline L7 payload tags (`empty`, `unknown`, `ipv4`, `ipv6`, `icmp`). Conntrack state, TCP stream reassembly, full L7 protocol detectors, hostlists, and ipsets land cleanly in Milestone 3.
- **Multi-binary crate layout:** Place the `nfqws2` executable at `src/bin/nfqws2.rs` (replacing the `Hello, world!` placeholder in `src/main.rs`) so Milestone 5 can add `src/bin/ip2net.rs` and `src/bin/mdig.rs` alongside shared library modules in `src/`.
- **Rust and project hygiene gates:** Every task must satisfy `cargo clippy --all-targets --offline -- -D warnings` (once `clap` is resolved), `cargo test --offline`, strict single-responsibility modules (`mod.rs` limited to `pub mod` and `pub use`), zero `#[cfg(test)]`/`#[test]` inside `src/`, no `unwrap()`/`expect()` in production code, `thiserror` for library errors, and one atomic commit per verified slice.

## Dependency Graph

```text
Milestone 1 (Complete): packet + rawsend + lua core
    |
    +--> Task 2.1: NFQUEUE intercepter (maxlen, rcvbuf, SIOCGIFNAME, fwmark guard, poll/signals)
    |        |
    +--> Task 2.2: Profile filter primitives + stateful CLI/config/blob parser
    |        |
    |        v
    +--> Task 2.3: Desync engine + Lua desync context (`ctx`, `desync`, cutoff, execution_plan)
             |
         [Checkpoint 2A: Packet -> filter -> Lua desync -> verdict end-to-end]
             |
             v
         Task 2.4: Timer pool + Lua timer bindings + poll timeout integration
             |
             v
         Task 2.5: `nfqws2` binary entry point, daemon/pidfile/droproot/caps, live smoke test
             |
         [Checkpoint 2B: Working `nfqws2` daemon for dry-run, `--intercept=0`, and NFQUEUE]
             |
             v
Milestone 3: Conntrack, TCP reassembly, L7 protocol/payload detectors, hostlists, ipsets, ipcache
             |
             v
Milestone 4: Lua crypto/gzip/time/stat parity + full `zapret2/lua/*.lua` test coverage
             |
             v
Milestone 5: `ip2net` and `mdig` binaries + `CHANGELOG.md` and release tagging
```

## Task List

Tasks and detailed acceptance criteria are tracked in `tasks/todo.md`.

### Milestone 2, Phase 1: Interception, CLI, and Desync Core
- [ ] Task 2.1: Upgrade `intercepter` with NFQUEUE tuning, persistent `SIOCGIFNAME`, fwmark loop guard, and `poll()` wakeup
- [ ] Task 2.2: Implement profile filters, default/custom blobs, and sequential `nfqws2` CLI parser
- [ ] Task 2.3: Implement core `desync` pipeline and Lua desync-context bindings

### Checkpoint 2A: Synthetic End-to-End Pipeline
- [ ] All unit and integration tests pass (`cargo test --offline`)
- [ ] Clippy passes cleanly (`cargo clippy --all-targets --offline -- -D warnings`)
- [ ] Synthetic packets traverse fwmark guard, profile matching, Lua desync action, and Pass/Drop/Modify verdicts
- [ ] Review with user before proceeding to Phase 2

### Milestone 2, Phase 2: Timers and `nfqws2` Process Lifecycle
- [ ] Task 2.4: Implement timer pool, Lua `timer_*` bindings, and `poll()` timeout / `--intercept=0` loop
- [ ] Task 2.5: Wire `src/bin/nfqws2.rs` with daemonize, pidfile, privilege drop, signal handling, and live namespace smoke test

### Checkpoint 2B: Milestone 2 Complete
- [ ] All acceptance criteria in `tasks/todo.md` met
- [ ] Full offline test suite and live `unshare -r -n` tests pass
- [ ] Ready for Milestone 3 planning

### Future Milestones (High-Level Roadmap)
- **Milestone 3 (Conntrack, L7, Hostlists, IPsets):** Bidirectional TCP/UDP conntrack (`conntrack.c`), stream reassembly, L7 protocol probes (`protocol.c`: HTTP, TLS + `tls_mod`, QUIC, DTLS, WireGuard, STUN, DNS, XMPP, DHT, Discord, MTProto, BitTorrent), `resolve_pos`/`resolve_multi_pos`/`resolve_range`, hostlist + autohostlist with SIGHUP reload, and CIDR ipset trie + `ipcache`.
- **Milestone 4 (Full Lua API Parity):** Crypto bindings (`hash`, `aes`, `aes_gcm`, `aes_ctr`, `hkdf`, `bcryptorandom`) + QUIC Initial decryption, streaming gzip/gunzip via cached `flate2`/`miniz_oxide`, `stat`/time helpers, `--writable`, and full verification against `zapret-antidpi.lua`, `zapret-auto.lua`, and `zapret-obfs.lua`.
- **Milestone 5 (Companion Binaries & Release):** Port `src/bin/ip2net.rs` and `src/bin/mdig.rs`, add `CHANGELOG.md`, and prepare semantic version release tags.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| `nfq` netlink socket requires `CAP_NET_ADMIN` and kernel `nfnetlink_queue` module for live NFQUEUE testing | Med | Keep unit/integration packet dispatch testable via a `PacketSource` or handler callback without root, and gate live NFQUEUE tests with `#[ignore]` in `unshare -r -n` just like `tests/rawsend_live.rs`. |
| Stateful `nfqws2` CLI flags (`--new`, `--template`, `--import`, `--payload`, `--lua-desync`) have subtle ordering rules | High | Mirror `nfqws.c` parsing order directly and write table-driven tests covering multi-profile, template import, range scoping, and `@config` file expansion. |
| `nfq::Queue::recv` blocks without timeout when timers or signals arrive | High | Set `queue.set_nonblocking(true)` (or poll `queue.as_raw_fd()` via `libc::poll` with next timer delta) and inspect atomic signal flags after `EINTR` or timeout. |
| Lua `desync` callbacks mutate `dissect` and invoke `rawsend_dissect` re-entrantly | Med | Keep `desync` context borrow scopes short, avoid holding `RefCell` borrows across Lua calls, and cover re-entrant `rawsend_dissect` + `VERDICT_MODIFY` in `tests/desync_pipeline.rs`. |

## Open Questions

1. **Drop unused `clap` dependency from `Cargo.toml`?** `nfqws2` requires a stateful sequential GNU option parser (because `--new`, `--payload`, and `--out-range` modify subsequent flags), and removing unused `clap` immediately enables `cargo clippy --all-targets --offline -- -D warnings` with zero manifest warnings. Confirm whether to remove `clap` now (it can be re-added in Milestone 5 if desired for `ip2net`/`mdig`).
2. **Replace placeholder `src/main.rs` with `src/bin/nfqws2.rs`?** Moving to `src/bin/nfqws2.rs` aligns the output binary name directly with `zapret2`'s `nfqws2` and prepares the layout for `src/bin/ip2net.rs` and `src/bin/mdig.rs`. Confirm this layout before Task 2.5.
