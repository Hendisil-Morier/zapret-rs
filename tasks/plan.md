# Implementation Plan: zapret-rs (Milestone 3 and Roadmap)

## Overview

Milestone 1 delivered the core packet engine (`src/packet`), Linux `SOCK_RAW` packet injector and topology queries (`src/rawsend`), and hardened LuaJIT runtime with `zapret2`-compatible packet and system bindings (`src/lua`). Milestone 2 completed the working `nfqws2` Linux daemon with hardened NFQUEUE interception (`src/intercepter`), TOML + `clap` configuration (`src/config`), core profile dispatch (`src/desync`), `CLOCK_BOOTTIME` Lua timers (`src/timer`), and daemon/privilege-drop/signal lifecycle (`src/runtime`, `src/bin/nfqws2.rs`).

Milestone 3 turns `nfqws2` into a full stateful DPI desync engine in four vertical slices: bidirectional conntrack and continuous TCP/QUIC stream reassembly (`Task 3.1`), full L7 protocol detectors, QUIC Initial decryption, `tls_mod`, and position markers (`Task 3.2`), domain hostlists, autohostlists, CIDR IPsets, and `ipcache` (`Task 3.3`), and config/CLI/pipeline/SIGHUP integration (`Task 3.4`). Subsequent milestones cover remaining Lua crypto/gzip/stat/time parity (`Milestone 4`) and the `ip2net` and `mdig` companion binaries (`Milestone 5`).

## Architecture Decisions

- **Synchronous `poll()` loop over `nfq::Queue` (no async runtime):** `nfq` 0.2.6 implements `AsRawFd` and `AsFd` on `Queue` and already disables `NETLINK_NO_ENOBUFS`. Pairing `nfq::Queue` with `libc::poll` and a single persistent `AF_INET` `SOCK_DGRAM` `OwnedFd` for `SIOCGIFNAME` matches `zapret2/nfq2/nfqws.c` without adding `tokio` or `mio`.
- **Offline-cached crypto & gzip crates for Milestone 3 (`ring` + `flate2`, plus pure-Rust AES-256 block):** Add `ring = "0.17.14"` (for QUIC Initial HKDF-SHA256, AES-128-GCM, and header protection) and `flate2 = { version = "1.1.11", default-features = false, features = ["rust_backend"] }` (for transparent `0x1F 0x8B` gzipped hostlists/ipsets and later Milestone 4 Lua gzip/gunzip reuse), alongside a small pure-Rust FIPS-197 AES-256 single-block ECB module (`src/protocol/aes_block.rs`) for `IsMTProto` and Milestone 4 reuse. Every crate and transitive dependency is verified present in the local Cargo cache.
- **Strict single-responsibility module split (`<= 400` lines in `src/`, `<= 450` in `tests/`):**
  - `src/conntrack/`: `types.rs`, `reasm.rs`, `pool.rs`, and pure facade `mod.rs`.
  - `src/protocol/`: `http.rs`, `tls.rs`, `tls_mod.rs`, `aes_block.rs`, `quic.rs`, `datagram.rs`, `markers.rs`, and pure facade `mod.rs`.
  - `src/lists/`: `file_loader.rs`, `hostlist.rs`, `autohostlist.rs`, `ipset.rs`, `ipcache.rs`, and pure facade `mod.rs`.
  - `src/lua/`: add `ctrack_encode.rs` and `protocol_api.rs` while keeping `desync_api.rs` and `desync_encode.rs` concise.
  - `src/config/`: split `schema.rs` by moving profile/autohostlist TOML schemas into `profile_schema.rs` and extracting `ConntrackConfig`/`IpCacheConfig`/`AutoHostlistConfig` into `runtime_cfg.rs`.
  - `src/desync/`: split `engine.rs` by delegating TCP/UDP stateful probing, reassembly, and replay into `tcp_udp.rs` and ICMP/raw-IP into `icmp_ip.rs`.
- **Surgical implementation discipline:** Persist symbol coordinates and ABI invariants in `scratch/m3_context.md`, locate targets via search, and use bounded `StartLine`/`EndLine` reads immediately before edits.
- **Multi-binary crate layout & repository hygiene gates:** Keep `src/bin/nfqws2.rs` alongside shared library modules so Milestone 5 can add `src/bin/ip2net.rs` and `src/bin/mdig.rs`. Every task must pass `cargo clippy --all-targets --offline -- -D warnings` and `cargo nextest run --offline --show-progress none --no-pager` (including `tests/repo_hygiene.rs` checks), using `thiserror` and atomic commits.

## Dependency Graph

```text
Milestone 1 (Complete): packet + rawsend + lua core
    |
    v
Milestone 2 (Complete): intercepter + config/CLI + baseline desync + timers + nfqws2 binary
    |
    v
Task 3.1: Conntrack, TCP reassembly, PacketRange, `desync.track`, `conntrack_feed`, cutoffs
    |
    v
Task 3.2: L7 probes, QUIC Initial decrypt/defrag, `tls_mod`, position markers & Lua bindings
    |
[Checkpoint 3A: Stateful conntrack + L7 + markers verified offline]
    |
    v
Task 3.3: Hostlists, autohostlist failure detector, CIDR IPsets, gzip loader, IPCache
    |
    v
Task 3.4: Config split & CLI flags, full DesyncEngine wiring, SIGHUP reload, M3 E2E tests
    |
[Checkpoint 3B: Milestone 3 complete — full offline nextest + unshare -r -n live tests]
    |
    v
Milestone 4: Lua crypto/gzip/time/stat parity + full `zapret2/lua/*.lua` test coverage
    |
    v
Milestone 5: `ip2net` and `mdig` binaries + `CHANGELOG.md` and release tagging
```

## Task List

Tasks and detailed acceptance criteria are tracked in [todo.md](file:///home/morier/Documents/projects/zapret-rs/tasks/todo.md).

### Milestone 2 (Complete)
- [x] Task 2.1: Upgrade `intercepter` with NFQUEUE tuning, persistent `SIOCGIFNAME`, fwmark loop guard, and `poll()` wakeup
- [x] Task 2.2: Implement profile filters, blobs, TOML config schema, and `clap` CLI
- [x] Task 2.3: Implement core `desync` pipeline and Lua desync-context bindings
- [x] Checkpoint 2A: Synthetic End-to-End Pipeline
- [x] Task 2.4: Implement timer pool, Lua `timer_*` bindings, and `poll()` timeout / `--intercept=0` loop
- [x] Task 2.5: Wire `src/bin/nfqws2.rs` with daemonize, pidfile, privilege drop, signal handling, and live namespace smoke test
- [x] Checkpoint 2B: Milestone 2 Complete

### Milestone 3: Conntrack, L7 Detectors, Hostlists, IPsets, and IPCache
- [x] Task 3.1: Conntrack, continuous TCP stream reassembly, `PacketRange`, `desync.track`, `conntrack_feed`, and cutoffs
- [x] Task 3.2: L7 protocol/payload detectors, QUIC Initial decryption, `tls_mod`, and position markers
- [x] Checkpoint 3A: Conntrack + L7 + Markers Verified
- [x] Task 3.3: Hostlists, autohostlist failure detection, disjoint CIDR IPsets, gzip loader, and `ipcache`
- [x] Task 3.4: Config split, CLI options, full `DesyncEngine` wiring, `SIGHUP` reload, and E2E tests
- [x] Checkpoint 3B: Milestone 3 Complete

### Future Milestones (High-Level Roadmap)
- **Milestone 4 (Full Lua API Parity):** Lua bindings for crypto (`hash`, `aes`, `aes_gcm`, `aes_ctr`, `hkdf`, `bcryptorandom`), streaming gzip/gunzip via `flate2`, `stat`/time helpers (`localtime`, `gmtime`, `timelocal`, `timegm`), `--writable`, and full verification against `zapret-antidpi.lua`, `zapret-auto.lua`, and `zapret-obfs.lua`.
- **Milestone 5 (Companion Binaries & Release):** Port `src/bin/ip2net.rs` and `src/bin/mdig.rs`, add `CHANGELOG.md`, and prepare semantic version release tags.

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Lua `RegistryKey` cycles or stale registry entries leak across `ConntrackReInitTrack` / teardown | Med | Store per-connection `lua_state` and `lua_instance_cutoff` as `mlua::RegistryKey` fields on `CtrackEntry`, replace cleanly on TCP SYN re-init, and clear the conntrack pool inside `LuaRuntime` before shutdown. |
| Overlapping/retransmitted TCP segments corrupt TLS ClientHello reassembly or deadlock `delayed` replay | High | Match `zapret2`'s exact `ReasmFeed` signed-delta bounds (`0x100000`), server window check (`winsize_calc >= sz`), max 64 queued packets, and automatic `send_delayed` + `reasm_cancel_rediscover` fallback. |
| Offline builds fail if a new dependency pulls uncached crates | High | Verified `ring = "0.17.14"` and `flate2 = "1.1.11"` (rust backend) plus all transitive crates exist in local `~/.cargo/registry/src`; verify `cargo check --offline` immediately after adding each dependency. |
| Large subsystems push `schema.rs`, `model.rs`, `l7.rs`, or `engine.rs` over `repo_hygiene`'s 400-line ceiling | Med | Pre-split `profile_schema.rs`, `runtime_cfg.rs`, `desync/tcp_udp.rs`, and `desync/icmp_ip.rs` ahead of Milestone 3 feature additions, running `repo_hygiene` on every slice. |
| Live QUIC Initial or MTProto test vectors regress silently on subtle bit/endian offsets | Med | Add self-contained Rust unit/integration test vectors verified directly against `zapret2`'s byte layouts, HKDF labels, and synthetic TCP/UDP packet streams. |
