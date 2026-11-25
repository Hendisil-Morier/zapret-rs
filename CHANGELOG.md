# Changelog

All notable changes to `zapret-rs` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-11-25

### Added

- **Live Config Reload (`reload_config` & Tab 3 Push):** Added `reload_config` wire command validating replacement TOML via `AppConfig::from_toml_str`, rejecting immutable `qnum`/`fwmark` changes cleanly, and hot-swapping `DesyncEngine` profiles via `replace_profiles` with status profile refresh; added `[p] Push Config` on Tab 3 when attached.
- **Daemon Control Socket Server (`nfqws2`):** Added local Unix domain socket IPC (`src/control`) authenticated via `0600` permissions and `SO_PEERCRED` same-UID verification, exposing `hello`, `status`, `subscribe`/`unsubscribe`, `reload_lists`, and `stop` over newline-delimited JSON. Added `--control-socket <PATH|off|default>` (`control_socket` in TOML, defaulting to `$XDG_RUNTIME_DIR/zapret-rs/control.sock` or `/run/zapret-rs/control.sock`) and `--control-pass-sample <N>` (`control_pass_sample` in TOML, defaulting to `20`).
- **TUI Remote Attach Mode (`zapret-rs` Tab 2):** Added automatic control socket discovery and live telemetry streaming in [src/tui/remote.rs](src/tui/remote.rs), showing `ATTACHED` status with remote PID/profiles without managing `nftables`, supporting `--control-socket <PATH>`, `x` to detach, `l` to reload daemon lists, and `S` with a confirmation dialog to stop the daemon.

### Changed

- **Shared Telemetry Module (`src/telemetry`):** Extracted `PacketCounters`, `PacketVerdict`, `PacketRecord`, and `build_packet_record` out of `src/tui/` into an always-built `src/telemetry` module with `serde` derives so headless `nfqws2` (`--no-default-features`) and the TUI share identical packet inspection models.
- **Non-Intercept Timer Loop Callbacks (`src/timer`):** Added `run_no_intercept_callbacks` so `--intercept=0` invocations can safely run control commands and live profile swaps without borrowing conflicts.

## [1.0.1] - 2026-11-25

### Security

- **Symlink-Hardened Runtime File Handling:** Replaced path-following checks in `src/runtime/writable.rs` with `open(O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` plus `fstat`/`fchown` and `O_NOFOLLOW` writability probing, added `O_NOFOLLOW` on PID file creation in `src/runtime/process.rs`, and added `SOCK_CLOEXEC` to raw/netlink sockets in `src/rawsend`.
- **Bounded Memory Caps (`conntrack`, `ipcache`, `gunzip`):** Added `DEFAULT_CTRACK_MAX_ENTRIES` (`65_536`) in `src/conntrack` and `DEFAULT_IPCACHE_MAX_ENTRIES` (`65_536`) with bounded `try_touch` eviction in `src/lists/ipcache.rs`, and enforced `DEFAULT_MAX_INFLATE_OUTPUT` (`64 MiB`) in `src/lua/gzip_inflate.rs`.

### Performance

- **Interface Name Caching & NFQUEUE Dispatch:** Checked `desync_fwmark` before resolving interface names in `src/intercepter/nfqueue.rs`, added a 5-second bounded interface name cache with zero-allocation borrowed pair lookups in `src/intercepter/ifname.rs`, and cut `ifname_resolve_lo` release latency from `146.8 ns/op` to `19.1 ns/op`.
- **Desync Dispatch & IPCache Hot Paths:** Stored interface names up to 16 bytes inline on the stack (`IfaceKey`) in `src/lists/ipcache.rs`, precomputed Lua action instance labels on `ProfileRuntime`, passed a single `boottime_now()` timestamp through packet dispatch, gated `client_label` formatting on `hostlist_auto_debug`, eliminated redundant `hostname` clones, and cached unmatched flow lookups (`profile_searched`) on `CtrackEntry` with `SIGHUP` reset support, cutting established and unmatched packet overhead by `46%` to `52%`.
- **`RawSender` Socket Option Cache & 4-Bit Shoup GHASH:** Cached applied `SO_MARK` and `SO_BINDTODEVICE` state per socket in `src/rawsend/sender.rs` (`rawsend_loopback_v4` `1346.1 -> 1036.6 ns/op`) and replaced bit-by-bit `GF(2^128)` multiplication in `src/crypto/aes_gcm.rs` with a compile-time 4-bit reduction table (`aes_gcm_crypt_680b` `11498.4 -> 7110.4 ns/op`).

### Changed

- **Cargo Manifest & Benchmark Harness:** Added `default-run = "nfqws2"` and a `[[bench]]` target (`benches/hotpath.rs`, `harness = false`) in `Cargo.toml` so `cargo bench` and bare `cargo run --release` work out of the box.

## [1.0.0] - 2026-11-25

### Added

- **Core Packet Engine & Raw Injection:** Added zero-dependency IPv4/IPv6/TCP/UDP/ICMP wire dissection, RFC 1071/pseudo-header checksum fixups, IP fragmentation, and packet reconstruction in `src/packet`, alongside Linux `SOCK_RAW` injection (`SO_MARK`, `SO_BINDTODEVICE`), source IP lookup, and interface enumeration in `src/rawsend`.
- **`nfqws2` Daemon & Runtime Lifecycle:** Added hardened Linux NFQUEUE interception (`4096` queue limit, `1 MiB` receive buffer, best-effort fail-open, persistent `SIOCGIFNAME` resolution, `fwmark` loop guard, and `poll()` loop) in `src/intercepter`, TOML configuration and `clap` CLI overrides in `src/config`, PID file/daemonize/privilege drop/`CAP_NET_RAW` + `CAP_NET_ADMIN` capability retention/`SIGINT` + `SIGTERM` + `SIGHUP` signal handling/`--writable` setup in `src/runtime`, `CLOCK_BOOTTIME` timers and `--intercept=0` runner in `src/timer`, and the `nfqws2` binary in `src/bin/nfqws2.rs`.
- **Stateful Conntrack, L7 Classifiers, Lists & Desync Engine:** Added bidirectional TCP/UDP connection tracking, continuous stream reassembly, and FIFO delayed-packet replay in `src/conntrack`; L7 detectors (HTTP, TLS, `tls_mod`, QUIC Initial decryption and defragmentation, MTProto, XMPP, DNS, WireGuard, DHT, Discord IP discovery, STUN, DTLS, BitTorrent, uTP-BT) and split position markers in `src/protocol`; plain and gzipped hostlists, autohostlist failure detection, disjoint CIDR IPsets, and TTL `ipcache` with DNS response learning in `src/lists`; and stateful profile routing, reassembly replay, and `SIGHUP` list reloading in `src/desync`.
- **Full `zapret2` LuaJIT API Parity:** Added vendored LuaJIT runtime bindings (`src/lua`) and pure-Rust SHA-224/256, HMAC, HKDF, AES-128/192/256 ECB/CTR/GCM (`src/crypto`), streaming RFC 1952/zlib/raw deflate over `flate2` `rust_backend`, and POSIX `stat`/calendar-time helpers, verified end-to-end against unmodified `zapret2/lua/{zapret-lib,zapret-antidpi,zapret-auto,zapret-obfs,zapret-pcap,zapret-tests}.lua`.
- **Companion CLI Binaries:** Added streaming IPv4/IPv6 CIDR aggregator `ip2net` (`src/tools/ip2net.rs`, `src/bin/ip2net.rs`) with anti-carpet-bombing smallest-subnet selection, and multi-threaded DNS resolver and wire query helper `mdig` (`src/tools/{mdig_backend,mdig_dns,mdig_resolver}.rs`, `src/bin/mdig.rs`) supporting `EAI_AGAIN` retries, transparent IP/CIDR filtering, `--stats`, `--log-resolved`/`--log-failed`, `--dns-make-query`, and `--dns-parse-query`.
