# Changelog

All notable changes to `zapret-rs` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.3.1] - 2026-11-26

### Fixed

- **Windows Strategy Finder Overlapped I/O (`WinDivertRecvEx`):** Replaced synchronous blocking `WinDivertRecv` with overlapped `WinDivertRecvEx` + `WaitForSingleObject`, unblocking `WorkerCmd::Swap` acknowledgments during Strategy Finder sweeps even when no network traffic is present.
- **Narrow-Terminal TUI Layout & Wrapping:** Added compact header tab labels (`1:Find`, `2:Run`, `3:Cfg`, `4:Spd`, `5:Stat`) on narrow terminals, auto-sized the Tab 2 controller height for wrapped profile lists, wrapped long `Live Scan Log` / `Daemon Log` lines, shortened Tab 5's `curl` summary, and added `Left`/`Right` (`h`/`l`) horizontal scrolling on Tab 5 `Summary` cells.

### Docs

- Updated [README.md](README.md) with Tab 5 (`Status`), prebuilt Linux/Windows GitHub Release archives, and Windows Terminal (Admin) launch instructions.

## [1.3.0] - 2026-11-26

### Added

- **Operational Component Status Tab (`5: Status`):** Added Tab 5 displaying live `[OK]` / `[WARN]` / `[ERR]` health checks for Privileges, Packet Driver (`WinDivert` / `nftables` + `NFQUEUE`), Lua Scripts, `curl` Probe (including HTTP/3 detection), Config (`nfqws2.toml`), and Daemon & IPC (`zapret-rs.service` on Linux), with `[r]` refresh and remediation details.
- **Release Packaging CI:** Added `release-linux` (`tar.gz`) and `release-windows` (`zip` bundling `WinDivert.dll`, `WinDivert64.sys`, and license) workflows with shared `Swatinem/rust-cache@v2` and `actions/cache@v4` caching on `v*` tags.
- **Keep Existing Merge Option:** Added `[k] Keep Existing` to the post-scan merge modal so users can discard a new scan config and preserve their existing `nfqws2.toml`.

### Changed

- **Windows TUI Engine Labels:** Tab 2 headers, controller panel, help popup, and run logs now display `WinDivert` instead of `nfqws2` on Windows.

### Fixed

- **WinDivert Packet Injection:** Resolved `IfIdx` via Win32 `GetBestInterfaceEx` (`iphlpapi.dll`) when `ifout` is absent and ran `WinDivertHelperCalcChecksums` before `WinDivertSend` to fix silent injection failures and NIC checksum offloading.
- **Windows Console & Error Reporting:** Forced `CP_UTF8` (`65001`) at TUI startup, used ASCII `<`/`>` scroll arrows on Windows `conhost.exe`, improved `Scan Progress` gauge contrast, reported `"WinDivert packet interception failed"` instead of Linux `NFQUEUE` on Windows, bundled `tests/fixtures/fake/*.bin`, and gated Linux/Unix-only integration tests and benchmarks.

## [1.2.1] - 2026-11-26

### Added

- **Loopback IPC Token Authentication:** Added per-session 32-character hex token authentication with constant-time XOR verification for non-Unix (Windows) loopback control connections.
- **GitHub Actions CI:** Added `.github/workflows/ci.yml` running Linux `clippy`, `--no-default-features`, `nextest`, and Windows `x86_64-pc-windows-gnu` build checks.

### Fixed

- **Windows TUI Privilege & Firewall Flow:** Replaced Linux `sudo` / `nftables` prompts and `sudo setcap` modals on Windows with `WinDivertFirewallBackend` and an Administrator privileges notice.
- **WinDivert Clean Shutdown:** Implemented `Sync` on `WinDivertHandle` and added a scoped stop-watcher to unblock `WinDivertRecv` during shutdown.
- **Installer Symlink Replacement & Test Stability:** Fixed `zapret-rs install` to replace pre-existing destination symlinks before `setcap`, stabilized `mdig` passthrough output ordering in tests, and resolved bundled `lua/` test paths via `CARGO_MANIFEST_DIR`.

## [1.2.0] - 2026-11-26

### Added

- **Unified Multicall Binary & Built-in Installer:** Consolidated `nfqws2`, `strat_finder`, `ip2net`, `mdig`, and the TUI into a single `zapret-rs` executable with `argv[0]` symlink routing, bundled `lua/*.lua` XDG extraction, and `install` / `uninstall` subcommands (`--symlinks`, `--systemd`).
- **Experimental Windows Support (WinDivert):** Added dynamic `LoadLibraryW` WinDivert 2.2 bindings (`WinDivertIntercepter`, `WinDivertSender`, `WinDivertFirewallBackend`), `SetConsoleCtrlHandler` signal handling, Win32 `TokenElevation` checks, loopback TCP control IPC, and `daemon` / `scan` / TUI wiring for `x86_64-pc-windows-gnu`.
- **TUI Speed Test, Mouse Support, Domain Scope & Themes:** Added Tab 4 before/after `curl` speed comparison, mouse click and scroll wheel support across all four tabs, Tab 1 `Domain Scope` (`Scanned Only`, `All Domains`, `Auto Hostlist`) with non-destructive profile merging, Tab 3 live Auto Hostlist viewer, Tab 2 packet inspector `/` query filter, configurable themes, and `R` daemon restart.
- **`systemd` Integration & `nftables` Improvements:** Added `contrib/systemd/` service and path-watcher units, ambient `CAP_NET_ADMIN` preservation for `--nft`, and `nft` forward-chain / `tailscale0` egress handling.

### Changed

- **OS-Agnostic Core & `src/tools/` Reorganization:** Decoupled `PacketIntercepter`, `PacketSender`, `FirewallBackend`, `ControlStream`, monotonic clock, writable directory, and privilege helpers from Linux-specific syscalls; grouped `src/tools/` into `daemon/`, `mdig/`, and `strat/` subdirectories.
- **User-Focused README:** Rewrote [README.md](README.md) with quick-start install, TUI, CLI, and Windows instructions.

### Fixed

- **Daemon Startup & Restart Races:** Bound the control socket before installing auto-`nft` rules, switched `start_via_systemd` to `systemctl restart` to avoid `Type=simple` deactivation races, stopped active daemons before Strategy Finder scans, and deduplicated slot-wide `AllDomains`/`AutoHostlist` profiles.

## [1.1.0] - 2026-11-25

### Added

- **Live Config Reload (`reload_config` & Tab 3 Push):** Added `reload_config` wire command validating replacement TOML via `AppConfig::from_toml_str`, rejecting immutable `qnum`/`fwmark` changes cleanly, and hot-swapping `DesyncEngine` profiles via `replace_profiles` with status profile refresh; added `[p] Push Config` on Tab 3 when attached.
- **Standalone Auto `nftables` Flag (`nfqws2 --nft` / `auto_nft`):** Added `--nft` (`auto_nft = true` in TOML) so standalone `nfqws2` can install `table inet zapret_strat_finder` for configured queue/fwmark/ports at startup, refresh ports on `reload_config`, and delete the table cleanly on exit.
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
