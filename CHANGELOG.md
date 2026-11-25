# Changelog

All notable changes to `zapret-rs` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-25

### Added

- **Core Packet Engine & Raw Injection:** Added zero-dependency IPv4/IPv6/TCP/UDP/ICMP wire dissection, RFC 1071/pseudo-header checksum fixups, IP fragmentation, and packet reconstruction in `src/packet`, alongside Linux `SOCK_RAW` injection (`SO_MARK`, `SO_BINDTODEVICE`), source IP lookup, and interface enumeration in `src/rawsend`.
- **`nfqws2` Daemon & Runtime Lifecycle:** Added hardened Linux NFQUEUE interception (`4096` queue limit, `1 MiB` receive buffer, best-effort fail-open, persistent `SIOCGIFNAME` resolution, `fwmark` loop guard, and `poll()` loop) in `src/intercepter`, TOML configuration and `clap` CLI overrides in `src/config`, PID file/daemonize/privilege drop/`CAP_NET_RAW` + `CAP_NET_ADMIN` capability retention/`SIGINT` + `SIGTERM` + `SIGHUP` signal handling/`--writable` setup in `src/runtime`, `CLOCK_BOOTTIME` timers and `--intercept=0` runner in `src/timer`, and the `nfqws2` binary in `src/bin/nfqws2.rs`.
- **Stateful Conntrack, L7 Classifiers, Lists & Desync Engine:** Added bidirectional TCP/UDP connection tracking, continuous stream reassembly, and FIFO delayed-packet replay in `src/conntrack`; L7 detectors (HTTP, TLS, `tls_mod`, QUIC Initial decryption and defragmentation, MTProto, XMPP, DNS, WireGuard, DHT, Discord IP discovery, STUN, DTLS, BitTorrent, uTP-BT) and split position markers in `src/protocol`; plain and gzipped hostlists, autohostlist failure detection, disjoint CIDR IPsets, and TTL `ipcache` with DNS response learning in `src/lists`; and stateful profile routing, reassembly replay, and `SIGHUP` list reloading in `src/desync`.
- **Full `zapret2` LuaJIT API Parity:** Added vendored LuaJIT runtime bindings (`src/lua`) and pure-Rust SHA-224/256, HMAC, HKDF, AES-128/192/256 ECB/CTR/GCM (`src/crypto`), streaming RFC 1952/zlib/raw deflate over `flate2` `rust_backend`, and POSIX `stat`/calendar-time helpers, verified end-to-end against unmodified `zapret2/lua/{zapret-lib,zapret-antidpi,zapret-auto,zapret-obfs,zapret-pcap,zapret-tests}.lua`.
- **Companion CLI Binaries:** Added streaming IPv4/IPv6 CIDR aggregator `ip2net` (`src/tools/ip2net.rs`, `src/bin/ip2net.rs`) with anti-carpet-bombing smallest-subnet selection, and multi-threaded DNS resolver and wire query helper `mdig` (`src/tools/{mdig_backend,mdig_dns,mdig_resolver}.rs`, `src/bin/mdig.rs`) supporting `EAI_AGAIN` retries, transparent IP/CIDR filtering, `--stats`, `--log-resolved`/`--log-failed`, `--dns-make-query`, and `--dns-parse-query`.
