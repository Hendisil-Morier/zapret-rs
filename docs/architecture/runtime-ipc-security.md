# Privilege Lifecycle, Platform Backends, Control IPC & Companion Tools

This document details Linux/Windows daemon startups, security hardening boundaries, Control Socket IPC, and companion utilities under `src/runtime/`, `src/control/`, and `src/tools/`.

## 1. Linux Daemon Startup & Privilege Transitions (`src/tools/daemon/linux.rs`, `src/runtime/`)

Linux execution strictly orders privileged initialization before dropping root or minimizing capabilities:

1. **Root/chroot setup & identity:** Applies `--chdir` (`apply_chdir`) and resolves target `--user`/`--uid` (`resolve_identity`, supporting `initgroups` + supplementary GIDs).
2. **Pre-validation:** Verifies readability of `--lua-init` files (`verify_lua_init_files`) and list files (`verify_list_files`) before allocating firewall rules or sockets so `--dry-run` exits cleanly with accurate errors.
3. **Firewall rules (`--nft`):** When `auto_nft` and `intercept` are enabled, `NftFirewallBackend` (`src/tools/strat/nft.rs`) installs an isolated temporary `zapret_strat_finder` `nftables` table covering deduplicated TCP/UDP port ranges (`collect_config_port_ranges`), returning an RAII `FirewallHandle` that cleans up rules on shutdown.
4. **Writable directory & PID guard (`--writable`, `--pidfile`):** `prepare_writable_dir` transfers ownership only for newly created leaf directories using `O_NOFOLLOW` symlink safety; `PidFileGuard` opens PID files without following symlinks and cleans them up on graceful exit (`SIGINT`/`SIGTERM`).
5. **Privilege drop & ambient capabilities (`src/runtime/caps.rs`, `src/runtime/privilege.rs`):** Retains `CAP_NET_ADMIN` + `CAP_NET_RAW` in effective/permitted/inheritable/ambient capability sets (`retain_net_capabilities_for`, supporting `systemd` `AmbientCapabilities`) while dropping EUID/EGID via `drop_privileges_for`. Under `NoNewPrivileges` (`has_no_new_privs`), `sudo` elevation wrappers are skipped automatically instead of failing on interactive prompts.
6. **Verified helper binaries (`src/runtime/trusted_bin.rs`):** External invocations (`nft`, `sudo`, `setcap`, `systemctl`) require resolved absolute paths in root-owned directories, rejecting relative traversal, unowned binaries, or writable binary modes. Explicitly supplied `nft` paths in untrusted directories are refused before execution.
7. **Live control & reload (`poll_signals_and_commands`):** `SIGHUP` calls `engine.reload_lists()`. Control-socket `reload_config` swaps validated profiles atomically, recalculates `--nft` queue ports, installs the updated table, and disarms the superseded `FirewallHandle` guard.

## 2. Windows WinDivert Daemon Lifecycle (`src/tools/daemon/windows.rs`)

On Windows, `run_daemon_windows` compiles packet interception against dynamically loaded `WinDivert.dll`:

- **Safe DLL loading (`src/intercepter/windivert_ffi.rs`):** Restricts DLL lookup away from insecure CWD fallbacks and pins heap-allocated `OVERLAPPED` descriptors safely across `CancelIoEx` cancellations.
- **Filter rebinding on live reload:** Computes inclusive `(tcp_ranges, udp_ranges)` via `build_windivert_filter_ranges`. When `reload_config` adds or removes ports, `poll_windows_loop` flags `round_stop` cleanly so the outer loop tears down the active `WinDivertIntercepter` and reopens it with the updated WinDivert filter expression without terminating the daemon process.

## 3. Control Socket IPC Protocol (`src/control/`)

`ControlServer` runs alongside the daemon over a local Unix domain socket (Linux, default `/run/zapret-rs/control.sock` or `$XDG_RUNTIME_DIR/zapret-rs/control.sock`, created via symlink-safe `prepare_control_socket_dir`) or cross-platform IPC transport:

- **Bounded framing (`src/control/codec.rs`):** Newline-delimited JSON messages are capped strictly at `MAX_CONTROL_LINE_BYTES = 64 KiB` (`encode_line` / `LineReader`, preserving partial frames across poll timeouts).
- **Mandatory version handshake (`CONTROL_PROTOCOL_VERSION = 1`):** Clients must send `{"op":"hello","version":1}` before issuing commands; mismatches return `ControlErrorCode::UnsupportedVersion` (`HandshakeRequired` if omitted).
- **Commands (`Request`):** `Hello`, `Status` (returns `DaemonStatus`: `version`, `pid`, `qnum`, `fwmark`, `intercept`, `profile_names`, `config_path`, `pass_sample_rate`, `CountersSnapshot`), `Subscribe` (streams periodic `counters` and sampled `packet` records with `pass_sample_rate` divisor), `Unsubscribe`, `ReloadLists`, `ReloadConfig { toml }`, and `Stop`.
- **Telemetry fanout (`TelemetryHub`):** Uses lock-free atomic `PacketCounters` (`total`, `passed`, `reassembled`, `modified`, `desynced`) and isolated per-client bounded channels (`fanout` drops lagging slow consumers without stalling NFQUEUE packet verdicts).

## 4. Strategy Finder, Web UI, Installer & CLI Utilities (`src/tools/`)

| Tool Module | Binary / Subcommand | Core Capabilities & Hardening Guards |
|---|---|---|
| `tools/strat/` | `scan` / `strat_finder` | Expands strategy catalog (`Quick`/`Standard`/`Force`), runs baseline + candidate probes with `--globoff` (`probe.rs` validates hostnames via `parse_clean_domain` blocking raw IPs/globs/localhost SSRF), computes minimal multi-domain set cover (`select_minimal_cover`), renders `nfqws2.toml` (`render_nfqws2_toml_scoped`), and mutates hostlist/exclude entries (`parse_hostlist_entry` accepts both hostnames and bare IPs). |
| `tools/web/` | `web` & in-TUI `W` | Embedded zero-CDN HTTP/1.1 + SSE dashboard (`MAX_HTTP_WORKERS = 16`, `5s` client I/O timeout, cookie HMAC signing, Host/Origin/Sec-Fetch-Site/CSP DNS-rebinding checks even under `--no-auth`, `/api/login` rate limiting, and `config_guard::validate_web_toml_paths` confining `POST /api/config` & `/api/domains` paths to the config directory). |
| `tools/installer.rs`, `installer_sys.rs` | `install` / `uninstall` | Exclusive `O_NOFOLLOW` binary staging into `<prefix>/bin/zapret-rs`, bundled Lua extraction (`lua_bundle::extract_bundled_lua`) into `<prefix>/share/zapret-rs/lua`, optional `nfqws2`/`strat_finder`/`ip2net`/`mdig` symlinks, `setcap cap_net_admin,cap_net_raw+ep`, and `/etc/systemd/system/zapret-rs.service` generation with `AmbientCapabilities`. |
| `tools/ip2net.rs` | `ip2net` | Streaming IPv4/IPv6 CIDR subnet aggregator matching `zapret2/ip2net` (`DEFAULT_V4_MUL/DIV = 3/4`, `v4 zct 2..10`, `v6 zct 64..72`). |
| `tools/mdig/` | `mdig` | Multi-threaded DNS resolver with CIDR pass-through and `EAI_AGAIN` retry tracking. |
| `tools/dns.rs` | `dns` | Inspects and configures OS DNS/DoH presets (`cloudflare`, `google`, `quad9`, `adguard`, `auto`). |
