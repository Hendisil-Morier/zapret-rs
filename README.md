# zapret-rs

`zapret-rs` (`v1.0.1`) is a Linux Rust port of [`zapret2`](https://github.com/bol-van/zapret2), delivering a memory-safe `nfqws2` NFQUEUE DPI desync daemon, embedded LuaJIT runtime compatible with unmodified `zapret2/lua/*.lua` scripts, and the `ip2net` and `mdig` companion utilities.

## Binaries & Workspace Layout

- **`nfqws2`** ([src/bin/nfqws2.rs](src/bin/nfqws2.rs)): Main NFQUEUE packet interception and Lua desync daemon.
- **`ip2net`** ([src/bin/ip2net.rs](src/bin/ip2net.rs)): Streaming IPv4/IPv6 address and CIDR subnet aggregator.
- **`mdig`** ([src/bin/mdig.rs](src/bin/mdig.rs)): Multi-threaded DNS resolver and raw RFC 1035 query/reply tool.

Core library subsystems live under [src/](src): `packet`, `rawsend`, `intercepter`, `config`, `conntrack`, `protocol`, `lists`, `desync`, `crypto`, `lua`, `timer`, `runtime`, and `tools`.

## Building & Running Tests

Build all release binaries (`target/release/{nfqws2,ip2net,mdig}`):

```bash
cargo build --release
```

Run static checks, offline unit/integration suites (including repository hygiene checks), and isolated live kernel namespace tests:

```bash
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo bench
unshare -r -n bash -c 'ip link set lo up && cargo nextest run --run-ignored only'
```

## `nfqws2` Configuration & Usage

`nfqws2` uses a strict TOML configuration file (`#[serde(deny_unknown_fields)]`) whose fields map directly to CLI overrides. Example `nfqws2.toml`:

```toml
qnum = 200
fwmark = 0x40000000
writable = true
lua_init = ["lua/zapret-lib.lua", "lua/zapret-antidpi.lua"]

[[profiles]]
name = "tls-desync"
filter_tcp = ["443"]
filter_l7 = ["tls"]
hostlist = ["zapret-hosts.txt"]

[[profiles.actions]]
func = "fake"
payload = ["tls_client_hello"]
args = { blob = "fake_default_tls", badsum = true, repeats = 2 }
```

Common CLI invocations:

```bash
# Validate TOML configuration and Lua scripts without intercepting packets
nfqws2 --config /etc/zapret/nfqws2.toml --dry-run

# Run startup Lua scripts and timer callbacks without opening NFQUEUE
nfqws2 --intercept=0 --lua-init=@lua/zapret-lib.lua --lua-init='DLOG_CONDUP("ok")'

# Run daemonized, drop privileges after pre-initialization, and reload lists on SIGHUP
nfqws2 --config /etc/zapret/nfqws2.toml --user nobody --daemon --pidfile /run/nfqws2.pid
kill -HUP "$(cat /run/nfqws2.pid)"
```

## Linux Capabilities

Packet interception and raw L3 reinjection require Linux `CAP_NET_ADMIN` (for NFQUEUE binding) and `CAP_NET_RAW` (for `SOCK_RAW` injection), either by starting as `root` before dropping privileges via `--user`/`--uid` or by granting capabilities to the binary:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep target/release/nfqws2
```

## Companion Tools

```bash
# Collapse IPv4 hosts into /22../30 subnets at >= 3/4 fill ratio (or -6 for IPv6)
ip2net -4 --prefix-length=22-30 --v4-threshold=3/4 < ips.txt > subnets.txt
ip2net -6 --prefix-length=56-64 --v6-threshold=5 < ip6s.txt > subnets6.txt

# Multi-threaded DNS lookup with EAI_AGAIN retries and progress stats
mdig --family=46 --threads=30 --eagain=10 --stats=1000 < domains.txt > ips.txt

# Raw RFC 1035 DNS query generation and reply parsing (e.g., over DoH)
mdig --family=6 --dns-make-query=example.com \
  | curl -s --data-binary @- -H "Content-Type: application/dns-message" https://cloudflare-dns.com/dns-query \
  | mdig --dns-parse-query
```

### Interactive TUI (`zapret-rs`)

For an all-in-one terminal UI covering strategy discovery, live `nfqws2` execution with real-time packet counters, `~/.config/zapret-rs/nfqws2.toml` preview/saving, and privilege diagnostics, run the `zapret-rs` binary directly:

```bash
# Launch the interactive TUI as your normal user
./target/release/zapret-rs
```

If network capabilities are not set yet (for example right after rebuilding), press `g` inside the TUI to run `sudo setcap cap_net_admin,cap_net_raw+ep` on the binary and restart seamlessly with capabilities active. To avoid re-granting capabilities across dev rebuilds, copy the binary to `~/.local/bin/zapret-rs` once and `setcap` that installed copy.

### Strategy Finder (`nfqws2 --strat-finder` / `strat_finder`)

`nfqws2 --strat-finder` (also available as the standalone `strat_finder` binary) replaces `zapret2/blockcheck2.sh` with a single-process, least-privilege Rust scanner. Grant only `CAP_NET_ADMIN` and `CAP_NET_RAW` once so you never run `nfqws2`, LuaJIT, `curl`, or config file writes as root:

```bash
# One-time setup: grant only network capabilities to the binary
sudo setcap cap_net_admin,cap_net_raw+ep ./target/release/nfqws2

# Run the interactive wizard as your normal user (elevates only `nft` via sudo for the temporary table)
./target/release/nfqws2 --strat-finder

# Or manage the temporary nftables rules manually (zero sudo calls inside nfqws2)
./target/release/nfqws2 --strat-finder --print-nft
./target/release/nfqws2 --strat-finder --no-nft

# Preview the expanded strategy catalog offline (no capabilities required)
./target/release/nfqws2 --strat-finder --list-strategies --level quick --proto http,tls13,http3

# Non-interactive scan writing a minimal nfqws2.toml in ~/.config/zapret-rs/
./target/release/nfqws2 --strat-finder \
  --domain blocked1.example,blocked2.example \
  --level quick \
  --stop-on-first \
  --lua-dir ./lua \
  --write-config ~/.config/zapret-rs/nfqws2.toml

# Run nfqws2 as your normal user with the generated config
./target/release/nfqws2 --config ~/.config/zapret-rs/nfqws2.toml
```

Every `curl` probe child clears all Linux capabilities and enables `PR_SET_NO_NEW_PRIVS` before `exec`, and `--write-config` refuses symlinks via `O_NOFOLLOW`. If invoked under `sudo`, `nfqws2 --strat-finder` automatically drops UID 0 back to `SUDO_UID`/`SUDO_GID` at startup.
