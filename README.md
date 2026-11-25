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
