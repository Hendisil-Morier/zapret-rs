# zapret-rs

`zapret-rs` (`v1.3.0`) is a fast, memory-safe DPI (Deep Packet Inspection) bypass tool and terminal UI written in Rust, compatible with [`zapret2`](https://github.com/bol-van/zapret2) Lua strategies.

It ships as a single executable (`zapret-rs`) with built-in Lua scripts, an interactive Strategy Finder, a live packet monitor, and `systemd` integration on Linux (plus experimental Windows 10/11 support via WinDivert).

## Quick Start (Linux)

### 1. Build and Install

```bash
cargo build --release
```

Install for your current user (places the binary in `~/.local/bin/zapret-rs`, extracts bundled Lua scripts, and grants network permissions):

```bash
./target/release/zapret-rs install
```

Or install system-wide with compatibility symlinks (`nfqws2`, `strat_finder`, `ip2net`, `mdig`) and a `systemd` background service:

```bash
sudo ./target/release/zapret-rs install --symlinks --systemd
```

To remove it later, run `zapret-rs uninstall` (or `sudo zapret-rs uninstall --systemd`).

### 2. Launch the Interactive TUI

Run `zapret-rs` in your terminal:

```bash
zapret-rs
```

The TUI has four tabs:

1. **Strategy Finder (`1`):** Enter one or more blocked domains, choose a scan level, and run the finder to automatically discover working bypass rules and save `~/.config/zapret-rs/nfqws2.toml`.
2. **Run `nfqws2` (`2`):** Start (`r`), stop (`S`), or restart (`R`) the daemon, watch live packet counters, and inspect intercepted traffic. Press `x` to detach and leave the daemon running in the background.
3. **Config & Diag (`3`):** View or edit `nfqws2.toml`, push profile changes to the running daemon (`p`), or grant network capabilities (`g`) if needed.
4. **Speed Test (`4`):** Measure connection speed before and after enabling your active bypass rules.

Press `?` at any time to see the keybindings for the current tab.

## Command-Line Mode

If you prefer running without the TUI (or want to script it), `zapret-rs` exposes subcommands for every tool:

```bash
# Find working bypass strategies automatically and write nfqws2.toml
zapret-rs scan --domain example.com --level quick --write-config ~/.config/zapret-rs/nfqws2.toml

# Run the DPI bypass daemon with automatic temporary nftables rules
zapret-rs daemon --config ~/.config/zapret-rs/nfqws2.toml --nft

# Validate a config file without intercepting packets
zapret-rs daemon --config ~/.config/zapret-rs/nfqws2.toml --dry-run

# Collapse IP lists into CIDR subnets (ip2net)
zapret-rs ip2net -4 --prefix-length=22-30 < ips.txt > subnets.txt

# Multi-threaded DNS lookup (mdig)
zapret-rs mdig --family=46 --threads=30 < domains.txt > ips.txt
```

If you installed with `--symlinks`, you can also invoke `nfqws2`, `strat_finder`, `ip2net`, and `mdig` directly by name.

## Windows (Experimental)

Windows 10 and 11 (`x64`) are supported via WinDivert:

1. Download `WinDivert-2.2.2-A.zip` from [reqrypt.org/windivert.html](https://reqrypt.org/windivert.html) or [github.com/basil00/WinDivert/releases](https://github.com/basil00/WinDivert/releases).
2. Copy `WinDivert.dll` and `WinDivert64.sys` from the `x64` folder into the same folder as `zapret-rs.exe`.
3. Open an **Administrator** terminal and run:

```powershell
.\zapret-rs.exe daemon --config nfqws2.toml
```

## Configuration (`nfqws2.toml`)

`zapret-rs` uses a TOML config file (generated automatically by `zapret-rs scan` or written by hand):

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

### Permissions & `systemd` Service (Linux)

On Linux, packet interception needs only `CAP_NET_ADMIN` and `CAP_NET_RAW` instead of running the whole daemon as `root`. `zapret-rs install` sets these capabilities on the binary automatically, or you can grant them manually:

```bash
sudo setcap cap_net_admin,cap_net_raw+ep ~/.local/bin/zapret-rs
```

When installed with `--systemd`, `zapret-rs.service` runs under your user account with `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`, manages its own temporary `nftables` table (`--nft`), and exposes a same-UID control socket at `/run/zapret-rs/control.sock` (or `$XDG_RUNTIME_DIR/zapret-rs/control.sock` when run manually) so the TUI can attach and reload configs without root prompts.

---

## For Developers

### Project Layout

Core subsystems live under [src/](src): `packet`, `rawsend`, `intercepter`, `config`, `conntrack`, `protocol`, `lists`, `desync`, `crypto`, `lua`, `timer`, `runtime`, `telemetry`, `control`, `tools` (`daemon/`, `mdig/`, `strat/`), and `tui`.

### Running Checks & Tests

```bash
cargo clippy --all-targets -- -D warnings
cargo nextest run
cargo bench
unshare -r -n bash -c 'ip link set lo up && cargo nextest run --run-ignored only'
```

### Cross-Compiling for Windows from Linux

With the `x86_64-pc-windows-gnu` Rust target and `mingw-w64-gcc` installed:

```bash
cargo build --target x86_64-pc-windows-gnu --release
```

The resulting executable is written to `target/x86_64-pc-windows-gnu/release/zapret-rs.exe`.
