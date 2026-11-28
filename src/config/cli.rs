//! `clap`-derived CLI definition and configuration override resolution for `nfqws2`.

/// Path types for `--config`, `--pidfile`, and `--chdir` flags.
use std::path::PathBuf;

/// `clap` derive macro for clean top-level CLI parsing and help/version output.
use clap::Parser;

/// Typed configuration errors returned when resolving or validating overrides.
use crate::config::error::ConfigError;
/// Decimal and `0x`-hex parser shared with fwmark filter syntax.
use crate::config::filter::parse_u32_radix;
/// L7 payload disable list parser for `--payload-disable` and `--reasm-disable`.
use crate::config::l7::parse_l7_disable_mask;
/// Validated application configuration, Lua init variants, and writable mode.
use crate::config::model::{AppConfig, LuaInitEntry, WritableDirConfig};
/// Conntrack `S:E:F[:U]` timeout parser for `--ctrack-timeouts`.
use crate::config::runtime_cfg::parse_timeouts;
/// Shared option-assignment helpers and `control_socket` parser reused across TOML and CLI.
use crate::config::schema::{assign_cloned_some, assign_some, parse_control_socket_str};

/// Parses `--fwmark` from decimal or `0x` hex notation for `clap`.
fn parse_fwmark_arg(raw: &str) -> Result<u32, String>
{
    parse_u32_radix(raw).ok_or_else(|| format!("invalid fwmark '{raw}' (expected u32 or 0xHEX)"))
}

/// Parses boolean flags supporting both `true`/`false` and `zapret2`-compatible `1`/`0` syntax.
fn parse_bool_arg(raw: &str) -> Result<bool, String>
{
    match raw
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => Err(format!("invalid boolean '{raw}' (expected 0/1 or true/false)")),
    }
}

/// Top-level command-line flags accepted by `nfqws2`.
#[derive(Debug, Clone, Parser)]
#[command(name = "nfqws2", version, about = "Rust port of zapret2 NFQUEUE DPI desync daemon")]
pub struct CliArgs
{
    /// Path to TOML configuration file.
    #[arg(short = 'c', long = "config")]
    pub config: Option<PathBuf>,
    /// Override NFQUEUE queue number.
    #[arg(long = "qnum")]
    pub qnum: Option<u16>,
    /// Override desync firewall mark (decimal or 0xHEX).
    #[arg(long = "fwmark", value_parser = parse_fwmark_arg)]
    pub fwmark: Option<u32>,
    /// Override IPv4 `SO_BINDTODEVICE` routing fixup.
    #[arg(long = "bind-fix4", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub bind_fix4: Option<bool>,
    /// Override IPv6 `SO_BINDTODEVICE` routing fixup.
    #[arg(long = "bind-fix6", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub bind_fix6: Option<bool>,
    /// Enable or disable server mode direction semantics.
    #[arg(long = "server", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub server: Option<bool>,
    /// Enable or disable debug output.
    #[arg(long = "debug", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub debug: Option<bool>,
    /// Validate configuration and exit with code 0 without intercepting packets.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Enable or disable packet interception (when false, runs startup Lua/timers and exits).
    #[arg(long = "intercept", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub intercept: Option<bool>,
    /// Fork into background daemon mode.
    #[arg(long = "daemon", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub daemon: Option<bool>,
    /// Override PID file path.
    #[arg(long = "pidfile")]
    pub pidfile: Option<PathBuf>,
    /// Override startup working directory.
    #[arg(long = "chdir")]
    pub chdir: Option<PathBuf>,
    /// Drop privileges to the named system user.
    #[arg(long = "user")]
    pub user: Option<String>,
    /// Drop privileges to explicit numeric `uid[:gid1,gid2,...]`.
    #[arg(long = "uid")]
    pub uid: Option<String>,
    /// Override forced Lua garbage collection interval in seconds (`0` disables periodic GC).
    #[arg(long = "lua-gc")]
    pub lua_gc: Option<u64>,
    /// Override conntrack stage timeouts (`syn:est:fin[:udp]` in seconds).
    #[arg(long = "ctrack-timeouts")]
    pub ctrack_timeouts: Option<String>,
    /// Disable internal connection tracking.
    #[arg(long = "ctrack-disable", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub ctrack_disable: Option<bool>,
    /// Override IP cache lifetime in seconds (`0` disables expiration).
    #[arg(long = "ipcache-lifetime")]
    pub ipcache_lifetime: Option<u32>,
    /// Enable or disable DNS response hostname caching in IP cache.
    #[arg(long = "ipcache-hostname", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub ipcache_hostname: Option<bool>,
    /// Exclude L7 payloads from discovery (`"all"` when given with no value).
    #[arg(long = "payload-disable", num_args = 0..=1, default_missing_value = "all")]
    pub payload_disable: Option<String>,
    /// Exclude L7 payloads from client-side reassembly (`"all"` when given with no value).
    #[arg(long = "reasm-disable", num_args = 0..=1, default_missing_value = "all")]
    pub reasm_disable: Option<String>,
    /// Override autohostlist failure debug log file path.
    #[arg(long = "hostlist-auto-debug")]
    pub hostlist_auto_debug: Option<PathBuf>,
    /// Create a writable directory for Lua scripts (`$TMPDIR/zapret-rs` or `/tmp/zapret-rs` by default) and export `WRITABLE`.
    #[arg(long = "writable", num_args = 0..=1, default_missing_value = "")]
    pub writable: Option<String>,
    /// Unix control socket path override (`"off"` disables, `"default"` uses runtime dir default).
    #[arg(long = "control-socket")]
    pub control_socket: Option<String>,
    /// PASS telemetry sampling divisor (`1` in N forwarded to subscribers, `0` disables PASS).
    #[arg(long = "control-pass-sample")]
    pub control_pass_sample: Option<u64>,
    /// Automatically install temporary `nftables` queue rules on startup and delete them on exit.
    #[arg(long = "nft", num_args = 0..=1, default_missing_value = "true", value_parser = parse_bool_arg)]
    pub nft: Option<bool>,
    /// Append Lua startup script (`@path` for file, otherwise inline Lua source).
    #[arg(long = "lua-init")]
    pub lua_init: Vec<String>,
    /// Launch the built-in interactive DPI strategy finder (`nfqws2 --strat-finder --help` for options).
    #[arg(long = "strat-finder")]
    pub strat_finder: bool,
}

/// Copies optional scalar network/runtime flags from `cli` into `cfg`.
fn apply_scalar_cli_overrides(cli: &CliArgs, cfg: &mut AppConfig)
{
    assign_some(&mut cfg.qnum, cli.qnum);
    assign_some(&mut cfg.fwmark, cli.fwmark);
    assign_some(&mut cfg.bind_fix4, cli.bind_fix4);
    assign_some(&mut cfg.bind_fix6, cli.bind_fix6);
    assign_some(&mut cfg.server, cli.server);
    assign_some(&mut cfg.debug, cli.debug);
    assign_some(&mut cfg.intercept, cli.intercept);
    assign_some(&mut cfg.daemon, cli.daemon);
    assign_some(&mut cfg.lua_gc, cli.lua_gc);
    assign_some(
        &mut cfg
            .conntrack
            .disable,
        cli.ctrack_disable,
    );
    assign_some(
        &mut cfg
            .ipcache
            .lifetime_sec,
        cli.ipcache_lifetime,
    );
    assign_some(
        &mut cfg
            .ipcache
            .hostname,
        cli.ipcache_hostname,
    );
    assign_some(&mut cfg.control_pass_sample, cli.control_pass_sample);
    assign_some(&mut cfg.auto_nft, cli.nft);
}

/// Copies optional path and string-parsed overrides from `cli` into `cfg`.
fn apply_parsed_cli_overrides(cli: &CliArgs, cfg: &mut AppConfig) -> Result<(), ConfigError>
{
    assign_cloned_some(&mut cfg.pidfile, &cli.pidfile);
    assign_cloned_some(&mut cfg.chdir, &cli.chdir);
    assign_cloned_some(&mut cfg.user, &cli.user);
    assign_cloned_some(&mut cfg.uid, &cli.uid);
    assign_cloned_some(&mut cfg.hostlist_auto_debug, &cli.hostlist_auto_debug);
    if let Some(raw_timeouts) = cli
        .ctrack_timeouts
        .as_deref()
    {
        cfg.conntrack
            .timeouts = parse_timeouts(raw_timeouts)?;
    }
    if let Some(payload_disable) = &cli.payload_disable
    {
        cfg.payload_disable = parse_l7_disable_mask(std::slice::from_ref(payload_disable))?;
    }
    if let Some(reasm_disable) = &cli.reasm_disable
    {
        cfg.reasm_disable = parse_l7_disable_mask(std::slice::from_ref(reasm_disable))?;
    }
    if let Some(raw_writable) = &cli.writable
    {
        let trimmed = raw_writable.trim();
        cfg.writable = Some(
            if trimmed.is_empty()
            {
                WritableDirConfig::Default
            }
            else
            {
                WritableDirConfig::Custom(PathBuf::from(trimmed))
            },
        );
    }
    if let Some(raw_ctrl) = &cli.control_socket
    {
        cfg.control_socket = parse_control_socket_str(raw_ctrl, None)?;
    }
    for entry in &cli.lua_init
    {
        if let Some(path) = entry.strip_prefix('@')
        {
            if path
                .trim()
                .is_empty()
            {
                return Err(ConfigError::Validation("empty --lua-init @path".to_owned()));
            }
            cfg.lua_init
                .push(LuaInitEntry::File(PathBuf::from(path)));
        }
        else
        {
            cfg.lua_init
                .push(LuaInitEntry::Inline(entry.clone()));
        }
    }
    Ok(())
}

/// Resolves runtime configuration by merging optional TOML config with CLI overrides and validating invariants.
pub fn resolve_config(cli: &CliArgs) -> Result<AppConfig, ConfigError>
{
    let mut cfg = match &cli.config
    {
        Some(path) => AppConfig::from_toml_file(path)?,
        None => AppConfig::default(),
    };
    apply_scalar_cli_overrides(cli, &mut cfg);
    apply_parsed_cli_overrides(cli, &mut cfg)?;
    cfg.validate()?;
    Ok(cfg)
}
