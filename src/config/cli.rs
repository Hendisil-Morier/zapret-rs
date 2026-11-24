//! `clap`-derived CLI definition and configuration override resolution for `nfqws2`.

/// Path types for `--config`, `--pidfile`, and `--chdir` flags.
use std::path::PathBuf;

/// `clap` derive macro for clean top-level CLI parsing and help/version output.
use clap::Parser;

/// Typed configuration errors returned when resolving or validating overrides.
use crate::config::error::ConfigError;
/// Decimal and `0x`-hex parser shared with fwmark filter syntax.
use crate::config::filter::parse_u32_radix;
/// Validated application configuration loaded from TOML and overridden by CLI flags.
use crate::config::schema::AppConfig;

/// Parses `--fwmark` from decimal or `0x` hex notation for `clap`.
fn parse_fwmark_arg(raw: &str) -> Result<u32, String> {
    parse_u32_radix(raw).ok_or_else(|| format!("invalid fwmark '{raw}' (expected u32 or 0xHEX)"))
}

/// Top-level command-line flags accepted by `nfqws2`.
#[derive(Debug, Clone, Parser)]
#[command(
    name = "nfqws2",
    version,
    about = "Rust port of zapret2 NFQUEUE DPI desync daemon"
)]
pub struct CliArgs {
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
    #[arg(long = "bind-fix4", num_args = 0..=1, default_missing_value = "true")]
    pub bind_fix4: Option<bool>,
    /// Override IPv6 `SO_BINDTODEVICE` routing fixup.
    #[arg(long = "bind-fix6", num_args = 0..=1, default_missing_value = "true")]
    pub bind_fix6: Option<bool>,
    /// Enable or disable debug output.
    #[arg(long = "debug", num_args = 0..=1, default_missing_value = "true")]
    pub debug: Option<bool>,
    /// Validate configuration and exit with code 0 without intercepting packets.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Enable or disable packet interception (when false, runs startup Lua/timers and exits).
    #[arg(long = "intercept", num_args = 0..=1, default_missing_value = "true")]
    pub intercept: Option<bool>,
    /// Fork into background daemon mode.
    #[arg(long = "daemon", num_args = 0..=1, default_missing_value = "true")]
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
}

/// Loads TOML config (when specified) and merges any explicit CLI overrides.
pub fn resolve_config(cli: &CliArgs) -> Result<AppConfig, ConfigError> {
    let mut cfg = match &cli.config {
        Some(path) => AppConfig::from_toml_file(path)?,
        None => AppConfig::default(),
    };
    if let Some(qnum) = cli.qnum {
        cfg.qnum = qnum;
    }
    if let Some(fwmark) = cli.fwmark {
        cfg.fwmark = fwmark;
    }
    if let Some(bind_fix4) = cli.bind_fix4 {
        cfg.bind_fix4 = bind_fix4;
    }
    if let Some(bind_fix6) = cli.bind_fix6 {
        cfg.bind_fix6 = bind_fix6;
    }
    if let Some(debug) = cli.debug {
        cfg.debug = debug;
    }
    if let Some(intercept) = cli.intercept {
        cfg.intercept = intercept;
    }
    if let Some(daemon) = cli.daemon {
        cfg.daemon = daemon;
    }
    if let Some(pidfile) = &cli.pidfile {
        cfg.pidfile = Some(pidfile.clone());
    }
    if let Some(chdir) = &cli.chdir {
        cfg.chdir = Some(chdir.clone());
    }
    if let Some(user) = &cli.user {
        cfg.user = Some(user.clone());
    }
    if let Some(uid) = &cli.uid {
        cfg.uid = Some(uid.clone());
    }
    if let Some(lua_gc) = cli.lua_gc {
        cfg.lua_gc = lua_gc;
    }

    cfg.validate()?;
    Ok(cfg)
}
