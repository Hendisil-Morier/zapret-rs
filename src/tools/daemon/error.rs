//! Unified startup and runtime error enum shared by Linux and Windows `nfqws2` daemons.

/// Path buffer carried inside Lua script and list file diagnostics.
#[cfg(target_os = "linux")]
use std::path::PathBuf;

/// Typed `thiserror` derive macro implemented across `zapret-rs` domain error enums.
use thiserror::Error;

/// CLI parsing, config loading, and TOML profile validation errors.
use crate::config::ConfigError;
/// Control IPC directory, socket, and transport errors.
use crate::control::ControlServerError;
/// Kernel NFQUEUE / WinDivert interception errors.
use crate::intercepter::IntercepterError;
/// Embedded LuaJIT initialization, script loading, and callback errors.
use crate::lua::LuaEngineError;
/// Raw L3 socket / WinDivert injector errors.
use crate::rawsend::RawSendError;
/// Process lifecycle, UID, capability, PID file, and writable directory errors.
use crate::runtime::ProcessError;

/// Unified error type surfaced cleanly from `nfqws2` startup and event loops.
#[derive(Debug, Error)]
pub enum DaemonError {
    /// CLI parsing or TOML validation failure.
    #[error("{0}")]
    Config(#[from] ConfigError),
    /// Control socket setup or binding failure.
    #[error("{0}")]
    Control(#[from] ControlServerError),
    /// Process initialization, privilege drop, capability, PID, or directory failure.
    #[error("{0}")]
    Process(#[from] ProcessError),
    /// Raw L3 socket/injector initialization failure.
    #[error("{0}")]
    RawSend(#[from] RawSendError),
    /// Embedded LuaJIT initialization, script execution, or missing profile action function.
    #[error("{0}")]
    Lua(#[from] LuaEngineError),
    /// Kernel packet interception bind, receive, poll, or verdict submission error.
    #[error("{0}")]
    Intercepter(#[from] IntercepterError),
    /// Operating-system I/O error (e.g., working-directory change).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// Temporary `nftables` queue rule installation failure when `--nft` is enabled.
    #[cfg(target_os = "linux")]
    #[error("temporary nftables setup failed: {0}")]
    Nft(#[source] std::io::Error),
    /// Referenced `--lua-init` script file could not be opened under active privileges.
    #[cfg(target_os = "linux")]
    #[error("cannot open Lua init script '{}': {source}", path.display())]
    ScriptIo {
        /// Filesystem path of the unreadable startup Lua script.
        path: PathBuf,
        /// Underlying OS error returned by `File::open`.
        #[source]
        source: std::io::Error,
    },
    /// Referenced hostlist, ipset, autohostlist, or debug log file failed validation.
    #[cfg(target_os = "linux")]
    #[error("cannot load list file '{}': {source}", path.display())]
    ListIo {
        /// Filesystem path of the invalid or inaccessible list file.
        path: PathBuf,
        /// Underlying OS or gzip decoding error.
        #[source]
        source: std::io::Error,
    },
}
