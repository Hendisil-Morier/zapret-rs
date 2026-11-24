//! Typed process lifecycle, capability retention, privilege drop, and signal handler errors.

/// Filesystem path type included in `chdir` and PID file error diagnostics.
use std::path::PathBuf;

/// Derive macro implementing `std::error::Error` and `Display` cleanly.
use thiserror::Error;

/// Errors raised during process initialization, daemonization, privilege dropping, or signal setup.
#[derive(Debug, Error)]
pub enum ProcessError {
    /// Failed to change the working directory via `--chdir`.
    #[error("failed to change working directory to '{}': {source}", path.display())]
    Chdir {
        /// Target working directory path requested by configuration or CLI.
        path: PathBuf,
        /// Underlying OS error returned by `chdir`.
        #[source]
        source: std::io::Error,
    },
    /// Failed to create, write, or flush the daemon PID file.
    #[error("failed to manage PID file '{}': {source}", path.display())]
    PidFile {
        /// Resolved PID file path targeted on disk.
        path: PathBuf,
        /// Underlying OS I/O error returned during file creation or writing.
        #[source]
        source: std::io::Error,
    },
    /// System account lookup for `--user` failed or returned no matching passwd record.
    #[error("user account lookup failed: {0}")]
    UserLookup(String),
    /// Malformed numeric `--uid` (`uid[:gid1,gid2,...]`) specification.
    #[error("invalid uid specification '{0}' (expected uid[:gid1,gid2,...])")]
    InvalidUidSpec(String),
    /// Failed one step of UID/GID/supplementary-group transition or `PR_SET_KEEPCAPS`.
    #[error("privilege drop failed at {step}: {source}")]
    PrivilegeDrop {
        /// Kernel or libc step name (`prctl(PR_SET_KEEPCAPS)`, `initgroups`, `setgroups`, `setgid`, `setuid`).
        step: &'static str,
        /// Underlying OS error (`EPERM`, `EINVAL`, etc.).
        #[source]
        source: std::io::Error,
    },
    /// Failed to inspect or constrain Linux process capabilities via `capget`/`capset`/`prctl`.
    #[error("capability management failed at {step}: {source}")]
    Capabilities {
        /// Capability syscall or step identifier (`capget`, `capset(...)`, etc.).
        step: &'static str,
        /// Underlying OS error (`EPERM`, `EINVAL`, `EFAULT`, etc.).
        #[source]
        source: std::io::Error,
    },
    /// Failed during background daemon fork, `setsid`, or standard descriptor redirection.
    #[error("daemonize failed at {step}: {source}")]
    Daemonize {
        /// Step identifier within daemonization (`fork`, `setsid`, `open(/dev/null)`, `dup2`).
        step: &'static str,
        /// Underlying OS error returned by libc.
        #[source]
        source: std::io::Error,
    },
    /// Failed to install a POSIX signal disposition via `sigaction`.
    #[error("failed to install signal handler for {signal}: {source}")]
    SignalInstall {
        /// Signal name (`SIGINT`, `SIGTERM`, `SIGHUP`).
        signal: &'static str,
        /// Underlying OS error returned by `sigaction`.
        #[source]
        source: std::io::Error,
    },
}
