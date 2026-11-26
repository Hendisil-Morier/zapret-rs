//! Daemon process lifecycle, privilege dropping, Linux capability retention, and signal flags.

/// Linux capability checks, bounding-set drops, and `CAP_NET_ADMIN`/`CAP_NET_RAW` retention.
#[cfg(target_os = "linux")]
pub mod caps;
/// Typed process lifecycle and privilege transition error enum.
pub mod error;
/// UID/GID identity parsing, `getpwnam_r` resolution, `chdir`, PID file guard, and `daemonize`.
#[cfg(target_os = "linux")]
pub mod process;
/// Async-signal-safe `SIGINT`, `SIGTERM`, and `SIGHUP` flags and `sigaction` installation.
#[cfg(unix)]
pub mod signals;
/// Writable Lua directory preparation and `WRITABLE` environment export (`--writable`).
pub mod writable;

/// Re-exported capability constants and privilege retention helpers.
#[cfg(target_os = "linux")]
pub use caps::{
    CAP_MASK_NET, SECBIT_NO_SETUID_FIXUP, clear_child_privileges, has_effective_caps,
    retain_net_capabilities, retain_net_capabilities_for, set_process_caps,
};
/// Re-exported process lifecycle error type.
pub use error::ProcessError;
/// Re-exported identity resolution, privilege drop, `chdir`, PID guard, and daemonization helpers.
#[cfg(target_os = "linux")]
pub use process::{
    IdentitySpec, PidFileGuard, apply_chdir, daemonize, drop_privileges, drop_privileges_for,
    drop_sudo_root_if_needed, parse_uid_spec, resolve_identity, resolve_user_spec,
};
/// Re-exported POSIX signal handler registration and atomic flag helpers.
#[cfg(unix)]
pub use signals::{
    install_signal_handlers, quit_flag, reload_flag, reset_signal_flags, take_reload_requested,
};
/// Re-exported `--writable` directory defaults and preparation helpers.
pub use writable::{
    DEFAULT_WRITABLE_SUBDIR, ensure_writable_dir, prepare_writable_dir,
    resolve_default_writable_dir,
};
