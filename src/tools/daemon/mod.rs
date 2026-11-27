//! Daemon CLI dispatcher and Linux/Windows event-loop runtimes.

/// Shared `nfqws2` daemon CLI runner (`run_nfqws2_cli`).
pub mod cli;
/// Shared `nfqws2` startup and runtime error type across Linux and Windows runners.
#[cfg(any(target_os = "linux", windows))]
pub mod error;
/// Linux `nfqws2` NFQUEUE daemon startup and event loop runtime.
#[cfg(target_os = "linux")]
pub mod linux;
/// Windows WinDivert daemon startup pipeline and event loop.
#[cfg(windows)]
pub mod windows;

/// Public API re-export for the shared `nfqws2` daemon CLI entry point.
pub use cli::run_nfqws2_cli;
