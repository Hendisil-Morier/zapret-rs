//! Async-signal-safe termination/reload flags (`SIGINT`/`SIGTERM`/`SIGHUP` on Unix, console Ctrl on Windows).

/// Raw POSIX `c_int` signal identifier passed to libc `sigaction`.
#[cfg(unix)]
use std::ffi::c_int;
/// Lock-free atomic booleans updated safely inside async signal handlers.
use std::sync::atomic::{AtomicBool, Ordering};

/// Process lifecycle error wrapper returned if `sigaction` registration fails.
use crate::runtime::error::ProcessError;

/// Global termination flag set atomically by `SIGINT` and `SIGTERM` handlers.
static QUIT_REQUESTED: AtomicBool = AtomicBool::new(false);
/// Global list-reload flag set atomically by the `SIGHUP` handler.
static RELOAD_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Async-signal-safe disposition recording termination requests from `SIGINT` or `SIGTERM`.
#[cfg(unix)]
extern "C" fn handle_quit_signal(_sig: c_int)
{
    // Only async-signal-safe atomic stores are allowed inside a POSIX signal handler.
    QUIT_REQUESTED.store(true, Ordering::SeqCst);
}

/// Async-signal-safe disposition recording configuration/list reload requests from `SIGHUP`.
#[cfg(unix)]
extern "C" fn handle_hup_signal(_sig: c_int)
{
    RELOAD_REQUESTED.store(true, Ordering::SeqCst);
}

/// Returns the shared process termination flag checked by `QueueCatcher` and `run_no_intercept`.
pub fn quit_flag() -> &'static AtomicBool
{
    &QUIT_REQUESTED
}

/// Returns the shared reload notification flag set upon receiving `SIGHUP`.
pub fn reload_flag() -> &'static AtomicBool
{
    &RELOAD_REQUESTED
}

/// Atomically reads and clears the pending `SIGHUP` reload flag.
pub fn take_reload_requested() -> bool
{
    RELOAD_REQUESTED.swap(false, Ordering::AcqRel)
}

/// Resets `QUIT_REQUESTED` and `RELOAD_REQUESTED` back to `false` before installing handlers.
pub fn reset_signal_flags()
{
    QUIT_REQUESTED.store(false, Ordering::SeqCst);
    RELOAD_REQUESTED.store(false, Ordering::SeqCst);
}

/// Registers one non-restarting (`sa_flags = 0`) POSIX signal handler via `libc::sigaction`.
#[cfg(unix)]
fn install_one(sig: c_int, name: &'static str, handler: extern "C" fn(c_int)) -> Result<(), ProcessError>
{
    // SAFETY: `libc::sigaction` is a plain C struct whose zero-initialized fields are overwritten below.
    let mut sa: libc::sigaction = unsafe { std::mem::zeroed() };
    // SAFETY: `sa.sa_mask` points to a valid stack `sigset_t` inside `sa`.
    if unsafe { libc::sigemptyset(&raw mut sa.sa_mask) } < 0
    {
        return Err(ProcessError::SignalInstall { signal: name, source: std::io::Error::last_os_error() });
    }
    // Deliberately omit `SA_RESTART` so blocking `poll()`/`sleep()` calls return `EINTR` immediately.
    sa.sa_flags = 0;
    sa.sa_sigaction = handler as *const () as libc::sighandler_t;

    // SAFETY: `sa` is fully initialized and `oldact` is null.
    let rc = unsafe { libc::sigaction(sig, &raw const sa, std::ptr::null_mut()) };
    if rc < 0
    {
        Err(ProcessError::SignalInstall { signal: name, source: std::io::Error::last_os_error() })
    }
    else
    {
        Ok(())
    }
}

/// Resets signal flags and installs non-restarting handlers for `SIGINT`, `SIGTERM`, and `SIGHUP`.
#[cfg(unix)]
pub fn install_signal_handlers() -> Result<(), ProcessError>
{
    reset_signal_flags();
    install_one(libc::SIGINT, "SIGINT", handle_quit_signal)?;
    install_one(libc::SIGTERM, "SIGTERM", handle_quit_signal)?;
    install_one(libc::SIGHUP, "SIGHUP", handle_hup_signal)?;
    Ok(())
}

/// Windows `SetConsoleCtrlHandler` callback setting `QUIT_REQUESTED` on Ctrl-C/Ctrl-Break/Close.
#[cfg(windows)]
unsafe extern "system" fn console_ctrl_handler(_ctrl_type: u32) -> i32
{
    QUIT_REQUESTED.store(true, Ordering::SeqCst);
    1
}

/// Resets signal flags and installs a Windows console Ctrl handler for clean shutdown.
#[cfg(windows)]
pub fn install_signal_handlers() -> Result<(), ProcessError>
{
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn SetConsoleCtrlHandler(handler: Option<unsafe extern "system" fn(u32) -> i32>, add: i32) -> i32;
    }

    reset_signal_flags();
    // SAFETY: `console_ctrl_handler` matches the Win32 `PHANDLER_ROUTINE` ABI and is static.
    if unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), 1) } == 0
    {
        return Err(ProcessError::SignalInstall {
            signal: "SetConsoleCtrlHandler",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(())
}

/// Fallback signal installer on non-Unix, non-Windows targets.
#[cfg(not(any(unix, windows)))]
pub fn install_signal_handlers() -> Result<(), ProcessError>
{
    reset_signal_flags();
    Ok(())
}
