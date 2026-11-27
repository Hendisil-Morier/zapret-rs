//! OS-agnostic runtime privilege checks and elevation-drop wrappers.

/// Process lifecycle error type returned by capability or privilege-drop operations.
use crate::runtime::error::ProcessError;
/// Linux capability mask and capability/sudo drop helpers.
#[cfg(target_os = "linux")]
use crate::runtime::caps::{CAP_MASK_NET, has_effective_caps, has_no_new_privs as linux_no_new_privs};
/// Linux `sudo` UID-drop helper.
#[cfg(target_os = "linux")]
use crate::runtime::process::drop_sudo_root_if_needed;

/// Resolved target UID, optional username for `initgroups`, and primary/supplementary GID list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySpec {
    /// Target numeric user ID.
    pub uid: u32,
    /// Optional system username passed to `initgroups(3)` when resolving `--user`.
    pub user: Option<String>,
    /// Target group list (`gids[0]` becomes primary GID; remaining entries apply to `setgroups`).
    pub gids: Vec<u32>,
}

/// Returns the calling effective user ID on Unix, or `0` on non-Unix targets.
pub fn current_uid_or_zero() -> u32 {
    #[cfg(unix)]
    {
        // SAFETY: `geteuid` takes no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Returns `true` when the current Windows process token has elevated Administrator privileges.
#[cfg(windows)]
fn is_windows_admin() -> bool {
    /// Win32 `TOKEN_QUERY` access right.
    const TOKEN_QUERY: u32 = 0x0008;
    /// Win32 `TOKEN_INFORMATION_CLASS::TokenElevation` (`20`).
    const TOKEN_ELEVATION_CLASS: u32 = 20;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> isize;
        fn CloseHandle(h_object: isize) -> i32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process_handle: isize, desired_access: u32, token_handle: *mut isize) -> i32;
        fn GetTokenInformation(
            token_handle: isize,
            token_information_class: u32,
            token_information: *mut u32,
            token_information_length: u32,
            return_length: *mut u32,
        ) -> i32;
    }

    let mut token: isize = 0;
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle and `token` is valid stack storage.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return false;
    }
    let mut elevation: u32 = 0;
    let mut ret_len: u32 = 0;
    // SAFETY: `elevation` is a 4-byte `TOKEN_ELEVATION` struct (`DWORD TokenIsElevated`).
    let ok = unsafe {
        GetTokenInformation(
            token,
            TOKEN_ELEVATION_CLASS,
            &raw mut elevation,
            std::mem::size_of::<u32>() as u32,
            &raw mut ret_len,
        )
    };
    // SAFETY: `token` was opened by `OpenProcessToken`.
    let _ = unsafe { CloseHandle(token) };
    ok != 0 && elevation != 0
}

/// Returns `true` when Linux `NoNewPrivileges` prevents `sudo` elevation; always `false` elsewhere.
pub fn has_no_new_privs() -> bool {
    #[cfg(target_os = "linux")]
    {
        linux_no_new_privs()
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

/// Returns `true` when the current process holds packet capture/injection privileges.
pub fn has_packet_capture_privileges() -> Result<bool, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        has_effective_caps(CAP_MASK_NET)
    }
    #[cfg(windows)]
    {
        Ok(is_windows_admin())
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        Ok(false)
    }
}

/// Drops elevated `sudo` root UID/GID when applicable on Linux, returning `(uid, gid)` if dropped.
pub fn drop_elevated_root_if_needed() -> Result<Option<(u32, u32)>, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        drop_sudo_root_if_needed()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(None)
    }
}
