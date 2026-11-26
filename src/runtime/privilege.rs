//! OS-agnostic runtime privilege checks and elevation-drop wrappers.

/// Process lifecycle error type returned by capability or privilege-drop operations.
use crate::runtime::error::ProcessError;
/// Linux capability mask and capability/sudo drop helpers.
#[cfg(target_os = "linux")]
use crate::runtime::caps::{CAP_MASK_NET, has_effective_caps};
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

/// Returns `true` when the current process holds packet capture/injection privileges.
pub fn has_packet_capture_privileges() -> Result<bool, ProcessError> {
    #[cfg(target_os = "linux")]
    {
        has_effective_caps(CAP_MASK_NET)
    }
    #[cfg(not(target_os = "linux"))]
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
