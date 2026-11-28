//! Linux capability inspection, bounding-set reduction, and `CAP_NET_RAW`/`CAP_NET_ADMIN` retention.

/// Raw OS integer types for `capget`/`capset` ABI structures and `prctl` arguments.
use std::ffi::{c_int, c_ulong};
/// Filesystem reader for querying the running kernel's maximum capability index.
use std::fs;

/// Process lifecycle error wrapper returned on capability check or transition failures.
use crate::runtime::error::ProcessError;

/// Linux v3 capability header magic (`_LINUX_CAPABILITY_VERSION_3` in `<linux/capability.h>`).
/// Version 3 uses two `CapUserData` structs covering 64-bit capability masks.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;
/// Kernel capability bit permitting bounding-set drops (`CAP_SETPCAP` = 8).
const CAP_SETPCAP: u32 = 8;
/// Kernel capability bit permitting Netfilter/NFQUEUE configuration (`CAP_NET_ADMIN` = 12).
const CAP_NET_ADMIN: u32 = 12;
/// Kernel capability bit permitting raw IP packet sockets (`CAP_NET_RAW` = 13).
const CAP_NET_RAW: u32 = 13;
/// Fallback maximum capability number when `/proc/sys/kernel/cap_last_cap` cannot be read.
const DEFAULT_CAP_LAST_CAP: i32 = 40;
/// `PR_CAP_AMBIENT` sub-operation checking whether a capability bit is in the ambient set.
const PR_CAP_AMBIENT_IS_SET: c_int = 1;
/// `PR_CAP_AMBIENT` sub-operation raising a permitted+inheritable bit into the ambient set.
const PR_CAP_AMBIENT_RAISE: c_int = 2;

/// Securebit flag disabling capability wipe across `setuid` to/from UID 0 (`SECBIT_NO_SETUID_FIXUP`).
pub const SECBIT_NO_SETUID_FIXUP: c_int = 1 << 2;
/// Combined capability mask required by `nfqws2` packet interception and raw socket injection.
pub const CAP_MASK_NET: u64 = (1u64 << CAP_NET_ADMIN) | (1u64 << CAP_NET_RAW);

/// Kernel ABI header passed to `SYS_capget` and `SYS_capset` (`struct __user_cap_header_struct`).
#[repr(C)]
struct CapUserHeader
{
    /// Capability ABI version (`LINUX_CAPABILITY_VERSION_3`).
    version: u32,
    /// Target thread/process ID (`0` targets the calling thread).
    pid: c_int,
}

/// One 32-bit capability slice passed to `SYS_capget`/`SYS_capset` (`struct __user_cap_data_struct`).
/// Kernel v3 expects an array of two structs covering bits `0..=31` and `32..=63`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct CapUserData
{
    /// Effective capability bits active for permission checks.
    effective: u32,
    /// Permitted capability bits eligible to become effective.
    permitted: u32,
    /// Inheritable capability bits preserved across `execve`.
    inheritable: u32,
}

/// Queries the current thread's effective, permitted, and inheritable capability sets via `SYS_capget`.
/// Returns OS errors (`EINVAL`, `EFAULT`, `ESRCH`) mapped directly from `errno`.
fn capget_current() -> Result<[CapUserData; 2], std::io::Error>
{
    let mut header = CapUserHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let mut data = [CapUserData::default(); 2];
    // SAFETY: `header` uses `LINUX_CAPABILITY_VERSION_3`, matching the two-element `data` array ABI.
    let rc = unsafe { libc::syscall(libc::SYS_capget, &raw mut header, data.as_mut_ptr()) };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(data) }
}

/// Returns `true` when every capability bit in `mask` is active in the calling thread's effective set.
pub fn has_effective_caps(mask: u64) -> Result<bool, ProcessError>
{
    if mask == 0
    {
        return Ok(true);
    }
    let data = capget_current().map_err(|source| ProcessError::Capabilities { step: "capget", source })?;
    let low = mask as u32;
    let high = (mask >> 32) as u32;
    Ok((data[0].effective & low) == low && (data[1].effective & high) == high)
}

/// Returns `true` when `cap` is currently active in the calling thread's ambient set.
fn ambient_cap_active(cap: u32) -> bool
{
    // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_IS_SET` inspects boolean ambient flag for `cap`.
    unsafe { libc::prctl(libc::PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET as c_ulong, cap as c_ulong, 0, 0) == 1 }
}

/// Returns `true` when `cap` is present in both permitted and inheritable sets (e.g. systemd
/// `AmbientCapabilities` alongside file capabilities that clear the initial ambient mask on `execve`).
fn inheritable_cap_active(cap: u32) -> bool
{
    if cap >= 32
    {
        return false;
    }
    let bit = 1u32 << cap;
    capget_current()
        .map(|d| (d[0].permitted & bit) != 0 && (d[0].inheritable & bit) != 0)
        .unwrap_or(false)
}

/// Returns `true` when Linux `PR_GET_NO_NEW_PRIVS` is active (blocking setuid helpers like `sudo`).
pub fn has_no_new_privs() -> bool
{
    // SAFETY: `PR_GET_NO_NEW_PRIVS` reads thread boolean flag and ignores trailing arguments.
    unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
}

/// Applies `mask` as effective/permitted sets and `inheritable` as the inheritable capability set.
/// Invokes `SYS_capset` (`pid = 0`) and returns `errno` (`EPERM` if raising unpermitted bits).
fn set_process_caps_with_inheritable(mask: u64, inheritable: u64) -> Result<(), std::io::Error>
{
    let mut header = CapUserHeader { version: LINUX_CAPABILITY_VERSION_3, pid: 0 };
    let low = mask as u32;
    let high = (mask >> 32) as u32;
    let inh_low = inheritable as u32;
    let inh_high = (inheritable >> 32) as u32;
    let mut data = [
        CapUserData { effective: low, permitted: low, inheritable: inh_low },
        CapUserData { effective: high, permitted: high, inheritable: inh_high },
    ];
    // SAFETY: `header` targets self (`pid = 0`) under v3 ABI with initialized two-element `data`.
    let rc = unsafe { libc::syscall(libc::SYS_capset, &raw mut header, data.as_mut_ptr()) };
    if rc < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

/// Applies `mask` as both the effective and permitted capability sets while clearing inheritable bits.
pub fn set_process_caps(mask: u64) -> Result<(), std::io::Error>
{
    set_process_caps_with_inheritable(mask, 0)
}

/// Reads the highest valid capability number supported by the running kernel from `/proc/sys/kernel/cap_last_cap`.
fn read_cap_last_cap() -> i32
{
    fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| {
            s.trim()
                .parse::<i32>()
                .ok()
        })
        .filter(|&n| n >= 0)
        .unwrap_or(DEFAULT_CAP_LAST_CAP)
}

/// Cleans all Linux capabilities and sets `PR_SET_NO_NEW_PRIVS` for an unprivileged child process.
///
/// Uses only async-signal-safe syscalls (`prctl`, `SYS_capset`) so it is safe inside
/// `std::os::unix::process::CommandExt::pre_exec` hooks before spawning untrusted subprocesses
/// such as `curl`.
pub fn clear_child_privileges() -> std::io::Result<()>
{
    // Best-effort clear of ambient capabilities (unsupported on Linux < 4.3 -> EINVAL).
    // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_CLEAR_ALL` takes zero pointer arguments.
    let _ = unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong, 0, 0, 0) };
    set_process_caps(0)?;
    // SAFETY: `PR_SET_NO_NEW_PRIVS` takes integer flag `1` and zero trailing args.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as c_ulong, 0, 0, 0) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Drops unnecessary capabilities and clears the bounding set while retaining `CAP_NET_ADMIN|CAP_NET_RAW`.
///
/// Mirrors `zapret2`'s `dropcaps()`: first attempts bounding-set pruning if `CAP_SETPCAP` is available,
/// then locks effective/permitted caps down to `CAP_MASK_NET`. When `require_net_caps` is `false`
/// (e.g. `--intercept=0`), lack of network capabilities is non-fatal and remaining privileges are cleared.
pub fn retain_net_capabilities(require_net_caps: bool) -> Result<(), ProcessError>
{
    retain_net_capabilities_for(require_net_caps, false)
}

/// Retains `CAP_NET_ADMIN|CAP_NET_RAW`, preserving pre-existing ambient `CAP_NET_ADMIN` only
/// when already ambient (e.g., under systemd `AmbientCapabilities`), never promoting file caps.
pub fn retain_net_capabilities_for(
    require_net_caps: bool,
    preserve_nft_ambient: bool,
) -> Result<(), ProcessError>
{
    retain_net_capabilities_internal(require_net_caps, preserve_nft_ambient, false)
}

/// Retains `CAP_NET_ADMIN|CAP_NET_RAW` immediately after dropping root UID, raising ambient
/// `CAP_NET_ADMIN` when `raise_nft_ambient` is requested so `--nft` can spawn trusted `nft`.
pub fn retain_net_capabilities_from_root(
    require_net_caps: bool,
    raise_nft_ambient: bool,
) -> Result<(), ProcessError>
{
    retain_net_capabilities_internal(require_net_caps, raise_nft_ambient, true)
}

/// Shared capability-retention implementation optionally allowing root-dropped ambient promotion.
fn retain_net_capabilities_internal(
    require_net_caps: bool,
    preserve_nft_ambient: bool,
    allow_raise_from_permitted: bool,
) -> Result<(), ProcessError>
{
    let can_keep_nft_ambient = preserve_nft_ambient
        && (ambient_cap_active(CAP_NET_ADMIN)
            || inheritable_cap_active(CAP_NET_ADMIN)
            || (allow_raise_from_permitted
                && capget_current()
                    .map(|d| (d[0].permitted & (1u32 << CAP_NET_ADMIN)) != 0)
                    .unwrap_or(false)));
    let inh = if can_keep_nft_ambient { 1u64 << CAP_NET_ADMIN } else { 0 };
    if inh == 0
    {
        // SAFETY: `PR_CAP_AMBIENT` + `PR_CAP_AMBIENT_CLEAR_ALL` takes zero pointer arguments.
        let _ =
            unsafe { libc::prctl(libc::PR_CAP_AMBIENT, libc::PR_CAP_AMBIENT_CLEAR_ALL as c_ulong, 0, 0, 0) };
    }
    if set_process_caps_with_inheritable(CAP_MASK_NET | (1u64 << CAP_SETPCAP) | inh, inh).is_ok()
    {
        let max_cap = read_cap_last_cap();
        for cap in 0..=max_cap
        {
            if cap < 64 && (inh & (1u64 << cap)) != 0
            {
                continue;
            }
            // Best-effort per capability bit: container/seccomp profiles may deny `PR_CAPBSET_DROP`.
            // SAFETY: `PR_CAPBSET_DROP` reads integer capability index `cap` and ignores trailing args.
            let _ = unsafe { libc::prctl(libc::PR_CAPBSET_DROP, cap as c_ulong, 0, 0, 0) };
        }
    }

    match set_process_caps_with_inheritable(CAP_MASK_NET, inh)
    {
        Ok(()) =>
        {
            if inh != 0 && !ambient_cap_active(CAP_NET_ADMIN)
            {
                // SAFETY: `PR_CAP_AMBIENT_RAISE` promotes permitted+inheritable `CAP_NET_ADMIN` after root UID drop.
                let _ = unsafe {
                    libc::prctl(
                        libc::PR_CAP_AMBIENT,
                        PR_CAP_AMBIENT_RAISE as c_ulong,
                        CAP_NET_ADMIN as c_ulong,
                        0,
                        0,
                    )
                };
            }
            Ok(())
        }
        Err(source) =>
        {
            if !require_net_caps
            {
                let _ = set_process_caps(0);
                return Ok(());
            }
            if has_effective_caps(CAP_MASK_NET)?
            {
                return Ok(());
            }
            Err(ProcessError::Capabilities { step: "capset(CAP_NET_ADMIN|CAP_NET_RAW)", source })
        }
    }
}
