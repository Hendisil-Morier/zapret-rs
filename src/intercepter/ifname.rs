//! Persistent `SIOCGIFNAME` socket helper and bounded short-TTL cache for resolving Linux interface indices.

/// Interior mutability preserving `&self` lookup signature while caching resolved interface names.
use std::cell::RefCell;
/// Persistent UDP control socket handle for `SIOCGIFNAME` `ioctl` calls.
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// Typed error enum for socket creation failures.
use crate::intercepter::error::IntercepterError;
/// Monotonic boottime seconds clock used to bound cached `ifindex -> name` lifetime.
use crate::timer::boottime_secs;

/// Lifetime in monotonic seconds before a cached `ifindex -> name` mapping refreshes via `SIOCGIFNAME`.
const IFNAME_CACHE_TTL_SEC: i64 = 5;
/// Maximum number of cached interface mappings retained simultaneously.
const IFNAME_CACHE_MAX_ENTRIES: usize = 128;

/// Single cached `(ifindex -> name)` entry paired with its expiration second.
#[derive(Debug, Clone)]
struct CachedIfName
{
    /// Linux kernel interface index key.
    ifindex: u32,
    /// Resolved UTF-8 interface name (up to `IFNAMSIZ - 1` bytes).
    name: Box<str>,
    /// Monotonic boottime second when this entry was fetched via `SIOCGIFNAME`.
    fetched_sec: i64,
}

/// Resolves Linux network interface indices to interface names using one persistent UDP control socket
/// and a bounded short-TTL cache.
#[derive(Debug)]
pub struct IfNameResolver
{
    /// Persistent `AF_INET` `SOCK_DGRAM | SOCK_CLOEXEC` file descriptor reused for `SIOCGIFNAME` `ioctl` calls.
    sock: OwnedFd,
    /// Small bounded cache mapping active interface indices to borrowed names.
    cache: RefCell<Vec<CachedIfName>>,
}

impl IfNameResolver
{
    /// Opens an `AF_INET` `SOCK_DGRAM | SOCK_CLOEXEC` control socket for interface name lookups.
    pub fn new() -> Result<Self, IntercepterError>
    {
        // SAFETY: `libc::socket` takes integer constants and returns a new FD or `-1` on error.
        let raw_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
        if raw_fd < 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: `raw_fd` was just returned by `libc::socket` and is exclusively owned here.
        let sock = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        Ok(Self { sock, cache: RefCell::new(Vec::with_capacity(8)) })
    }

    /// Resolves `ifindex` via cache or `SIOCGIFNAME`, returning `None` for `0` or unknown interfaces.
    pub fn resolve(&self, ifindex: u32) -> Option<String>
    {
        let now = boottime_secs();
        let slot_idx = self.ensure_cached(ifindex, now)?;
        let cache = self.cache.borrow();
        cache.get(slot_idx).map(|entry| entry.name.as_ref().to_owned())
    }

    /// Resolves `(indev, outdev)` together and passes borrowed `Option<&str>` names to `f` without allocation.
    pub(crate) fn resolve_pair<R>(
        &self,
        indev: u32,
        outdev: u32,
        f: impl FnOnce(Option<&str>, Option<&str>) -> R,
    ) -> R
    {
        let now = boottime_secs();
        let in_present = self.ensure_cached(indev, now).is_some();
        let out_present = self.ensure_cached(outdev, now).is_some();
        let cache = self.cache.borrow();
        let ifin =
            in_present.then(|| cache.iter().find(|e| e.ifindex == indev).map(|e| e.name.as_ref())).flatten();
        let ifout = out_present
            .then(|| cache.iter().find(|e| e.ifindex == outdev).map(|e| e.name.as_ref()))
            .flatten();
        f(ifin, ifout)
    }

    /// Ensures `ifindex` is populated cleanly inside `self.cache` if valid, returning its cache slot index.
    fn ensure_cached(&self, ifindex: u32, now: i64) -> Option<usize>
    {
        if ifindex == 0
        {
            return None;
        }
        if let Some(pos) = self
            .cache
            .borrow()
            .iter()
            .position(|entry| entry.ifindex == ifindex && now - entry.fetched_sec < IFNAME_CACHE_TTL_SEC)
        {
            return Some(pos);
        }

        let resolved = self.resolve_uncached(ifindex);
        let mut cache = self.cache.borrow_mut();
        match resolved
        {
            Some(name) =>
            {
                if let Some(pos) = cache.iter().position(|entry| entry.ifindex == ifindex)
                {
                    cache[pos].name = name.into_boxed_str();
                    cache[pos].fetched_sec = now;
                    return Some(pos);
                }
                cache.retain(|entry| now - entry.fetched_sec < IFNAME_CACHE_TTL_SEC);
                if cache.len() >= IFNAME_CACHE_MAX_ENTRIES
                {
                    cache.remove(0);
                }
                cache.push(CachedIfName { ifindex, name: name.into_boxed_str(), fetched_sec: now });
                Some(cache.len() - 1)
            }
            None =>
            {
                cache.retain(|entry| entry.ifindex != ifindex);
                None
            }
        }
    }

    /// Queries the kernel directly with `SIOCGIFNAME` without consulting or mutating the cache.
    fn resolve_uncached(&self, ifindex: u32) -> Option<String>
    {
        let idx = libc::c_int::try_from(ifindex).ok()?;
        // SAFETY: `libc::ifreq` is a plain C struct for which all-zero initialization is valid.
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        ifr.ifr_ifru.ifru_ifindex = idx;

        // SAFETY: `SIOCGIFNAME` reads `ifr_ifru.ifru_ifindex` and writes a NUL-terminated name into `ifr_name`.
        let rc = unsafe { libc::ioctl(self.sock.as_raw_fd(), libc::SIOCGIFNAME, &raw mut ifr) };
        if rc < 0
        {
            return None;
        }

        let len = ifr.ifr_name.iter().position(|&ch| ch == 0).unwrap_or(ifr.ifr_name.len());
        if len == 0
        {
            return None;
        }
        let mut buf = [0u8; libc::IFNAMSIZ];
        for (dst, &src) in buf[..len].iter_mut().zip(&ifr.ifr_name[..len])
        {
            *dst = src as u8;
        }
        Some(String::from_utf8_lossy(&buf[..len]).into_owned())
    }
}
