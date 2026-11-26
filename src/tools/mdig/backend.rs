//! `mdig` runtime configuration, domain validation helpers, and `libc::getaddrinfo` backend.

/// C string conversion for nul-terminated `getaddrinfo` hostnames.
#[cfg(unix)]
use std::ffi::CString;
/// Parsed IPv4 and IPv6 host address types returned from OS lookups.
use std::net::IpAddr;
/// Explicit IPv4/IPv6 constructors used by the Unix `libc::getaddrinfo` decoder.
#[cfg(unix)]
use std::net::{Ipv4Addr, Ipv6Addr};
/// Portable standard-library DNS lookup used on non-Unix targets.
#[cfg(not(unix))]
use std::net::ToSocketAddrs;

/// Typed error derivation for invalid `mdig` configuration flags.
use thiserror::Error;

/// Shared family configuration parsed alongside resolver options.
use crate::tools::mdig::dns::MdigFamily;

/// Default worker thread count (`1`).
pub const DEFAULT_MDIG_THREADS: usize = 1;
/// Maximum allowed worker thread count (`100`).
pub const MAX_MDIG_THREADS: usize = 100;
/// Default `EAI_AGAIN` retry attempt limit (`10`).
pub const DEFAULT_EAGAIN_ATTEMPTS: u32 = 10;
/// Maximum allowed `EAI_AGAIN` retry attempts (`1000`).
pub const MAX_EAGAIN_ATTEMPTS: u32 = 1000;
/// Default backoff delay in milliseconds between `EAI_AGAIN` retries (`500`).
pub const DEFAULT_EAGAIN_DELAY_MS: u64 = 500;
/// Maximum allowed backoff delay in milliseconds (`100000`).
pub const MAX_EAGAIN_DELAY_MS: u64 = 100_000;

/// GNU/Linux glibc `EAI_ADDRFAMILY` error code omitted from `libc`'s Linux bindings.
#[cfg(all(target_os = "linux", target_env = "gnu"))]
const GLIBC_EAI_ADDRFAMILY: i32 = -9;

/// Errors returned while validating `mdig` runtime options.
#[derive(Debug, Error)]
pub enum MdigConfigError {
    /// `--family` was not `"4"`, `"6"`, or `"46"`.
    #[error("ip family must be 4,6 or 46")]
    InvalidFamily(String),
    /// `--threads` was non-numeric or outside `1..=100`.
    #[error("thread number must be within 1..100")]
    InvalidThreads(String),
    /// `--eagain` was non-numeric or outside `1..=1000`.
    #[error("eagain must be within 1..1000")]
    InvalidEagain(String),
    /// `--eagain-delay` was non-numeric or outside `0..=100000`.
    #[error("eagain-delay must be within 0..100000")]
    InvalidEagainDelay(String),
    /// `--stats` was not a valid signed integer.
    #[error("invalid parameter for stats : {0}")]
    InvalidStats(String),
}

/// Validated runtime configuration governing `mdig` resolution and logging behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdigConfig {
    /// Allowed address family (`4`, `6`, or `46`).
    pub family: MdigFamily,
    /// Number of worker threads draining stdin.
    pub threads: usize,
    /// Maximum resolve attempts per domain on `EAI_AGAIN`.
    pub eagain: u32,
    /// Delay in milliseconds between `EAI_AGAIN` attempts (`0` disables sleep).
    pub eagain_delay_ms: u64,
    /// Emit per-thread diagnostic progress messages to `stderr`.
    pub verbose: bool,
    /// Domain interval for periodic `mdig stats` reporting (`0` disables stats).
    pub stats_every: u64,
}

impl Default for MdigConfig {
    /// Returns default `mdig` settings (`--family=4 --threads=1 --eagain=10 --eagain-delay=500`).
    fn default() -> Self {
        Self {
            family: MdigFamily::Ipv4,
            threads: DEFAULT_MDIG_THREADS,
            eagain: DEFAULT_EAGAIN_ATTEMPTS,
            eagain_delay_ms: DEFAULT_EAGAIN_DELAY_MS,
            verbose: false,
            stats_every: 0,
        }
    }
}

impl MdigConfig {
    /// Validates raw CLI flag strings into an [`MdigConfig`] matching `mdig.c` bounds.
    pub fn from_options(
        family: Option<&str>,
        threads: Option<&str>,
        eagain: Option<&str>,
        eagain_delay: Option<&str>,
        verbose: bool,
        stats: Option<&str>,
    ) -> Result<Self, MdigConfigError> {
        let family = match family {
            Some(s) => {
                MdigFamily::parse(s).ok_or_else(|| MdigConfigError::InvalidFamily(s.into()))?
            }
            None => MdigFamily::Ipv4,
        };
        let threads = match threads {
            Some(s) => s
                .parse::<usize>()
                .ok()
                .filter(|&n| (1..=MAX_MDIG_THREADS).contains(&n))
                .ok_or_else(|| MdigConfigError::InvalidThreads(s.into()))?,
            None => DEFAULT_MDIG_THREADS,
        };
        let eagain = match eagain {
            Some(s) => s
                .parse::<u32>()
                .ok()
                .filter(|&n| (1..=MAX_EAGAIN_ATTEMPTS).contains(&n))
                .ok_or_else(|| MdigConfigError::InvalidEagain(s.into()))?,
            None => DEFAULT_EAGAIN_ATTEMPTS,
        };
        let eagain_delay_ms = match eagain_delay {
            Some(s) => s
                .parse::<u64>()
                .ok()
                .filter(|&n| n <= MAX_EAGAIN_DELAY_MS)
                .ok_or_else(|| MdigConfigError::InvalidEagainDelay(s.into()))?,
            None => DEFAULT_EAGAIN_DELAY_MS,
        };
        let stats_every = match stats {
            Some(s) => {
                let raw = s
                    .parse::<i64>()
                    .map_err(|_| MdigConfigError::InvalidStats(s.into()))?;
                if raw <= 0 { 0 } else { raw as u64 }
            }
            None => 0,
        };
        Ok(Self { family, threads, eagain, eagain_delay_ms, verbose, stats_every })
    }
}

/// DNS lookup failure wrapping a `libc::EAI_*` status code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolveError {
    /// Raw `EAI_*` error code returned by `getaddrinfo` or a test stub.
    pub code: i32,
}

impl ResolveError {
    /// Returns `true` when the failure is temporary (`EAI_AGAIN`) and eligible for retry.
    pub const fn is_again(self) -> bool {
        #[cfg(unix)]
        {
            self.code == libc::EAI_AGAIN
        }
        #[cfg(not(unix))]
        {
            let _ = self.code;
            false
        }
    }

    /// Maps a `libc::EAI_*` error code to the symbolic string printed by `mdig.c`.
    pub const fn eai_name(self) -> &'static str {
        #[cfg(unix)]
        {
            match self.code {
                libc::EAI_NONAME => "EAI_NONAME",
                libc::EAI_AGAIN => "EAI_AGAIN",
                #[cfg(all(target_os = "linux", target_env = "gnu"))]
                GLIBC_EAI_ADDRFAMILY => "EAI_ADDRFAMILY",
                libc::EAI_NODATA => "EAI_NODATA",
                libc::EAI_BADFLAGS => "EAI_BADFLAGS",
                libc::EAI_FAIL => "EAI_FAIL",
                libc::EAI_MEMORY => "EAI_MEMORY",
                libc::EAI_FAMILY => "EAI_FAMILY",
                libc::EAI_SERVICE => "EAI_SERVICE",
                libc::EAI_SOCKTYPE => "EAI_SOCKTYPE",
                libc::EAI_SYSTEM => "EAI_SYSTEM",
                _ => "UNKNOWN",
            }
        }
        #[cfg(not(unix))]
        {
            let _ = self.code;
            "EAI_FAIL"
        }
    }
}

/// Thread-safe domain resolution abstraction allowing deterministic offline test doubles.
pub trait DnsResolver: Send + Sync {
    /// Resolves `domain` for `family`, returning matching IP addresses or a `ResolveError`.
    fn resolve(&self, domain: &str, family: MdigFamily) -> Result<Vec<IpAddr>, ResolveError>;
}

/// Production DNS resolver backed by POSIX `libc::getaddrinfo` on Unix or `ToSocketAddrs` elsewhere.
pub struct LibcResolver;

/// RAII guard invoking `libc::freeaddrinfo` on a non-null `addrinfo` linked list.
#[cfg(unix)]
struct AddrInfoGuard(*mut libc::addrinfo);

#[cfg(unix)]
impl Drop for AddrInfoGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { libc::freeaddrinfo(self.0) };
        }
    }
}

#[cfg(unix)]
impl DnsResolver for LibcResolver {
    fn resolve(&self, domain: &str, family: MdigFamily) -> Result<Vec<IpAddr>, ResolveError> {
        let Ok(c_dom) = CString::new(domain) else {
            return Err(ResolveError { code: libc::EAI_NONAME });
        };
        let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
        hints.ai_family = match family {
            MdigFamily::Ipv4 => libc::AF_INET,
            MdigFamily::Ipv6 => libc::AF_INET6,
            MdigFamily::Ipv46 => libc::AF_UNSPEC,
        };
        hints.ai_socktype = libc::SOCK_DGRAM;

        let mut res: *mut libc::addrinfo = std::ptr::null_mut();
        let rc = unsafe { libc::getaddrinfo(c_dom.as_ptr(), std::ptr::null(), &hints, &mut res) };
        if rc != 0 {
            return Err(ResolveError { code: rc });
        }

        let _guard = AddrInfoGuard(res);
        let mut addrs = Vec::new();
        let mut cur = res;
        while !cur.is_null() {
            let info = unsafe { &*cur };
            if !info.ai_addr.is_null() {
                match info.ai_family {
                    libc::AF_INET
                        if (info.ai_addrlen as usize) >= std::mem::size_of::<libc::sockaddr_in>() =>
                    {
                        let sin = unsafe { &*(info.ai_addr.cast::<libc::sockaddr_in>()) };
                        addrs.push(IpAddr::V4(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes())));
                    }
                    libc::AF_INET6
                        if (info.ai_addrlen as usize)
                            >= std::mem::size_of::<libc::sockaddr_in6>() =>
                    {
                        let sin6 = unsafe { &*(info.ai_addr.cast::<libc::sockaddr_in6>()) };
                        addrs.push(IpAddr::V6(Ipv6Addr::from(sin6.sin6_addr.s6_addr)));
                    }
                    _ => {}
                }
            }
            cur = info.ai_next;
        }
        Ok(addrs)
    }
}

#[cfg(not(unix))]
impl DnsResolver for LibcResolver {
    fn resolve(&self, domain: &str, family: MdigFamily) -> Result<Vec<IpAddr>, ResolveError> {
        let Ok(iter) = (domain, 0_u16).to_socket_addrs() else {
            return Err(ResolveError { code: -1 });
        };
        let mut addrs = Vec::new();
        for sock in iter {
            let ip = sock.ip();
            let keep = match family {
                MdigFamily::Ipv4 => ip.is_ipv4(),
                MdigFamily::Ipv6 => ip.is_ipv6(),
                MdigFamily::Ipv46 => true,
            };
            if keep && !addrs.contains(&ip) {
                addrs.push(ip);
            }
        }
        Ok(addrs)
    }
}

/// Validates domain characters against `mdig.c`'s `dom_valid` rules.
pub fn is_valid_domain(dom: &str) -> bool {
    !dom.is_empty()
        && !dom.starts_with('.')
        && dom
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// Sanitizes up to 64 bytes of an invalid domain for readable verbose logging.
pub fn beautify_invalid_domain(raw: &[u8]) -> String {
    raw.iter()
        .take(64)
        .map(|&b| if b < 0x20 || (b & 0x80) != 0 { '?' } else { char::from(b) })
        .collect()
}
