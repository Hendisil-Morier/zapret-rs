//! Pairing-token authentication, signed `HttpOnly` session cookies, and CSRF checks.

/// Target socket bind address validation ensuring `--no-auth` stays loopback-only.
use std::net::SocketAddr;
/// Synchronized `/api/login` failed-attempt throttling state.
use std::sync::Mutex;
/// Wall-clock UNIX timestamps for session cookie expiration checks.
use std::time::{SystemTime, UNIX_EPOCH};

/// Existing FIPS 180-4 SHA-256 and RFC 2104 HMAC primitives shared across `zapret-rs`.
use crate::crypto::{HashAlg, hmac_sha2, sha2_hash};
/// Parsed HTTP request metadata inspected for bearer tokens, cookies, and CSRF headers.
use crate::tools::web::http::HttpRequest;

/// Cookie name storing the signed web session token (`exp.nonce.hmac`).
pub const SESSION_COOKIE_NAME: &str = "zapret_session";
/// Default web UI session lifetime (12 hours).
const DEFAULT_SESSION_TTL_SECS: u64 = 12 * 3600;
/// Random nonce length for CSRF and HMAC cookie uniqueness (128-bit -> 32 hex chars).
const NONCE_HEX_LEN: usize = 32;

/// Authentication gate protecting HTTP control endpoints from unauthorized LAN access.
#[derive(Debug, Clone)]
pub enum WebAuth {
    /// Loopback-only mode explicitly unlocked via `--no-auth`.
    Disabled,
    /// Passcode + HMAC-signed cookie authentication mode.
    Required {
        /// SHA-256 digest of the active pairing passcode (avoids storing plain length leaks).
        token_digest: Vec<u8>,
        /// Random per-process 256-bit secret signing `zapret_session` cookies.
        signing_key: [u8; 32],
        /// Session validity window in seconds.
        session_ttl_secs: u64,
    },
}

/// Returns current UNIX epoch seconds (`0` only if system clock precedes `1970-01-01`).
pub fn unix_now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// Encodes `bytes` as lowercase hexadecimal text cleanly without external dependencies.
fn to_hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Constant-time equality comparison for equal-length digests; returns `false` on length skew.
fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Generates a phone-friendly 16-hex-char pairing passcode (`xxxx-xxxx-xxxx-xxxx`) via OS CSPRNG.
fn generate_pairing_token() -> String {
    let raw = rand::random::<u64>();
    let hex = format!("{raw:016x}");
    format!("{}-{}-{}-{}", &hex[0..4], &hex[4..8], &hex[8..12], &hex[12..16])
}

/// Parses `"Bearer <token>"` case-insensitively on scheme from an HTTP `Authorization` header.
fn parse_bearer_token(header: &str) -> Option<&str> {
    let (scheme, token) = header.trim().split_once(char::is_whitespace)?;
    if scheme.eq_ignore_ascii_case("bearer") {
        let trimmed = token.trim();
        if trimmed.is_empty() { None } else { Some(trimmed) }
    } else {
        None
    }
}

/// Extracts a named cookie value from an HTTP `Cookie` header.
fn extract_cookie<'a>(cookie_header: &'a str, name: &str) -> Option<&'a str> {
    for part in cookie_header.split(';') {
        if let Some((k, v)) = part.trim().split_once('=')
            && k.trim() == name
        {
            return Some(v.trim());
        }
    }
    None
}

impl WebAuth {
    /// Builds [`WebAuth`] for `bind`, generating a random pairing token when omitted.
    ///
    /// Returns `(auth, generated_token)` where `generated_token` is `Some` when auto-generated.
    pub fn new(
        bind: SocketAddr,
        explicit_token: Option<String>,
        no_auth: bool,
    ) -> Result<(Self, Option<String>), String> {
        if no_auth {
            if !bind.ip().is_loopback() {
                return Err(format!(
                    "refusing --no-auth on non-loopback address {bind}; omit --no-auth or pass --token"
                ));
            }
            return Ok((Self::Disabled, None));
        }

        let (plain_token, generated) = match explicit_token {
            Some(tok) => {
                let trimmed = tok.trim().to_owned();
                if trimmed.is_empty() {
                    return Err("web auth token must not be empty".to_owned());
                }
                (trimmed, None)
            }
            None => {
                let tok = generate_pairing_token();
                (tok.clone(), Some(tok))
            }
        };

        let token_digest = sha2_hash(HashAlg::Sha256, plain_token.as_bytes());
        let mut signing_key = [0u8; 32];
        signing_key[..16].copy_from_slice(&rand::random::<u128>().to_le_bytes());
        signing_key[16..].copy_from_slice(&rand::random::<u128>().to_le_bytes());
        Ok((
            Self::Required { token_digest, signing_key, session_ttl_secs: DEFAULT_SESSION_TTL_SECS },
            generated,
        ))
    }

    /// Returns `true` when requests must present a valid passcode or session cookie.
    pub const fn is_required(&self) -> bool {
        matches!(self, Self::Required { .. })
    }

    /// Constant-time checks `candidate` against the SHA-256 token digest.
    pub fn verify_token(&self, candidate: &str) -> bool {
        let Self::Required { token_digest, .. } = self else {
            return true;
        };
        let digest = sha2_hash(HashAlg::Sha256, candidate.trim().as_bytes());
        const_time_eq(&digest, token_digest)
    }

    /// Mints a signed `exp.nonce.hmac` cookie value valid until `now_secs + session_ttl_secs`.
    pub fn issue_session_cookie(&self, now_secs: u64) -> Option<String> {
        let Self::Required { signing_key, session_ttl_secs, .. } = self else {
            return None;
        };
        let exp = now_secs.saturating_add(*session_ttl_secs);
        let nonce = format!("{:032x}", rand::random::<u128>());
        let payload = format!("{exp}.{nonce}");
        let sig = to_hex_lower(&hmac_sha2(HashAlg::Sha256, signing_key, payload.as_bytes()));
        Some(format!("{payload}.{sig}"))
    }

    /// Formats a `Set-Cookie` header value storing or clearing [`SESSION_COOKIE_NAME`].
    pub fn format_set_cookie(value: &str, max_age_secs: u64) -> String {
        format!(
            "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age_secs}"
        )
    }

    /// Verifies an incoming cookie string against the HMAC signature and expiration timestamp.
    pub fn verify_session_value(&self, raw: &str, now_secs: u64) -> bool {
        let Self::Required { signing_key, .. } = self else {
            return true;
        };
        let mut parts = raw.split('.');
        let (Some(exp_s), Some(nonce), Some(sig_hex), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return false;
        };
        let Ok(exp) = exp_s.parse::<u64>() else {
            return false;
        };
        if nonce.len() != NONCE_HEX_LEN || now_secs > exp {
            return false;
        }
        let payload = format!("{exp}.{nonce}");
        let expected_sig = to_hex_lower(&hmac_sha2(HashAlg::Sha256, signing_key, payload.as_bytes()));
        const_time_eq(sig_hex.as_bytes(), expected_sig.as_bytes())
    }

    /// Returns `true` when `req` holds valid bearer credentials or an active signed session cookie.
    pub fn is_authorized(&self, req: &HttpRequest, now_secs: u64) -> bool {
        if !self.is_required() {
            return true;
        }
        if let Some(auth_hdr) = req.header("authorization")
            && let Some(token) = parse_bearer_token(auth_hdr)
            && self.verify_token(token)
        {
            return true;
        }
        if let Some(cookie_hdr) = req.header("cookie")
            && let Some(val) = extract_cookie(cookie_hdr, SESSION_COOKIE_NAME)
            && self.verify_session_value(val, now_secs)
        {
            return true;
        }
        false
    }

    /// Validates that state-mutating `POST` requests come from same-origin fetch/JSON rather than
    /// bare HTML cross-site form submissions.
    pub fn passes_csrf_guard(req: &HttpRequest) -> bool {
        if let Some(ct) = req.header("content-type")
            && ct.to_ascii_lowercase().starts_with("application/json")
        {
            return true;
        }
        req.header("x-zapret-action").is_some()
    }

    /// Rejects cross-site `Origin`/`Sec-Fetch-Site` headers and DNS-rebinding `Host` headers
    /// (especially critical on loopback listeners where `--no-auth` may be active).
    pub fn passes_host_and_origin_guard(req: &HttpRequest, bind_addr: SocketAddr) -> bool {
        let Some(raw_host) = req.header("host").map(str::trim).filter(|h| !h.is_empty()) else {
            return false;
        };
        if raw_host.chars().any(char::is_whitespace) || raw_host.contains('/') {
            return false;
        }
        let host_name = extract_authority_host(raw_host);
        if host_name.is_empty() {
            return false;
        }
        if bind_addr.ip().is_loopback() && !is_loopback_hostname(host_name, bind_addr) {
            return false;
        }
        if let Some(sfs) = req.header("sec-fetch-site").map(str::trim)
            && req.method == crate::tools::web::http::HttpMethod::Post
            && !sfs.eq_ignore_ascii_case("same-origin")
            && !sfs.eq_ignore_ascii_case("none")
        {
            return false;
        }
        if let Some(origin) = req.header("origin").map(str::trim) {
            let Some(after_scheme) = origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
            else {
                return false;
            };
            let origin_auth = after_scheme.split('/').next().unwrap_or("");
            if !origin_auth.eq_ignore_ascii_case(raw_host)
                && !extract_authority_host(origin_auth).eq_ignore_ascii_case(host_name)
            {
                return false;
            }
        }
        true
    }
}

/// Extracts hostname/IP without optional `:port` or IPv6 brackets (`[...]` -> `...`).
fn extract_authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
}

/// Returns `true` when `host` identifies a local loopback address or `localhost`.
fn is_loopback_hostname(host: &str, bind_addr: SocketAddr) -> bool {
    host.eq_ignore_ascii_case("localhost")
        || host == "127.0.0.1"
        || host == "::1"
        || host == bind_addr.ip().to_string()
}

/// Sliding-window failed `/api/login` attempt limiter preventing online passcode brute-forcing.
#[derive(Default)]
pub struct LoginRateLimiter {
    /// Synchronized failure count and active cooldown window timestamps.
    state: Mutex<LoginThrottleState>,
}

/// Internal state guarded by [`LoginRateLimiter`].
#[derive(Default)]
struct LoginThrottleState {
    /// Consecutive failed `/api/login` attempts in the active window.
    failures: u32,
    /// Start timestamp (UNIX seconds) of the active failure window.
    window_started: u64,
    /// Cooldown expiration timestamp (UNIX seconds) while locked out.
    locked_until: u64,
}

impl LoginRateLimiter {
    /// Returns `Ok(())` if login attempts are allowed at `now_secs`, else `Err(retry_after_secs)`.
    pub fn check_allowed(&self, now_secs: u64) -> Result<(), u64> {
        let guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if now_secs < guard.locked_until {
            Err(guard.locked_until - now_secs)
        } else {
            Ok(())
        }
    }

    /// Records a failed passcode attempt and triggers a 30s lockout after 5 failures within 60s.
    pub fn record_failure(&self, now_secs: u64) {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if now_secs.saturating_sub(guard.window_started) > 60 {
            guard.window_started = now_secs;
            guard.failures = 0;
        }
        guard.failures = guard.failures.saturating_add(1);
        if guard.failures >= 5 {
            guard.locked_until = now_secs.saturating_add(30);
        }
    }

    /// Resets failure counters after a successful passcode verification.
    pub fn record_success(&self) {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        guard.failures = 0;
        guard.locked_until = 0;
    }
}
