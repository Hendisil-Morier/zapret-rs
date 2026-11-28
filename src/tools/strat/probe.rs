//! HTTP/TLS/QUIC connectivity probe backends (`curl` + mockable [`ProbeBackend`] trait).

/// Deduplicated per-scan DNS resolution cache mapping `(domain, family)` to resolved IP.
use std::collections::HashMap;
/// Resolved target IP address and synchronous OS resolver trait for `--resolve` pinning.
use std::net::{IpAddr, ToSocketAddrs};
/// Unix `pre_exec` extension stripping all Linux capabilities before spawning `curl`.
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt as _;
/// Filesystem paths for the external `curl` executable.
use std::path::{Path, PathBuf};
/// Subprocess spawning for `curl` probes.
use std::process::Command;
/// Work-stealing atomic cursor for bounded parallel probe batches.
use std::sync::atomic::{AtomicUsize, Ordering};
/// Shared thread-safe cache and bounded worker-pool synchronization primitives.
use std::sync::{Arc, Mutex, RwLock};
/// Monotonic timing and request timeout durations.
use std::time::{Duration, Instant};

/// Async-signal-safe child privilege stripper (`capset(0)` + `PR_SET_NO_NEW_PRIVS`).
#[cfg(target_os = "linux")]
use crate::runtime::clear_child_privileges;
/// Target protocol and IP family enums shared with the strategy catalog.
use crate::tools::strat::catalog::{IpFamily, ProbeProtocol};
/// Classified probe outcomes, `-w` format string, and `curl` output classifier.
use crate::tools::strat::probe_classify::{PROBE_WRITE_OUT, ProbeOutcome, classify_curl_output};

/// Parameters describing one connectivity probe request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeRequest
{
    /// Target hostname (no scheme or path, e.g., `"example.com"`).
    pub domain: String,
    /// Protocol to test (`Http`, `Tls12`, `Tls13`, or `Http3`).
    pub proto: ProbeProtocol,
    /// IP address family (`V4` or `V6`).
    pub ipv: IpFamily,
    /// Maximum wall-clock time allowed for the request.
    pub timeout: Duration,
}

/// Upper bound on concurrent `curl` child processes launched by [`CurlProbeBackend::probe_batch`].
const MAX_PARALLEL_PROBES: usize = 8;

/// Formats `timeout` as a locale-independent decimal-second string (`0.2`..=`60`) for `curl`.
fn format_curl_timeout(timeout: Duration) -> String
{
    let ms = timeout.as_millis().clamp(200, 60_000) as u64;
    let (secs, frac) = (ms / 1000, ms % 1000);
    if frac == 0
    {
        secs.to_string()
    }
    else
    {
        let s = format!("{secs}.{frac:03}");
        s.trim_end_matches('0').to_owned()
    }
}

/// Formats one `curl --resolve` pin (`host:port:ip`, bracketing IPv6 addresses).
pub fn format_resolve_arg(domain: &str, port: u16, ip: IpAddr) -> String
{
    match ip
    {
        IpAddr::V4(v4) => format!("{domain}:{port}:{v4}"),
        IpAddr::V6(v6) => format!("{domain}:{port}:[{v6}]"),
    }
}

/// Injectable connectivity probe interface allowing live `curl` execution and offline mocks.
pub trait ProbeBackend
{
    /// Returns `true` if this backend supports HTTP/3 (QUIC) probing.
    fn supports_http3(&self) -> bool;

    /// Executes one connectivity probe against `req` and classifies the result.
    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome;

    /// Executes a batch of independent probes and returns outcomes in matching index order.
    fn probe_batch(&self, reqs: &[ProbeRequest]) -> Vec<ProbeOutcome>
    {
        reqs.iter().map(|req| self.probe(req)).collect()
    }
}

/// Thread-safe per-scan DNS resolution cache mapping `(domain, family)` to the resolved IP.
type ResolveCache = Arc<RwLock<HashMap<(String, IpFamily), Option<IpAddr>>>>;

/// Live [`ProbeBackend`] invoking the system `curl` binary with per-scan DNS resolution caching.
#[derive(Debug, Clone)]
pub struct CurlProbeBackend
{
    /// Path or executable name of `curl` (defaults to `"curl"`).
    curl_bin: PathBuf,
    /// Cached first resolved IP per `(domain, IpFamily)` avoiding repeat `getaddrinfo` lookups.
    resolve_cache: ResolveCache,
}

impl Default for CurlProbeBackend
{
    /// Constructs a [`CurlProbeBackend`] using `"curl"` from `PATH`.
    fn default() -> Self
    {
        Self::new(PathBuf::from("curl"))
    }
}

impl CurlProbeBackend
{
    /// Constructs a [`CurlProbeBackend`] pointing at an explicit `curl` binary path.
    pub fn new(curl_bin: PathBuf) -> Self
    {
        Self { curl_bin, resolve_cache: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Returns the configured `curl` binary path.
    pub fn curl_bin(&self) -> &Path
    {
        &self.curl_bin
    }

    /// Looks up or populates the cached IP for `(domain, ipv)` matching the target address family.
    fn cached_ip(&self, domain: &str, port: u16, ipv: IpFamily) -> Option<IpAddr>
    {
        let key = (domain.to_owned(), ipv);
        if let Ok(guard) = self.resolve_cache.read()
            && let Some(&cached) = guard.get(&key)
        {
            return cached;
        }
        let resolved = (domain, port)
            .to_socket_addrs()
            .ok()
            .and_then(|addrs| {
                addrs.map(|sa| sa.ip()).find(|ip| {
                    matches!((ipv, ip), (IpFamily::V4, IpAddr::V4(_)) | (IpFamily::V6, IpAddr::V6(_)))
                })
            })
            .filter(|ip| !is_ssrf_blocked_ip(*ip));
        if let Ok(mut guard) = self.resolve_cache.write()
        {
            guard.insert(key, resolved);
        }
        resolved
    }

    /// Builds the `curl` argument list for `req` (separated for deterministic unit testing).
    pub fn build_args(req: &ProbeRequest) -> Vec<String>
    {
        let scheme = if req.proto == ProbeProtocol::Http { "http" } else { "https" };
        let url = format!("{scheme}://{}/", req.domain);
        Self::build_url_args(&url, Some(req.proto), req.ipv, req.timeout, PROBE_WRITE_OUT)
    }

    /// Builds `curl` arguments fetching `url` and printing `write_out` after the transfer.
    ///
    /// Passes `--globoff` so bracket/brace characters cannot expand URL globs into SSRF sweeps.
    /// `proto = None` leaves TLS and HTTP version negotiation to `curl` (used by speed checks that
    /// must behave like ordinary browsing); `Some` pins the version exactly as strategy scans do.
    pub fn build_url_args(
        url: &str,
        proto: Option<ProbeProtocol>,
        ipv: IpFamily,
        timeout: Duration,
        write_out: &str,
    ) -> Vec<String>
    {
        let secs = format_curl_timeout(timeout);
        let null_sink = if cfg!(windows) { "NUL" } else { "/dev/null" };
        let mut args = vec![
            "-sS".to_owned(),
            "--globoff".to_owned(),
            "-o".to_owned(),
            null_sink.to_owned(),
            "--noproxy".to_owned(),
            "*".to_owned(),
            "--connect-timeout".to_owned(),
            secs.clone(),
            "--max-time".to_owned(),
            secs,
            if ipv == IpFamily::V4 { "-4" } else { "-6" }.to_owned(),
            "-w".to_owned(),
            write_out.to_owned(),
        ];
        match proto
        {
            None =>
            {}
            Some(ProbeProtocol::Http) => args.push("--http1.1".to_owned()),
            Some(ProbeProtocol::Tls12) => args.extend(["--tlsv1.2", "--tls-max", "1.2"].map(str::to_owned)),
            Some(ProbeProtocol::Tls13) => args.push("--tlsv1.3".to_owned()),
            Some(ProbeProtocol::Http3) => args.push("--http3-only".to_owned()),
        }
        args.push(url.to_owned());
        args
    }

    /// Creates a [`Command`] for `self.curl_bin` that drops all Linux capabilities and sets
    /// `PR_SET_NO_NEW_PRIVS` in the child before `execve` on Linux.
    pub(crate) fn unprivileged_command(&self) -> Command
    {
        #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
        let mut cmd = Command::new(&self.curl_bin);
        #[cfg(target_os = "linux")]
        // SAFETY: `clear_child_privileges` invokes only async-signal-safe `prctl` and `SYS_capset`.
        unsafe {
            cmd.pre_exec(clear_child_privileges);
        }
        cmd
    }
}

/// Returns `true` when `ip` targets loopback, unspecified, multicast, or link-local metadata space.
fn is_ssrf_blocked_ip(ip: IpAddr) -> bool
{
    match ip
    {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() || v4.is_multicast(),
        IpAddr::V6(v6) =>
        {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

impl ProbeBackend for CurlProbeBackend
{
    /// Runs `curl --version` unprivileged and checks whether `HTTP3` appears in `Features:`.
    fn supports_http3(&self) -> bool
    {
        let Ok(out) = self.unprivileged_command().arg("--version").output()
        else
        {
            return false;
        };
        if !out.status.success()
        {
            return false;
        }
        let text = String::from_utf8_lossy(&out.stdout);
        text.lines()
            .any(|line| line.starts_with("Features:") && line.split_whitespace().any(|tok| tok == "HTTP3"))
    }

    /// Invokes `curl` unprivileged for `req` (with `--resolve` cache hit when resolved) and classifies the output.
    fn probe(&self, req: &ProbeRequest) -> ProbeOutcome
    {
        if !req.domain.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
            || req.domain.starts_with('-')
            || req.domain.is_empty()
        {
            return ProbeOutcome::Failed { code: -1, detail: "invalid probe domain name".to_owned() };
        }
        let mut args = Self::build_args(req);
        if let Some(ip) = self.cached_ip(&req.domain, req.proto.default_port(), req.ipv)
        {
            let resolve = format_resolve_arg(&req.domain, req.proto.default_port(), ip);
            let url_idx = args.len().saturating_sub(1);
            args.splice(url_idx..url_idx, ["--resolve".to_owned(), resolve]);
        }
        let start = Instant::now();
        let output = match self.unprivileged_command().args(&args).output()
        {
            Ok(out) => out,
            Err(err) =>
            {
                return ProbeOutcome::Failed {
                    code: -1,
                    detail: format!("failed to spawn {}: {err}", self.curl_bin.display()),
                };
            }
        };
        let elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
        let exit_code = output.status.code().unwrap_or(-1);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_curl_output(&req.domain, exit_code, &stdout, &stderr, elapsed_ms)
    }

    /// Runs independent probes concurrently across a bounded worker pool preserving request order.
    fn probe_batch(&self, reqs: &[ProbeRequest]) -> Vec<ProbeOutcome>
    {
        if reqs.len() <= 1
        {
            return reqs.iter().map(|r| self.probe(r)).collect();
        }
        let next = AtomicUsize::new(0);
        let results: Mutex<Vec<Option<ProbeOutcome>>> = Mutex::new(vec![None; reqs.len()]);
        let workers = reqs.len().min(MAX_PARALLEL_PROBES);
        std::thread::scope(|scope| {
            for _ in 0..workers
            {
                scope.spawn(|| {
                    loop
                    {
                        let idx = next.fetch_add(1, Ordering::Relaxed);
                        if idx >= reqs.len()
                        {
                            break;
                        }
                        let outcome = self.probe(&reqs[idx]);
                        if let Ok(mut guard) = results.lock()
                        {
                            guard[idx] = Some(outcome);
                        }
                    }
                });
            }
        });
        results
            .into_inner()
            .unwrap_or_default()
            .into_iter()
            .map(|opt| opt.unwrap_or(ProbeOutcome::Failed { code: -1, detail: "worker panic".to_owned() }))
            .collect()
    }
}
