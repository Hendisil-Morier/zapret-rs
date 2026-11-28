//! Multi-threaded domain resolver worker pool, IP/CIDR pass-through filter, and stats tracking for `mdig`.

/// Buffered line input and output writer traits for stdin domains, stdout IPs, stderr, and logs.
use std::io::{BufRead, Write};
/// Parsed IPv4/IPv6 host address detection for transparent pass-through filtering.
use std::net::IpAddr;
/// Mutual exclusion primitives synchronizing shared input reading, stats counters, and outputs.
use std::sync::{Mutex, MutexGuard};
/// Monotonic elapsed timer for `--stats` progress reporting and `EAI_AGAIN` retry backoff.
use std::time::{Duration, Instant};

/// Resolver backend trait, validated config, and domain validation helpers.
use crate::tools::mdig::backend::{DnsResolver, MdigConfig, beautify_invalid_domain, is_valid_domain};
/// Address family filtering helpers for literal IPs and CIDRs.
use crate::tools::mdig::dns::MdigFamily;

/// Synchronized output sinks written by `mdig` worker threads.
pub struct MdigOutputs<'a>
{
    /// Output stream receiving resolved IP and pass-through CIDR lines.
    pub stdout: &'a mut (dyn Write + Send),
    /// Diagnostic stream receiving `--verbose` logs, errors, and `--stats` summaries.
    pub stderr: &'a mut (dyn Write + Send),
    /// Optional `--log-resolved` file receiving successfully handled domain lines.
    pub log_resolved: Option<&'a mut (dyn Write + Send)>,
    /// Optional `--log-failed` file receiving unresolved or rejected lines.
    pub log_failed: Option<&'a mut (dyn Write + Send)>,
}

/// Acquires a `Mutex` guard without panicking even if another thread panicked.
fn lock_unpoison<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T>
{
    match mutex.lock()
    {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Writes one `mdig stats` progress line to `stderr` under `io_mutex`.
fn write_stats_line(io_mutex: &Mutex<MdigOutputs<'_>>, start: Instant, ct: u64, ct_ok: u64)
{
    let secs = start
        .elapsed()
        .as_secs();
    let hh = secs / 3600;
    let mm = (secs / 60) % 60;
    let ss = secs % 60;
    let mut out = lock_unpoison(io_mutex);
    let _ = writeln!(
        out.stderr,
        "mdig stats : {hh:02}:{mm:02}:{ss:02} : domains={ct} success={ct_ok} error={}",
        ct - ct_ok
    );
}

/// Evaluates an IP or `IP/mask` line for transparent pass-through filtering.
fn try_passthrough_ip(dom: &str, family: MdigFamily) -> Option<Result<String, String>>
{
    let (ip_s, mask_opt) = match dom.split_once('/')
    {
        Some((left, right)) => (left, Some(right)),
        None => (dom, None),
    };
    let ip = ip_s
        .parse::<IpAddr>()
        .ok()?;
    let allowed = (ip.is_ipv4() && family.allows_v4()) || (ip.is_ipv6() && family.allows_v6());
    if !allowed
    {
        return Some(Err(format!("wrong address family {ip_s}")));
    }
    let Some(mask_s) = mask_opt
    else
    {
        return Some(Ok(ip_s.to_string()));
    };
    let max_bits: u32 = if ip.is_ipv4() { 32 } else { 128 };
    match mask_s.parse::<u32>()
    {
        Ok(mask) if mask < max_bits => Some(Ok(format!("{ip_s}/{mask}"))),
        Ok(mask) if mask == max_bits => Some(Ok(ip_s.to_string())),
        _ => Some(Err(format!("bad ip/subnet {dom}"))),
    }
}

/// Evaluates a UTF-8 line via IP/CIDR pass-through or `resolver`, returning `None` if syntactically invalid.
fn resolve_utf8_domain(
    tid: usize,
    dom: &str,
    cfg: &MdigConfig,
    resolver: &dyn DnsResolver,
    io_mutex: &Mutex<MdigOutputs<'_>>,
) -> Option<bool>
{
    if let Some(passthrough) = try_passthrough_ip(dom, cfg.family)
    {
        let mut out = lock_unpoison(io_mutex);
        return Some(match passthrough
        {
            Ok(line) =>
            {
                let _ = writeln!(out.stdout, "{line}");
                true
            }
            Err(msg) =>
            {
                if cfg.verbose
                {
                    let _ = writeln!(out.stderr, "[{tid}] {msg}");
                }
                false
            }
        });
    }
    if !is_valid_domain(dom)
    {
        return None;
    }
    if cfg.verbose
    {
        let mut out = lock_unpoison(io_mutex);
        let _ = writeln!(out.stderr, "[{tid}] resolving {dom}");
    }
    for _ in 0..cfg.eagain
    {
        match resolver.resolve(dom, cfg.family)
        {
            Ok(addrs) =>
            {
                let mut out = lock_unpoison(io_mutex);
                for ip in addrs
                {
                    let _ = writeln!(out.stdout, "{ip}");
                }
                return Some(true);
            }
            Err(err) =>
            {
                if cfg.verbose
                {
                    let mut out = lock_unpoison(io_mutex);
                    let _ = writeln!(
                        out.stderr,
                        "[{tid}] failed to resolve {dom} : result {} ({})",
                        err.code,
                        err.eai_name()
                    );
                }
                if err.is_again()
                {
                    if cfg.eagain_delay_ms > 0
                    {
                        std::thread::sleep(Duration::from_millis(cfg.eagain_delay_ms));
                    }
                    continue;
                }
                break;
            }
        }
    }
    Some(false)
}

/// Processes one non-empty trimmed input line inside a worker thread, returning `true` on success.
fn process_domain_line(
    tid: usize,
    raw: &[u8],
    cfg: &MdigConfig,
    resolver: &dyn DnsResolver,
    io_mutex: &Mutex<MdigOutputs<'_>>,
) -> bool
{
    let outcome = std::str::from_utf8(raw)
        .ok()
        .and_then(|dom| resolve_utf8_domain(tid, dom, cfg, resolver, io_mutex));
    let is_ok = match outcome
    {
        Some(ok) => ok,
        None =>
        {
            if cfg.verbose
            {
                let mut out = lock_unpoison(io_mutex);
                let _ = writeln!(out.stderr, "[{tid}] invalid domain : {}", beautify_invalid_domain(raw));
            }
            false
        }
    };

    let mut out = lock_unpoison(io_mutex);
    let log_target = if is_ok { &mut out.log_resolved } else { &mut out.log_failed };
    if let Some(writer) = log_target.as_deref_mut()
    {
        let _ = writer.write_all(raw);
        let _ = writer.write_all(b"\n");
    }
    is_ok
}

/// Worker loop draining stdin lines, resolving domains, and reporting stats per interval.
fn worker_loop<R: BufRead>(
    tid: usize,
    cfg: &MdigConfig,
    resolver: &dyn DnsResolver,
    input_mutex: &Mutex<&mut R>,
    io_mutex: &Mutex<MdigOutputs<'_>>,
    stats_mutex: &Mutex<(u64, u64)>,
    start: Instant,
)
{
    if cfg.verbose
    {
        let mut out = lock_unpoison(io_mutex);
        let _ = writeln!(out.stderr, "[{tid}] started");
    }
    let mut raw = Vec::with_capacity(256);
    loop
    {
        raw.clear();
        let bytes_read = {
            let mut input = lock_unpoison(input_mutex);
            input
                .read_until(b'\n', &mut raw)
                .unwrap_or(0)
        };
        if bytes_read == 0
        {
            break;
        }
        while matches!(raw.last(), Some(b'\n' | b'\r' | b' ' | b'\t'))
        {
            raw.pop();
        }
        let is_ok = !raw.is_empty() && process_domain_line(tid, &raw, cfg, resolver, io_mutex);
        if cfg.stats_every > 0
        {
            let (ct, ct_ok) = {
                let mut st = lock_unpoison(stats_mutex);
                st.0 += 1;
                if is_ok
                {
                    st.1 += 1;
                }
                *st
            };
            if ct.is_multiple_of(cfg.stats_every)
            {
                write_stats_line(io_mutex, start, ct, ct_ok);
            }
        }
    }
    if cfg.verbose
    {
        let mut out = lock_unpoison(io_mutex);
        let _ = writeln!(out.stderr, "[{tid}] ended");
    }
}

/// Runs `mdig` multi-threaded domain resolution and returns the number of spawned threads.
pub fn run_mdig_resolver<R: BufRead + Send>(
    cfg: &MdigConfig,
    resolver: &dyn DnsResolver,
    reader: &mut R,
    outputs: MdigOutputs<'_>,
) -> usize
{
    let start = Instant::now();
    let input_mutex = Mutex::new(reader);
    let io_mutex = Mutex::new(outputs);
    let stats_mutex = Mutex::new((0u64, 0u64));
    let mut started = 0usize;

    std::thread::scope(|scope| {
        for tid in 0..cfg.threads
        {
            let (input_ref, io_ref, stats_ref) = (&input_mutex, &io_mutex, &stats_mutex);
            let spawn_res = std::thread::Builder::new().spawn_scoped(scope, move || {
                worker_loop(tid, cfg, resolver, input_ref, io_ref, stats_ref, start);
            });
            match spawn_res
            {
                Ok(_) => started += 1,
                Err(_) =>
                {
                    let mut out = lock_unpoison(&io_mutex);
                    let _ = writeln!(out.stderr, "failed to create thread #{tid}");
                    break;
                }
            }
        }
    });

    if cfg.stats_every > 0
    {
        let (ct, ct_ok) = *lock_unpoison(&stats_mutex);
        write_stats_line(&io_mutex, start, ct, ct_ok);
    }
    let mut out = lock_unpoison(&io_mutex);
    let _ = out
        .stdout
        .flush();
    let _ = out
        .stderr
        .flush();
    if let Some(writer) = out
        .log_resolved
        .as_deref_mut()
    {
        let _ = writer.flush();
    }
    if let Some(writer) = out
        .log_failed
        .as_deref_mut()
    {
        let _ = writer.flush();
    }
    started
}
