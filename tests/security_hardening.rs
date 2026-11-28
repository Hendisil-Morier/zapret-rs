//! Regression tests for symlink hardening (`--writable`, `--pidfile`) and memory-cap bounds.
#![cfg(target_os = "linux")]

/// Temporary file and directory management for filesystem symlink checks.
use std::fs;
/// Write trait for compressing gzip bomb fixtures via `flate2`.
use std::io::Write;
/// IPv4 address types for conntrack 5-tuple and IPCache flood tests.
use std::net::{IpAddr, Ipv4Addr};
/// UNIX symlink creation for testing `O_NOFOLLOW` protections.
use std::os::unix::fs::symlink;
/// Path helpers scoped under `std::env::temp_dir()`.
use std::path::{Path, PathBuf};
/// Subprocess check ensuring `nfqws2 --writable` rejects a pre-planted `TMPDIR/zapret-rs` symlink.
use std::process::Command;

/// Pure-Rust gzip encoder used to build exact-boundary and oversized bomb test payloads.
use flate2::{Compression, write::GzEncoder};

/// Writable directory mode config (`Default` vs `Custom(PathBuf)`).
use zapret_rs::config::WritableDirConfig;
/// Default conntrack capacity cap and connection pool under test.
use zapret_rs::conntrack::{ConntrackPool, DEFAULT_CTRACK_MAX_ENTRIES};
/// Default IPCache capacity cap and cache under test.
use zapret_rs::lists::{DEFAULT_IPCACHE_MAX_ENTRIES, IpCache};
/// Streaming inflater and LuaJIT runtime used for gzip bomb resistance checks.
use zapret_rs::lua::{
    LuaConfig, LuaRuntime,
    gzip_inflate::{DEFAULT_MAX_INFLATE_OUTPUT, InflateMode, InflateStream},
};
/// Packet builders generating valid synthetic TCP SYN and ACK frames for conntrack flood tests.
use zapret_rs::packet::constants::{IPPROTO_TCP, TH_ACK, TH_SYN};
/// Packet header structs and wire reconstructor for building valid dissected packets.
use zapret_rs::packet::{
    DissectedPacket, Ipv4Header, ReconstructOptions, TcpHeader, dissect_packet, reconstruct_packet,
};
/// Runtime writable-directory validator and PID guard under test.
use zapret_rs::runtime::{PidFileGuard, ProcessError, ensure_writable_dir, resolve_default_writable_dir};
/// Monotonic boottime timestamps used to advance flow and cache expiry sweeps.
use zapret_rs::timer::MonotonicTime;

/// Returns a `zapret-rs daemon` command backed by the compiled unified binary.
fn nfqws2_cmd() -> Command
{
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("daemon");
    cmd
}

/// RAII temporary test directory removed on drop.
struct TempDir(PathBuf);

impl TempDir
{
    fn new(label: &str) -> Self
    {
        let dir = std::env::temp_dir().join(format!("zapret_rs_sec_{}_{}", std::process::id(), label));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }

    fn path(&self) -> &Path
    {
        &self.0
    }
}

impl Drop for TempDir
{
    fn drop(&mut self)
    {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Compresses `data` into a standard RFC 1952 gzip payload.
fn gzip_bytes(data: &[u8]) -> Vec<u8>
{
    let mut enc = GzEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data)
        .expect("write gzip payload");
    enc.finish()
        .expect("finish gzip payload")
}

/// Builds a dissected IPv4 TCP packet for conntrack capacity testing.
fn make_syn_or_ack(src_last: u8, sport: u16, flags: u8) -> DissectedPacket
{
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 40,
            id: 1,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: [10, 0, 0, src_last],
            dst: [93, 184, 216, 34],
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: sport,
            d_port: 443,
            seq: 1000,
            ack: 2000,
            reserved: 0,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        ..DissectedPacket::default()
    };
    let wire = reconstruct_packet(&dis, &ReconstructOptions::default()).expect("reconstruct tcp");
    dissect_packet(&wire, false)
}

#[test]
fn writable_dir_refuses_symlink_in_custom_and_default_modes()
{
    let tmp = TempDir::new("writable_symlink");
    let victim_dir = tmp
        .path()
        .join("victim_dir");
    fs::create_dir(&victim_dir).expect("create victim dir");

    let custom_link = tmp
        .path()
        .join("custom_link");
    symlink(&victim_dir, &custom_link).expect("create custom symlink");

    let err = ensure_writable_dir(&WritableDirConfig::Custom(custom_link), None)
        .expect_err("symlink custom writable dir must be rejected");
    match err
    {
        ProcessError::WritableDir { source, .. } =>
        {
            assert!(
                matches!(source.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)),
                "unexpected errno for symlink writable dir: {source:?}"
            );
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    // Plant `<TMPDIR>/zapret-rs` symlink and confirm `nfqws2 --writable` refuses to accept it.
    let tmp_root = tmp
        .path()
        .join("tmpdir_env");
    fs::create_dir(&tmp_root).expect("create tmpdir env");
    let default_target = resolve_default_writable_dir(Some(tmp_root.as_os_str()));
    symlink(&victim_dir, &default_target).expect("create default writable symlink");

    let out = nfqws2_cmd()
        .env("TMPDIR", &tmp_root)
        .env_remove("WRITABLE")
        .args(["--intercept=0", "--writable"])
        .output()
        .expect("run nfqws2 --writable against symlink");
    assert!(
        !out.status
            .success(),
        "nfqws2 must fail when default --writable is a symlink"
    );

    // Genuine owned directory continues to work cleanly.
    let real_dir = tmp
        .path()
        .join("real_writable");
    let resolved = ensure_writable_dir(&WritableDirConfig::Custom(real_dir), None)
        .expect("genuine owned writable dir must succeed");
    assert!(resolved.is_dir());
}

#[test]
fn pidfile_guard_refuses_symlink_without_truncating_target()
{
    let tmp = TempDir::new("pidfile_symlink");
    let victim = tmp
        .path()
        .join("victim.txt");
    fs::write(&victim, b"keep-intact").expect("write victim file");

    let pid_link = tmp
        .path()
        .join("daemon.pid");
    symlink(&victim, &pid_link).expect("create pid symlink");

    match PidFileGuard::create(&pid_link)
    {
        Err(ProcessError::PidFile { source, .. }) =>
        {
            assert_eq!(source.raw_os_error(), Some(libc::ELOOP));
        }
        Ok(_) => panic!("PidFileGuard::create must reject symlinks"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(&victim).expect("read victim file"),
        "keep-intact",
        "symlink target must remain untruncated"
    );

    let real_pid = tmp
        .path()
        .join("normal.pid");
    {
        let mut guard = PidFileGuard::create(&real_pid).expect("create normal pidfile");
        guard
            .write_current_pid()
            .expect("write pid");
        assert!(real_pid.is_file());
    }
    assert!(!real_pid.exists(), "PidFileGuard drop removes regular pidfile");
}

#[test]
fn conntrack_pool_caps_entries_and_recovers_after_expiry()
{
    let mut pool = ConntrackPool::default();
    assert_eq!(pool.max_entries(), DEFAULT_CTRACK_MAX_ENTRIES);
    pool.set_max_entries(4);

    for idx in 0..4u16
    {
        let pkt = make_syn_or_ack(10 + idx as u8, 10_000 + idx, TH_SYN);
        let t = MonotonicTime { sec: 100 + i64::from(idx), nsec: 0 };
        assert!(
            pool.feed(None, &pkt, t)
                .expect("feed syn")
                .is_some(),
            "flow {idx} within cap must insert"
        );
    }
    assert_eq!(pool.len(), 4);

    // Refresh flow 0 so flow 1 (`sec=101`) becomes the oldest idle flow.
    let flow0_ack = make_syn_or_ack(10, 10_000, TH_ACK);
    assert!(
        pool.feed(None, &flow0_ack, MonotonicTime { sec: 105, nsec: 0 })
            .expect("update tracked flow")
            .is_some()
    );

    // 5th distinct SYN evicts the oldest idle entry (`flow 1`) instead of locking out new flows.
    let overflow_pkt = make_syn_or_ack(99, 20_000, TH_SYN);
    assert!(
        pool.feed(None, &overflow_pkt, MonotonicTime { sec: 106, nsec: 0 })
            .expect("feed overflow syn")
            .is_some()
    );
    assert_eq!(pool.len(), 4);
    let evicted_probe = make_syn_or_ack(11, 10_001, TH_ACK);
    assert!(
        pool.double_search(&evicted_probe)
            .is_none(),
        "oldest flow 1 must be evicted"
    );
    assert!(
        pool.double_search(&flow0_ack)
            .is_some(),
        "refreshed flow 0 must remain tracked"
    );

    // Once un-ACKed SYN flows pass timeout (`60s`), cap check purges them while keeping the
    // established flow (timeout `300s`), leaving room cleanly.
    let expired_time = MonotonicTime { sec: 200, nsec: 0 };
    assert_eq!(pool.purge_rate_limited(expired_time.sec), 3);
    assert_eq!(pool.len(), 1);

    // Spoofed/unexpected reverse-direction SYN against active flow 0 must NOT reinit state.
    {
        let (rc, _) = pool
            .double_search(&flow0_ack)
            .expect("flow 0 active");
        let mut entry = rc.borrow_mut();
        entry.cutoff = true;
        entry.hostname = Some("keep.example".to_owned());
    }
    let rev_syn = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 40,
            id: 2,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: [93, 184, 216, 34],
            dst: [10, 0, 0, 10],
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: 443,
            d_port: 10_000,
            seq: 9999,
            ack: 0,
            reserved: 0,
            data_offset: 5,
            flags: TH_SYN,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        ..DissectedPacket::default()
    };
    let (_, b_rev) = pool
        .feed(None, &rev_syn, MonotonicTime { sec: 201, nsec: 0 })
        .expect("feed reverse syn")
        .expect("entry remains");
    assert!(b_rev);
    let (rc, _) = pool
        .double_search(&flow0_ack)
        .expect("flow 0 still exists");
    let entry = rc.borrow();
    assert!(entry.cutoff, "reverse SYN must not wipe cutoff");
    assert_eq!(
        entry
            .hostname
            .as_deref(),
        Some("keep.example"),
        "reverse SYN must not wipe host"
    );
}

#[test]
fn ipcache_caps_entries_and_recovers_after_expiry()
{
    let mut cache = IpCache::new(30, true);
    assert_eq!(cache.max_entries(), DEFAULT_IPCACHE_MAX_ENTRIES);
    cache.set_max_entries(4);

    for host_octet in 1..=4u8
    {
        cache.put_hostname(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, host_octet)),
            &format!("host{host_octet}.example"),
            false,
            100 + i64::from(host_octet),
        );
    }
    assert_eq!(cache.len(), 4);

    // Refresh entry 1 so entry 2 (`last_sec=102`) is oldest.
    let first_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    cache.put_hostname(first_ip, "updated.example", false, 105);

    // 5th distinct IP evicts the oldest entry (`192.0.2.2`) rather than failing closed.
    let overflow_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5));
    cache.put_hostname(overflow_ip, "overflow.example", false, 106);
    assert_eq!(cache.len(), 4);
    assert_eq!(cache.get_hostname(overflow_ip), Some(("overflow.example", false)));
    assert_eq!(cache.get_hostname(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2))), None);
    assert_eq!(cache.get_hostname(first_ip), Some(("updated.example", false)));
    assert!(
        cache
            .try_touch(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 6)), "", 107)
            .is_some()
    );
    assert_eq!(cache.len(), 4);

    // After lifetime expiration (107 + 30 = 137), stale entries purge cleanly on next new insert.
    let fresh_ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));
    cache.put_hostname(fresh_ip, "recovered.example", false, 140);
    assert_eq!(cache.len(), 1);
    assert_eq!(cache.get_hostname(fresh_ip), Some(("recovered.example", false)));
}

#[test]
fn gunzip_inflate_enforces_output_cap_and_rejects_bomb()
{
    let exact = gzip_bytes(&vec![b'A'; 1024]);
    let over = gzip_bytes(&vec![b'A'; 1025]);

    let mut ok_stream = InflateStream::with_max_output(InflateMode::Gzip, 1024);
    let (out, eof) = ok_stream
        .inflate(&exact, 1024)
        .expect("exact limit passes");
    assert!(eof);
    assert_eq!(out.len(), 1024);

    let mut single_over = InflateStream::with_max_output(InflateMode::Gzip, 1024);
    assert!(
        single_over
            .inflate(&over, 1024)
            .is_none(),
        "1025-byte single chunk must fail 1024-byte cap"
    );

    // Verify cumulative cap holds across small chunks as well.
    let mut chunked_over = InflateStream::with_max_output(InflateMode::Gzip, 1024);
    let mut failed = false;
    for chunk in over.chunks(8)
    {
        if chunked_over
            .inflate(chunk, 128)
            .is_none()
        {
            failed = true;
            break;
        }
    }
    assert!(failed, "chunked inflate exceeding cumulative 1024-byte cap must fail");

    // Verify default 64 MiB Lua gunzip cap rejects a 65 MiB zero-filled gzip bomb safely.
    assert_eq!(DEFAULT_MAX_INFLATE_OUTPUT, 64 * 1024 * 1024);
    let bomb = gzip_bytes(&vec![0u8; 65 * 1024 * 1024]);
    assert!(bomb.len() < 512 * 1024, "compressed zero bomb unexpectedly large: {}", bomb.len());

    let rt = LuaRuntime::new(LuaConfig::default()).expect("create lua runtime");
    rt.lua()
        .globals()
        .set(
            "BOMB",
            rt.lua()
                .create_string(&bomb)
                .expect("lua bomb string"),
        )
        .expect("set BOMB global");
    let rejected: bool = rt
        .lua()
        .load(
            r#"
            local zs = gunzip_init()
            assert(zs ~= nil)
            local pos = 1
            local rejected = false
            while pos <= #BOMB do
                local out, eof = gunzip_inflate(zs, BOMB:sub(pos, pos + 4095))
                if out == nil then
                    rejected = true
                    break
                end
                pos = pos + 4096
            end
            gunzip_end(zs)
            return rejected
            "#,
        )
        .eval()
        .expect("eval gzip bomb script");
    assert!(rejected, "Lua gunzip_inflate must reject output above 64 MiB default cap");
}

#[test]
fn systemd_unit_template_enables_ambient_caps_and_auto_nft()
{
    let systemd_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("contrib/systemd");
    let unit = fs::read_to_string(systemd_dir.join("zapret-rs.service"))
        .expect("read contrib/systemd/zapret-rs.service");
    assert!(unit.contains("AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW"));
    assert!(unit.contains("RuntimeDirectory=zapret-rs"));
    assert!(unit.contains("--nft"));
    assert!(unit.contains("--control-socket /run/zapret-rs/control.sock"));

    let path_unit =
        fs::read_to_string(systemd_dir.join("zapret-rs.path")).expect("read contrib/systemd/zapret-rs.path");
    assert!(path_unit.contains("PathChanged=__REPO__/target/release/zapret-rs"));
    assert!(path_unit.contains("Unit=zapret-rs-restart.service"));

    let restart_unit = fs::read_to_string(systemd_dir.join("zapret-rs-restart.service"))
        .expect("read contrib/systemd/zapret-rs-restart.service");
    assert!(restart_unit.contains("try-restart zapret-rs.service"));

    if !zapret_rs::runtime::has_effective_caps(zapret_rs::runtime::CAP_MASK_NET).unwrap_or(false)
    {
        assert!(zapret_rs::runtime::retain_net_capabilities_for(false, true).is_ok());
    }
}
