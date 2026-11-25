//! Repeatable `--release` hot-path microbenchmark harness for `zapret-rs` packet processing.
//!
//! Run with:
//! `cargo build --release --example hotpath_bench --offline && target/release/examples/hotpath_bench`

/// Shared interior mutability for mock `PacketSender` injection.
use std::cell::RefCell;
/// Temporary hostlist/ipset setup and fake payload fixture loading.
use std::fs;
/// Black-box hint preventing dead-code elimination around timed workloads.
use std::hint::black_box;
/// IPv4 address construction for synthetic flows and IPCache benchmarks.
use std::net::{IpAddr, Ipv4Addr};
/// Filesystem paths for `zapret2` Lua scripts, fake blobs, and temp list files.
use std::path::{Path, PathBuf};
/// Single-threaded reference counting for `DesyncEngine` mock senders.
use std::rc::Rc;
/// High-resolution monotonic wall-clock timer for measuring microbenchmarks.
use std::time::Instant;

/// TOML configuration loader for initializing realistic `DesyncEngine` instances.
use zapret_rs::config::AppConfig;
/// Pure-Rust AES-128-GCM encryption under benchmark.
use zapret_rs::crypto::aes_gcm_crypt;
/// Core DPI desync engine under benchmark.
use zapret_rs::desync::DesyncEngine;
/// NFQUEUE packet wrapper, verdict decision enum, and `SIOCGIFNAME` resolver.
use zapret_rs::intercepter::{Decision, IfNameResolver, QueuedPacket};
/// IPCache TTL lookup and refresh implementation under benchmark.
use zapret_rs::lists::IpCache;
/// IPv4/TCP header constants for constructing wire-valid benchmark packets.
use zapret_rs::packet::constants::{IPPROTO_TCP, TH_ACK, TH_PUSH, TH_SYN};
/// Packet assembly structures and checksum-computing wire reconstructor.
use zapret_rs::packet::{DissectedPacket, Ipv4Header, ReconstructOptions, TcpHeader, reconstruct_packet};
/// Raw packet injector trait and real raw socket implementation.
use zapret_rs::rawsend::{PacketSender, RawSendError, RawSender};

/// No-op mock sender discarding injected packets in memory to isolate CPU hot paths.
struct NullSender;

impl PacketSender for NullSender {
    fn send(
        &mut self,
        _dst: IpAddr,
        _fwmark: u32,
        _ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError> {
        black_box(packet.len());
        Ok(())
    }
}

/// Resolves the sibling `zapret2` repository path relative to `CARGO_MANIFEST_DIR`.
fn zapret2_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("zapret2")
        .join(rel)
}

/// Builds a wire-valid IPv4/TCP packet with valid IP and TCP checksums.
fn build_tcp4_packet(
    src: ([u8; 4], u16),
    dst: ([u8; 4], u16),
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x1234,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src: src.0,
            dst: dst.0,
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: src.1,
            d_port: dst.1,
            seq,
            ack,
            reserved: 0,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
            options: Vec::new(),
        }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default())
        .expect("benchmark TCP packet reconstruction should succeed")
}

/// Builds a `DesyncEngine` backed by `zapret-lib.lua` + `zapret-antidpi.lua` and `NullSender`.
fn build_engine(top_toml: &str, extra_toml: &str) -> DesyncEngine {
    let lib_lua = zapret2_path("lua/zapret-lib.lua");
    let antidpi_lua = zapret2_path("lua/zapret-antidpi.lua");
    let fake_tls = zapret2_path("files/fake/tls_clienthello_www_google_com.bin");
    let toml = format!(
        "lua_init = [\"{}\", \"{}\"]\n{top_toml}\n[blobs]\nfake_default_tls = {{ file = \"{}\" }}\n{extra_toml}",
        lib_lua.display(),
        antidpi_lua.display(),
        fake_tls.display(),
    );
    let cfg = AppConfig::from_toml_str(&toml, None).expect("valid benchmark TOML config");
    let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(NullSender));
    DesyncEngine::with_sender(&cfg, sender).expect("benchmark DesyncEngine should initialize")
}

/// Runs `warmup` unmeasured iterations followed by `iters` timed iterations and prints `ns/op`.
fn run_bench<F: FnMut()>(name: &str, warmup: usize, iters: usize, mut f: F) {
    for _ in 0..warmup {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    let elapsed_ns = start.elapsed().as_nanos() as f64;
    let ns_per_op = elapsed_ns / (iters as f64);
    let ops_per_sec = 1e9_f64 / ns_per_op;
    println!("{name:<30} {ns_per_op:9.1} ns/op  ({ops_per_sec:10.0} ops/s)");
}

/// Benchmarks established-flow TCP pass-through when `out_range` cuts off all actions.
fn bench_tcp_established_cutoff(tls_ch: &[u8]) {
    let engine = build_engine(
        "",
        r#"
[[profiles]]
filter_tcp = ["443"]

[[profiles.actions]]
func = "fake"
payload = ["tls_client_hello"]
out_range = "-d1"
args = { blob = "fake_default_tls" }
"#,
    );
    let syn = build_tcp4_packet(([10, 0, 0, 2], 40001), ([93, 184, 216, 34], 443), 1, 0, TH_SYN, &[]);
    let ch = build_tcp4_packet(([10, 0, 0, 2], 40001), ([93, 184, 216, 34], 443), 2, 1, TH_ACK | TH_PUSH, tls_ch);
    let app = vec![0x17u8; 1400];
    let data = build_tcp4_packet(([10, 0, 0, 2], 40001), ([93, 184, 216, 34], 443), 1000, 1, TH_ACK | TH_PUSH, &app);

    let seed = [(&syn, 1u32), (&ch, 2u32)];
    for (raw, id) in seed {
        let pkt = QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("lo"), payload: raw };
        black_box(engine.process_packet(&pkt));
    }

    let pkt = QueuedPacket { packet_id: 3, mark: 0, ifin: None, ifout: Some("lo"), payload: &data };
    run_bench("tcp_established_cutoff", 1_000, 50_000, || {
        black_box(engine.process_packet(&pkt));
    });
}

/// Benchmarks established-flow TCP pass-through without cutoff (`always` range + non-matching payload).
fn bench_tcp_established_runnable_miss(tls_ch: &[u8]) {
    let engine = build_engine(
        "",
        r#"
[[profiles]]
filter_tcp = ["443"]

[[profiles.actions]]
func = "fake"
payload = ["tls_client_hello"]
out_range = "a"
args = { blob = "fake_default_tls" }
"#,
    );
    let syn = build_tcp4_packet(([10, 0, 0, 2], 40002), ([93, 184, 216, 34], 443), 1, 0, TH_SYN, &[]);
    let ch = build_tcp4_packet(([10, 0, 0, 2], 40002), ([93, 184, 216, 34], 443), 2, 1, TH_ACK | TH_PUSH, tls_ch);
    let app = vec![0x17u8; 1400];
    let data = build_tcp4_packet(([10, 0, 0, 2], 40002), ([93, 184, 216, 34], 443), 1000, 1, TH_ACK | TH_PUSH, &app);

    for (id, raw) in [(1u32, &syn), (2u32, &ch)] {
        let pkt = QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("lo"), payload: raw };
        black_box(engine.process_packet(&pkt));
    }

    let pkt = QueuedPacket { packet_id: 3, mark: 0, ifin: None, ifout: Some("lo"), payload: &data };
    run_bench("tcp_established_runnable_miss", 1_000, 50_000, || {
        black_box(engine.process_packet(&pkt));
    });
}

/// Benchmarks full TLS ClientHello Lua desync dispatch (`fake:blob=fake_default_tls`).
fn bench_tcp_tls_fake_desync(tls_ch: &[u8]) {
    let engine = build_engine(
        "ctrack_disable = true",
        r#"
[[profiles]]
filter_tcp = ["443"]

[[profiles.actions]]
func = "fake"
payload = ["tls_client_hello"]
args = { blob = "fake_default_tls" }
"#,
    );
    let ch = build_tcp4_packet(([10, 0, 0, 2], 40003), ([93, 184, 216, 34], 443), 2, 1, TH_ACK | TH_PUSH, tls_ch);
    let pkt = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("lo"), payload: &ch };
    run_bench("tcp_tls_fake_desync", 500, 15_000, || {
        let dec = engine.process_packet(&pkt);
        debug_assert!(matches!(dec, Decision::Pass));
        black_box(dec);
    });
}

/// Benchmarks an unmatched TCP flow when profiles hold file-backed hostlist and ipset lists.
fn bench_unmatched_tcp_with_lists() {
    let dir = std::env::temp_dir().join(format!("zapret-rs-bench-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create temp benchmark dir");
    let hl_path = dir.join("hosts.txt");
    let ip_path = dir.join("ips.txt");
    let hl_body = (0..100).map(|i| format!("blocked-{i}.example.com\n")).collect::<String>();
    let ip_body = (0..100).map(|i| format!("198.51.100.{i}\n")).collect::<String>();
    fs::write(&hl_path, hl_body).expect("write benchmark hostlist");
    fs::write(&ip_path, ip_body).expect("write benchmark ipset");

    let extra = format!(
        "[[profiles]]\nfilter_tcp = [\"80\", \"443\"]\nhostlist = [\"{}\"]\nipset = [\"{}\"]\n[[profiles.actions]]\nfunc = \"fake\"\n",
        hl_path.display(),
        ip_path.display(),
    );
    let engine = build_engine("", &extra);
    let syn = build_tcp4_packet(([10, 0, 0, 2], 40004), ([192, 0, 2, 10], 22), 1, 0, TH_SYN, &[]);
    let data = build_tcp4_packet(([10, 0, 0, 2], 40004), ([192, 0, 2, 10], 22), 2, 1, TH_ACK | TH_PUSH, b"SSH-2.0-client\r\n");

    let syn_pkt = QueuedPacket { packet_id: 1, mark: 0, ifin: None, ifout: Some("lo"), payload: &syn };
    black_box(engine.process_packet(&syn_pkt));

    let pkt = QueuedPacket { packet_id: 2, mark: 0, ifin: None, ifout: Some("lo"), payload: &data };
    run_bench("unmatched_tcp_with_lists", 1_000, 30_000, || {
        black_box(engine.process_packet(&pkt));
    });

    // Port 443 flow NOT in the profile's hostlist/ipset exercises `profile_matches_full` + file `stat(2)`.
    let syn443 = build_tcp4_packet(([10, 0, 0, 2], 40005), ([192, 0, 2, 11], 443), 1, 0, TH_SYN, &[]);
    let data443 = build_tcp4_packet(([10, 0, 0, 2], 40005), ([192, 0, 2, 11], 443), 2, 1, TH_ACK | TH_PUSH, &[0x17; 128]);
    let syn443_pkt = QueuedPacket { packet_id: 3, mark: 0, ifin: None, ifout: Some("lo"), payload: &syn443 };
    black_box(engine.process_packet(&syn443_pkt));
    let data443_pkt = QueuedPacket { packet_id: 4, mark: 0, ifin: None, ifout: Some("lo"), payload: &data443 };
    run_bench("unmatched_443_file_lists", 500, 10_000, || {
        black_box(engine.process_packet(&data443_pkt));
    });
    let _ = fs::remove_dir_all(&dir);
}

/// Benchmarks `IfNameResolver::resolve` combined with `IpCache` TTL update and lookup.
fn bench_ifname_and_ipcache() {
    let resolver = IfNameResolver::new().expect("open AF_INET SIOCGIFNAME socket");
    // SAFETY: `c"lo"` is a valid NUL-terminated static C string literal.
    let lo_idx = unsafe { libc::if_nametoindex(c"lo".as_ptr()) };
    assert_ne!(lo_idx, 0, "loopback interface must exist");

    let mut cache = IpCache::new(7200, true);
    let ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let mut ttl = 64u8;
    run_bench("ifname_resolve_lo", 1_000, 50_000, || {
        black_box(resolver.resolve(lo_idx));
    });
    run_bench("ipcache_ttl_update_get", 1_000, 100_000, || {
        cache.update_ttl(ip, "eth0", &mut ttl, false, 1000);
        black_box(cache.get_ttl(ip, "eth0", false));
    });
}

/// Benchmarks 680-byte AES-128-GCM encryption matching Lua `aes_gcm` QUIC/TLS payload sizes.
fn bench_aes_gcm_680b() {
    let key = [0x11u8; 16];
    let iv = [0x22u8; 12];
    let pt = [0x33u8; 680];
    let aad = [0x44u8; 20];
    run_bench("aes_gcm_crypt_680b", 1_000, 25_000, || {
        let res = aes_gcm_crypt(true, &key, &iv, &pt, &aad).expect("AES-GCM encrypt succeeds");
        black_box(res);
    });
}

/// Benchmarks repeated loopback IPv4 raw injection with constant `fwmark` and `ifout = "lo"`.
fn bench_rawsend_loopback() {
    let mut sender = RawSender::new(true, true);
    sender.preinit().expect("RawSender::preinit requires CAP_NET_RAW");
    let pkt = build_tcp4_packet(([127, 0, 0, 1], 40009), ([127, 0, 0, 1], 443), 1, 0, TH_SYN, &[]);
    let dst = IpAddr::V4(Ipv4Addr::LOCALHOST);
    run_bench("rawsend_loopback_v4", 200, 10_000, || {
        sender
            .send(dst, 0x4000_0000, Some("lo"), &pkt)
            .expect("rawsend loopback should succeed");
    });
}

fn main() {
    let raw_mode = std::env::args().any(|arg| arg == "--raw");
    let tls_ch = fs::read(zapret2_path("files/fake/tls_clienthello_www_google_com.bin"))
        .expect("read TLS ClientHello fixture");

    bench_tcp_established_cutoff(&tls_ch);
    bench_tcp_established_runnable_miss(&tls_ch);
    bench_tcp_tls_fake_desync(&tls_ch);
    bench_unmatched_tcp_with_lists();
    bench_ifname_and_ipcache();
    bench_aes_gcm_680b();
    if raw_mode {
        bench_rawsend_loopback();
    }
}
