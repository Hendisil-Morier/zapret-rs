//! End-to-end Milestone 4 integration tests executing unmodified `zapret2/lua/*.lua` scripts.

/// Shared mock [`PacketSender`] and `zapret-lib.lua` path constants.
mod common;

/// Interior mutability for sharing [`CapturingSender`] across engine/runtime instances.
use std::cell::RefCell;
/// Temporary directory creation and PCAP file verification on disk.
use std::fs;
/// File path and owned path buffers for unmodified `zapret2` scripts and fixtures.
use std::path::{Path, PathBuf};
/// Single-thread reference counting for passing [`CapturingSender`] into [`DesyncEngine`].
use std::rc::Rc;
/// Atomic sequence counter generating isolated temporary directories.
use std::sync::atomic::{AtomicU64, Ordering};

/// Mock packet transmitter shared across script integration tests.
use common::CapturingSender;
/// TOML config builder, default fake blobs, and `--writable` configuration mode.
use zapret_rs::config::{AppConfig, FAKE_HTTP_REQUEST_DEFAULT, WritableDirConfig, default_blobs};
/// Full stateful DPI desync engine.
use zapret_rs::desync::DesyncEngine;
/// Interception packet wrapper and kernel verdict decision enum.
use zapret_rs::intercepter::{Decision, QueuedPacket};
/// Embedded LuaJIT runtime and configuration struct.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// Wire protocol constants and TCP flags used to construct synthetic flows.
use zapret_rs::packet::constants::{
    IPPROTO_TCP, IPPROTO_UDP, TH_ACK, TH_PUSH, TH_RST, TH_SYN,
};
/// Dissected L3/L4 packet model, dissector, and checksum-computing reconstructor.
use zapret_rs::packet::{
    DissectedPacket, Ipv4Header, ReconstructOptions, TcpHeader, UdpHeader, dissect_packet,
    reconstruct_packet,
};
/// TLS handshake inspector and SNI host extractor used to verify `fake` + `tls_mod`.
use zapret_rs::protocol::tls_hello_extract_host;
/// Abstract packet transmitter coerced from [`CapturingSender`].
use zapret_rs::rawsend::PacketSender;
/// Startup `--writable` directory preparation exporting `WRITABLE`.
use zapret_rs::runtime::prepare_writable_dir;
/// Monotonic boottime clock and Lua timer scheduler.
use zapret_rs::timer::{TimerPool, boottime_ms};

/// Directory containing all unmodified `zapret2` Lua scripts.
const ZAPRET2_LUA_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua");
/// Path to `zapret2`'s fake TLS ClientHello binary fixture.
const TLS_HELLO_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/fake/tls_clienthello_www_google_com.bin"
);
/// Peer IP endpoints shared by synthetic client/server IPv4 test flows.
const CLI_IP: [u8; 4] = [10, 0, 0, 2];
/// Server IPv4 address used in synthetic flows.
const SRV_IP: [u8; 4] = [93, 184, 216, 34];
/// Atomic sequence counter ensuring unique temp dirs across tests.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// RAII temporary directory deleted cleanly when dropped.
struct TempDir(PathBuf);

impl TempDir {
    /// Creates a unique directory inside `std::env::temp_dir()`.
    fn new(prefix: &str) -> Self {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), id));
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }
}

impl Drop for TempDir {
    /// Recursively removes temporary test artifacts.
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Builds a checksum-valid IPv4/TCP packet with explicit sequence/ack numbers, flags, and payload.
#[allow(clippy::too_many_arguments)]
fn build_tcp4(
    src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8],
) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4, header_len: 5, tos: 0, total_len: 0, id: 0x1001, frag_off: 0,
            ttl: 64, protocol: IPPROTO_TCP, checksum: 0, src, dst, options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: sport, d_port: dport, seq, ack, reserved: 0, data_offset: 5,
            flags, window: 65535, checksum: 0, urgent_ptr: 0, options: Vec::new(),
        }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid TCP packet")
}

/// Builds a checksum-valid IPv4/UDP datagram.
fn build_udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4, header_len: 5, tos: 0, total_len: 0, id: 0x2002, frag_off: 0,
            ttl: 64, protocol: IPPROTO_UDP, checksum: 0, src, dst, options: Vec::new(),
        }),
        udp: Some(UdpHeader { s_port: sport, d_port: dport, len: 0, checksum: 0 }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid UDP packet")
}

/// Builds an outgoing queued packet descriptor on `eth0`.
const fn out_pkt(id: u32, payload: &[u8]) -> QueuedPacket<'_> {
    QueuedPacket { packet_id: id, mark: 0, ifin: None, ifout: Some("eth0"), payload }
}

/// Builds an incoming queued packet descriptor on `eth0`.
const fn in_pkt(id: u32, payload: &[u8]) -> QueuedPacket<'_> {
    QueuedPacket { packet_id: id, mark: 0, ifin: Some("eth0"), ifout: None, payload }
}

/// Parses `toml_str` relative to `ZAPRET2_LUA_DIR` and builds a [`DesyncEngine`] with [`CapturingSender`].
fn engine_with_capture(toml_str: &str) -> (DesyncEngine, Rc<RefCell<CapturingSender>>) {
    let cfg = AppConfig::from_toml_str(toml_str, Some(Path::new(ZAPRET2_LUA_DIR)))
        .expect("valid TOML config referencing zapret2/lua");
    let cap = Rc::new(RefCell::new(CapturingSender::default()));
    let sender: Rc<RefCell<dyn PacketSender>> = cap.clone();
    let engine = DesyncEngine::with_sender(&cfg, sender).expect("DesyncEngine initializes");
    (engine, cap)
}

/// Completes a tracked SYN / SYN+ACK handshake (`seq=1000`, `server_seq=2000`) through `engine`.
fn handshake_tcp4(engine: &DesyncEngine, sport: u16, dport: u16) {
    let syn = build_tcp4(CLI_IP, SRV_IP, sport, dport, 1000, 0, TH_SYN, &[]);
    let syn_ack = build_tcp4(SRV_IP, CLI_IP, dport, sport, 2000, 1001, TH_SYN | TH_ACK, &[]);
    assert_eq!(engine.process_packet(&out_pkt(1, &syn)), Decision::Pass);
    assert_eq!(engine.process_packet(&in_pkt(2, &syn_ack)), Decision::Pass);
}

/// Loads all 6 unmodified `zapret2/lua/*.lua` files and runs every non-live `zapret-tests.lua` suite.
#[test]
fn all_zapret2_lua_scripts_load_and_non_live_tests_pass() {
    let cap = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = LuaRuntime::with_sender(LuaConfig::default(), cap).expect("LuaRuntime initializes");
    for (name, data) in default_blobs() {
        rt.set_blob(&name, &data).expect("set default blob");
    }
    let lua_dir = Path::new(ZAPRET2_LUA_DIR);
    for script in [
        "zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua",
        "zapret-obfs.lua", "zapret-pcap.lua", "zapret-tests.lua",
    ] {
        rt.exec_file(&lua_dir.join(script))
            .unwrap_or_else(|e| panic!("failed loading unmodified {script}: {e}"));
    }

    rt.exec_str(
        r#"
        test_run({
            test_crypto, test_bin, test_time, test_gzip, test_ipstr, test_dissect,
            test_csum, test_resolve, test_get_source_ip, test_ifaddrs, test_timer
        })
        local active = timer_enum()
        assert(#active == 3, "expected t0/t1/t2 timers from test_timer()")
        "#,
    )
    .expect("all non-live zapret-tests.lua suites must pass");

    let base = boottime_ms();
    for offset in [150u64, 550, 750, 1500, 2250, 3000] {
        TimerPool::run_expired(rt.timer_pool(), rt.lua(), base.saturating_add(offset));
    }
    rt.exec_str("assert(#timer_enum() == 0, 'all test_timer callbacks must complete and clean up')")
        .expect("timer callbacks scheduled by test_timer() must fire cleanly");
}

/// Verifies `syndata`, `fake+tls_mod`, `multisplit`, `multidisorder`, `fakedsplit`, and `hostfakesplit`.
#[test]
fn zapret_antidpi_tcp_strategies_work_unmodified() {
    // 1) syndata
    let (eng, cap) = engine_with_capture(
        r#"
lua_init = ["zapret-lib.lua", "zapret-antidpi.lua"]
[[profiles]]
filter_tcp = ["*"]
[[profiles.actions]]
func = "syndata"
in_range = "a"
out_range = "a"
args = { blob = "fake_default_http" }
"#,
    );
    let syn = build_tcp4(CLI_IP, SRV_IP, 40001, 80, 1000, 0, TH_SYN, &[]);
    // Initial outgoing SYN DROP triggers `ct_new_postnat_fix` (TTL=1, proto=255 dummy packet).
    let Decision::Replace(postnat_dummy) = eng.process_packet(&out_pkt(1, &syn)) else {
        panic!("expected postnat-fix Replace on dropped initial SYN");
    };
    assert_eq!((postnat_dummy[8], postnat_dummy[9]), (1, 255));
    let pkts = &cap.borrow().packets;
    assert_eq!(pkts.len(), 1);
    assert_eq!(dissect_packet(&pkts[0].data, false).payload.as_deref(), Some(FAKE_HTTP_REQUEST_DEFAULT));

    // 2) fake + tls_mod = "rnd,rndsni,dupsid"
    let tls_hello = fs::read(TLS_HELLO_FIXTURE).expect("read TLS ClientHello fixture");
    let (eng, cap) = engine_with_capture(
        r#"
lua_init = ["zapret-lib.lua", "zapret-antidpi.lua"]
[[profiles]]
filter_tcp = ["443"]
[[profiles.actions]]
func = "fake"
in_range = "x"
out_range = "a"
args = { blob = "fake_default_tls", tls_mod = "rnd,rndsni,dupsid", ip_ttl = 3 }
"#,
    );
    handshake_tcp4(&eng, 40002, 443);
    let pkt_tls = build_tcp4(CLI_IP, SRV_IP, 40002, 443, 1001, 2001, TH_ACK | TH_PUSH, &tls_hello);
    assert_eq!(eng.process_packet(&out_pkt(3, &pkt_tls)), Decision::Pass);
    let fake_dis = dissect_packet(&cap.borrow().packets[0].data, false);
    assert_eq!(fake_dis.ip.as_ref().expect("ip").ttl, 3);
    let fake_pl = fake_dis.payload.as_deref().expect("fake tls payload");
    assert_eq!(&fake_pl[44..76], &tls_hello[44..76], "dupsid must copy client session id");
    assert_ne!(tls_hello_extract_host(fake_pl, true).as_deref(), Some("www.iana.org"));

    let http_req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // 3) multisplit + seqovl
    let (eng, cap) = engine_with_capture(
        r#"
lua_init = ["zapret-lib.lua", "zapret-antidpi.lua"]
[[profiles]]
filter_tcp = ["80"]
[[profiles.actions]]
func = "multisplit"
out_range = "a"
args = { pos = "midsld", seqovl = 4 }
"#,
    );
    handshake_tcp4(&eng, 40003, 80);
    let pkt_http = build_tcp4(CLI_IP, SRV_IP, 40003, 80, 1001, 2001, TH_ACK | TH_PUSH, http_req);
    assert_eq!(eng.process_packet(&out_pkt(4, &pkt_http)), Decision::Drop);
    let ms = &cap.borrow().packets;
    assert_eq!(ms.len(), 2);
    let d0 = dissect_packet(&ms[0].data, false);
    let d1 = dissect_packet(&ms[1].data, false);
    assert_eq!(d0.tcp.as_ref().expect("t0").seq, 997);
    let p0 = d0.payload.as_deref().expect("p0");
    assert_eq!(&p0[..4], b"\0\0\0\0");
    let mut rebuilt = p0[4..].to_vec();
    rebuilt.extend_from_slice(d1.payload.as_deref().expect("p1"));
    assert_eq!(rebuilt.as_slice(), http_req);

    // 4) multidisorder ("host,endhost")
    let (eng, cap) = engine_with_capture(
        r#"
lua_init = ["zapret-lib.lua", "zapret-antidpi.lua"]
[[profiles]]
filter_tcp = ["80"]
[[profiles.actions]]
func = "multidisorder"
out_range = "a"
args = { pos = "host,endhost" }
"#,
    );
    handshake_tcp4(&eng, 40004, 80);
    assert_eq!(eng.process_packet(&out_pkt(5, &pkt_http)), Decision::Drop);
    let mut parts: Vec<(u32, Vec<u8>)> = cap
        .borrow()
        .packets
        .iter()
        .map(|p| {
            let d = dissect_packet(&p.data, false);
            (d.tcp.expect("tcp").seq, d.payload.expect("pl"))
        })
        .collect();
    assert_eq!(parts.len(), 3);
    assert!(parts[0].0 > parts[1].0 && parts[1].0 > parts[2].0);
    parts.sort_by_key(|(seq, _)| *seq);
    let md_rebuilt: Vec<u8> = parts.into_iter().flat_map(|(_, b)| b).collect();
    assert_eq!(md_rebuilt.as_slice(), http_req);

    // 5) fakedsplit + 6) hostfakesplit
    for (func, extra_args) in [
        ("fakedsplit", r#"pos = "midsld", ip_ttl = 2"#),
        ("hostfakesplit", r#"host = "safe.org", midhost = "midsld", ip_ttl = 2"#),
    ] {
        let toml = format!(
            r#"
lua_init = ["zapret-lib.lua", "zapret-antidpi.lua"]
[[profiles]]
filter_tcp = ["80"]
[[profiles.actions]]
func = "{func}"
out_range = "a"
args = {{ {extra_args} }}
"#
        );
        let (eng, cap) = engine_with_capture(&toml);
        handshake_tcp4(&eng, 40005, 80);
        assert_eq!(eng.process_packet(&out_pkt(6, &pkt_http)), Decision::Drop);
        let pkts = &cap.borrow().packets;
        let mut reals = Vec::new();
        let mut fake_found = 0usize;
        for p in pkts {
            let d = dissect_packet(&p.data, false);
            let ttl = d.ip.expect("ip").ttl;
            let pl = d.payload.expect("pl");
            if ttl == 64 {
                reals.extend_from_slice(&pl);
            } else {
                assert_eq!(ttl, 2);
                fake_found += 1;
                if func == "hostfakesplit" {
                    assert!(pl.windows(8).any(|w| w == b"safe.org"));
                }
            }
        }
        assert!(fake_found >= 2, "{func} must emit fake segments");
        assert_eq!(reals.as_slice(), http_req, "{func} real segments must reconstruct HTTP");
    }
}

/// Verifies `zapret-obfs.lua::wgobfs` encrypt/decrypt round-trip and tag-mismatch rejection.
#[test]
fn zapret_obfs_wgobfs_encrypt_decrypt_roundtrip() {
    let toml = r#"
lua_init = ["zapret-lib.lua", "zapret-obfs.lua"]
[[profiles]]
filter_udp = ["*"]
[[profiles.actions]]
func = "wgobfs"
in_range = "a"
out_range = "a"
args = { secret = "shared-pass", padmin = 4, padmax = 12 }
"#;
    let (client_eng, _) = engine_with_capture(toml);
    let (peer_eng, _) = engine_with_capture(toml);

    let mut wg_init = vec![1u8, 0, 0, 0];
    wg_init.extend((4u8..148).map(|i| i.wrapping_mul(5)));
    assert_eq!(wg_init.len(), 148);
    let orig_wire = build_udp4(CLI_IP, SRV_IP, 51820, 51820, &wg_init);

    let Decision::Replace(obf_wire) = client_eng.process_packet(&out_pkt(1, &orig_wire)) else {
        panic!("expected Decision::Replace from wgobfs encryption");
    };
    let obf_dis = dissect_packet(&obf_wire, false);
    let obf_len = obf_dis.payload.as_ref().expect("obf payload").len();
    assert!((148 + 30 + 4..=148 + 30 + 12).contains(&obf_len));

    let Decision::Replace(dec_wire) = peer_eng.process_packet(&out_pkt(2, &obf_wire)) else {
        panic!("expected Decision::Replace from wgobfs decryption");
    };
    let dec_dis = dissect_packet(&dec_wire, false);
    assert_eq!(dec_dis.payload.as_deref(), Some(wg_init.as_slice()));

    // Corrupting one byte inside the AEAD ciphertext/tag must fail tag verification and pass cleanly.
    let mut tampered_dis = dissect_packet(&obf_wire, false);
    tampered_dis.payload.as_mut().expect("pl")[30] ^= 0xFF;
    let tampered_wire = reconstruct_packet(&tampered_dis, &ReconstructOptions::default()).unwrap();
    assert_eq!(peer_eng.process_packet(&out_pkt(3, &tampered_wire)), Decision::Pass);
}

/// Verifies `zapret-auto.lua::circular` rotates strategies after `fails = 2` incoming RST failures.
#[test]
fn zapret_auto_circular_rotates_strategy_on_failures() {
    let toml = r#"
lua_init = [
    "zapret-lib.lua",
    "zapret-auto.lua",
    { inline = "strat_log = {}; function record_strat(ctx, desync) strat_log[#strat_log + 1] = desync.arg.strategy end" },
]
[[profiles]]
filter_tcp = ["80"]
[[profiles.actions]]
func = "circular"
in_range = "a"
out_range = "a"
args = { fails = 2, inseq = 4096 }
[[profiles.actions]]
func = "record_strat"
payload = ["http_req"]
out_range = "a"
args = { strategy = "1" }
[[profiles.actions]]
func = "record_strat"
payload = ["http_req"]
out_range = "a"
args = { strategy = "2" }
"#;
    let (eng, _) = engine_with_capture(toml);
    let http_req = b"GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n";

    for sport in [41001u16, 41002] {
        handshake_tcp4(&eng, sport, 80);
        let req = build_tcp4(CLI_IP, SRV_IP, sport, 80, 1001, 2001, TH_ACK | TH_PUSH, http_req);
        assert_eq!(eng.process_packet(&out_pkt(10, &req)), Decision::Pass);
        let rst = build_tcp4(SRV_IP, CLI_IP, 80, sport, 2001, 1001 + http_req.len() as u32, TH_RST | TH_ACK, &[]);
        assert_eq!(eng.process_packet(&in_pkt(11, &rst)), Decision::Pass);
    }

    handshake_tcp4(&eng, 41003, 80);
    let req3 = build_tcp4(CLI_IP, SRV_IP, 41003, 80, 1001, 2001, TH_ACK | TH_PUSH, http_req);
    assert_eq!(eng.process_packet(&out_pkt(12, &req3)), Decision::Pass);

    let log: Vec<String> = eng.runtime().lua().load("return strat_log").eval().unwrap();
    assert_eq!(log, vec!["1", "1", "2"]);
}

/// Verifies one nanosecond-PCAP packet record header and payload at byte offset `off`.
fn assert_pcap_record(raw: &[u8], off: usize, pkt: &[u8]) -> usize {
    assert_eq!(u32::from_be_bytes(raw[off + 8..off + 12].try_into().unwrap()) as usize, pkt.len());
    assert_eq!(u32::from_be_bytes(raw[off + 12..off + 16].try_into().unwrap()) as usize, pkt.len());
    assert_eq!(&raw[off + 16..off + 16 + pkt.len()], pkt);
    off + 16 + pkt.len()
}

/// Verifies `zapret-pcap.lua::pcap` writes a valid big-endian nanosecond PCAP under `WRITABLE`.
#[test]
fn zapret_pcap_writes_valid_nanosecond_pcap_under_writable() {
    let tmp = TempDir::new("zapret_rs_pcap");
    let dir = prepare_writable_dir(&WritableDirConfig::Custom(tmp.0.join("writable")), None)
        .expect("prepare writable dir");
    let toml = r#"
lua_init = ["zapret-lib.lua", "zapret-pcap.lua"]
[[profiles]]
filter_udp = ["*"]
[[profiles.actions]]
func = "pcap"
in_range = "a"
out_range = "a"
args = { file = "capture.pcap" }
"#;
    let (eng, _) = engine_with_capture(toml);
    let p1 = build_udp4(CLI_IP, SRV_IP, 50001, 53, b"packet-one");
    let p2 = build_udp4(CLI_IP, SRV_IP, 50002, 443, b"packet-two-longer");
    assert_eq!(eng.process_packet(&out_pkt(1, &p1)), Decision::Pass);
    assert_eq!(eng.process_packet(&out_pkt(2, &p2)), Decision::Pass);

    let raw = fs::read(dir.join("capture.pcap")).expect("read capture.pcap");
    assert_eq!(raw.len(), 24 + 16 + p1.len() + 16 + p2.len());
    assert_eq!(&raw[0..8], &[0xA1, 0xB2, 0x3C, 0x4D, 0x00, 0x02, 0x00, 0x04]);
    assert_eq!(&raw[16..24], &[0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x65]);
    let next = assert_pcap_record(&raw, 24, &p1);
    assert_pcap_record(&raw, next, &p2);
}
