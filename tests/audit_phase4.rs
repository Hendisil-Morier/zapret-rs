//! Phase 4 regression tests covering wire hostname sanitization, caps, Lua safety, conntrack eviction, and hot-path bounds.

/// Autohostlist pool, sanitization, and IPCache primitives under test.
use std::cell::RefCell;
use std::rc::Rc;

use zapret_rs::lists::{
    AutoHostlistAction, AutoHostlistRecordCtx, AutoHostlistSettings, HostFailPool,
    HostlistCollection, HostlistFile, IpCache, sanitize_http_host, sanitize_wire_hostname,
};
use zapret_rs::config::L7Proto;
use zapret_rs::desync::dns_cache::feed_dns_response;
use zapret_rs::protocol::{http_extract_host, tls_hello_extract_host};

/// Builds a synthetic TLS ClientHello carrying the raw `sni_bytes` inside extension `0x0000`.
fn build_tls_ch_with_raw_sni(sni_bytes: &[u8]) -> Vec<u8> {
    let entry_len = 3 + sni_bytes.len();
    let sni_list_len = entry_len;
    let ext_payload_len = 2 + sni_list_len;
    let ext_total = 4 + ext_payload_len;
    let mut body = Vec::new();
    body.push(0x01);
    let hs_len_pos = body.len();
    body.extend_from_slice(&[0, 0, 0]);
    body.extend_from_slice(&[0x03, 0x03]);
    body.extend_from_slice(&[0u8; 32]);
    body.push(0); // sid_len
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]); // compression
    body.extend_from_slice(&(ext_total as u16).to_be_bytes());
    body.extend_from_slice(&0u16.to_be_bytes());
    body.extend_from_slice(&(ext_payload_len as u16).to_be_bytes());
    body.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    body.push(0); // host_name
    body.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    body.extend_from_slice(sni_bytes);

    let hs_len = (body.len() - 4) as u32;
    body[hs_len_pos..hs_len_pos + 3].copy_from_slice(&hs_len.to_be_bytes()[1..]);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(&body);
    rec
}

/// Builds a minimal IPv4 DNS A response for raw QNAME `labels`.
fn build_dns_a_response_with_qname(labels: &[&[u8]]) -> Vec<u8> {
    let mut pkt = vec![
        0x12, 0x34, // txid
        0x81, 0x80, // flags: standard query response, no error
        0x00, 0x01, // qdcount = 1
        0x00, 0x01, // ancount = 1
        0x00, 0x00, 0x00, 0x00,
    ];
    for lbl in labels {
        pkt.push(lbl.len() as u8);
        pkt.extend_from_slice(lbl);
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    pkt.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
    pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // TYPE=A, CLASS=IN
    pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL
    pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLEN
    pkt.extend_from_slice(&[93, 184, 216, 34]);
    pkt
}

/// Verifies wire hostnames with directive/control chars are rejected across TLS, HTTP, DNS, and autohostlist.
#[test]
fn wire_hostnames_reject_directive_injection_and_bound_fail_pool() {
    assert_eq!(sanitize_wire_hostname("!exempt.example"), None);
    assert_eq!(sanitize_wire_hostname("^strict.example"), None);
    assert_eq!(sanitize_wire_hostname("#comment.example"), None);
    assert_eq!(sanitize_wire_hostname(";comment.example"), None);
    assert_eq!(sanitize_wire_hostname("evil\n!exempt.example"), None);
    assert_eq!(sanitize_http_host("[2001:DB8::1]:8443").as_deref(), Some("[2001:db8::1]:8443"));
    assert_eq!(sanitize_http_host("evil.com/path"), None);

    for bad_sni in [
        b"!exempt.example".as_slice(),
        b"^strict.example".as_slice(),
        b"bad\n!exempt.com".as_slice(),
        b"nul\x00host.com".as_slice(),
    ] {
        let ch = build_tls_ch_with_raw_sni(bad_sni);
        assert_eq!(tls_hello_extract_host(&ch, false), None);
    }

    let bad_http = b"GET / HTTP/1.1\r\nHost: !exempt.example\r\n\r\n";
    assert_eq!(http_extract_host(bad_http), None);
    let ok_http = b"GET / HTTP/1.1\r\nHost: Example.ORG:8080\r\n\r\n";
    assert_eq!(http_extract_host(ok_http).as_deref(), Some("example.org:8080"));

    let ipcache = RefCell::new(IpCache::new(60, true));
    let injected_dns = build_dns_a_response_with_qname(&[b"!exempt", b"com"]);
    assert!(!feed_dns_response(&injected_dns, &ipcache, 10));
    assert!(ipcache.borrow().is_empty());

    let mut fail_pool = HostFailPool::with_max_entries(2);
    assert_eq!(fail_pool.record_failure("!injected.com", 60, 100), 0);
    assert_eq!(fail_pool.record_failure("a.example", 60, 100), 1);
    assert_eq!(fail_pool.record_failure("b.example", 60, 101), 1);
    assert_eq!(fail_pool.record_failure("c.example", 60, 102), 1);
    assert_eq!(fail_pool.len(), 2, "HostFailPool must evict oldest entry at cap");
    assert!(fail_pool.get("a.example").is_none());

    let autolist = Rc::new(RefCell::new(HostlistFile::default()));
    let hostlists = HostlistCollection::default();
    let settings = AutoHostlistSettings {
        fail_threshold: 1,
        ..AutoHostlistSettings::default()
    };
    let mut ctx = AutoHostlistRecordCtx {
        settings: &settings,
        fail_pool: &mut fail_pool,
        hostlists: &hostlists,
        autolist_file: &autolist,
        debug_log: None,
        profile_n: 1,
        profile_name: "test",
        client_label: "127.0.0.1:1234",
        l7proto: L7Proto::Tls,
        now_sec: 105,
    };
    assert_eq!(
        zapret_rs::lists::record_autohost_failure(&mut ctx, "!bad.org", false),
        AutoHostlistAction::Ignored
    );
}

/// Minimal `PacketSender` stub for instantiating `LuaRuntime` in unit tests.
struct NoopSender;

impl zapret_rs::rawsend::PacketSender for NoopSender {
    fn send(
        &mut self,
        _: std::net::IpAddr,
        _: u32,
        _: Option<&str>,
        _: &[u8],
    ) -> Result<(), zapret_rs::rawsend::RawSendError> {
        Ok(())
    }
}

/// Verifies `ChunkMode::Text` blocks LuaJIT binary bytecode and registry expiry reclaims dropped keys.
#[test]
fn lua_blocks_binary_bytecode_and_reclaims_expired_registry_slots() {
    use zapret_rs::conntrack::CtrackEntry;
    use zapret_rs::lua::{LuaConfig, LuaRuntime};
    use zapret_rs::timer::pool::TimerPool;

    let rt = LuaRuntime::with_sender(LuaConfig::default(), Rc::new(RefCell::new(NoopSender)))
        .expect("LuaRuntime should initialize");

    // Generate genuine LuaJIT binary bytecode (`\x1bLJ...`) from within Lua and test rejection.
    let bytecode: Vec<u8> = rt
        .lua()
        .load("return string.dump(function() return 123 end)")
        .eval::<mlua::LuaString>()
        .expect("string.dump should succeed")
        .as_bytes()
        .to_vec();
    assert!(bytecode.starts_with(b"\x1bLJ"), "expected LuaJIT bytecode magic");
    let bytecode_str = String::from_utf8_lossy(&bytecode);
    assert!(rt.exec_str(&bytecode_str).is_err(), "exec_str must reject bytecode");

    let tmp_dir = std::env::temp_dir().join(format!("zapret-lua-bc-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&tmp_dir);
    let bc_path = tmp_dir.join("evil.luac");
    std::fs::write(&bc_path, &bytecode).expect("write temp bytecode");
    assert!(rt.exec_file(&bc_path).is_err(), "exec_file must reject binary bytecode");
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // Weak-value probe proves oneshot timer + timer_del release registry references deterministically.
    rt.exec_str(
        r#"
        weak_probe = setmetatable({}, { __mode = "v" })
        local payload = { tag = "reclaim" }
        weak_probe[1] = payload
        timer_set("once_probe", function() end, 10, true, payload)
        payload = nil
        "#,
    )
    .expect("oneshot timer registration must succeed");

    TimerPool::run_expired(rt.timer_pool(), rt.lua(), u64::MAX / 2);
    rt.lua().gc_collect().expect("gc_collect must succeed");
    let timer_alive: bool = rt
        .lua()
        .load("return weak_probe[1] ~= nil")
        .eval()
        .expect("eval weak_probe");
    assert!(!timer_alive, "expired oneshot timer must release registry value");

    // Verify `CtrackEntry::reinit` also releases old `lua_state` table references.
    let mut entry = CtrackEntry::new(Some(rt.lua())).expect("ctrack entry");
    if let Some(ref key) = entry.lua_state {
        let tbl: mlua::Table = rt.lua().registry_value(key).expect("lua_state table");
        let weak: mlua::Table = rt.lua().globals().get("weak_probe").expect("weak_probe");
        weak.set(2, tbl).expect("set weak_probe[2]");
    }
    entry.reinit(Some(rt.lua())).expect("reinit must succeed");
    rt.lua().gc_collect().expect("gc_collect must succeed");
    let ctrack_alive: bool = rt
        .lua()
        .load("return weak_probe[2] ~= nil")
        .eval()
        .expect("eval weak_probe[2]");
    assert!(!ctrack_alive, "CtrackEntry::reinit must release old lua_state registry slot");
}

/// Verifies concurrent flows share a global reassembly/delayed byte budget that returns to zero on drop.
#[test]
fn conntrack_global_buffer_budget_caps_multi_flow_amplification_and_frees_to_zero() {
    use zapret_rs::conntrack::{
        ConntrackPool, ConntrackTimeouts, DEFAULT_GLOBAL_REASM_BUDGET_BYTES, DelayedPacket,
        CtrackPositions,
    };
    use zapret_rs::packet::constants::{IPPROTO_TCP, TH_SYN};
    use zapret_rs::packet::{DissectedPacket, Ipv4Header, TcpHeader};
    use zapret_rs::timer::MonotonicTime;

    let mut pool = ConntrackPool::new(ConntrackTimeouts::default());
    assert_eq!(pool.max_buffer_bytes(), DEFAULT_GLOBAL_REASM_BUDGET_BYTES);
    pool.set_max_buffer_bytes(1024);
    assert_eq!(pool.queued_bytes(), 0);

    let make_syn = |src_octet: u8| DissectedPacket {
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
            src: [10, 0, 0, src_octet],
            dst: [93, 184, 216, 34],
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port: 12_000,
            d_port: 443,
            seq: 1,
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

    let t = MonotonicTime { sec: 50, nsec: 0 };
    let (e1, _) = pool.feed(None, &make_syn(1), t).expect("f1").expect("e1");
    let (e2, _) = pool.feed(None, &make_syn(2), t).expect("f2").expect("e2");
    let (e3, _) = pool.feed(None, &make_syn(3), t).expect("f3").expect("e3");

    // Flow 1 allocates 600B reassembly + 200B delayed packet -> 800B used across pool.
    assert!(e1.borrow_mut().try_start_reasm(600, 1));
    assert!(e1.borrow_mut().push_delayed(DelayedPacket {
        raw: vec![0xAA; 200],
        fwmark: 0,
        ifin: None,
        ifout: None,
        tpos: CtrackPositions::default(),
    }));
    assert_eq!(pool.queued_bytes(), 800);

    // Flow 2 requesting 400B reassembly would total 1200B > 1024B -> rejected.
    assert!(!e2.borrow_mut().try_start_reasm(400, 1));
    // Flow 2 pushing 300B delayed also fails (> 1024B), while 200B fits cleanly (total 1000B).
    assert!(!e2.borrow_mut().push_delayed(DelayedPacket {
        raw: vec![0xBB; 300],
        fwmark: 0,
        ifin: None,
        ifout: None,
        tpos: CtrackPositions::default(),
    }));
    assert!(e2.borrow_mut().push_delayed(DelayedPacket {
        raw: vec![0xCC; 200],
        fwmark: 0,
        ifin: None,
        ifout: None,
        tpos: CtrackPositions::default(),
    }));
    assert_eq!(pool.queued_bytes(), 1000);

    // Releasing flow 1 reasm and taking delayed drops budget down to 200B, then freeing flow 2 hits 0.
    e1.borrow_mut().clear_reasm();
    let _ = e1.borrow_mut().take_delayed();
    assert_eq!(pool.queued_bytes(), 200);

    // Dropping flow 2 / clearing pool must bring queued_bytes back to exactly 0.
    drop(e1);
    drop(e2);
    drop(e3);
    pool.clear();
    assert_eq!(pool.queued_bytes(), 0);
}

/// Verifies `nfqueue::drain_batch_with` yields after `MAX_NFQUEUE_BATCH_PACKETS` so outer timers stay responsive.
#[cfg(target_os = "linux")]
#[test]
fn nfqueue_drain_batch_yields_after_cap() {
    use std::io::ErrorKind;
    use std::sync::atomic::AtomicBool;
    use zapret_rs::intercepter::nfqueue::{MAX_NFQUEUE_BATCH_PACKETS, drain_batch_with};

    let stop = AtomicBool::new(false);
    let mut remaining = MAX_NFQUEUE_BATCH_PACKETS + 15;
    let mut handled = 0usize;

    let stopped = drain_batch_with(
        MAX_NFQUEUE_BATCH_PACKETS,
        &stop,
        |err: &std::io::Error| err.kind() == ErrorKind::WouldBlock,
        |_| false,
        || {
            if remaining == 0 {
                Err(std::io::Error::from(ErrorKind::WouldBlock))
            } else {
                remaining -= 1;
                handled += 1;
                Ok(())
            }
        },
    )
    .expect("first batch should yield cleanly");
    assert!(!stopped);
    assert_eq!(handled, MAX_NFQUEUE_BATCH_PACKETS);
    assert_eq!(remaining, 15, "remainder must wait for next poll tick");

    let stopped2 = drain_batch_with(
        MAX_NFQUEUE_BATCH_PACKETS,
        &stop,
        |err: &std::io::Error| err.kind() == ErrorKind::WouldBlock,
        |_| false,
        || {
            if remaining == 0 {
                Err(std::io::Error::from(ErrorKind::WouldBlock))
            } else {
                remaining -= 1;
                handled += 1;
                Ok(())
            }
        },
    )
    .expect("second batch should drain tail and stop on WouldBlock");
    assert!(!stopped2);
    assert_eq!(handled, MAX_NFQUEUE_BATCH_PACKETS + 15);
    assert_eq!(remaining, 0);
}

/// Verifies cached Lua action callbacks and TelemetryHub subscriber gating skip idle formatting.
#[test]
fn cached_lua_action_and_idle_telemetry_gating_work() {
    use std::sync::Arc;
    use zapret_rs::config::AppConfig;
    use zapret_rs::control::{DaemonStatusMeta, TelemetryHub};
    use zapret_rs::lua::{LuaConfig, LuaRuntime};
    use zapret_rs::telemetry::{PacketCounters, PacketVerdict};

    let cfg = AppConfig::from_toml_str(
        r#"
lua_init = [{ inline = "function drop_test(ctx, desync) return VERDICT_PASS end" }]
[[profiles]]
filter_tcp = ["443"]
[[profiles.actions]]
in_range = "a"
out_range = "a"
func = "drop_test"
"#,
        None,
    )
    .expect("valid test config");

    let rt = LuaRuntime::with_sender(LuaConfig::default(), Rc::new(RefCell::new(NoopSender)))
        .expect("runtime");
    rt.apply_app_config(&cfg).expect("apply config caches action");
    let func = rt
        .resolve_cached_action(0, 0, "drop_test")
        .expect("cached action key resolves O(1)");
    assert!(func.call::<u8>(()).is_ok());

    let hub = TelemetryHub::new(
        Arc::new(PacketCounters::default()),
        DaemonStatusMeta {
            version: "1.0.0".to_owned(),
            pid: 1,
            qnum: 200,
            fwmark: 0x4000_0000,
            intercept: false,
            profile_names: Vec::new(),
            config_path: None,
        },
        10,
    );
    assert!(
        !hub.should_publish(PacketVerdict::Pass) && !hub.should_publish(PacketVerdict::Desync),
        "idle TelemetryHub with 0 subscribers must skip PacketRecord building"
    );
}
