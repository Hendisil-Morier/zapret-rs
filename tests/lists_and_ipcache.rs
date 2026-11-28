//! Integration tests verifying plain/gzip list loaders, hostlists, autohostlists, IPsets, and IPCache.

/// Interior mutability for shared file wrappers inside hostlist and ipset collections.
use std::cell::RefCell;
/// Compression writer and `Write` trait for creating real single/multi-member `.gz` test fixtures.
use std::io::Write;
/// Unified IPv4/IPv6 addresses for CIDR prefix tree and IPCache checks.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
/// Temporary directory creation and cleanup inside OS temp storage.
use std::path::{Path, PathBuf};
/// Reference counting matching production collection ownership.
use std::rc::Rc;
/// Atomic test-directory suffix counter guaranteeing uniqueness across parallel nextest runners.
use std::sync::atomic::{AtomicU64, Ordering};

/// Gzip encoder from offline `flate2` used to build real gzip test inputs.
use flate2::{Compression, write::GzEncoder};

/// Payload and protocol enums used in TCP/UDP autohostlist triggers.
use zapret_rs::config::{L7Payload, L7Proto};
/// Conntrack entry and position snapshots driven through failure-trigger evaluators.
use zapret_rs::conntrack::{ConnState, CtrackEntry, CtrackPositions, RETRANS_COUNTER_STOP};
/// Hostlists, autohostlist state machine, disjoint CIDR IPsets, and IPCache under test.
use zapret_rs::lists::{
    AutoHostlistAction, AutoHostlistRecordCtx, AutoHostlistSettings, DEFAULT_IPCACHE_LIFETIME_SEC,
    EMPTY_AUTOLIST_SENTINEL, HostFailPool, HostlistCheckOutcome, HostlistCollection, HostlistFile,
    HostlistPool, HostlistRef, HostlistSearchResult, IpCache, IpSet, IpsetCollection, IpsetFile,
    check_tcp_incoming_trigger, check_tcp_retrans_trigger, check_udp_trigger, parse_cidr4, parse_cidr6,
    parse_list_line_token, reset_autohost_failure, seq_within,
};
/// IPv4/TCP protocol constants matching wire dissect inputs.
use zapret_rs::packet::constants::{IPPROTO_TCP, IPPROTO_UDP, TH_RST};

/// Monotonic counter separating temporary directories created within one test process.
static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// RAII temporary workspace removed automatically on drop.
struct TempWorkspace(PathBuf);

impl TempWorkspace
{
    /// Creates a unique directory under `std::env::temp_dir()`.
    fn new(prefix: &str) -> Self
    {
        let id = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), id));
        std::fs::create_dir_all(&dir).expect("create temp test dir");
        Self(dir)
    }

    /// Returns a child file path inside this temporary workspace.
    fn path(&self, name: &str) -> PathBuf
    {
        self.0.join(name)
    }
}

impl Drop for TempWorkspace
{
    fn drop(&mut self)
    {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Encodes `chunks` as concatenated gzip members (`MultiGzDecoder` multi-member format).
fn write_multi_member_gzip(path: &Path, chunks: &[&[u8]])
{
    let mut combined = Vec::new();
    for chunk in chunks
    {
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(chunk).expect("write gzip chunk");
        combined.extend_from_slice(&enc.finish().expect("finish gzip chunk"));
    }
    std::fs::write(path, combined).expect("write gzip fixture");
}

/// Verifies comment skipping, flag matching (`^`/`!`), `no_match_subdomains`, exclude-before-include, and reload resilience.
#[test]
fn hostlist_flags_suffixes_gzip_and_reload_resilience()
{
    assert_eq!(parse_list_line_token("  # comment"), None);
    assert_eq!(parse_list_line_token("\t; comment"), None);
    assert_eq!(parse_list_line_token("// slash comment"), None);
    assert_eq!(parse_list_line_token("  Example.COM # inline"), Some("Example.COM"));

    let mut pool = HostlistPool::new();
    for line in [
        "# comment line",
        "^ExactOnly.ORG",
        "!blocked.parent.org",
        "parent.org",
        "^!Strict.Exempt.net",
        "exempt.net",
        "10.20.30.40",
    ]
    {
        assert!(pool.add_raw_line(line));
    }

    assert_eq!(pool.search("exactonly.org", false), HostlistSearchResult::Matched);
    assert_eq!(pool.search("sub.exactonly.org", false), HostlistSearchResult::NotFound);
    assert_eq!(pool.search("a.parent.org", false), HostlistSearchResult::Matched);
    assert_eq!(pool.search("sub.blocked.parent.org", false), HostlistSearchResult::Exempted);
    // `^!` exempts only the exact hostname, allowing child subdomains to match parent `exempt.net`.
    assert_eq!(pool.search("strict.exempt.net", false), HostlistSearchResult::Exempted);
    assert_eq!(pool.search("a.strict.exempt.net", false), HostlistSearchResult::Matched);
    // IP literals disable subdomain traversal (`no_match_subdomains = true`).
    assert_eq!(pool.search("10.20.30.40", true), HostlistSearchResult::Matched);
    assert_eq!(pool.search("99.10.20.30", true), HostlistSearchResult::NotFound);

    // File loading: concatenated multi-member `.gz` hostlist + corrupt `.gz` error + deleted resilience.
    let ws = TempWorkspace::new("zapret_rs_hl");
    let gz_path = ws.path("hosts.txt.gz");
    write_multi_member_gzip(&gz_path, &[b"# m1\nALPHA.org\n", b"^beta.com\n"]);

    let inc_file = Rc::new(RefCell::new(HostlistFile::from_path(gz_path.clone())));
    inc_file.borrow_mut().load_initial().expect("initial gz load");
    assert_eq!(inc_file.borrow().pool.len(), 2);

    let ex_path = ws.path("exclude.txt");
    std::fs::write(&ex_path, "excluded.alpha.org\n").expect("write exclude");
    let ex_file = Rc::new(RefCell::new(HostlistFile::from_path(ex_path)));
    ex_file.borrow_mut().load_initial().expect("initial exclude");

    let empty_auto = Rc::new(RefCell::new(HostlistFile::inline()));
    let col = HostlistCollection {
        include: vec![
            HostlistRef { file: Rc::clone(&inc_file), is_autolist: false },
            HostlistRef { file: Rc::clone(&empty_auto), is_autolist: true },
        ],
        exclude: vec![Rc::clone(&ex_file)],
    };
    col.ensure_autolists_non_empty();
    assert!(empty_auto.borrow().pool.search(EMPTY_AUTOLIST_SENTINEL, false) == HostlistSearchResult::Matched);

    assert_eq!(
        col.check("www.alpha.org", false, false),
        HostlistCheckOutcome { matched: true, excluded: false }
    );
    assert_eq!(
        col.check("excluded.alpha.org", false, false),
        HostlistCheckOutcome { matched: false, excluded: true }
    );

    // Removing the backing file keeps in-memory entries intact across reload checks.
    std::fs::remove_file(&gz_path).expect("remove gz");
    assert!(!inc_file.borrow_mut().reload_if_changed().expect("missing stays ok"));
    assert_eq!(
        col.check("www.alpha.org", false, false),
        HostlistCheckOutcome { matched: true, excluded: false }
    );

    // Corrupt `.gz` returns an Err and clears the pool (`LoadHostList`).
    let bad_gz = ws.path("bad.gz");
    std::fs::write(&bad_gz, [0x1F, 0x8B, 0x08, 0xFF, 0x00]).expect("write corrupt gz");
    let mut bad_file = HostlistFile::from_path(bad_gz);
    assert!(bad_file.load_initial().is_err());
}

/// Verifies disjoint IPv4/IPv6 CIDR coalescing, boundary bits, gzip ipsets, and dual-IP checks.
#[test]
fn ipset_disjoint_prefix_tree_gzip_and_dual_ip_checks()
{
    assert_eq!(parse_cidr4("192.168.1.5"), Some((Ipv4Addr::new(192, 168, 1, 5), 32)));
    assert_eq!(parse_cidr4("10.0.0.0/8"), Some((Ipv4Addr::new(10, 0, 0, 0), 8)));
    assert_eq!(parse_cidr4("10.0.0.0/33"), None);
    assert_eq!(
        parse_cidr6("2001:db8::/32").expect("valid v6 cidr").0,
        "2001:db8::".parse::<Ipv6Addr>().expect("v6")
    );

    let mut set = IpSet::new();
    assert!(set.add_raw_line("10.0.0.1/32"));
    assert_eq!(set.len_v4(), 1);
    assert!(set.add_raw_line("10.0.0.0/24"));
    // Broader `/24` subsumes the earlier `/32`, leaving one disjoint prefix.
    assert_eq!(set.len_v4(), 1);
    assert!(set.add_raw_line("10.0.0.128/25"));
    // Narrower `/25` is already covered by `/24`, keeping length 1.
    assert_eq!(set.len_v4(), 1);
    assert!(set.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 255))));
    assert!(!set.contains(IpAddr::V4(Ipv4Addr::new(10, 0, 1, 0))));
    assert!(!set.add_raw_line("not-an-ip-subnet"));

    assert!(set.add_raw_line("2001:db8::/32"));
    assert!(set.contains("2001:db8::dead:beef".parse().expect("v6")));
    assert!(!set.contains("2001:db9::1".parse().expect("v6")));

    // Test `/0` full match guard against shift overflow.
    let mut any_v4 = IpSet::new();
    assert!(any_v4.add_v4(Ipv4Addr::UNSPECIFIED, 0));
    assert!(any_v4.contains(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));

    let ws = TempWorkspace::new("zapret_rs_ips");
    let inc_gz = ws.path("ips.gz");
    write_multi_member_gzip(&inc_gz, &[b"; header comment\n192.0.2.0/24\nbadline\n2001:db8::/32\n"]);
    let inc_file = Rc::new(RefCell::new(IpsetFile::from_path(inc_gz)));
    inc_file.borrow_mut().load_initial().expect("load gz ipset");

    let ex_plain = ws.path("ips_ex.txt");
    std::fs::write(&ex_plain, "192.0.2.99/32\n").expect("write ex ipset");
    let ex_file = Rc::new(RefCell::new(IpsetFile::from_path(ex_plain)));
    ex_file.borrow_mut().load_initial().expect("load ex ipset");

    let ips = IpsetCollection { include: vec![Rc::clone(&inc_file)], exclude: vec![Rc::clone(&ex_file)] };

    let matched_rev = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    let unmatched = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1));
    let excluded = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99));

    // Dual-IP match passes when reverse IP matches include, and fails if either matches exclude.
    assert!(ips.check(unmatched, Some(matched_rev), false));
    assert!(!ips.check(matched_rev, Some(excluded), false));
}

/// Verifies `IpCache` hostname/TTL isolation, expiry boundaries, and 1 Hz purge throttling.
#[test]
fn ipcache_hostnames_ttls_expiry_and_rate_limit()
{
    let ip4 = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
    let mut cache = IpCache::new(60, true);
    assert_eq!(IpCache::default().lifetime_sec(), DEFAULT_IPCACHE_LIFETIME_SEC);

    cache.put_hostname(ip4, "example.com", false, 100);
    assert_eq!(cache.get_hostname(ip4), Some(("example.com", false)));

    let mut ttl = 52u8;
    cache.update_ttl(ip4, "eth0", &mut ttl, false, 100);
    // Client TTL entries stay keyed by `(ip, iface)` while hostnames live under `(ip, "")`.
    assert_eq!(cache.get_ttl(ip4, "eth0", false), Some(52));
    assert_eq!(cache.get_ttl(ip4, "wlan0", false), None);
    assert_eq!(cache.get_ttl(ip4, "eth0", true), None);

    let mut unknown_ttl = 0u8;
    cache.update_ttl(ip4, "eth0", &mut unknown_ttl, false, 105);
    assert_eq!(unknown_ttl, 52);

    // Rate-limited purge runs only once per monotonic second `105`, then evicts at `165`.
    cache.purge_rate_limited(105);
    assert_eq!(cache.len(), 2);
    cache.purge_rate_limited(165);
    assert_eq!(cache.len(), 0);

    // `lifetime_sec = 0` disables expiration indefinitely.
    let mut immortal = IpCache::new(0, false);
    immortal.put_hostname(ip4, "ignored.com", false, 10);
    assert_eq!(immortal.get_hostname(ip4), None);
    let mut keep_ttl = 64u8;
    immortal.update_ttl(ip4, "lo", &mut keep_ttl, false, 10);
    immortal.purge(1_000_000);
    assert_eq!(immortal.get_ttl(ip4, "lo", false), Some(64));
}

/// Verifies `HostFailPool` fixed failure windows, autolist self-append without reload storm, and TCP/UDP triggers.
#[test]
fn autohostlist_fail_pool_append_and_tcp_udp_triggers()
{
    let settings = AutoHostlistSettings {
        fail_threshold: 2,
        fail_time_sec: 10,
        retrans_threshold: 2,
        retrans_maxseq: 32_768,
        retrans_reset: true,
        incoming_maxseq: 4_096,
        udp_out: 3,
        udp_in: 1,
        fail_cooldown_sec: 0,
        sibling_threshold: 2,
        confirm_block: false,
    };
    assert!(settings.validate().is_ok());

    let mut fail_pool = HostFailPool::new();
    assert_eq!(fail_pool.record_failure("blocked.example", 10, 100), 1);
    assert_eq!(fail_pool.get("blocked.example").expect("present").expire_sec, 110);
    // Failure window deadline stays fixed at `110` instead of sliding on second failure at `105`.
    assert_eq!(fail_pool.record_failure("blocked.example", 10, 105), 2);
    assert_eq!(fail_pool.get("blocked.example").expect("present").expire_sec, 110);
    fail_pool.purge_rate_limited(110);
    assert!(fail_pool.is_empty());

    let ws = TempWorkspace::new("zapret_rs_auto");
    let auto_path = ws.path("auto.txt");
    let dbg_path = ws.path("auto-debug.log");
    std::fs::write(&auto_path, "!exempt.example\n").expect("seed autolist");
    let autolist_file = Rc::new(RefCell::new(HostlistFile::from_path(auto_path.clone())));
    autolist_file.borrow_mut().load_initial().expect("load auto");

    let hostlists = HostlistCollection {
        include: vec![HostlistRef { file: Rc::clone(&autolist_file), is_autolist: true }],
        exclude: Vec::new(),
    };

    // `!exempt.example` reaches threshold but must NOT be appended.
    for t in [200, 201]
    {
        let mut ctx = AutoHostlistRecordCtx {
            settings: &settings,
            fail_pool: &mut fail_pool,
            hostlists: &hostlists,
            autolist_file: &autolist_file,
            debug_log: Some(&dbg_path),
            profile_n: 1,
            profile_name: "p1",
            client_label: "127.0.0.1:1234",
            l7proto: L7Proto::Tls,
            now_sec: t,
        };
        let act = zapret_rs::lists::record_autohost_failure(&mut ctx, "exempt.example", false);
        if t == 201
        {
            assert_eq!(act, AutoHostlistAction::SkippedDuplicateOrExempt);
        }
    }

    // `newblocked.org` hits threshold 2 => appended, added to pool, `mod_sig` refreshed (no reload).
    for (idx, t) in [210, 211].into_iter().enumerate()
    {
        let mut ctx = AutoHostlistRecordCtx {
            settings: &settings,
            fail_pool: &mut fail_pool,
            hostlists: &hostlists,
            autolist_file: &autolist_file,
            debug_log: Some(&dbg_path),
            profile_n: 1,
            profile_name: "p1",
            client_label: "127.0.0.1:5678",
            l7proto: L7Proto::Tls,
            now_sec: t,
        };
        let act = zapret_rs::lists::record_autohost_failure(&mut ctx, "newblocked.org", false);
        assert_eq!(
            act,
            if idx == 0 { AutoHostlistAction::FailCounted(1) } else { AutoHostlistAction::AddedToList }
        );
    }
    assert!(!autolist_file.borrow_mut().reload_if_changed().expect("sig refreshed"));
    assert!(std::fs::read_to_string(&auto_path).expect("auto content").contains("newblocked.org\n"));
    assert!(std::fs::read_to_string(&dbg_path).expect("debug log").contains("adding to"));

    // Verify TCP retransmission, incoming RST/DPI-redirect, `seq_within` 32-bit wrap, and UDP triggers.
    assert!(seq_within(5, u32::MAX - 10, 10));
    let mut entry = CtrackEntry::new(None).expect("entry");
    entry.hostname = Some("newblocked.org".to_owned());
    entry.hostname_ah_check = true;
    entry.pos.ipproto = IPPROTO_TCP;
    entry.pos.state = ConnState::Established;
    entry.pos.client.seq0 = 1000;
    entry.pos.client.seq_last = 1001;
    entry.pos.client.pos = 1200;
    entry.pos.client.uppos_prev = 1300; // `uppos_prev >= pos` => retransmission
    assert_eq!(check_tcp_retrans_trigger(&mut entry, &settings), None);
    assert_eq!(check_tcp_retrans_trigger(&mut entry, &settings), Some(true));
    assert_eq!(entry.req_retrans_counter, RETRANS_COUNTER_STOP);

    // Sequence beyond `retrans_maxseq` ends failure tracking cleanly (`Some(false)` reset).
    let mut seq_far = CtrackEntry::new(None).expect("entry");
    seq_far.hostname_ah_check = true;
    seq_far.pos.ipproto = IPPROTO_TCP;
    seq_far.pos.state = ConnState::Established;
    seq_far.pos.client.seq0 = 1000;
    seq_far.pos.client.seq_last = 1000 + settings.retrans_maxseq + 1;
    assert_eq!(check_tcp_retrans_trigger(&mut seq_far, &settings), Some(false));
    assert_eq!(seq_far.req_retrans_counter, RETRANS_COUNTER_STOP);

    let mut inc_entry = CtrackEntry::new(None).expect("entry");
    inc_entry.hostname = Some("example.com".to_owned());
    inc_entry.hostname_ah_check = true;
    inc_entry.pos.server.seq0 = 5000;
    inc_entry.pos.server.seq_last = 5001;
    let redir = b"HTTP/1.1 302 Found\r\nLocation: http://warning.isp.net/block\r\n\r\n";
    assert_eq!(
        check_tcp_incoming_trigger(&mut inc_entry, 0, Some(redir), L7Payload::HttpReply, &settings),
        Some(true)
    );
    let mut rst_entry = CtrackEntry::new(None).expect("entry");
    rst_entry.hostname_ah_check = true;
    rst_entry.pos.server.seq0 = 5000;
    rst_entry.pos.server.seq_last = 5001;
    assert_eq!(
        check_tcp_incoming_trigger(&mut rst_entry, TH_RST, None, L7Payload::Empty, &settings),
        Some(true)
    );

    let mut udp_entry = CtrackEntry::new(None).expect("entry");
    udp_entry.hostname = Some("quic.example.com".to_owned());
    udp_entry.hostname_ah_check = true;
    let mut tpos = CtrackPositions { ipproto: IPPROTO_UDP, ..CtrackPositions::default() };
    tpos.client.pcounter = 3;
    tpos.server.pcounter = 1;
    assert_eq!(check_udp_trigger(&mut udp_entry, &tpos, &settings), Some(true));
    fail_pool.record_failure("quic.example.com", 10, 300);
    assert_eq!(
        reset_autohost_failure(&mut fail_pool, "quic.example.com", None, 1, "p1", "", L7Proto::Quic),
        AutoHostlistAction::ResetOnSuccess
    );
}
