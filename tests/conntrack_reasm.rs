//! Integration tests for bidirectional conntrack, stream reassembly, and `PacketRange` evaluation.

/// Packet range evaluator under test.
use zapret_rs::config::PacketRange;
/// Conntrack pool, position structs, timeouts, and stream reassembler under test.
use zapret_rs::conntrack::{
    ConnState, ConntrackPool, ConntrackTimeouts, CtrackPosition, StreamReassembler,
};
/// Packet constants for building synthetic TCP/UDP flows.
use zapret_rs::packet::constants::{
    IPPROTO_TCP, IPPROTO_UDP, TCP_KIND_MSS, TCP_KIND_SCALE, TH_ACK, TH_FIN, TH_PUSH, TH_SYN,
};
/// Wire packet types and reconstructor for building valid synthetic IPv4 packets.
use zapret_rs::packet::{
    DissectedPacket, Ipv4Header, ReconstructOptions, TcpHeader, TcpOption, UdpHeader,
    dissect_packet, reconstruct_packet,
};
/// Monotonic boottime `timespec` value used for deterministic expiry tests.
use zapret_rs::timer::MonotonicTime;

/// Builds a valid IPv4 + TCP packet between client (`10.0.0.2:41000`) and server (`93.184.216.34:443`).
#[allow(clippy::too_many_arguments)]
fn build_tcp4_pkt(
    from_server: bool,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    options: Vec<TcpOption>,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let (src, dst, s_port, d_port) = if from_server {
        ([93, 184, 216, 34], [10, 0, 0, 2], 443, 41000)
    } else {
        ([10, 0, 0, 2], [93, 184, 216, 34], 41000, 443)
    };
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x2222,
            frag_off: 0,
            ttl,
            protocol: IPPROTO_TCP,
            checksum: 0,
            src,
            dst,
            options: Vec::new(),
        }),
        tcp: Some(TcpHeader {
            s_port,
            d_port,
            seq,
            ack,
            reserved: 0,
            data_offset: 5,
            flags,
            window,
            checksum: 0,
            urgent_ptr: 0,
            options,
        }),
        payload: (!payload.is_empty()).then(|| payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid synthetic TCP packet")
}

/// Builds a valid IPv4 + UDP packet between client (`10.0.0.2:50000`) and server (`8.8.8.8:53`).
fn build_udp4_pkt(from_server: bool, payload: &[u8]) -> Vec<u8> {
    let (src, dst, s_port, d_port) = if from_server {
        ([8, 8, 8, 8], [10, 0, 0, 2], 53, 50000)
    } else {
        ([10, 0, 0, 2], [8, 8, 8, 8], 50000, 53)
    };
    let dis = DissectedPacket {
        ip: Some(Ipv4Header {
            version: 4,
            header_len: 5,
            tos: 0,
            total_len: 0,
            id: 0x3333,
            frag_off: 0,
            ttl: 64,
            protocol: IPPROTO_UDP,
            checksum: 0,
            src,
            dst,
            options: Vec::new(),
        }),
        udp: Some(UdpHeader {
            s_port,
            d_port,
            len: 0,
            checksum: 0,
        }),
        payload: Some(payload.to_vec()),
        ..DissectedPacket::default()
    };
    reconstruct_packet(&dis, &ReconstructOptions::default()).expect("valid synthetic UDP packet")
}

/// Verifies TCP SYN/SYN-ACK/ESTABLISHED/FIN transitions, scale capping, wrapping sequences, and re-init.
#[test]
fn conntrack_tcp_lifecycle_options_wraparound_and_reinit() {
    let mut pool = ConntrackPool::new(ConntrackTimeouts::default());
    let t0 = MonotonicTime { sec: 100, nsec: 500_000_000 };

    // Mid-stream PSH+ACK without prior SYN returns None.
    let mid = dissect_packet(
        &build_tcp4_pkt(false, 100, 200, TH_ACK | TH_PUSH, 1024, vec![], b"hi", 64),
        false,
    );
    assert!(pool.feed(None, &mid, t0).expect("feed ok").is_none());

    // Client SYN near u32::MAX with scale > 14 (clamped to 14) and MSS=1460.
    let syn_seq = 0xFFFF_FF00u32;
    let syn_opts = vec![
        TcpOption { kind: TCP_KIND_MSS, data: Some(vec![0x05, 0xB4]) },
        TcpOption { kind: TCP_KIND_SCALE, data: Some(vec![20]) },
    ];
    let syn = dissect_packet(
        &build_tcp4_pkt(false, syn_seq, 0, TH_SYN, 1000, syn_opts, &[], 64),
        false,
    );
    let (entry_rc, rev) = pool.feed(None, &syn, t0).expect("feed ok").expect("tracked");
    assert!(!rev);
    {
        let e = entry_rc.borrow();
        assert_eq!(e.pos.state, ConnState::Syn);
        assert_eq!(e.pos.client.scale, 14);
        assert_eq!(e.pos.client.mss, 1460);
        assert_eq!(e.pos.client.winsize_calc, 1000);
        assert_eq!(e.pos.client.seq0, syn_seq);
    }

    // Server SYN-ACK establishes server scale/mss and preserves Syn unshifted winsize_calc.
    let srv_seq0 = 5000u32;
    let sa_opts = vec![
        TcpOption { kind: TCP_KIND_MSS, data: Some(vec![0x05, 0x78]) },
        TcpOption { kind: TCP_KIND_SCALE, data: Some(vec![7]) },
    ];
    let synack = dissect_packet(
        &build_tcp4_pkt(true, srv_seq0, syn_seq.wrapping_add(1), TH_SYN | TH_ACK, 512, sa_opts, &[], 52),
        false,
    );
    let (_, rev_sa) = pool.feed(None, &synack, t0).expect("feed ok").expect("tracked");
    assert!(rev_sa);

    // Client ACK moves state -> Established and shifts client winsize_calc << 14.
    let ack = dissect_packet(
        &build_tcp4_pkt(false, syn_seq.wrapping_add(1), srv_seq0 + 1, TH_ACK, 100, vec![], &[], 64),
        false,
    );
    pool.feed(None, &ack, t0).expect("feed ok").expect("tracked");
    assert_eq!(entry_rc.borrow().pos.state, ConnState::Established);
    assert_eq!(entry_rc.borrow().pos.client.winsize_calc, 100u32 << 14);

    // First client data chunk (300 bytes) wraps past 32-bit zero; followed by identical retransmit.
    let data = dissect_packet(
        &build_tcp4_pkt(false, syn_seq.wrapping_add(1), srv_seq0 + 1, TH_ACK | TH_PUSH, 100, vec![], &[0xAA; 300], 64),
        false,
    );
    pool.feed(None, &data, t0).expect("feed ok");
    assert!(!entry_rc.borrow().pos.client.is_retransmission());
    assert_eq!(entry_rc.borrow().pos.client.rel_pos(), 301);

    pool.feed(None, &data, t0).expect("feed ok");
    assert!(entry_rc.borrow().pos.client.is_retransmission());
    assert_eq!(entry_rc.borrow().pos.client.pdcounter, 2);
    assert_eq!(entry_rc.borrow().pos.client.pbcounter, 600);

    // Jump > 2 GiB sets sticky rseq_over_2g; FIN transitions state -> Fin; new SYN reinits.
    let far = dissect_packet(
        &build_tcp4_pkt(false, syn_seq.wrapping_add(0x9000_0000), srv_seq0 + 1, TH_ACK | TH_FIN, 100, vec![], &[], 64),
        false,
    );
    pool.feed(None, &far, t0).expect("feed ok");
    assert!(entry_rc.borrow().pos.client.rseq_over_2g);
    assert_eq!(entry_rc.borrow().pos.state, ConnState::Fin);

    let resyn = dissect_packet(&build_tcp4_pkt(false, 42, 0, TH_SYN, 100, vec![], &[], 64), false);
    pool.feed(None, &resyn, t0).expect("feed ok");
    assert!(!entry_rc.borrow().pos.client.rseq_over_2g);
    assert_eq!(entry_rc.borrow().pos.client.pcounter, 1);

    // SYN-ACK-first creation creates reversed entry keeping client in src/sport.
    let mut pool2 = ConntrackPool::default();
    let (_, rev2) = pool2.feed(None, &synack, t0).expect("ok").expect("synack creates");
    assert!(rev2);
}

/// Verifies UDP bidirectional tracking, `double_search`, `drop_conn`, and rate-limited expiry sweeps.
#[test]
fn conntrack_udp_double_search_drop_and_purge_timeouts() {
    let timeouts = ConntrackTimeouts {
        syn: 10,
        established: 20,
        fin: 5,
        udp: 15,
        purge_interval: 10,
    };
    let mut pool = ConntrackPool::new(timeouts);
    let u0 = dissect_packet(&build_udp4_pkt(false, b"ping"), false);
    let u1 = dissect_packet(&build_udp4_pkt(true, b"pong42"), false);

    let (e_rc, rev0) = pool.feed(None, &u0, MonotonicTime { sec: 100, nsec: 0 }).expect("ok").expect("udp");
    assert!(!rev0);
    let (_, rev1) = pool.feed(None, &u1, MonotonicTime { sec: 102, nsec: 0 }).expect("ok").expect("udp rev");
    assert!(rev1);
    assert_eq!(e_rc.borrow().pos.client.pbcounter, 4);
    assert_eq!(e_rc.borrow().pos.server.pbcounter, 6);
    assert!(pool.double_search(&u1).expect("found").1);

    // Rate-limited purge skips before purge_interval elapses, then evicts once past udp=15s.
    assert_eq!(pool.purge_rate_limited(105), 0);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool.purge_rate_limited(117), 1);
    assert!(pool.is_empty());

    // Explicit cutoff flag evicts even before timeout; drop_conn works from reverse side.
    let (e2, _) = pool.feed(None, &u0, MonotonicTime { sec: 200, nsec: 0 }).expect("ok").expect("udp2");
    e2.borrow_mut().cutoff = true;
    assert_eq!(pool.purge_now(200), 1);
    pool.feed(None, &u0, MonotonicTime { sec: 200, nsec: 0 }).expect("ok");
    assert!(pool.drop_conn(&u1));
    assert!(pool.is_empty());
}

/// Verifies continuous stream reassembly, overlapping retransmission overwrite, and gap/overflow errors.
#[test]
fn stream_reassembler_handles_chunks_overlaps_gaps_and_overflow() {
    let mut r = StreamReassembler::default();
    assert!(r.is_empty());
    r.init(10, 1000);

    assert!(r.feed(1000, b"ABCD"));
    assert!(r.feed(990, b"12345")); // wholly before start -> ignored
    assert!(r.feed(1002, b"cdEF")); // overlaps [1002..1004], extends to 1006
    assert!(!r.feed(1007, b"Z")); // forward gap -> rejected
    assert!(!r.feed(1006, b"TOO_LONG!!")); // overflow -> rejected
    assert!(!r.is_full());

    assert!(r.feed(1006, b"GHIJ"));
    assert!(r.is_full());
    assert_eq!(r.data(), b"ABcdEFGHIJ");
}

/// Verifies `PacketRange` evaluation (`n`/`d`/`b`/`s`/`p`/`a`/`x`, `-` vs `<`, overflow, and `None`).
#[test]
fn packet_range_evaluates_counters_seq_exclusive_and_overflow() {
    let pos = CtrackPosition {
        pcounter: 3,
        pdcounter: 2,
        pbcounter: 200,
        seq0: 1000,
        seq_last: 1050,
        pos: 1150,
        ..CtrackPosition::default()
    };

    let inc = PacketRange::parse("d1-d2").expect("d1-d2");
    let exc = PacketRange::parse("d1<d2").expect("d1<d2");
    assert!(inc.check_pos_range(Some(&pos)));
    assert!(!exc.check_pos_range(Some(&pos)));
    assert!(!inc.check_pos_cutoff(Some(&pos)));
    assert!(exc.check_pos_cutoff(Some(&pos)));

    assert!(PacketRange::parse("n3-n3").expect("n3").check_pos_range(Some(&pos)));
    assert!(PacketRange::parse("b100-b200").expect("b").check_pos_range(Some(&pos)));
    assert!(PacketRange::parse("s50-p150").expect("s-p").check_pos_range(Some(&pos)));

    let over = CtrackPosition { rseq_over_2g: true, ..pos };
    assert!(!PacketRange::parse("s0-s100").expect("s").check_pos_range(Some(&over)));
    assert!(PacketRange::parse("s0-s100").expect("s").check_pos_cutoff(Some(&over)));

    // Without conntrack: only a..a avoids cutoff and matches range.
    assert!(PacketRange::ALWAYS.check_pos_range(None));
    assert!(!PacketRange::ALWAYS.check_pos_cutoff(None));
    assert!(!inc.check_pos_range(None));
    assert!(inc.check_pos_cutoff(None));
}
