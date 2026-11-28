//! Integration tests for control socket protocol serialization and bounded JSON framing.

use std::io::Cursor;

use zapret_rs::control::{
    CONTROL_PROTOCOL_VERSION, CodecError, ControlErrorCode, CountersSnapshot, DEFAULT_PASS_SAMPLE_RATE,
    DaemonStatus, MAX_CONTROL_LINE_BYTES, Request, Response, decode_line, encode_line, read_bounded_line,
    read_message, validate_protocol_version, write_message,
};
use zapret_rs::desync::PacketOutcome;
use zapret_rs::intercepter::QueuedPacket;
use zapret_rs::telemetry::{PacketCounters, PacketVerdict, build_packet_record};

fn sample_packet_record() -> zapret_rs::telemetry::PacketRecord
{
    // Minimal valid 20B IPv4 + 20B TCP SYN packet.
    let mut raw = vec![0u8; 40];
    raw[0] = 0x45;
    raw[3] = 40;
    raw[8] = 64;
    raw[9] = 6;
    raw[12..16].copy_from_slice(&[192, 168, 1, 23]);
    raw[16..20].copy_from_slice(&[93, 184, 216, 34]);
    raw[20..22].copy_from_slice(&51234u16.to_be_bytes());
    raw[22..24].copy_from_slice(&443u16.to_be_bytes());
    raw[32] = 0x50;
    raw[33] = 0x02;
    let qp = QueuedPacket { packet_id: 1, payload: &raw, mark: 0x4000_0000, ifout: Some("eth0"), ifin: None };
    build_packet_record(7, &qp, &PacketOutcome::Desync(Some("tls13:multisplit".to_owned())))
}

#[test]
fn round_trip_every_request_and_response_variant()
{
    let requests = vec![
        Request::Hello { version: CONTROL_PROTOCOL_VERSION },
        Request::Status,
        Request::Subscribe { pass_sample_rate: None },
        Request::Subscribe { pass_sample_rate: Some(10) },
        Request::Unsubscribe,
        Request::ReloadLists,
        Request::ReloadConfig { toml: "[[profiles]]\nname = \"p1\"\n".to_owned() },
        Request::Stop,
    ];
    let mut wire = Vec::new();
    for req in &requests
    {
        write_message(&mut wire, req).expect("encode request");
    }
    let mut reader = Cursor::new(&wire);
    let mut decoded_reqs = Vec::new();
    while let Some(req) = read_message::<_, Request>(&mut reader).expect("decode request")
    {
        decoded_reqs.push(req);
    }
    assert_eq!(decoded_reqs, requests);

    let rec = sample_packet_record();
    assert_eq!(rec.verdict, PacketVerdict::Desync);
    let status = DaemonStatus {
        version: "1.0.1".to_owned(),
        pid: 4242,
        qnum: 200,
        fwmark: 0x4000_0000,
        intercept: true,
        profile_names: vec!["tls13:multisplit".to_owned()],
        config_path: Some("/etc/zapret-rs/nfqws2.toml".to_owned()),
        pass_sample_rate: DEFAULT_PASS_SAMPLE_RATE,
        counters: CountersSnapshot { total: 100, passed: 90, reassembled: 4, modified: 1, desynced: 5 },
    };
    let responses = vec![
        Response::HelloOk { version: CONTROL_PROTOCOL_VERSION, daemon_version: "1.0.1".to_owned() },
        Response::Ack { op: "reload_lists".to_owned(), message: Some("reloaded 2 files".to_owned()) },
        Response::Status(status),
        Response::Counters(CountersSnapshot {
            total: 101,
            passed: 91,
            reassembled: 4,
            modified: 1,
            desynced: 5,
        }),
        Response::Packet(rec),
        Response::Error {
            code: ControlErrorCode::UnsupportedVersion,
            message: "version mismatch".to_owned(),
        },
    ];
    let mut resp_wire = Vec::new();
    for resp in &responses
    {
        let encoded = encode_line(resp).expect("encode response line");
        let text = std::str::from_utf8(&encoded).expect("utf8");
        let single: Response = decode_line(text).expect("decode_line");
        assert_eq!(&single, resp);
        resp_wire.extend_from_slice(&encoded);
    }
    let mut resp_reader = Cursor::new(&resp_wire);
    let mut decoded_resps = Vec::new();
    while let Some(resp) = read_message::<_, Response>(&mut resp_reader).expect("decode response")
    {
        decoded_resps.push(resp);
    }
    assert_eq!(decoded_resps, responses);
}

#[test]
fn counters_snapshot_round_trips_into_atomic_counters()
{
    let src = PacketCounters::default();
    src.total
        .store(50, std::sync::atomic::Ordering::Relaxed);
    src.passed
        .store(40, std::sync::atomic::Ordering::Relaxed);
    src.reassembled
        .store(3, std::sync::atomic::Ordering::Relaxed);
    src.modified
        .store(2, std::sync::atomic::Ordering::Relaxed);
    src.desynced
        .store(5, std::sync::atomic::Ordering::Relaxed);

    let snap = CountersSnapshot::from(&src);
    let dst = PacketCounters::default();
    snap.store_into(&dst);
    assert_eq!(dst.snapshot(), (50, 40, 3, 2, 5));
}

#[test]
fn oversized_line_and_malformed_json_return_typed_errors()
{
    let huge = format!("{{\"op\":\"status\",\"pad\":\"{}\"}}\n", "a".repeat(MAX_CONTROL_LINE_BYTES + 128));
    let mut reader = Cursor::new(huge.as_bytes());
    let err = read_message::<_, Request>(&mut reader).expect_err("oversized line must fail");
    assert!(matches!(err, CodecError::LineTooLong { max } if max == MAX_CONTROL_LINE_BYTES));

    let too_long_encode =
        Response::Ack { op: "test".to_owned(), message: Some("x".repeat(MAX_CONTROL_LINE_BYTES + 64)) };
    let enc_err = encode_line(&too_long_encode).expect_err("oversized encode must fail");
    assert!(matches!(enc_err, CodecError::LineTooLong { .. }));

    let mut bad_json = Cursor::new(b"{not json at all\n".as_slice());
    let json_err = read_message::<_, Request>(&mut bad_json).expect_err("malformed json must fail");
    assert!(matches!(json_err, CodecError::Json(_)));

    let mut empty = Cursor::new(b"".as_slice());
    assert!(
        read_bounded_line(&mut empty, MAX_CONTROL_LINE_BYTES)
            .expect("eof")
            .is_none()
    );
}

#[test]
fn unknown_protocol_version_is_reported_distinctly()
{
    assert!(validate_protocol_version(CONTROL_PROTOCOL_VERSION).is_ok());
    let err = validate_protocol_version(CONTROL_PROTOCOL_VERSION + 7).expect_err("unknown version must fail");
    assert!(matches!(
        err,
        CodecError::UnsupportedVersion {
            expected: CONTROL_PROTOCOL_VERSION,
            got
        } if got == CONTROL_PROTOCOL_VERSION + 7
    ));
}
