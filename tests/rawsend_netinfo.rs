//! Integration tests for kernel source-IP route lookup, `get_ifaddrs`, and `PacketSender` / `RawSender`.
#![cfg(target_os = "linux")]

/// Standard IP address types for loopback route and interface assertions.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Raw send error type and network topology / raw socket sender APIs.
use zapret_rs::rawsend::{PacketSender, RawSendError, RawSender, get_ifaddrs, get_source_ip};

/// In-memory mock sender recording calls to `PacketSender::send` and `send_repeat`.
#[derive(Default)]
struct RecordingSender
{
    /// Captured `(dst, fwmark, ifout, packet)` records.
    sent: Vec<(IpAddr, u32, Option<String>, Vec<u8>)>,
}

impl PacketSender for RecordingSender
{
    /// Appends each transmitted packet and routing metadata into `self.sent`.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>
    {
        self.sent.push((dst, fwmark, ifout.map(str::to_owned), packet.to_vec()));
        Ok(())
    }
}

/// Verifies `get_source_ip` returns loopback addresses for `127.0.0.1` and (when routed) `::1`.
#[test]
fn get_source_ip_resolves_loopback_addresses()
{
    let v4_target = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert_eq!(get_source_ip(v4_target), Some(v4_target));

    let v6_target = IpAddr::V6(Ipv6Addr::LOCALHOST);
    if let Some(src6) = get_source_ip(v6_target)
    {
        assert_eq!(src6, v6_target);
    }
}

/// Verifies `get_ifaddrs` discovers the loopback interface `"lo"` with an index and `127.0.0.1`.
#[test]
fn get_ifaddrs_enumerates_loopback_interface()
{
    let ifaces = get_ifaddrs().expect("get_ifaddrs should succeed on Linux");
    assert!(!ifaces.is_empty());

    let lo =
        ifaces.iter().find(|iface| iface.name == "lo").expect("loopback interface `lo` should be present");
    assert!(lo.index.is_some());
    assert!(
        lo.addrs.iter().any(|addr| addr.addr == IpAddr::V4(Ipv4Addr::LOCALHOST)),
        "loopback should carry 127.0.0.1"
    );
}

/// Verifies `RawSender` construction and default `PacketSender::send_repeat` repetition behavior.
#[test]
fn raw_sender_constructs_and_send_repeat_forwards_n_times()
{
    let _sender = RawSender::new(true, true);

    let mut mock = RecordingSender::default();
    let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    mock.send_repeat(3, dst, 0x4000_0001, Some("eth0"), b"pkt").expect("mock send_repeat should succeed");

    assert_eq!(mock.sent.len(), 3);
    for entry in &mock.sent
    {
        assert_eq!(entry.0, dst);
        assert_eq!(entry.1, 0x4000_0001);
        assert_eq!(entry.2.as_deref(), Some("eth0"));
        assert_eq!(entry.3, b"pkt");
    }
}
