//! L7 protocol probe tables and stateful TCP/UDP classification helpers.

/// Interior mutability for recording discovered `l7proto` on [`CtrackEntry`].
use std::cell::RefCell;
/// Single-thread reference counting for shared [`CtrackEntry`] handles.
use std::rc::Rc;

/// Classified L7 protocol and payload tags checked against `--payload-disable`.
use crate::config::{L7Payload, L7Proto, l7_payload_matches};
/// Conntrack record and directional positions for MTProto first-data detection.
use crate::conntrack::{CtrackEntry, CtrackPositions};
/// Stateless TCP and UDP L7 classifiers ported in Task 3.2.
use crate::protocol::{
    is_bt_handshake, is_dht, is_discord_ip_discovery_request, is_dns_query, is_dns_response,
    is_dtls_client_hello, is_dtls_server_hello, is_http, is_http_reply, is_mtproto, is_quic_initial,
    is_stun_message, is_tls_client_hello_partial, is_tls_server_hello_partial, is_utp_bt_handshake,
    is_wireguard_data, is_wireguard_handshake_cookie, is_wireguard_handshake_initiation,
    is_wireguard_handshake_response, is_wireguard_keepalive, is_xmpp_features, is_xmpp_proceed_tls,
    is_xmpp_starttls, is_xmpp_stream,
};

/// One table row mapping a payload detector predicate to its [`L7Payload`] and [`L7Proto`].
struct ProtocolProbe
{
    /// Expected classified payload variant when `check` succeeds.
    l7p: L7Payload,
    /// Protocol group associated with `l7p`.
    l7: L7Proto,
    /// Packet payload matcher predicate.
    check: fn(&[u8]) -> bool,
    /// When `true`, only test this probe if flow `l7proto` already equals `l7` (e.g., WireGuard data).
    l7match: bool,
}

/// Outgoing client-to-server TCP L7 probe table (`dpi_desync_tcp_packet_play`).
const TCP_OUT_PROBES: &[ProtocolProbe] = &[
    ProtocolProbe {
        l7p: L7Payload::TlsClientHello,
        l7: L7Proto::Tls,
        check: is_tls_client_hello_partial,
        l7match: false,
    },
    ProtocolProbe { l7p: L7Payload::HttpReq, l7: L7Proto::Http, check: is_http, l7match: false },
    ProtocolProbe { l7p: L7Payload::XmppStream, l7: L7Proto::Xmpp, check: is_xmpp_stream, l7match: false },
    ProtocolProbe {
        l7p: L7Payload::XmppStarttls,
        l7: L7Proto::Xmpp,
        check: is_xmpp_starttls,
        l7match: false,
    },
    ProtocolProbe { l7p: L7Payload::BtHandshake, l7: L7Proto::Bt, check: is_bt_handshake, l7match: false },
];

/// Incoming server-to-client TCP L7 probe table (`dpi_desync_tcp_packet_play`).
const TCP_IN_PROBES: &[ProtocolProbe] = &[
    ProtocolProbe {
        l7p: L7Payload::TlsServerHello,
        l7: L7Proto::Tls,
        check: is_tls_server_hello_partial,
        l7match: false,
    },
    ProtocolProbe { l7p: L7Payload::HttpReply, l7: L7Proto::Http, check: is_http_reply, l7match: false },
    ProtocolProbe { l7p: L7Payload::XmppStream, l7: L7Proto::Xmpp, check: is_xmpp_stream, l7match: false },
    ProtocolProbe {
        l7p: L7Payload::XmppProceed,
        l7: L7Proto::Xmpp,
        check: is_xmpp_proceed_tls,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::XmppFeatures,
        l7: L7Proto::Xmpp,
        check: is_xmpp_features,
        l7match: false,
    },
    ProtocolProbe { l7p: L7Payload::BtHandshake, l7: L7Proto::Bt, check: is_bt_handshake, l7match: false },
];

/// First-data-packet MTProto TCP probe (`is_mtproto` runs only at `seq_last - seq0 == 1`).
const MTPROTO_PROBE: &[ProtocolProbe] = &[ProtocolProbe {
    l7p: L7Payload::MtprotoInitial,
    l7: L7Proto::Mtproto,
    check: is_mtproto,
    l7match: false,
}];

/// Standard bidirectional UDP L7 probe table (`udp_standard_protocol_probe`).
const UDP_PROBES: &[ProtocolProbe] = &[
    ProtocolProbe { l7p: L7Payload::QuicInitial, l7: L7Proto::Quic, check: is_quic_initial, l7match: false },
    ProtocolProbe {
        l7p: L7Payload::DiscordIpDiscovery,
        l7: L7Proto::Discord,
        check: is_discord_ip_discovery_request,
        l7match: false,
    },
    ProtocolProbe { l7p: L7Payload::Stun, l7: L7Proto::Stun, check: is_stun_message, l7match: false },
    ProtocolProbe { l7p: L7Payload::DnsQuery, l7: L7Proto::Dns, check: is_dns_query, l7match: false },
    ProtocolProbe { l7p: L7Payload::DnsResponse, l7: L7Proto::Dns, check: is_dns_response, l7match: false },
    ProtocolProbe { l7p: L7Payload::Dht, l7: L7Proto::Dht, check: is_dht, l7match: false },
    ProtocolProbe {
        l7p: L7Payload::DtlsClientHello,
        l7: L7Proto::Dtls,
        check: is_dtls_client_hello,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::DtlsServerHello,
        l7: L7Proto::Dtls,
        check: is_dtls_server_hello,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::UtpBtHandshake,
        l7: L7Proto::UtpBt,
        check: is_utp_bt_handshake,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::WireguardInitiation,
        l7: L7Proto::Wireguard,
        check: is_wireguard_handshake_initiation,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::WireguardResponse,
        l7: L7Proto::Wireguard,
        check: is_wireguard_handshake_response,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::WireguardCookie,
        l7: L7Proto::Wireguard,
        check: is_wireguard_handshake_cookie,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::WireguardKeepalive,
        l7: L7Proto::Wireguard,
        check: is_wireguard_keepalive,
        l7match: false,
    },
    ProtocolProbe {
        l7p: L7Payload::WireguardData,
        l7: L7Proto::Wireguard,
        check: is_wireguard_data,
        l7match: true,
    },
];

/// Runs a probe table respecting `payload_disable` and updates `l7proto`, `l7payload`, and `ctrack`.
fn run_probes(
    probes: &[ProtocolProbe],
    payload: &[u8],
    payload_disable: u64,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    l7proto: &mut L7Proto,
    l7payload: &mut L7Payload,
)
{
    for probe in probes
    {
        if !l7_payload_matches(probe.l7p, payload_disable)
            && (!probe.l7match || *l7proto == probe.l7)
            && (probe.check)(payload)
        {
            *l7payload = probe.l7p;
            if *l7proto == L7Proto::Unknown
            {
                *l7proto = probe.l7;
                if let Some(entry_rc) = ctrack
                {
                    entry_rc
                        .borrow_mut()
                        .l7proto = probe.l7;
                }
            }
            break;
        }
    }
}

/// Classifies server-to-client TCP payload bytes (`ps.b_reverse == true`).
pub(crate) fn probe_tcp_incoming(
    payload: &[u8],
    payload_disable: u64,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    l7proto: &mut L7Proto,
    l7payload: &mut L7Payload,
)
{
    run_probes(TCP_IN_PROBES, payload, payload_disable, ctrack, l7proto, l7payload);
}

/// Classifies client-to-server TCP payload bytes including first-packet MTProto fallback.
pub(crate) fn probe_tcp_outgoing(
    payload: &[u8],
    payload_disable: u64,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    tpos: Option<&CtrackPositions>,
    l7proto: &mut L7Proto,
    l7payload: &mut L7Payload,
)
{
    run_probes(TCP_OUT_PROBES, payload, payload_disable, ctrack, l7proto, l7payload);
    if *l7payload == L7Payload::Unknown
        && tpos.is_some_and(|p| {
            p.client
                .seq_last
                .wrapping_sub(
                    p.client
                        .seq0,
                )
                == 1
        })
    {
        run_probes(MTPROTO_PROBE, payload, payload_disable, ctrack, l7proto, l7payload);
    }
}

/// Classifies bidirectional UDP datagram payloads (`udp_standard_protocol_probe`).
pub(crate) fn probe_udp(
    payload: &[u8],
    payload_disable: u64,
    ctrack: Option<&Rc<RefCell<CtrackEntry>>>,
    l7proto: &mut L7Proto,
    l7payload: &mut L7Payload,
)
{
    run_probes(UDP_PROBES, payload, payload_disable, ctrack, l7proto, l7payload);
}
