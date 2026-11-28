//! Unit and CLI tests for OS DNS/DoH preset parsing, platform parser helpers, and `dns` multicall routing.

/// DNS preset, parser helpers, and multicall router under test.
use zapret_rs::tools::dns::{
    DnsPreset, parse_linux_default_iface, parse_resolv_conf_servers, parse_windows_connected_interfaces,
};
use zapret_rs::tools::{MulticallApplet, resolve_multicall};

/// Asserts `DnsPreset` cycling order, CLI round-trips, and DoH template invariants.
fn assert_dns_preset_cycle()
{
    let mut p = DnsPreset::Cloudflare;
    for expected in DnsPreset::ALL
    {
        assert_eq!(p, expected);
        assert_eq!(DnsPreset::from_name(p.cli_name()), Some(p));
        if p == DnsPreset::Auto
        {
            assert!(
                p.ipv4_servers()
                    .is_none()
                    && p.doh_template()
                        .is_none()
            );
        }
        else
        {
            assert!(
                p.ipv4_servers()
                    .is_some()
                    && p.doh_template()
                        .is_some_and(|t| t.starts_with("https://"))
            );
        }
        p = p.next();
    }
    assert_eq!(p, DnsPreset::Cloudflare);
}

#[test]
fn dns_presets_parse_cycle_and_expose_doh_templates()
{
    for (name, expected) in [
        ("cloudflare", Some(DnsPreset::Cloudflare)),
        ("1.1.1.1", Some(DnsPreset::Cloudflare)),
        ("Google", Some(DnsPreset::Google)),
        ("quad9", Some(DnsPreset::Quad9)),
        ("adguard", Some(DnsPreset::AdGuard)),
        ("auto", Some(DnsPreset::Auto)),
        ("dhcp", Some(DnsPreset::Auto)),
        ("unknown", None),
    ]
    {
        assert_eq!(DnsPreset::from_name(name), expected);
    }

    assert_dns_preset_cycle();
}

#[test]
fn dns_platform_parsers_extract_interfaces_and_servers()
{
    let route = "\
Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0
wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0
";
    assert_eq!(parse_linux_default_iface(route).as_deref(), Some("wlan0"));

    let resolv = "# comment\nnameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch lan\n";
    assert_eq!(parse_resolv_conf_servers(resolv), vec!["1.1.1.1", "8.8.8.8"]);

    let netsh = "\
Admin State    State          Type             Interface Name
-------------------------------------------------------------------------
Enabled        Disconnected   Dedicated        Ethernet
Enabled        Connected      Dedicated        Wi-Fi
Enabled        Connected      Dedicated        Ethernet 2
";
    assert_eq!(parse_windows_connected_interfaces(netsh), vec!["Wi-Fi", "Ethernet 2"]);
}

#[test]
fn multicall_routes_dns_subcommand()
{
    let (applet, args) = resolve_multicall(["zapret-rs", "dns", "status"]);
    assert_eq!(applet, MulticallApplet::Dns);
    assert_eq!(args.len(), 2);
    assert_eq!(args[1], "status");
}
