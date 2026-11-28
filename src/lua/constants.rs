//! Security hardening and global constant registration for the `zapret2`-compatible LuaJIT state.

/// Core `mlua` types for global table mutation.
use mlua::{Lua, Table, Value};

/// Application runtime configuration and default Lua GC interval mapped into [`LuaConfig`].
use crate::config::{AppConfig, DEFAULT_LUA_GC_INTERVAL};
/// Typed configuration errors are unnecessary here; conntrack timeouts flow directly into Lua state.
use crate::conntrack::ConntrackTimeouts;
/// Protocol, queue/fwmark defaults, verdict, flag, and compatibility constants.
use crate::packet::constants::{
    DEFAULT_DESYNC_FWMARK, DEFAULT_MSS, DEFAULT_QUEUE_NUM, ICMP_BASE_LEN, ICMP_DEST_UNREACH, ICMP_ECHO,
    ICMP_ECHOREPLY, ICMP_INFO_REPLY, ICMP_INFO_REQUEST, ICMP_PARAMETERPROB, ICMP_REDIRECT,
    ICMP_REDIRECT_HOST, ICMP_REDIRECT_NET, ICMP_REDIRECT_TOSHOST, ICMP_REDIRECT_TOSNET, ICMP_TIME_EXCEEDED,
    ICMP_TIMESTAMP, ICMP_TIMESTAMPREPLY, ICMP_TIMXCEED_INTRANS, ICMP_TIMXCEED_REASS,
    ICMP_UNREACH_FILTER_PROHIB, ICMP_UNREACH_HOST, ICMP_UNREACH_HOST_PRECEDENCE, ICMP_UNREACH_HOST_PROHIB,
    ICMP_UNREACH_HOST_UNKNOWN, ICMP_UNREACH_NEEDFRAG, ICMP_UNREACH_NET, ICMP_UNREACH_NET_PROHIB,
    ICMP_UNREACH_NET_UNKNOWN, ICMP_UNREACH_PORT, ICMP_UNREACH_PRECEDENCE_CUTOFF, ICMP_UNREACH_PROTOCOL,
    ICMP_UNREACH_SRCFAIL, ICMP_UNREACH_TOSHOST, ICMP_UNREACH_TOSNET, ICMP6_DST_UNREACH,
    ICMP6_DST_UNREACH_ADDR, ICMP6_DST_UNREACH_ADMIN, ICMP6_DST_UNREACH_BEYONDSCOPE, ICMP6_DST_UNREACH_NOPORT,
    ICMP6_DST_UNREACH_NOROUTE, ICMP6_ECHO_REPLY, ICMP6_ECHO_REQUEST, ICMP6_PACKET_TOO_BIG, ICMP6_PARAM_PROB,
    ICMP6_PARAMPROB_HEADER, ICMP6_PARAMPROB_NEXTHEADER, ICMP6_PARAMPROB_OPTION, ICMP6_TIME_EXCEED_REASSEMBLY,
    ICMP6_TIME_EXCEED_TRANSIT, ICMP6_TIME_EXCEEDED, IP_BASE_LEN, IP_DF, IP_FLAGMASK, IP_MF, IP_OFFMASK,
    IP_RF, IP6_BASE_LEN, IP6F_MORE_FRAG, IPPROTO_AH, IPPROTO_DSTOPTS, IPPROTO_ESP, IPPROTO_FRAGMENT,
    IPPROTO_HIP, IPPROTO_HOPOPTS, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_IPIP, IPPROTO_IPV6,
    IPPROTO_MH, IPPROTO_NONE, IPPROTO_ROUTING, IPPROTO_SCTP, IPPROTO_SHIM6, IPPROTO_TCP, IPPROTO_UDP,
    IPTOS_DSCP_MASK, IPTOS_ECN_CE, IPTOS_ECN_ECT0, IPTOS_ECN_ECT1, IPTOS_ECN_MASK, IPTOS_ECN_NOT_ECT,
    IPV6_FLOWINFO_MASK, IPV6_FLOWLABEL_MASK, LUA_COMPAT_VER, MLD_LISTENER_QUERY, MLD_LISTENER_REDUCTION,
    MLD_LISTENER_REPORT, ND_NEIGHBOR_ADVERT, ND_NEIGHBOR_SOLICIT, ND_REDIRECT, ND_ROUTER_ADVERT,
    ND_ROUTER_SOLICIT, TCP_BASE_LEN, TCP_KIND_AO, TCP_KIND_END, TCP_KIND_FASTOPEN, TCP_KIND_MD5,
    TCP_KIND_MSS, TCP_KIND_NOOP, TCP_KIND_SACK, TCP_KIND_SACK_PERM, TCP_KIND_SCALE, TCP_KIND_TS, TH_ACK,
    TH_CWR, TH_ECE, TH_FIN, TH_PUSH, TH_RST, TH_SYN, TH_URG, UDP_BASE_LEN, VERDICT_DROP, VERDICT_MASK,
    VERDICT_MODIFY, VERDICT_PASS, VERDICT_PRESERVE_NEXT,
};

/// Runtime boolean and queue parameters exposed as Lua globals.
#[derive(Debug, Clone)]
pub struct LuaConfig
{
    /// Version string bound to `NFQWS2_VER`.
    pub verstr: String,
    /// Netfilter queue number bound to `qnum`.
    pub qnum: u32,
    /// Desync firewall mark bound to `desync_fwmark`.
    pub desync_fwmark: u32,
    /// Enable `SO_BINDTODEVICE` routing fixup for IPv4 raw sends.
    pub bind_fix4: bool,
    /// Enable `SO_BINDTODEVICE` routing fixup for IPv6 raw sends.
    pub bind_fix6: bool,
    /// Verbose debug logging flag (`b_debug`).
    pub debug: bool,
    /// Daemon mode flag (`b_daemon`).
    pub daemon: bool,
    /// Server-mode direction flag (`b_server`).
    pub server: bool,
    /// Hostname caching flag (`b_ipcache_hostname`).
    pub cache_hostname: bool,
    /// Conntrack disabled flag (`b_ctrack_disable`).
    pub ctrack_disable: bool,
    /// Idle timeouts and purge cadence for the built-in conntrack table.
    pub ctrack_timeouts: ConntrackTimeouts,
    /// Forced garbage collection interval in seconds (0 = disabled).
    pub lua_gc_sec: u64,
}

impl Default for LuaConfig
{
    /// Returns sensible Linux runtime defaults matching `zapret2`'s default `params_s`.
    fn default() -> Self
    {
        Self {
            verstr: env!("CARGO_PKG_VERSION").to_owned(),
            qnum: u32::from(DEFAULT_QUEUE_NUM),
            desync_fwmark: DEFAULT_DESYNC_FWMARK,
            bind_fix4: false,
            bind_fix6: false,
            debug: false,
            daemon: false,
            server: false,
            cache_hostname: false,
            ctrack_disable: false,
            ctrack_timeouts: ConntrackTimeouts::default(),
            lua_gc_sec: DEFAULT_LUA_GC_INTERVAL,
        }
    }
}

impl From<&AppConfig> for LuaConfig
{
    /// Derives [`LuaConfig`] settings for `LuaRuntime::new` from resolved [`AppConfig`].
    fn from(config: &AppConfig) -> Self
    {
        Self {
            qnum: u32::from(config.qnum),
            desync_fwmark: config.fwmark,
            bind_fix4: config.bind_fix4,
            bind_fix6: config.bind_fix6,
            debug: config.debug,
            daemon: config.daemon,
            server: config.server,
            cache_hostname: config.ipcache.hostname,
            ctrack_disable: config.conntrack.disable,
            ctrack_timeouts: config.conntrack.timeouts,
            lua_gc_sec: config.lua_gc,
            ..Self::default()
        }
    }
}

/// Removes dangerous OS command/FFI/debug primitives (`os.execute`, `io.popen`, `package.loadlib`, `debug`)
/// matching `lua_sec_harden` in `zapret2/nfq2/lua.c`.
pub fn harden_lua(lua: &Lua) -> mlua::Result<()>
{
    let globals = lua.globals();

    if let Some(os_tbl) = globals.get::<Option<Table>>("os")?
    {
        os_tbl.set("execute", Value::Nil)?;
    }
    if let Some(io_tbl) = globals.get::<Option<Table>>("io")?
    {
        io_tbl.set("popen", Value::Nil)?;
    }
    if let Some(pkg_tbl) = globals.get::<Option<Table>>("package")?
    {
        pkg_tbl.set("loadlib", Value::Nil)?;
        if let Some(loaded) = pkg_tbl.get::<Option<Table>>("loaded")?
        {
            loaded.set("debug", Value::Nil)?;
        }
    }
    globals.set("debug", Value::Nil)?;

    Ok(())
}

/// Populates all numeric, string, and boolean global constants expected by `zapret-lib.lua` and user scripts.
pub fn register_constants(lua: &Lua, config: &LuaConfig) -> mlua::Result<()>
{
    let globals = lua.globals();

    globals.set("NFQWS2_VER", config.verstr.as_str())?;

    let uint_constants: &[(&str, i64)] = &[
        ("qnum", i64::from(config.qnum)),
        ("desync_fwmark", i64::from(config.desync_fwmark)),
        ("NFQWS2_COMPAT_VER", i64::from(LUA_COMPAT_VER)),
        ("VERDICT_PASS", i64::from(VERDICT_PASS)),
        ("VERDICT_MODIFY", i64::from(VERDICT_MODIFY)),
        ("VERDICT_DROP", i64::from(VERDICT_DROP)),
        ("VERDICT_MASK", i64::from(VERDICT_MASK)),
        ("VERDICT_PRESERVE_NEXT", i64::from(VERDICT_PRESERVE_NEXT)),
        ("DEFAULT_MSS", i64::from(DEFAULT_MSS)),
        ("IP_BASE_LEN", IP_BASE_LEN as i64),
        ("IP6_BASE_LEN", IP6_BASE_LEN as i64),
        ("TCP_BASE_LEN", TCP_BASE_LEN as i64),
        ("UDP_BASE_LEN", UDP_BASE_LEN as i64),
        ("ICMP_BASE_LEN", ICMP_BASE_LEN as i64),
        ("TCP_KIND_END", i64::from(TCP_KIND_END)),
        ("TCP_KIND_NOOP", i64::from(TCP_KIND_NOOP)),
        ("TCP_KIND_MSS", i64::from(TCP_KIND_MSS)),
        ("TCP_KIND_SCALE", i64::from(TCP_KIND_SCALE)),
        ("TCP_KIND_SACK_PERM", i64::from(TCP_KIND_SACK_PERM)),
        ("TCP_KIND_SACK", i64::from(TCP_KIND_SACK)),
        ("TCP_KIND_TS", i64::from(TCP_KIND_TS)),
        ("TCP_KIND_MD5", i64::from(TCP_KIND_MD5)),
        ("TCP_KIND_AO", i64::from(TCP_KIND_AO)),
        ("TCP_KIND_FASTOPEN", i64::from(TCP_KIND_FASTOPEN)),
        ("TH_FIN", i64::from(TH_FIN)),
        ("TH_SYN", i64::from(TH_SYN)),
        ("TH_RST", i64::from(TH_RST)),
        ("TH_PUSH", i64::from(TH_PUSH)),
        ("TH_ACK", i64::from(TH_ACK)),
        ("TH_URG", i64::from(TH_URG)),
        ("TH_ECE", i64::from(TH_ECE)),
        ("TH_CWR", i64::from(TH_CWR)),
        ("IP_RF", i64::from(IP_RF)),
        ("IP_DF", i64::from(IP_DF)),
        ("IP_MF", i64::from(IP_MF)),
        ("IP_OFFMASK", i64::from(IP_OFFMASK)),
        ("IP_FLAGMASK", i64::from(IP_FLAGMASK)),
        ("IPTOS_ECN_MASK", i64::from(IPTOS_ECN_MASK)),
        ("IPTOS_ECN_NOT_ECT", i64::from(IPTOS_ECN_NOT_ECT)),
        ("IPTOS_ECN_ECT1", i64::from(IPTOS_ECN_ECT1)),
        ("IPTOS_ECN_ECT0", i64::from(IPTOS_ECN_ECT0)),
        ("IPTOS_ECN_CE", i64::from(IPTOS_ECN_CE)),
        ("IPTOS_DSCP_MASK", i64::from(IPTOS_DSCP_MASK)),
        ("IP6F_MORE_FRAG", i64::from(IP6F_MORE_FRAG)),
        ("IPV6_FLOWLABEL_MASK", i64::from(IPV6_FLOWLABEL_MASK)),
        ("IPV6_FLOWINFO_MASK", i64::from(IPV6_FLOWINFO_MASK)),
        ("IPPROTO_IP", i64::from(IPPROTO_IP)),
        ("IPPROTO_IPIP", i64::from(IPPROTO_IPIP)),
        ("IPPROTO_IPV6", i64::from(IPPROTO_IPV6)),
        ("IPPROTO_ICMP", i64::from(IPPROTO_ICMP)),
        ("IPPROTO_TCP", i64::from(IPPROTO_TCP)),
        ("IPPROTO_UDP", i64::from(IPPROTO_UDP)),
        ("IPPROTO_ICMPV6", i64::from(IPPROTO_ICMPV6)),
        ("IPPROTO_SCTP", i64::from(IPPROTO_SCTP)),
        ("IPPROTO_HOPOPTS", i64::from(IPPROTO_HOPOPTS)),
        ("IPPROTO_ROUTING", i64::from(IPPROTO_ROUTING)),
        ("IPPROTO_FRAGMENT", i64::from(IPPROTO_FRAGMENT)),
        ("IPPROTO_AH", i64::from(IPPROTO_AH)),
        ("IPPROTO_ESP", i64::from(IPPROTO_ESP)),
        ("IPPROTO_DSTOPTS", i64::from(IPPROTO_DSTOPTS)),
        ("IPPROTO_MH", i64::from(IPPROTO_MH)),
        ("IPPROTO_HIP", i64::from(IPPROTO_HIP)),
        ("IPPROTO_SHIM6", i64::from(IPPROTO_SHIM6)),
        ("IPPROTO_NONE", i64::from(IPPROTO_NONE)),
        ("ICMP_ECHOREPLY", i64::from(ICMP_ECHOREPLY)),
        ("ICMP_DEST_UNREACH", i64::from(ICMP_DEST_UNREACH)),
        ("ICMP_REDIRECT", i64::from(ICMP_REDIRECT)),
        ("ICMP_ECHO", i64::from(ICMP_ECHO)),
        ("ICMP_TIME_EXCEEDED", i64::from(ICMP_TIME_EXCEEDED)),
        ("ICMP_PARAMETERPROB", i64::from(ICMP_PARAMETERPROB)),
        ("ICMP_TIMESTAMP", i64::from(ICMP_TIMESTAMP)),
        ("ICMP_TIMESTAMPREPLY", i64::from(ICMP_TIMESTAMPREPLY)),
        ("ICMP_INFO_REQUEST", i64::from(ICMP_INFO_REQUEST)),
        ("ICMP_INFO_REPLY", i64::from(ICMP_INFO_REPLY)),
        ("ICMP_UNREACH_NET", i64::from(ICMP_UNREACH_NET)),
        ("ICMP_UNREACH_HOST", i64::from(ICMP_UNREACH_HOST)),
        ("ICMP_UNREACH_PROTOCOL", i64::from(ICMP_UNREACH_PROTOCOL)),
        ("ICMP_UNREACH_PORT", i64::from(ICMP_UNREACH_PORT)),
        ("ICMP_UNREACH_NEEDFRAG", i64::from(ICMP_UNREACH_NEEDFRAG)),
        ("ICMP_UNREACH_SRCFAIL", i64::from(ICMP_UNREACH_SRCFAIL)),
        ("ICMP_UNREACH_NET_UNKNOWN", i64::from(ICMP_UNREACH_NET_UNKNOWN)),
        ("ICMP_UNREACH_HOST_UNKNOWN", i64::from(ICMP_UNREACH_HOST_UNKNOWN)),
        ("ICMP_UNREACH_NET_PROHIB", i64::from(ICMP_UNREACH_NET_PROHIB)),
        ("ICMP_UNREACH_HOST_PROHIB", i64::from(ICMP_UNREACH_HOST_PROHIB)),
        ("ICMP_UNREACH_TOSNET", i64::from(ICMP_UNREACH_TOSNET)),
        ("ICMP_UNREACH_TOSHOST", i64::from(ICMP_UNREACH_TOSHOST)),
        ("ICMP_UNREACH_FILTER_PROHIB", i64::from(ICMP_UNREACH_FILTER_PROHIB)),
        ("ICMP_UNREACH_HOST_PRECEDENCE", i64::from(ICMP_UNREACH_HOST_PRECEDENCE)),
        ("ICMP_UNREACH_PRECEDENCE_CUTOFF", i64::from(ICMP_UNREACH_PRECEDENCE_CUTOFF)),
        ("ICMP_REDIRECT_NET", i64::from(ICMP_REDIRECT_NET)),
        ("ICMP_REDIRECT_HOST", i64::from(ICMP_REDIRECT_HOST)),
        ("ICMP_REDIRECT_TOSNET", i64::from(ICMP_REDIRECT_TOSNET)),
        ("ICMP_REDIRECT_TOSHOST", i64::from(ICMP_REDIRECT_TOSHOST)),
        ("ICMP_TIMXCEED_INTRANS", i64::from(ICMP_TIMXCEED_INTRANS)),
        ("ICMP_TIMXCEED_REASS", i64::from(ICMP_TIMXCEED_REASS)),
        ("ICMP6_ECHO_REQUEST", i64::from(ICMP6_ECHO_REQUEST)),
        ("ICMP6_ECHO_REPLY", i64::from(ICMP6_ECHO_REPLY)),
        ("ICMP6_DST_UNREACH", i64::from(ICMP6_DST_UNREACH)),
        ("ICMP6_PACKET_TOO_BIG", i64::from(ICMP6_PACKET_TOO_BIG)),
        ("ICMP6_TIME_EXCEEDED", i64::from(ICMP6_TIME_EXCEEDED)),
        ("ICMP6_PARAM_PROB", i64::from(ICMP6_PARAM_PROB)),
        ("MLD_LISTENER_QUERY", i64::from(MLD_LISTENER_QUERY)),
        ("MLD_LISTENER_REPORT", i64::from(MLD_LISTENER_REPORT)),
        ("MLD_LISTENER_REDUCTION", i64::from(MLD_LISTENER_REDUCTION)),
        ("ND_ROUTER_SOLICIT", i64::from(ND_ROUTER_SOLICIT)),
        ("ND_ROUTER_ADVERT", i64::from(ND_ROUTER_ADVERT)),
        ("ND_NEIGHBOR_SOLICIT", i64::from(ND_NEIGHBOR_SOLICIT)),
        ("ND_NEIGHBOR_ADVERT", i64::from(ND_NEIGHBOR_ADVERT)),
        ("ND_REDIRECT", i64::from(ND_REDIRECT)),
        ("ICMP6_DST_UNREACH_NOROUTE", i64::from(ICMP6_DST_UNREACH_NOROUTE)),
        ("ICMP6_DST_UNREACH_ADMIN", i64::from(ICMP6_DST_UNREACH_ADMIN)),
        ("ICMP6_DST_UNREACH_BEYONDSCOPE", i64::from(ICMP6_DST_UNREACH_BEYONDSCOPE)),
        ("ICMP6_DST_UNREACH_ADDR", i64::from(ICMP6_DST_UNREACH_ADDR)),
        ("ICMP6_DST_UNREACH_NOPORT", i64::from(ICMP6_DST_UNREACH_NOPORT)),
        ("ICMP6_TIME_EXCEED_TRANSIT", i64::from(ICMP6_TIME_EXCEED_TRANSIT)),
        ("ICMP6_TIME_EXCEED_REASSEMBLY", i64::from(ICMP6_TIME_EXCEED_REASSEMBLY)),
        ("ICMP6_PARAMPROB_HEADER", i64::from(ICMP6_PARAMPROB_HEADER)),
        ("ICMP6_PARAMPROB_NEXTHEADER", i64::from(ICMP6_PARAMPROB_NEXTHEADER)),
        ("ICMP6_PARAMPROB_OPTION", i64::from(ICMP6_PARAMPROB_OPTION)),
    ];

    for &(name, value) in uint_constants
    {
        globals.set(name, value)?;
    }

    let bool_constants: &[(&str, bool)] = &[
        ("b_debug", config.debug),
        ("b_daemon", config.daemon),
        ("b_server", config.server),
        ("b_ipcache_hostname", config.cache_hostname),
        ("b_ctrack_disable", config.ctrack_disable),
    ];

    for &(name, value) in bool_constants
    {
        globals.set(name, value)?;
    }

    Ok(())
}
