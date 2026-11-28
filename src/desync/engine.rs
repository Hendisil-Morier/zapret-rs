//! Core stateful DPI desync engine dispatching intercepted packets through profiles and Lua actions.

/// Interior mutability for sharing [`PacketSender`] and rate-limited `IpCache`.
use std::cell::RefCell;
/// Optional autohostlist debug log path stored on the engine.
use std::path::PathBuf;
/// Single-thread reference counting for profile snapshots and packet senders.
use std::rc::Rc;

/// Profile definitions loaded into runtime structures and Lua validation.
use crate::config::{AppConfig, DesyncProfile};
/// Optional non-blocking background active DPI confirmation worker.
use crate::desync::auto_confirm::AutoConfirmWorker;
/// ICMP and non-TCP/UDP/ICMP raw IP packet processors.
use crate::desync::icmp_ip::{process_icmp_packet, process_raw_ip_packet};
/// Shared prolog state, replay metadata, packet outcome tag, and borrowed runtime services.
use crate::desync::play::{EngineServices, PacketOutcome, PlayState, ReplayContext};
/// Verdict aggregation, gate evaluation, Lua verdict decoding, context guards, and cutoff checks.
use crate::desync::profile_exec::{ProfileRunInput, execute_profile_run};
/// Deduplicated file registry, per-profile runtime hostlist/ipset state, and profile hot-swap.
use crate::desync::profile_state::{ListRegistry, ProfileRuntime, build_swapped_profiles};
/// Stateful TCP DPI desync processor (`process_tcp_packet`).
use crate::desync::tcp::process_tcp_packet;
/// Stateful UDP DPI desync processor (`process_udp_packet`).
use crate::desync::udp::process_udp_packet;
/// Cutoff predicates and stream-position extraction helper for profile execution.
use crate::desync::verdict::{all_actions_cut_off, any_action_runnable, extract_pos_for_side};
/// Intercepted packet metadata and kernel verdict decision enum.
use crate::intercepter::{Decision, QueuedPacket};
/// Global IP-to-hostname and incoming-TTL cache (`ip_cache`).
use crate::lists::IpCache;
/// Lua runtime, configuration, and engine error enum.
use crate::lua::{LuaConfig, LuaEngineError, LuaRuntime};
/// Dissected packet view and L3/L4 wire parser.
use crate::packet::{DissectedPacket, dissect_packet};
/// Abstract packet sender trait.
use crate::rawsend::PacketSender;
/// Real Linux raw socket packet sender implementation.
#[cfg(target_os = "linux")]
use crate::rawsend::RawSender;
/// Windows WinDivert raw packet injector implementation.
#[cfg(windows)]
use crate::rawsend::WinDivertSender;
/// Monotonic boottime clock queried once per dispatched packet.
use crate::timer::{MonotonicTime, boottime_now};

/// Orchestrates packet dissection, stateful conntrack, L7 probes, list matching, and Lua desync.
pub struct DesyncEngine
{
    /// Embedded LuaJIT runtime preloaded with blobs, startup scripts, and bindings.
    runtime: LuaRuntime,
    /// Shared raw packet transmitter used by Lua callbacks, delayed flushes, replay, and RSTs.
    pub(crate) sender: Rc<RefCell<dyn PacketSender>>,
    /// Ordered active profiles copied from [`AppConfig`] and wrapped in `Rc` for `execution_plan`.
    pub(crate) profiles: Vec<Rc<DesyncProfile>>,
    /// Per-profile instantiated hostlists, autohostlists, ipsets, and failure counters.
    pub(crate) profile_runtimes: Vec<ProfileRuntime>,
    /// Deduplicated filesystem list handles supporting `SIGHUP` `reload_lists()`.
    list_registry: ListRegistry,
    /// Global time-expiring IP-to-hostname and incoming-TTL cache.
    pub(crate) ipcache: RefCell<IpCache>,
    /// Server-mode direction flag (`--server`).
    pub(crate) server: bool,
    /// Enable diagnostic debug output to standard error.
    pub(crate) debug: bool,
    /// Desync firewall mark OR'd onto delayed/replayed outgoing sends (`params.desync_fwmark`).
    pub(crate) desync_fwmark: u32,
    /// Bitmask of L7 payloads excluded from discovery (`--payload-disable`).
    pub(crate) payload_disable: u64,
    /// Bitmask of L7 payloads excluded from client-side reassembly (`--reasm-disable`).
    pub(crate) reasm_disable: u64,
    /// Optional debug log file appended on autohostlist failure events.
    pub(crate) hostlist_auto_debug: Option<PathBuf>,
    /// High-level outcome recorded for the most recent packet (`Pass`, `Reasm`, `Modify`, `Desync`).
    pub(crate) last_outcome: RefCell<PacketOutcome>,
    /// Optional non-blocking background active confirmation worker when any profile sets `confirm_block`.
    auto_confirm: Option<AutoConfirmWorker>,
}

impl DesyncEngine
{
    /// Constructs a [`DesyncEngine`] using a real Linux `RawSender`.
    #[cfg(target_os = "linux")]
    pub fn new(config: &AppConfig) -> Result<Self, LuaEngineError>
    {
        let sender: Rc<RefCell<dyn PacketSender>> =
            Rc::new(RefCell::new(RawSender::new(config.bind_fix4, config.bind_fix6)));
        Self::with_sender(config, sender)
    }

    /// Constructs a [`DesyncEngine`] using a Windows `WinDivertSender`.
    #[cfg(windows)]
    pub fn new(config: &AppConfig) -> Result<Self, LuaEngineError>
    {
        let sender: Rc<RefCell<dyn PacketSender>> = Rc::new(RefCell::new(WinDivertSender::new()));
        Self::with_sender(config, sender)
    }

    /// Constructs a [`DesyncEngine`] using a caller-supplied [`PacketSender`] (e.g., mock sender in tests).
    pub fn with_sender(
        config: &AppConfig,
        sender: Rc<RefCell<dyn PacketSender>>,
    ) -> Result<Self, LuaEngineError>
    {
        let runtime = LuaRuntime::with_sender(LuaConfig::from(config), Rc::clone(&sender))?;
        Self::from_runtime(runtime, sender, config)
    }

    /// Shared initialization helper loading blobs, scripts, lists, and validating all profile actions.
    fn from_runtime(
        runtime: LuaRuntime,
        sender: Rc<RefCell<dyn PacketSender>>,
        config: &AppConfig,
    ) -> Result<Self, LuaEngineError>
    {
        runtime.apply_app_config(config)?;
        let (list_registry, profile_runtimes) =
            ListRegistry::load_from_config(config).map_err(|(_, err)| LuaEngineError::Io(err))?;
        let profiles: Vec<Rc<DesyncProfile>> = config
            .profiles
            .iter()
            .cloned()
            .map(Rc::new)
            .collect();
        let ipcache = RefCell::new(IpCache::new(
            i64::from(
                config
                    .ipcache
                    .lifetime_sec,
            ),
            config
                .ipcache
                .hostname,
        ));
        let auto_confirm = AutoConfirmWorker::for_profiles(&profiles, config.fwmark);
        Ok(Self {
            runtime,
            sender,
            profiles,
            profile_runtimes,
            list_registry,
            ipcache,
            server: config.server,
            debug: config.debug,
            desync_fwmark: config.fwmark,
            payload_disable: config.payload_disable,
            reasm_disable: config.reasm_disable,
            hostlist_auto_debug: config
                .hostlist_auto_debug
                .clone(),
            last_outcome: RefCell::new(PacketOutcome::Pass),
            auto_confirm,
        })
    }

    /// Returns a shared reference to the embedded [`LuaRuntime`].
    pub fn runtime(&self) -> &LuaRuntime
    {
        &self.runtime
    }

    /// Returns a shared reference to the engine's [`IpCache`] (protected by [`RefCell`]).
    pub fn ipcache(&self) -> &RefCell<IpCache>
    {
        &self.ipcache
    }

    /// Returns the loaded, active desync profiles evaluated for each packet.
    pub fn profiles(&self) -> &[Rc<DesyncProfile>]
    {
        &self.profiles
    }

    /// Swaps active profiles in-place after validating Lua callbacks, clearing conntrack and ipcache.
    pub fn replace_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), LuaEngineError>
    {
        let swapped = build_swapped_profiles(profiles, &self.runtime)?;
        self.list_registry = swapped.registry;
        self.profiles = swapped.profiles;
        self.profile_runtimes = swapped.runtimes;
        self.auto_confirm = AutoConfirmWorker::for_profiles(&self.profiles, self.desync_fwmark);
        self.runtime
            .conntrack()
            .borrow_mut()
            .clear();
        self.ipcache
            .borrow_mut()
            .clear();
        Ok(())
    }

    /// Resets modification signatures and reloads all hostlists and ipsets from disk (`SIGHUP`).
    pub fn reload_lists(&self)
    {
        self.list_registry
            .reload_all(&self.profile_runtimes);
        self.runtime
            .conntrack()
            .borrow_mut()
            .reset_unmatched_profiles();
    }

    /// Returns a borrowed [`EngineServices`] view shared with `play_prolog` and `dp_rediscovery`.
    pub(crate) fn services(&self) -> EngineServices<'_>
    {
        EngineServices {
            profiles: &self.profiles,
            profile_runtimes: &self.profile_runtimes,
            conntrack: self
                .runtime
                .conntrack(),
            ipcache: &self.ipcache,
            lua: self
                .runtime
                .lua(),
            ctrack_disable: self
                .runtime
                .config()
                .ctrack_disable,
            server: self.server,
            hostlist_auto_debug: self
                .hostlist_auto_debug
                .as_deref(),
            auto_confirm: self
                .auto_confirm
                .as_ref(),
        }
    }

    /// Upgrades `last_outcome` (`Pass` < `Reasm` < `Modify` < `Desync`) without downgrading replay hits.
    pub(crate) fn record_outcome(&self, outcome: PacketOutcome)
    {
        let mut slot = self
            .last_outcome
            .borrow_mut();
        if matches!(
            (&*slot, &outcome),
            (PacketOutcome::Pass, _)
                | (PacketOutcome::Reasm, PacketOutcome::Modify(_) | PacketOutcome::Desync(_))
                | (PacketOutcome::Modify(_), PacketOutcome::Desync(_))
        )
        {
            *slot = outcome;
        }
    }

    /// Processes one intercepted live packet and returns the kernel NFQUEUE [`Decision`].
    pub fn process_packet(&self, pkt: &QueuedPacket<'_>) -> Decision
    {
        let dbg = self
            .hostlist_auto_debug
            .as_deref();
        if let Some(c) = &self.auto_confirm
        {
            c.drain_and_apply(&self.profiles, &self.profile_runtimes, dbg);
        }
        self.last_outcome
            .replace(PacketOutcome::Pass);
        let now = boottime_now();
        self.ipcache
            .borrow_mut()
            .purge_rate_limited(now.sec);
        self.process_packet_play(&ReplayContext::live(), pkt, now)
    }

    /// Processes one live packet and returns both the kernel [`Decision`] and high-level [`PacketOutcome`].
    pub fn process_packet_traced(&self, pkt: &QueuedPacket<'_>) -> (Decision, PacketOutcome)
    {
        let decision = self.process_packet(pkt);
        (
            decision,
            self.last_outcome
                .borrow()
                .clone(),
        )
    }

    /// Dispatches one live or replayed packet through TCP, UDP, ICMP, or raw IP pipelines.
    pub(crate) fn process_packet_play(
        &self,
        replay: &ReplayContext<'_>,
        pkt: &QueuedPacket<'_>,
        now: MonotonicTime,
    ) -> Decision
    {
        let dis = dissect_packet(pkt.payload, false);
        if dis
            .ip
            .is_some()
            == dis
                .ip6
                .is_some()
        {
            return Decision::Pass;
        }
        if dis
            .tcp
            .is_some()
        {
            process_tcp_packet(self, replay, pkt, &dis, now)
        }
        else if dis
            .udp
            .is_some()
        {
            process_udp_packet(self, replay, pkt, &dis, now)
        }
        else if dis
            .icmp
            .is_some()
        {
            process_icmp_packet(self, pkt, &dis)
        }
        else
        {
            process_raw_ip_packet(self, pkt, &dis)
        }
    }

    /// Checks cutoffs/gates and invokes the matched profile's Lua desync actions (`desync` in `desync.c`).
    pub(crate) fn dispatch_state(
        &self,
        replay: &ReplayContext<'_>,
        pkt: &QueuedPacket<'_>,
        dis: &DissectedPacket,
        ps: &PlayState,
        reasm_data: Option<&[u8]>,
        decrypt_data: Option<&[u8]>,
    ) -> Decision
    {
        let Some(idx) = ps.profile_idx
        else
        {
            return Decision::Pass;
        };
        let profile = &self.profiles[idx];
        let instances = &self.profile_runtimes[idx].action_instances;
        if profile
            .actions
            .is_empty()
        {
            return Decision::Pass;
        }

        let track_rc = ps
            .ctrack_replay
            .as_ref();
        if let Some(entry_rc) = track_rc
        {
            let entry = entry_rc.borrow();
            if (ps.incoming && entry.lua_in_cutoff) || (!ps.incoming && entry.lua_out_cutoff)
            {
                return Decision::Pass;
            }
        }

        let pos_opt = if let Some(tp) = replay.tpos
        {
            Some(if ps.b_reverse { tp.server } else { tp.client })
        }
        else
        {
            extract_pos_for_side(track_rc, ps.b_reverse)
        };

        if all_actions_cut_off(profile, instances, track_rc, pos_opt.as_ref(), ps.incoming)
        {
            if let Some(entry_rc) = track_rc
            {
                let mut e = entry_rc.borrow_mut();
                if ps.incoming
                {
                    e.lua_in_cutoff = true;
                }
                else
                {
                    e.lua_out_cutoff = true;
                }
            }
            return Decision::Pass;
        }

        if !any_action_runnable(profile, instances, track_rc, pos_opt.as_ref(), ps.incoming, ps.l7payload)
        {
            return Decision::Pass;
        }

        match execute_profile_run(
            &self.runtime,
            self.server,
            self.debug,
            ProfileRunInput {
                profile_slot: idx,
                profile,
                instances,
                replay,
                pkt,
                dis,
                ps,
                pos_opt,
                reasm_data,
                decrypt_data,
            },
        )
        {
            Ok(decision) =>
            {
                let label = || {
                    Some(
                        profile
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("profile #{}", profile.index)),
                    )
                };
                match &decision
                {
                    Decision::Replace(_) => self.record_outcome(PacketOutcome::Modify(label())),
                    Decision::Drop => self.record_outcome(PacketOutcome::Desync(label())),
                    Decision::Pass =>
                    {}
                }
                decision
            }
            Err(err) =>
            {
                eprintln!("desync ERROR: {err}. passing packet unmodified.");
                Decision::Pass
            }
        }
    }
}
