//! Core stateful DPI desync engine dispatching intercepted packets through profiles and Lua actions.

/// Interior mutability for sharing [`PacketSender`] and rate-limited `IpCache`.
use std::cell::RefCell;
/// Optional autohostlist debug log path stored on the engine.
use std::path::PathBuf;
/// Single-thread reference counting for profile snapshots and packet senders.
use std::rc::Rc;

/// Dynamic Lua value variant matched against resolved desync callback functions.
use mlua::Value;

/// Profile definitions loaded into runtime structures and Lua validation.
use crate::config::{AppConfig, DesyncProfile};
/// ICMP and non-TCP/UDP/ICMP raw IP packet processors.
use crate::desync::icmp_ip::{process_icmp_packet, process_raw_ip_packet};
/// Shared prolog state, replay metadata, packet outcome tag, and borrowed runtime services.
use crate::desync::play::{EngineServices, PacketOutcome, PlayState, ReplayContext};
/// Deduplicated file registry, per-profile runtime hostlist/ipset state, and profile hot-swap.
use crate::desync::profile_state::{ListRegistry, ProfileRuntime, build_swapped_profiles};
/// Stateful TCP DPI desync processor (`process_tcp_packet`).
use crate::desync::tcp::process_tcp_packet;
/// Stateful UDP DPI desync processor (`process_udp_packet`).
use crate::desync::udp::process_udp_packet;
/// Verdict aggregation, gate evaluation, Lua verdict decoding, context guards, and cutoff checks.
use crate::desync::verdict::{
    SessionCtxGuard, action_is_runnable, aggregate_verdict, all_actions_cut_off,
    any_action_runnable, extract_pos_for_side, finalize_decision, invoke_action_callback,
    parse_lua_verdict,
};
/// Intercepted packet metadata and kernel verdict decision enum.
use crate::intercepter::{Decision, QueuedPacket};
/// Global IP-to-hostname and incoming-TTL cache (`ip_cache`).
use crate::lists::IpCache;
/// Lua runtime, error enum, and desync table/argument builders.
use crate::lua::{
    LuaEngineError, LuaRuntime,
    desync_encode::{DesyncTableInput, build_action_args_table, build_desync_table},
};
/// Default pass verdict bitmask initialized before profile actions execute.
use crate::packet::constants::VERDICT_PASS;
/// Dissected packet view and L3/L4 wire parser.
use crate::packet::{DissectedPacket, dissect_packet};
/// Abstract packet sender trait.
use crate::rawsend::PacketSender;
/// Real Linux raw socket packet sender implementation.
#[cfg(target_os = "linux")]
use crate::rawsend::RawSender;
/// Monotonic boottime clock queried once per dispatched packet.
use crate::timer::{MonotonicTime, boottime_now};

/// Orchestrates packet dissection, stateful conntrack, L7 probes, list matching, and Lua desync.
pub struct DesyncEngine {
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
}

impl DesyncEngine {
    /// Constructs a [`DesyncEngine`] using a real Linux `RawSender`.
    #[cfg(target_os = "linux")]
    pub fn new(config: &AppConfig) -> Result<Self, LuaEngineError> {
        let sender: Rc<RefCell<dyn PacketSender>> =
            Rc::new(RefCell::new(RawSender::new(config.bind_fix4, config.bind_fix6)));
        Self::with_sender(config, sender)
    }

    /// Constructs a [`DesyncEngine`] using a caller-supplied [`PacketSender`] (e.g., mock sender in tests).
    pub fn with_sender(
        config: &AppConfig,
        sender: Rc<RefCell<dyn PacketSender>>,
    ) -> Result<Self, LuaEngineError> {
        let runtime = LuaRuntime::with_sender(config.to_lua_config(), Rc::clone(&sender))?;
        Self::from_runtime(runtime, sender, config)
    }

    /// Shared initialization helper loading blobs, scripts, lists, and validating all profile actions.
    fn from_runtime(
        runtime: LuaRuntime,
        sender: Rc<RefCell<dyn PacketSender>>,
        config: &AppConfig,
    ) -> Result<Self, LuaEngineError> {
        runtime.apply_app_config(config)?;
        let (list_registry, profile_runtimes) =
            ListRegistry::load_from_config(config).map_err(|(_, err)| LuaEngineError::Io(err))?;
        let profiles = config.profiles.iter().cloned().map(Rc::new).collect();
        let ipcache = RefCell::new(IpCache::new(
            i64::from(config.ipcache.lifetime_sec),
            config.ipcache.hostname,
        ));
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
            hostlist_auto_debug: config.hostlist_auto_debug.clone(),
            last_outcome: RefCell::new(PacketOutcome::Pass),
        })
    }

    /// Returns a shared reference to the embedded [`LuaRuntime`].
    pub fn runtime(&self) -> &LuaRuntime {
        &self.runtime
    }

    /// Returns a shared reference to the engine's [`IpCache`] (protected by [`RefCell`]).
    pub fn ipcache(&self) -> &RefCell<IpCache> {
        &self.ipcache
    }

    /// Returns the loaded, active desync profiles evaluated for each packet.
    pub fn profiles(&self) -> &[Rc<DesyncProfile>] {
        &self.profiles
    }

    /// Swaps active profiles in-place after validating Lua callbacks, clearing conntrack and ipcache.
    pub fn replace_profiles(&mut self, profiles: Vec<DesyncProfile>) -> Result<(), LuaEngineError> {
        let swapped = build_swapped_profiles(profiles, &self.runtime)?;
        self.list_registry = swapped.registry;
        self.profiles = swapped.profiles;
        self.profile_runtimes = swapped.runtimes;
        self.runtime.conntrack().borrow_mut().clear();
        self.ipcache.borrow_mut().clear();
        Ok(())
    }

    /// Resets modification signatures and reloads all hostlists and ipsets from disk (`SIGHUP`).
    pub fn reload_lists(&self) {
        self.list_registry.reload_all(&self.profile_runtimes);
        self.runtime.conntrack().borrow_mut().reset_unmatched_profiles();
    }

    /// Returns a borrowed [`EngineServices`] view shared with `play_prolog` and `dp_rediscovery`.
    pub(crate) fn services(&self) -> EngineServices<'_> {
        EngineServices {
            profiles: &self.profiles,
            profile_runtimes: &self.profile_runtimes,
            conntrack: self.runtime.conntrack(),
            ipcache: &self.ipcache,
            lua: self.runtime.lua(),
            ctrack_disable: self.runtime.config().ctrack_disable,
            server: self.server,
            hostlist_auto_debug: self.hostlist_auto_debug.as_deref(),
        }
    }

    /// Upgrades `last_outcome` (`Pass` < `Reasm` < `Modify` < `Desync`) without downgrading replay hits.
    pub(crate) fn record_outcome(&self, outcome: PacketOutcome) {
        let mut slot = self.last_outcome.borrow_mut();
        if matches!(
            (&*slot, &outcome),
            (PacketOutcome::Pass, _)
                | (PacketOutcome::Reasm, PacketOutcome::Modify(_) | PacketOutcome::Desync(_))
                | (PacketOutcome::Modify(_), PacketOutcome::Desync(_))
        ) {
            *slot = outcome;
        }
    }

    /// Processes one intercepted live packet and returns the kernel NFQUEUE [`Decision`].
    pub fn process_packet(&self, pkt: &QueuedPacket<'_>) -> Decision {
        self.last_outcome.replace(PacketOutcome::Pass);
        let now = boottime_now();
        self.ipcache.borrow_mut().purge_rate_limited(now.sec);
        self.process_packet_play(&ReplayContext::live(), pkt, now)
    }

    /// Processes one live packet and returns both the kernel [`Decision`] and high-level [`PacketOutcome`].
    pub fn process_packet_traced(&self, pkt: &QueuedPacket<'_>) -> (Decision, PacketOutcome) {
        let decision = self.process_packet(pkt);
        (decision, self.last_outcome.borrow().clone())
    }

    /// Dispatches one live or replayed packet through TCP, UDP, ICMP, or raw IP pipelines.
    pub(crate) fn process_packet_play(
        &self,
        replay: &ReplayContext<'_>,
        pkt: &QueuedPacket<'_>,
        now: MonotonicTime,
    ) -> Decision {
        let dis = dissect_packet(pkt.payload, false);
        if dis.ip.is_some() == dis.ip6.is_some() {
            return Decision::Pass;
        }
        if dis.tcp.is_some() {
            process_tcp_packet(self, replay, pkt, &dis, now)
        } else if dis.udp.is_some() {
            process_udp_packet(self, replay, pkt, &dis, now)
        } else if dis.icmp.is_some() {
            process_icmp_packet(self, pkt, &dis)
        } else {
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
    ) -> Decision {
        let Some(idx) = ps.profile_idx else {
            return Decision::Pass;
        };
        let profile = &self.profiles[idx];
        let instances = &self.profile_runtimes[idx].action_instances;
        if profile.actions.is_empty() {
            return Decision::Pass;
        }

        let track_rc = ps.ctrack_replay.as_ref();
        if let Some(entry_rc) = track_rc {
            let entry = entry_rc.borrow();
            if (ps.incoming && entry.lua_in_cutoff) || (!ps.incoming && entry.lua_out_cutoff) {
                return Decision::Pass;
            }
        }

        let pos_opt = if let Some(tp) = replay.tpos {
            Some(if ps.b_reverse { tp.server } else { tp.client })
        } else {
            extract_pos_for_side(track_rc, ps.b_reverse)
        };

        if all_actions_cut_off(profile, instances, track_rc, pos_opt.as_ref(), ps.incoming) {
            if let Some(entry_rc) = track_rc {
                let mut entry = entry_rc.borrow_mut();
                if ps.incoming {
                    entry.lua_in_cutoff = true;
                } else {
                    entry.lua_out_cutoff = true;
                }
            }
            return Decision::Pass;
        }

        if !any_action_runnable(profile, instances, track_rc, pos_opt.as_ref(), ps.incoming, ps.l7payload) {
            return Decision::Pass;
        }

        match self.try_run_profile(
            profile, instances, replay, pkt, dis, ps, pos_opt, reasm_data, decrypt_data,
        ) {
            Ok(decision) => {
                let label = || Some(profile.name.clone().unwrap_or_else(|| format!("profile #{}", profile.index)));
                match &decision {
                    Decision::Replace(_) => self.record_outcome(PacketOutcome::Modify(label())),
                    Decision::Drop => self.record_outcome(PacketOutcome::Desync(label())),
                    Decision::Pass => {}
                }
                decision
            }
            Err(err) => {
                eprintln!("desync ERROR: {err}. passing packet unmodified.");
                Decision::Pass
            }
        }
    }

    /// Executes matching profile actions in Lua and translates the combined verdict to [`Decision`].
    #[allow(clippy::too_many_arguments)]
    fn try_run_profile(
        &self,
        profile: &Rc<DesyncProfile>,
        instances: &[String],
        replay: &ReplayContext<'_>,
        pkt: &QueuedPacket<'_>,
        dis: &DissectedPacket,
        ps: &PlayState,
        mut pos_opt: Option<crate::conntrack::CtrackPosition>,
        reasm_data: Option<&[u8]>,
        decrypt_data: Option<&[u8]>,
    ) -> Result<Decision, String> {
        let lua = self.runtime.lua();
        let ctx_state = self.runtime.desync_ctx_state();
        let mut active_ctrack = ps.ctrack_replay.clone();
        let mut active_incoming = ps.incoming;
        let mut active_b_reverse = ps.b_reverse;

        {
            let mut state = ctx_state.borrow_mut();
            state.profile = Some(Rc::clone(profile));
            state.profile_n = profile.index;
            state.incoming = active_incoming;
            state.ctrack = active_ctrack.clone();
            state.cancel = false;
            state.valid = false;
            state.raw_packet.clear();
            state.raw_packet.extend_from_slice(pkt.payload);
        }
        let _session_guard = SessionCtxGuard(ctx_state);

        let desync_tbl = {
            let track_ref = active_ctrack.as_ref().map(|rc| rc.borrow());
            let table_input = DesyncTableInput {
                dis, profile, incoming: active_incoming, ifin: pkt.ifin, ifout: pkt.ifout,
                fwmark: pkt.mark, target_ip4: ps.target_ip4, target_ip6: ps.target_ip6,
                target_port: ps.target_port, l7payload: ps.l7payload, l7proto: ps.l7proto,
                track: track_ref.as_deref(), tpos: replay.tpos, b_reverse: active_b_reverse,
                replay_piece: replay.replay_piece, replay_piece_count: replay.replay_piece_count,
                reasm_offset: replay.reasm_offset, reasm_data, decrypt_data,
            };
            build_desync_table(lua, &table_input).map_err(|e| format!("failed to build desync table: {e}"))?
        };
        let ctx_ud = self.runtime.desync_ctx_userdata().map_err(|e| format!("failed to fetch desync ctx userdata: {e}"))?;
        let globals = lua.globals();

        let mut verdict = VERDICT_PASS;
        for (idx, action) in profile.actions.iter().enumerate() {
            let func_n = (idx as u32) + 1;
            let instance = &instances[idx];
            if !action_is_runnable(action, profile.index, instance, active_ctrack.as_ref(), pos_opt.as_ref(), active_incoming, ps.l7payload) {
                continue;
            }

            let func_val = globals.get::<Value>(action.func.as_str()).map_err(|e| format!("failed to resolve '{}': {e}", action.func))?;
            let Value::Function(func): Value = func_val else {
                return Err(format!("desync function '{}' does not exist", action.func));
            };

            let Some(arg_tbl) = build_action_args_table(lua, &action.args, Some(&desync_tbl), true)
                .map_err(|e| format!("failed to build args for '{}': {e}", action.func))?
            else {
                return Err(format!("missing blob referenced by '{}'", action.func));
            };

            desync_tbl
                .raw_set("arg", arg_tbl)
                .and_then(|()| desync_tbl.raw_set("func", action.func.as_str()))
                .and_then(|()| desync_tbl.raw_set("func_n", i64::from(func_n)))
                .and_then(|()| desync_tbl.raw_set("func_instance", instance.as_str()))
                .map_err(|e| format!("failed to update desync table fields: {e}"))?;

            let results = invoke_action_callback(ctx_state, &func, &ctx_ud, &desync_tbl, func_n, &action.func, instance)?;
            verdict = aggregate_verdict(verdict, parse_lua_verdict(&results)?);
            if ctx_state.borrow().cancel { break; }

            if active_ctrack.is_none() {
                let adopted = {
                    let state = ctx_state.borrow();
                    state.ctrack.as_ref().map(|rc| (Rc::clone(rc), state.incoming))
                };
                if let Some((rc, ctx_inc)) = adopted {
                    active_ctrack = Some(rc);
                    active_incoming = ctx_inc;
                    active_b_reverse = active_incoming ^ self.server;
                    pos_opt = extract_pos_for_side(active_ctrack.as_ref(), active_b_reverse);
                }
            }
        }

        finalize_decision(lua, &desync_tbl, verdict, pkt.payload.len(), self.debug)
    }
}
