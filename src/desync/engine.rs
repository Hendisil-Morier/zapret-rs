//! Core DPI desync engine dispatching intercepted packets through profile filters and Lua actions.

/// Interior mutability for sharing caller-supplied [`PacketSender`] and context state.
use std::cell::RefCell;
/// Single-thread reference counting for profile snapshots and packet senders.
use std::rc::Rc;

/// Dynamic Lua value variant matched against resolved desync callback functions.
use mlua::Value;

/// Profile, match input, L7 protocol/payload types evaluated per packet.
use crate::config::{AppConfig, DesyncProfile, L7Payload, L7Proto, ProfileMatchInput};
/// Tracked flow entry and per-direction position snapshot types.
use crate::conntrack::{CtrackEntry, CtrackPosition};
/// Verdict aggregation, gate evaluation, Lua verdict decoding, context guards, and conntrack helpers.
use crate::desync::verdict::{
    SessionCtxGuard, action_is_runnable, aggregate_verdict, all_actions_cut_off,
    any_action_runnable, classify_baseline_payload, extract_l3_ttl, extract_pos_for_side,
    finalize_decision, invoke_action_callback, parse_lua_verdict,
};
/// Intercepted packet metadata and kernel verdict decision enum.
use crate::intercepter::{Decision, QueuedPacket};
/// Lua runtime, error enum, and desync table/argument builders.
use crate::lua::{
    LuaEngineError, LuaRuntime,
    desync_encode::{
        DesyncTableInput, build_action_args_table, build_desync_table, desync_instance_name,
    },
};
/// Default pass verdict bitmask initialized before profile actions execute.
use crate::packet::constants::VERDICT_PASS;
/// Dissected packet view and L3/L4 wire parser.
use crate::packet::{DissectedPacket, dissect_packet};
/// Abstract packet sender trait for injectable/testable raw packet transmission.
use crate::rawsend::PacketSender;
/// Monotonic boottime `timespec` helper for conntrack feeding and idle sweeps.
use crate::timer::boottime_now;

/// Borrowed packet, direction, target, and conntrack metadata passed into profile execution.
struct DispatchMeta<'a> {
    /// Dissected L3/L4 view of the intercepted packet.
    dis: &'a DissectedPacket,
    /// Raw L3 wire bytes of the intercepted packet.
    raw_pkt: &'a [u8],
    /// Incoming interface name, if present.
    ifin: Option<&'a str>,
    /// Outgoing interface name, if present.
    ifout: Option<&'a str>,
    /// Kernel netfilter mark attached to the packet.
    fwmark: u32,
    /// Local host direction (`true` = incoming, `false` = outgoing).
    incoming: bool,
    /// Logical connection direction (`true` = server -> client, `false` = client -> server).
    b_reverse: bool,
    /// Resolved remote IPv4 address (`desync.target.ip`).
    target_ip4: Option<[u8; 4]>,
    /// Resolved remote IPv6 address (`desync.target.ip6`).
    target_ip6: Option<[u8; 16]>,
    /// Resolved remote transport port (`desync.target.port`).
    target_port: u16,
    /// Classified L7 payload tag.
    l7payload: L7Payload,
    /// Classified L7 protocol tag.
    l7proto: L7Proto,
    /// Active conntrack entry associated with this flow, if any.
    ctrack: Option<Rc<RefCell<CtrackEntry>>>,
    /// Copied position snapshot for range checks on the sender side.
    pos_opt: Option<CtrackPosition>,
}

/// Orchestrates packet dissection, profile filter selection, and `zapret2` Lua desync execution.
pub struct DesyncEngine {
    /// Embedded LuaJIT runtime preloaded with blobs, startup scripts, and bindings.
    runtime: LuaRuntime,
    /// Ordered active profiles copied from [`AppConfig`] and wrapped in `Rc` for `execution_plan`.
    profiles: Vec<Rc<DesyncProfile>>,
    /// Server-mode direction flag affecting target port extraction.
    server: bool,
    /// Enable diagnostic debug output to standard error.
    debug: bool,
}

impl DesyncEngine {
    /// Constructs a [`DesyncEngine`] using a real Linux [`crate::rawsend::RawSender`].
    pub fn new(config: &AppConfig) -> Result<Self, LuaEngineError> {
        let runtime = LuaRuntime::new(config.to_lua_config())?;
        Self::from_runtime(runtime, config)
    }

    /// Constructs a [`DesyncEngine`] using a caller-supplied [`PacketSender`] (e.g., mock sender in tests).
    pub fn with_sender(
        config: &AppConfig,
        sender: Rc<RefCell<dyn PacketSender>>,
    ) -> Result<Self, LuaEngineError> {
        let runtime = LuaRuntime::with_sender(config.to_lua_config(), sender)?;
        Self::from_runtime(runtime, config)
    }

    /// Shared initialization helper loading blobs, scripts, and validating all profile actions.
    fn from_runtime(runtime: LuaRuntime, config: &AppConfig) -> Result<Self, LuaEngineError> {
        runtime.apply_app_config(config)?;
        let server = runtime.config().server;
        let debug = runtime.config().debug;
        let profiles = config.profiles.iter().cloned().map(Rc::new).collect();
        Ok(Self {
            runtime,
            profiles,
            server,
            debug,
        })
    }

    /// Returns a shared reference to the embedded [`LuaRuntime`].
    pub fn runtime(&self) -> &LuaRuntime {
        &self.runtime
    }

    /// Returns the loaded, active desync profiles evaluated for each packet.
    pub fn profiles(&self) -> &[Rc<DesyncProfile>] {
        &self.profiles
    }

    /// Processes one intercepted packet and returns the kernel NFQUEUE [`Decision`].
    pub fn process_packet(&self, pkt: &QueuedPacket<'_>) -> Decision {
        let dis = dissect_packet(pkt.payload, false);
        if dis.ip.is_some() == dis.ip6.is_some() {
            return Decision::Pass;
        }

        let ctrack_hit = if !self.runtime.config().ctrack_disable {
            let now = boottime_now();
            let feed_res = {
                let mut pool = self.runtime.conntrack().borrow_mut();
                pool.purge_rate_limited(now.sec);
                pool.feed(Some(self.runtime.lua()), &dis, now)
            };
            match feed_res {
                Ok(hit) => hit,
                Err(err) => {
                    eprintln!("conntrack ERROR: {err}. passing packet unmodified.");
                    return Decision::Pass;
                }
            }
        } else {
            None
        };

        let (ctrack_rc, b_reverse, incoming) = match ctrack_hit {
            Some((entry_rc, rev)) => (Some(entry_rc), rev, rev ^ self.server),
            None => {
                let inc = pkt.ifin.is_some_and(|s| !s.is_empty())
                    && !pkt.ifout.is_some_and(|s| !s.is_empty());
                (None, inc, inc)
            }
        };

        let mut pos_opt = None;
        if let Some(entry_rc) = &ctrack_rc {
            let mut entry = entry_rc.borrow_mut();
            if incoming && entry.incoming_ttl == 0 {
                entry.incoming_ttl = extract_l3_ttl(&dis);
            }
            if (incoming && entry.lua_in_cutoff) || (!incoming && entry.lua_out_cutoff) {
                return Decision::Pass;
            }
            pos_opt = Some(if b_reverse {
                entry.pos.server
            } else {
                entry.pos.client
            });
        }

        let target_ip4 = dis.ip.as_ref().map(|ip| if incoming { ip.src } else { ip.dst });
        let target_ip6 = dis
            .ip6
            .as_ref()
            .map(|ip6| if incoming { ip6.src } else { ip6.dst });
        let port_from_src = incoming ^ self.server;
        let target_port = if let Some(tcp) = &dis.tcp {
            if port_from_src { tcp.s_port } else { tcp.d_port }
        } else if let Some(udp) = &dis.udp {
            if port_from_src { udp.s_port } else { udp.d_port }
        } else {
            0
        };

        let l7payload = classify_baseline_payload(&dis);
        let l7proto = L7Proto::Unknown;
        let match_input = ProfileMatchInput {
            is_v6: dis.ip6.is_some(),
            l4proto: dis.l4proto,
            port: target_port,
            icmp_type: dis.icmp.as_ref().map_or(0xFF, |h| h.icmp_type),
            icmp_code: dis.icmp.as_ref().map_or(0xFF, |h| h.icmp_code),
            fwmark: pkt.mark,
            l7proto,
        };

        let Some(profile) = self.profiles.iter().find(|p| p.matches(&match_input)) else {
            return Decision::Pass;
        };
        if profile.actions.is_empty() {
            return Decision::Pass;
        }

        if all_actions_cut_off(profile, ctrack_rc.as_ref(), pos_opt.as_ref(), incoming) {
            if let Some(entry_rc) = &ctrack_rc {
                let mut entry = entry_rc.borrow_mut();
                if incoming {
                    entry.lua_in_cutoff = true;
                } else {
                    entry.lua_out_cutoff = true;
                }
            }
            return Decision::Pass;
        }

        if !any_action_runnable(
            profile,
            ctrack_rc.as_ref(),
            pos_opt.as_ref(),
            incoming,
            l7payload,
        ) {
            return Decision::Pass;
        }

        let meta = DispatchMeta {
            dis: &dis,
            raw_pkt: pkt.payload,
            ifin: pkt.ifin,
            ifout: pkt.ifout,
            fwmark: pkt.mark,
            incoming,
            b_reverse,
            target_ip4,
            target_ip6,
            target_port,
            l7payload,
            l7proto,
            ctrack: ctrack_rc,
            pos_opt,
        };

        match self.try_run_profile(profile, meta) {
            Ok(decision) => decision,
            Err(err) => {
                eprintln!("desync ERROR: {err}. passing packet unmodified.");
                Decision::Pass
            }
        }
    }

    /// Runs matching actions on `profile` and resolves the combined verdict to a [`Decision`].
    fn try_run_profile(
        &self,
        profile: &Rc<DesyncProfile>,
        meta: DispatchMeta<'_>,
    ) -> Result<Decision, String> {
        let lua = self.runtime.lua();
        let ctx_state = self.runtime.desync_ctx_state();
        let mut active_ctrack = meta.ctrack;
        let mut active_incoming = meta.incoming;
        let mut active_b_reverse = meta.b_reverse;
        let mut pos_opt = meta.pos_opt;

        {
            let mut state = ctx_state.borrow_mut();
            state.profile = Some(Rc::clone(profile));
            state.profile_n = profile.index;
            state.incoming = active_incoming;
            state.ctrack = active_ctrack.clone();
            state.cancel = false;
            state.valid = false;
            state.raw_packet.clear();
            state.raw_packet.extend_from_slice(meta.raw_pkt);
        }
        let _session_guard = SessionCtxGuard(ctx_state);

        // Drop `track_ref` before any Lua callback executes so `instance_cutoff`/`lua_cutoff` can borrow mutably.
        let desync_tbl = {
            let track_ref = active_ctrack.as_ref().map(|rc| rc.borrow());
            let table_input = DesyncTableInput {
                dis: meta.dis,
                profile,
                incoming: active_incoming,
                ifin: meta.ifin,
                ifout: meta.ifout,
                fwmark: meta.fwmark,
                target_ip4: meta.target_ip4,
                target_ip6: meta.target_ip6,
                target_port: meta.target_port,
                l7payload: meta.l7payload,
                l7proto: meta.l7proto,
                track: track_ref.as_deref(),
                tpos: None,
                b_reverse: active_b_reverse,
                replay_piece: 0,
                replay_piece_count: 0,
                reasm_offset: 0,
                reasm_data: if meta.dis.tcp.is_some() {
                    meta.dis.payload.as_deref()
                } else {
                    None
                },
                decrypt_data: None,
            };
            build_desync_table(lua, &table_input)
                .map_err(|e| format!("failed to build desync table: {e}"))?
        };
        let ctx_ud = self
            .runtime
            .desync_ctx_userdata()
            .map_err(|e| format!("failed to fetch desync ctx userdata: {e}"))?;
        let globals = lua.globals();

        let mut verdict = VERDICT_PASS;
        for (idx, action) in profile.actions.iter().enumerate() {
            let func_n = (idx as u32) + 1;
            let instance = desync_instance_name(&action.func, profile.index, func_n);
            if !action_is_runnable(
                action,
                profile.index,
                &instance,
                active_ctrack.as_ref(),
                pos_opt.as_ref(),
                active_incoming,
                meta.l7payload,
            ) {
                continue;
            }

            let func_val = globals
                .get::<Value>(action.func.as_str())
                .map_err(|e| format!("failed to resolve '{}': {e}", action.func))?;
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

            let results = invoke_action_callback(
                ctx_state,
                &func,
                &ctx_ud,
                &desync_tbl,
                func_n,
                &action.func,
                &instance,
            )?;

            let action_verdict = parse_lua_verdict(&results)?;
            verdict = aggregate_verdict(verdict, action_verdict);

            if ctx_state.borrow().cancel {
                break;
            }

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

        finalize_decision(lua, &desync_tbl, verdict, meta.raw_pkt.len(), self.debug)
    }
}
