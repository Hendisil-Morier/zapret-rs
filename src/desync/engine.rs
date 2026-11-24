//! Core DPI desync engine dispatching intercepted packets through profile filters and Lua actions.

/// Interior mutability for sharing caller-supplied [`PacketSender`] and context state.
use std::cell::RefCell;
/// Single-thread reference counting for profile snapshots and packet senders.
use std::rc::Rc;

/// Core `mlua` types for invoking Lua desync callbacks and reading multi-return verdicts.
use mlua::{Function, MultiValue, Value};

/// Profile, match input, L7 protocol type, and payload mask evaluation helpers.
use crate::config::{AppConfig, DesyncProfile, L7Proto, ProfileMatchInput, l7_payload_matches};
/// Verdict aggregation, Lua verdict parsing, and baseline L7 payload classification.
use crate::desync::verdict::{aggregate_verdict, classify_baseline_payload, parse_lua_verdict};
/// Intercepted packet metadata and kernel verdict decision enum.
use crate::intercepter::{Decision, QueuedPacket};
/// Lua runtime, desync context state, table builders, and error definitions.
use crate::lua::{
    LuaEngineError, LuaRuntime,
    desync_api::DesyncContextState,
    desync_encode::{
        DesyncTableInput, build_action_args_table, build_desync_table, desync_instance_name,
    },
    packet_decode::lua_to_dissect,
};
/// Verdict action and preservation flags returned by Lua actions.
use crate::packet::constants::{
    VERDICT_DROP, VERDICT_MASK, VERDICT_MODIFY, VERDICT_PASS, VERDICT_PRESERVE_NEXT,
};
/// Packet dissector and wire reconstruction with RFC checksums.
use crate::packet::{ReconstructOptions, dissect_packet, reconstruct_packet};
/// Abstract packet sender trait for injectable/testable raw packet transmission.
use crate::rawsend::PacketSender;

/// RAII guard clearing per-packet state on [`DesyncContextState`] even across early returns.
struct SessionCtxGuard<'a>(
    /// Reference to the shared context cell cleared on drop.
    &'a Rc<RefCell<DesyncContextState>>,
);

impl Drop for SessionCtxGuard<'_> {
    /// Resets per-packet context fields when profile evaluation finishes.
    fn drop(&mut self) {
        let mut state = self.0.borrow_mut();
        state.valid = false;
        state.cancel = false;
        state.profile = None;
        state.raw_packet.clear();
        state.func.clear();
        state.instance.clear();
    }
}

/// RAII guard invalidating `ctx` immediately after each individual Lua callback returns.
struct ValidCtxGuard<'a>(
    /// Reference to the shared context cell whose `valid` flag is cleared on drop.
    &'a Rc<RefCell<DesyncContextState>>,
);

impl Drop for ValidCtxGuard<'_> {
    /// Marks `ctx` invalid so Lua cannot reuse a stashed context reference after returning.
    fn drop(&mut self) {
        self.0.borrow_mut().valid = false;
    }
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

        // shortcut: without conntrack, direction falls back to interface presence (`ifin && !ifout`) as in desync.c.
        let incoming =
            pkt.ifin.is_some_and(|s| !s.is_empty()) && !pkt.ifout.is_some_and(|s| !s.is_empty());
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

        let any_in_range = profile.actions.iter().any(|action| {
            let range = if incoming {
                action.in_range
            } else {
                action.out_range
            };
            range.matches_without_conntrack()
        });
        let any_wants_payload = profile
            .actions
            .iter()
            .any(|action| l7_payload_matches(l7payload, action.payload_mask));
        if !any_in_range || !any_wants_payload {
            return Decision::Pass;
        }

        let table_input = DesyncTableInput {
            dis: &dis,
            profile,
            incoming,
            ifin: pkt.ifin,
            ifout: pkt.ifout,
            fwmark: pkt.mark,
            target_ip4,
            target_ip6,
            target_port,
            l7payload,
            l7proto,
        };

        match self.try_run_profile(profile, pkt.payload, &table_input) {
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
        raw_pkt: &[u8],
        input: &DesyncTableInput<'_>,
    ) -> Result<Decision, String> {
        let lua = self.runtime.lua();
        let ctx_state = self.runtime.desync_ctx_state();
        {
            let mut state = ctx_state.borrow_mut();
            state.profile = Some(Rc::clone(profile));
            state.profile_n = profile.index;
            state.incoming = input.incoming;
            state.cancel = false;
            state.valid = false;
            state.raw_packet.clear();
            state.raw_packet.extend_from_slice(raw_pkt);
        }
        let _session_guard = SessionCtxGuard(ctx_state);

        let desync_tbl = build_desync_table(lua, input)
            .map_err(|e| format!("failed to build desync table: {e}"))?;
        let ctx_ud = self
            .runtime
            .desync_ctx_userdata()
            .map_err(|e| format!("failed to fetch desync ctx userdata: {e}"))?;
        let globals = lua.globals();

        let mut verdict = VERDICT_PASS;
        for (idx, action) in profile.actions.iter().enumerate() {
            let range = if input.incoming {
                action.in_range
            } else {
                action.out_range
            };
            if !range.matches_without_conntrack()
                || !l7_payload_matches(input.l7payload, action.payload_mask)
            {
                continue;
            }

            let func_n = (idx as u32) + 1;
            let instance = desync_instance_name(&action.func, profile.index, func_n);

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

            let results = Self::invoke_action_callback(
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
        }

        match verdict & VERDICT_MASK {
            VERDICT_DROP => Ok(Decision::Drop),
            VERDICT_MODIFY => {
                let dis_val = desync_tbl
                    .get::<Value>("dis")
                    .map_err(|e| format!("failed to read modified desync.dis: {e}"))?;
                let Value::Table(dis_tbl) = dis_val else {
                    return Err("dissect data is bad. VERDICT_MODIFY cancel".to_owned());
                };
                let mod_dis = lua_to_dissect(lua, &dis_tbl)
                    .map_err(|e| format!("failed to decode modified desync.dis: {e}"))?;
                let opts = ReconstructOptions {
                    keepsum: false,
                    badsum: false,
                    ip6_preserve_next: (verdict & VERDICT_PRESERVE_NEXT) != 0,
                    ip6_last_proto: None,
                };
                let mod_bytes = reconstruct_packet(&mod_dis, &opts)
                    .map_err(|e| format!("failed to reconstruct packet after VERDICT_MODIFY: {e}"))?;
                if self.debug {
                    eprintln!(
                        "reconstructed packet due to VERDICT_MODIFY. size {} => {}",
                        raw_pkt.len(),
                        mod_bytes.len()
                    );
                }
                Ok(Decision::Replace(mod_bytes))
            }
            _ => Ok(Decision::Pass),
        }
    }

    /// Arms `ctx.valid`, invokes a single Lua action function, and clears `ctx.valid` before returning.
    fn invoke_action_callback(
        ctx_state: &Rc<RefCell<DesyncContextState>>,
        func: &Function,
        ctx_ud: &mlua::AnyUserData,
        desync_tbl: &mlua::Table,
        func_n: u32,
        func_name: &str,
        instance: &str,
    ) -> Result<MultiValue, String> {
        {
            let mut state = ctx_state.borrow_mut();
            state.func_n = func_n;
            state.func.clear();
            state.func.push_str(func_name);
            state.instance.clear();
            state.instance.push_str(instance);
            state.valid = true;
        }
        let _valid_guard = ValidCtxGuard(ctx_state);
        func.call::<MultiValue>((ctx_ud.clone(), desync_tbl.clone()))
            .map_err(|e| format!("LUA ERROR: {e}"))
    }
}
