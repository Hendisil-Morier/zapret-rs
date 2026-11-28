//! Per-profile Lua desync action execution and `desync` table assembly.

/// Single-thread reference counting for active profiles and conntrack snapshots.
use std::rc::Rc;

/// Selected desync profile configuration passed into Lua actions.
use crate::config::DesyncProfile;
/// Conntrack stream position counters updated across mid-profile `ctrack` creation.
use crate::conntrack::CtrackPosition;
/// Shared prolog state and replay metadata supplied to per-profile execution.
use crate::desync::play::{PlayState, ReplayContext};
/// Verdict aggregation, gate checks, decision finalizer, and Lua action invocation helpers.
use crate::desync::verdict::{
    SessionCtxGuard, action_is_runnable, aggregate_verdict, extract_pos_for_side, finalize_decision,
    invoke_action_callback, parse_lua_verdict,
};
/// Kernel verdict decision and intercepted packet wrapper.
use crate::intercepter::{Decision, QueuedPacket};
/// Lua runtime, desync table builder, and action-argument table builder.
use crate::lua::{
    LuaRuntime,
    desync_encode::{DesyncTableInput, build_action_args_table, build_desync_table},
};
/// Dissected L3/L4 packet headers supplied to Lua action callbacks.
use crate::packet::DissectedPacket;
/// Default pass verdict bitmask initialized before profile actions execute.
use crate::packet::constants::VERDICT_PASS;

/// Bundled per-packet profile execution inputs passed to [`execute_profile_run`].
pub(super) struct ProfileRunInput<'a>
{
    /// Slot index of the active profile within the engine table.
    pub(super) profile_slot: usize,
    /// Selected desync profile definition and action list.
    pub(super) profile: &'a Rc<DesyncProfile>,
    /// Precomputed action instance identifiers aligned with `profile.actions`.
    pub(super) instances: &'a [String],
    /// Replay metadata distinguishing live packets from chunked/reassembled replays.
    pub(super) replay: &'a ReplayContext<'a>,
    /// Intercepted wire packet wrapper including interface names and fwmark.
    pub(super) pkt: &'a QueuedPacket<'a>,
    /// Dissected L3/L4 headers for the current packet.
    pub(super) dis: &'a DissectedPacket,
    /// Flow play state resolved before executing profile actions.
    pub(super) ps: &'a PlayState,
    /// Optional directional conntrack stream position counters.
    pub(super) pos_opt: Option<CtrackPosition>,
    /// Optional reassembled payload buffer passed to Lua desync tables.
    pub(super) reasm_data: Option<&'a [u8]>,
    /// Optional decrypted TLS/QUIC payload slice passed to Lua desync tables.
    pub(super) decrypt_data: Option<&'a [u8]>,
}

/// Executes matching profile actions in Lua and translates the combined verdict to [`Decision`].
pub(super) fn execute_profile_run(
    runtime: &LuaRuntime,
    server: bool,
    debug: bool,
    run: ProfileRunInput<'_>,
) -> Result<Decision, String>
{
    let mut pos_opt = run.pos_opt;
    let lua = runtime.lua();
    let ctx_state = runtime.desync_ctx_state();
    let mut state = ctx_state.borrow_mut();
    state.profile = Some(Rc::clone(run.profile));
    state.profile_n = run
        .profile
        .index;
    state.incoming = run
        .ps
        .incoming;
    state.ctrack = run
        .ps
        .ctrack_replay
        .clone();
    state.cancel = false;
    state.valid = false;
    state
        .raw_packet
        .clear();
    state
        .raw_packet
        .extend_from_slice(
            run.pkt
                .payload,
        );
    drop(state);
    let _session_guard = SessionCtxGuard(ctx_state);

    let desync_tbl = build_profile_desync_table(lua, &run)?;
    let ctx_ud = runtime
        .desync_ctx_userdata()
        .map_err(|e| format!("failed to fetch desync ctx userdata: {e}"))?;

    let mut active_ctrack = run
        .ps
        .ctrack_replay
        .clone();
    let mut active_incoming = run
        .ps
        .incoming;
    let mut verdict = VERDICT_PASS;
    for (idx, action) in run
        .profile
        .actions
        .iter()
        .enumerate()
    {
        let func_n = (idx as u32) + 1;
        let instance = &run.instances[idx];
        if !action_is_runnable(
            action,
            run.profile
                .index,
            instance,
            active_ctrack.as_ref(),
            pos_opt.as_ref(),
            active_incoming,
            run.ps
                .l7payload,
        )
        {
            continue;
        }

        let func = runtime.resolve_cached_action(run.profile_slot, idx, &action.func)?;
        let Some(arg_tbl) = build_action_args_table(lua, &action.args, Some(&desync_tbl), true)
            .map_err(|e| format!("failed to build args for '{}': {e}", action.func))?
        else
        {
            return Err(format!("missing blob referenced by '{}'", action.func));
        };
        desync_tbl
            .raw_set("arg", arg_tbl)
            .and_then(|()| {
                desync_tbl.raw_set(
                    "func",
                    action
                        .func
                        .as_str(),
                )
            })
            .and_then(|()| desync_tbl.raw_set("func_n", i64::from(func_n)))
            .and_then(|()| desync_tbl.raw_set("func_instance", instance.as_str()))
            .map_err(|e| format!("failed to update desync table fields: {e}"))?;

        let results =
            invoke_action_callback(ctx_state, &func, &ctx_ud, &desync_tbl, func_n, &action.func, instance)?;
        verdict = aggregate_verdict(verdict, parse_lua_verdict(&results)?);
        if ctx_state
            .borrow()
            .cancel
        {
            break;
        }
        if active_ctrack.is_none()
            && let Some((rc, ctx_inc)) = {
                let s = ctx_state.borrow();
                s.ctrack
                    .as_ref()
                    .map(|rc| (Rc::clone(rc), s.incoming))
            }
        {
            active_ctrack = Some(rc);
            active_incoming = ctx_inc;
            pos_opt = extract_pos_for_side(active_ctrack.as_ref(), active_incoming ^ server);
        }
    }

    finalize_decision(
        lua,
        &desync_tbl,
        verdict,
        run.pkt
            .payload
            .len(),
        debug,
    )
}

/// Constructs the per-profile Lua `desync` table from `run` packet and conntrack state.
fn build_profile_desync_table(lua: &mlua::Lua, run: &ProfileRunInput<'_>) -> Result<mlua::Table, String>
{
    let track_ref = run
        .ps
        .ctrack_replay
        .as_ref()
        .map(|rc| rc.borrow());
    let table_input = DesyncTableInput {
        dis: run.dis,
        profile: run.profile,
        incoming: run
            .ps
            .incoming,
        ifin: run
            .pkt
            .ifin,
        ifout: run
            .pkt
            .ifout,
        fwmark: run
            .pkt
            .mark,
        target_ip4: run
            .ps
            .target_ip4,
        target_ip6: run
            .ps
            .target_ip6,
        target_port: run
            .ps
            .target_port,
        l7payload: run
            .ps
            .l7payload,
        l7proto: run
            .ps
            .l7proto,
        track: track_ref.as_deref(),
        tpos: run
            .replay
            .tpos,
        b_reverse: run
            .ps
            .b_reverse,
        replay_piece: run
            .replay
            .replay_piece,
        replay_piece_count: run
            .replay
            .replay_piece_count,
        reasm_offset: run
            .replay
            .reasm_offset,
        reasm_data: run.reasm_data,
        decrypt_data: run.decrypt_data,
    };
    build_desync_table(lua, &table_input).map_err(|e| format!("failed to build desync table: {e}"))
}
