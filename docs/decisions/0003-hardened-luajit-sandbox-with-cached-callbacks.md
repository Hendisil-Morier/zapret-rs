# ADR-0003: Hardened LuaJIT Sandbox with Cached Callback Handles

## Status

Accepted

## Date

2026-11-27

## Context

DPI desync actions in `zapret2` rely on user-supplied and bundled Lua scripts (`zapret-lib.lua`, `zapret-antidpi.lua`) executed per packet inside the privileged interception process. Executing untrusted or corrupted scripts without sandboxing risks arbitrary OS command execution or memory corruption via binary LuaJIT bytecode, while dynamic `_G[name]` global table lookups and leaked `RegistryKey` references per packet or config reload degrade packet-loop latency and leak VM memory.

## Decision

1. Harden the embedded vendored LuaJIT state in `LuaRuntime` ([src/lua/runtime.rs](../../src/lua/runtime.rs), [src/lua/constants.rs](../../src/lua/constants.rs)) by stripping `os.execute`, `io.popen`, `package.loadlib`, and `debug` via `harden_lua`.
2. Enforce `mlua::chunk::ChunkMode::Text` on all script/inline loads so precompiled binary bytecode chunks are rejected.
3. Ignore `./lua` inside the current working directory during default script discovery ([src/tools/lua_bundle.rs](../../src/tools/lua_bundle.rs)) unless explicitly passed via `--lua-dir`.
4. Pre-resolve every profile action function at startup and `reload_config` into cached `Vec<Vec<RegistryKey>>` handles (`action_funcs`), calling `lua.expire_registry_values()` on periodic `do_gc` passes.

## Alternatives Considered

### Replace LuaJIT entirely with Rust-only strategy implementations
- **Pros:** Zero VM overhead, compile-time type safety for every strategy.
- **Cons:** Breaks drop-in compatibility with existing `zapret2` Lua scripts (`zapret-antidpi.lua`), user custom action functions, and `--lua-init` extensibility.
- **Rejected:** Preserving full `zapret2` Lua script compatibility is a core product goal.

### Look up Lua callback functions dynamically by name per packet
- **Pros:** Simpler `LuaRuntime` startup without storing `RegistryKey` matrices.
- **Cons:** Allocates/hashes strings on every matched packet's hot path and skips upfront validation of missing profile `func` names until live traffic arrives.
- **Rejected:** Cached `RegistryKey` slots provide O(1) slice-indexed dispatch and fail fast at config load/reload time.

## Consequences

- Daemon startups and hot reloads catch invalid/missing Lua function names before intercepting live traffic.
- Unprivileged `zapret-rs install` deployments or untrusted RW directories cannot hijack execution via precompiled bytecode or CWD `./lua` drops.
- Periodic `do_gc` calls keep long-running daemons free of `RegistryKey` leaks across repeated `reload_config` cycles.
