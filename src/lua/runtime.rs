//! Top-level [`LuaRuntime`] wrapper orchestrating LuaJIT creation, hardening, and script loading.

/// Interior mutability and single-thread sharing for injected packet senders and timestamps.
use std::cell::{Cell, RefCell};
/// Filesystem path handling for loading external Lua files.
use std::path::Path;
/// Single-thread reference counting for passing [`PacketSender`] into Lua closures.
use std::rc::Rc;

/// Embedded LuaJIT interpreter handle and registry/userdata types.
use mlua::{AnyUserData, Lua, RegistryKey, Value};

/// Configuration structs applied when loading blobs, scripts, and verifying desync functions.
use crate::config::{AppConfig, DesyncProfile, LuaInitEntry};
/// Bidirectional connection tracking pool shared between `DesyncEngine` and Lua `conntrack_feed`.
use crate::conntrack::ConntrackPool;
/// Bitwise logic and shift Lua primitives.
use crate::lua::bitwise::register_bitwise_functions;
/// Binary integer packing, byte mutation, random-blob, and hex primitives.
use crate::lua::bytes::register_bytes_functions;
/// Security hardening and protocol/runtime global constants.
use crate::lua::constants::{LuaConfig, harden_lua, register_constants};
/// Cryptographic Lua bindings (`hash`, `aes`, `aes_gcm`, `aes_ctr`, `hkdf`).
use crate::lua::crypto_api::register_crypto_functions;
/// Desync context userdata and Rust host execution helpers (`raw_packet`, `execution_plan`, cutoffs).
use crate::lua::desync_api::{
    DesyncContextState, create_desync_ctx_userdata, register_desync_functions,
};
/// Typed error wrapper for Lua runtime operations.
use crate::lua::error::LuaEngineError;
/// POSIX `stat` and calendar time (`localtime`, `gmtime`, `timelocal`, `timegm`) Lua bindings.
use crate::lua::fs_time_api::register_fs_time_functions;
/// Streaming gzip/gunzip Lua bindings (`gunzip_*`, `gzip_*`).
use crate::lua::gzip_api::register_gzip_functions;
/// Packet dissect, reconstruct, checksum, and IP string conversion bindings.
use crate::lua::packet_api::register_packet_functions;
/// Protocol split marker resolvers and TLS payload mutator bindings.
use crate::lua::protocol_api::register_protocol_functions;
/// Lua `rawsend` and `rawsend_dissect` kernel injection bindings.
use crate::lua::rawsend_api::register_rawsend_functions;
/// Logging, OS metadata, clock, and network inspection Lua bindings.
use crate::lua::system::register_system_functions;
/// Scheduled timer pool and host bindings.
use crate::lua::timer_api::register_timer_functions;
/// Abstract packet sender trait and Linux raw socket sender implementation.
use crate::rawsend::{PacketSender, RawSender};
/// Scheduled timer pool managing active timers and deadlines.
use crate::timer::pool::TimerPool;

/// Self-contained `zapret2`-compatible LuaJIT execution environment.
pub struct LuaRuntime {
    /// Embedded LuaJIT state initialized with `zapret2` globals and bindings.
    lua: Lua,
    /// Snapshot of runtime configuration flags exposed to Lua.
    config: LuaConfig,
    /// Shared per-packet desync execution context backed by Lua's `ctx` userdata.
    desync_ctx: Rc<RefCell<DesyncContextState>>,
    /// Lua registry handle preserving the singleton `ctx` userdata across packet calls.
    desync_ctx_key: RegistryKey,
    /// Shared bidirectional TCP/UDP connection tracking pool.
    conntrack: Rc<RefCell<ConntrackPool>>,
    /// Scheduled timer pool accessible from Lua and event loops.
    timer_pool: Rc<RefCell<TimerPool>>,
    /// Monotonic timestamp in milliseconds of the last completed garbage collection pass.
    last_gc_ms: Cell<u64>,
}

impl LuaRuntime {
    /// Creates a new [`LuaRuntime`] backed by a real Linux [`RawSender`].
    pub fn new(config: LuaConfig) -> Result<Self, LuaEngineError> {
        let sender: Rc<RefCell<dyn PacketSender>> =
            Rc::new(RefCell::new(RawSender::new(config.bind_fix4, config.bind_fix6)));
        Self::with_sender(config, sender)
    }

    /// Creates a new [`LuaRuntime`] using a caller-supplied [`PacketSender`] (e.g., for testing).
    pub fn with_sender(
        config: LuaConfig,
        sender: Rc<RefCell<dyn PacketSender>>,
    ) -> Result<Self, LuaEngineError> {
        let lua = Lua::new();
        harden_lua(&lua)?;
        register_constants(&lua, &config)?;
        register_bitwise_functions(&lua)?;
        register_bytes_functions(&lua)?;
        register_crypto_functions(&lua)?;
        register_gzip_functions(&lua)?;
        register_fs_time_functions(&lua)?;
        register_packet_functions(&lua)?;
        register_protocol_functions(&lua)?;
        register_system_functions(&lua, &config)?;
        register_rawsend_functions(&lua, &config, sender)?;

        let desync_ctx = Rc::new(RefCell::new(DesyncContextState::default()));
        let conntrack = Rc::new(RefCell::new(ConntrackPool::new(config.ctrack_timeouts)));
        register_desync_functions(
            &lua,
            &config,
            Rc::clone(&desync_ctx),
            Rc::clone(&conntrack),
        )?;

        let timer_pool = Rc::new(RefCell::new(TimerPool::new()));
        register_timer_functions(&lua, Rc::clone(&timer_pool))?;

        let desync_ctx_key = create_desync_ctx_userdata(&lua, Rc::clone(&desync_ctx))?;

        Ok(Self {
            lua,
            config,
            desync_ctx,
            desync_ctx_key,
            conntrack,
            timer_pool,
            last_gc_ms: Cell::new(0),
        })
    }

    /// Returns a shared reference to the underlying `mlua::Lua` state.
    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    /// Returns the runtime configuration active in this Lua environment.
    pub fn config(&self) -> &LuaConfig {
        &self.config
    }

    /// Returns the shared handle controlling the active Lua desync context state.
    pub fn desync_ctx_state(&self) -> &Rc<RefCell<DesyncContextState>> {
        &self.desync_ctx
    }

    /// Returns the shared handle controlling the connection tracking pool.
    pub fn conntrack(&self) -> &Rc<RefCell<ConntrackPool>> {
        &self.conntrack
    }

    /// Returns the shared handle controlling registered timers.
    pub fn timer_pool(&self) -> &Rc<RefCell<TimerPool>> {
        &self.timer_pool
    }

    /// Performs periodic Lua garbage collection if configured interval has elapsed.
    pub fn do_gc(&self, now_ms: u64) {
        if self.config.lua_gc_sec > 0 {
            let interval_ms = self.config.lua_gc_sec.saturating_mul(1000);
            let last = self.last_gc_ms.get();
            if now_ms.saturating_sub(last) >= interval_ms {
                let _ = self.lua.gc_collect();
                self.last_gc_ms.set(now_ms);
            }
        }
    }

    /// Fetches the singleton `desync_ctx` userdata handle stored in Lua's registry.
    pub fn desync_ctx_userdata(&self) -> mlua::Result<AnyUserData> {
        self.lua.registry_value(&self.desync_ctx_key)
    }

    /// Registers a named binary blob global variable directly into Lua's `_G`.
    pub fn set_blob(&self, name: &str, data: &[u8]) -> Result<(), LuaEngineError> {
        let lua_str = self.lua.create_string(data)?;
        self.lua.globals().set(name, lua_str)?;
        Ok(())
    }

    /// Verifies that every action function referenced by `profiles` exists as a Lua function in `_G`.
    pub fn verify_desync_functions(&self, profiles: &[DesyncProfile]) -> Result<(), LuaEngineError> {
        let globals = self.lua.globals();
        for profile in profiles {
            for action in &profile.actions {
                if !matches!(globals.get::<Value>(action.func.as_str())?, Value::Function(_)) {
                    return Err(LuaEngineError::MissingFunction(action.func.clone()));
                }
            }
        }
        Ok(())
    }

    /// Loads `config.blobs`, executes `config.lua_init` scripts, and verifies profile action functions.
    pub fn apply_app_config(&self, config: &AppConfig) -> Result<(), LuaEngineError> {
        for (name, data) in &config.blobs {
            self.set_blob(name, data)?;
        }
        for entry in &config.lua_init {
            match entry {
                LuaInitEntry::File(path) => self.exec_file(path)?,
                LuaInitEntry::Inline(code) => self.exec_str(code)?,
            }
        }
        self.verify_desync_functions(&config.profiles)?;
        Ok(())
    }

    /// Evaluates an inline Lua source string against this runtime.
    pub fn exec_str(&self, code: &str) -> Result<(), LuaEngineError> {
        self.lua.load(code).exec()?;
        Ok(())
    }

    /// Reads and executes a Lua script file from `path` using the file path as the chunk name.
    pub fn exec_file(&self, path: &Path) -> Result<(), LuaEngineError> {
        let source = std::fs::read(path)?;
        self.lua
            .load(&source)
            .set_name(path.to_string_lossy())
            .exec()?;
        Ok(())
    }
}

impl Drop for LuaRuntime {
    /// Clears conntrack entries and `ctx.ctrack` handles so Lua registry keys drop before `Lua`.
    fn drop(&mut self) {
        self.desync_ctx.borrow_mut().ctrack = None;
        self.conntrack.borrow_mut().clear();
    }
}
