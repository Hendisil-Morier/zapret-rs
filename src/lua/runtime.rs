//! Top-level [`LuaRuntime`] wrapper orchestrating LuaJIT creation, hardening, and script loading.

/// Interior mutability and single-thread sharing for injected packet senders.
use std::cell::RefCell;
/// Filesystem path handling for loading external Lua files.
use std::path::Path;
/// Single-thread reference counting for passing [`PacketSender`] into Lua closures.
use std::rc::Rc;

/// Embedded LuaJIT interpreter handle.
use mlua::Lua;

/// Bitwise logic and shift Lua primitives.
use crate::lua::bitwise::register_bitwise_functions;
/// Binary integer packing, byte mutation, random-blob, and hex primitives.
use crate::lua::bytes::register_bytes_functions;
/// Security hardening and protocol/runtime global constants.
use crate::lua::constants::{LuaConfig, harden_lua, register_constants};
/// Typed error wrapper for Lua runtime operations.
use crate::lua::error::LuaEngineError;
/// Packet dissect, reconstruct, checksum, and IP string conversion bindings.
use crate::lua::packet_api::register_packet_functions;
/// Lua `rawsend` and `rawsend_dissect` kernel injection bindings.
use crate::lua::rawsend_api::register_rawsend_functions;
/// Logging, OS metadata, clock, and network inspection Lua bindings.
use crate::lua::system::register_system_functions;
/// Abstract packet sender trait and Linux raw socket sender implementation.
use crate::rawsend::{PacketSender, RawSender};

/// Self-contained `zapret2`-compatible LuaJIT execution environment.
pub struct LuaRuntime {
    /// Embedded LuaJIT state initialized with `zapret2` globals and bindings.
    lua: Lua,
    /// Snapshot of runtime configuration flags exposed to Lua.
    config: LuaConfig,
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
        register_packet_functions(&lua)?;
        register_system_functions(&lua, &config)?;
        register_rawsend_functions(&lua, &config, sender)?;
        Ok(Self { lua, config })
    }

    /// Returns a shared reference to the underlying `mlua::Lua` state.
    pub fn lua(&self) -> &Lua {
        &self.lua
    }

    /// Returns the runtime configuration active in this Lua environment.
    pub fn config(&self) -> &LuaConfig {
        &self.config
    }

    /// Registers a named binary blob global variable directly into Lua's `_G`.
    pub fn set_blob(&self, name: &str, data: &[u8]) -> Result<(), LuaEngineError> {
        let lua_str = self.lua.create_string(data)?;
        self.lua.globals().set(name, lua_str)?;
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
