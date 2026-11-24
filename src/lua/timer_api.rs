//! Lua host bindings for `timer_set`, `timer_del`, `timer_info`, and `timer_enum`.

/// Single-threaded interior mutability for shared timer pool access.
use std::cell::RefCell;
/// Reference counting for sharing timer pool handles across Lua closures.
use std::rc::Rc;

/// Core `mlua` types for table manipulation, functions, and variadic arguments.
use mlua::{Function, Lua, Value, Variadic};

/// Monotonic boottime clock reader for initializing activation timestamps.
use crate::timer::clock::boottime_ms;
/// Scheduled timer pool managing active timers and deadlines.
use crate::timer::pool::TimerPool;
/// Argument validation and value extraction helpers.
use crate::lua::helpers::{
    check_argc, check_argc_range, coerce_i64, is_truthy, require_strict_str,
};
/// Typed error wrapper for Lua engine operations.
use crate::lua::error::LuaEngineError;

/// Registers `timer_set`, `timer_del`, `timer_info`, and `timer_enum` into Lua `_G`.
pub fn register_timer_functions(
    lua: &Lua,
    pool: Rc<RefCell<TimerPool>>,
) -> Result<(), LuaEngineError> {
    let globals = lua.globals();

    // timer_set(name, func, period, [oneshot], [data])
    let pool_set = Rc::clone(&pool);
    let timer_set = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc_range("timer_set", &args, 3, 5)?;
        let name = require_strict_str(&args[0])?;

        let func_key = match &args[1] {
            Value::String(s) => {
                let func_name = s
                    .to_str()
                    .map_err(|_| mlua::Error::external("invalid UTF-8 function name"))?;
                let global_val = lua.globals().get::<Value>(&*func_name)?;
                match global_val {
                    Value::Function(f) => lua.create_registry_value(f)?,
                    _ => {
                        return Err(mlua::Error::external(format!(
                            "timer function '{func_name}' does not exist"
                        )));
                    }
                }
            }
            Value::Function(f) => lua.create_registry_value(f.clone())?,
            _ => return Err(mlua::Error::external("invalid timer function type")),
        };

        let period = coerce_i64(lua, &args[2])?;
        if period < 10 {
            return Err(mlua::Error::external("invalid timer period. must be >=10 ms"));
        }
        let period_ms = period as u64;

        let oneshot = args.get(3).is_some_and(is_truthy);

        let data_key = match args.get(4) {
            Some(val) if !val.is_nil() => Some(lua.create_registry_value(val.clone())?),
            _ => None,
        };

        let now = boottime_ms();
        pool_set
            .borrow_mut()
            .set(name, func_key, period_ms, oneshot, data_key, now)
            .map_err(mlua::Error::external)?;

        Ok(())
    })?;
    globals.set("timer_set", timer_set)?;

    // timer_del(name)
    let pool_del = Rc::clone(&pool);
    let timer_del = lua.create_function(move |_lua, args: Variadic<Value>| {
        check_argc("timer_del", &args, 1)?;
        let name = require_strict_str(&args[0])?;
        let deleted = pool_del.borrow_mut().del(&name);
        Ok(deleted)
    })?;
    globals.set("timer_del", timer_del)?;

    // timer_info(name)
    let pool_info = Rc::clone(&pool);
    let timer_info = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc("timer_info", &args, 1)?;
        let name = require_strict_str(&args[0])?;
        let info_opt = pool_info.borrow().info(&name);

        match info_opt {
            Some(info) => {
                let tbl = lua.create_table()?;
                tbl.set("name", info.name.as_str())?;
                if let Some(func) = pool_info
                    .borrow()
                    .get_func_key(&name)
                    .and_then(|k| lua.registry_value::<Function>(k).ok())
                {
                    tbl.set("func", func)?;
                }
                tbl.set("period", info.period_ms)?;
                tbl.set("oneshot", info.oneshot)?;
                tbl.set("fires", info.fires)?;
                Ok(Value::Table(tbl))
            }
            None => Ok(Value::Nil),
        }
    })?;
    globals.set("timer_info", timer_info)?;

    // timer_enum()
    let pool_enum = Rc::clone(&pool);
    let timer_enum = lua.create_function(move |lua, args: Variadic<Value>| {
        check_argc("timer_enum", &args, 0)?;
        let names = pool_enum.borrow().enum_names();
        let tbl = lua.create_table()?;
        for (idx, name) in names.into_iter().enumerate() {
            tbl.set(idx + 1, name)?;
        }
        Ok(tbl)
    })?;
    globals.set("timer_enum", timer_enum)?;

    Ok(())
}
