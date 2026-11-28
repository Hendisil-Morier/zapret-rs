//! Scheduled timer pool managing registration, re-entrant callbacks, and monotonic deadlines.

/// Single-threaded reference counting and interior mutability for timer pool sharing.
use std::cell::RefCell;
/// Standard collections for ordered timer storage.
use std::collections::BTreeMap;
/// Reference counting for passing shared timer pool handles into Lua closures.
use std::rc::Rc;

/// Embedded Lua types for executing callbacks and retrieving registry keys.
use mlua::{Function, Lua, RegistryKey, Value};

/// Monotonic boottime clock reader for deadline calculation.
use crate::timer::clock::boottime_ms;

/// Minimum timer period allowed by `zapret2` in milliseconds.
pub const MIN_TIMER_PERIOD_MS: u64 = 10;

/// Read-only snapshot of timer metadata exposed to Lua `timer_info(name)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimerInfo
{
    /// Unique timer identification string.
    pub name: String,
    /// Timer period in milliseconds.
    pub period_ms: u64,
    /// Whether the timer automatically deletes itself after the first activation.
    pub oneshot: bool,
    /// Total number of successful or attempted activations so far.
    pub fires: u64,
}

/// Internal registration record for one active timer.
pub struct TimerEntry
{
    /// Unique timer identification string.
    pub name: String,
    /// Registry key holding the Lua callback function.
    pub func_key: RegistryKey,
    /// Optional registry key holding user-supplied data passed to the callback.
    pub data_key: Option<RegistryKey>,
    /// Configured period in milliseconds (must be >= 10 ms).
    pub period_ms: u64,
    /// Whether the timer automatically deletes itself after firing.
    pub oneshot: bool,
    /// Monotonic boottime timestamp in milliseconds when the timer next activates.
    pub bt_next: u64,
    /// Total activation counter.
    pub fires: u64,
    /// Unique sequence counter identifying this timer instance.
    pub seq: u64,
}

/// Container managing scheduled Lua timers, re-entrant mutations, and deadline tracking.
pub struct TimerPool
{
    /// Registered timers keyed by unique string name.
    timers: BTreeMap<String, TimerEntry>,
    /// Mutation flag indicating timers were inserted, deleted, or replaced during execution.
    dirty: bool,
    /// Monotonically increasing sequence generator to distinguish recreated timer instances.
    next_seq: u64,
}

impl Default for TimerPool
{
    fn default() -> Self
    {
        Self::new()
    }
}

impl TimerPool
{
    /// Creates an empty timer pool with default sequence tracking.
    pub fn new() -> Self
    {
        Self { timers: BTreeMap::new(), dirty: false, next_seq: 1 }
    }

    /// Returns `true` if no timers are currently scheduled.
    pub fn is_empty(&self) -> bool
    {
        self.timers.is_empty()
    }

    /// Returns the number of currently scheduled timers.
    pub fn len(&self) -> usize
    {
        self.timers.len()
    }

    /// Returns whether the timer pool was mutated since the flag was last cleared.
    pub fn is_dirty(&self) -> bool
    {
        self.dirty
    }

    /// Clears or marks the re-entrancy mutation flag.
    pub fn set_dirty(&mut self, dirty: bool)
    {
        self.dirty = dirty;
    }

    /// Inserts or replaces a timer identified by `name`.
    ///
    /// Rejects configurations where `period_ms < MIN_TIMER_PERIOD_MS`.
    pub fn set(
        &mut self,
        name: String,
        func_key: RegistryKey,
        period_ms: u64,
        oneshot: bool,
        data_key: Option<RegistryKey>,
        now_ms: u64,
    ) -> Result<(), &'static str>
    {
        if period_ms < MIN_TIMER_PERIOD_MS
        {
            return Err("invalid timer period. must be >=10 ms");
        }

        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        let bt_next = now_ms.saturating_add(period_ms);

        let entry =
            TimerEntry { name: name.clone(), func_key, data_key, period_ms, oneshot, bt_next, fires: 0, seq };

        self.timers.insert(name, entry);
        self.dirty = true;
        Ok(())
    }

    /// Removes the timer named `name`, returning `true` if it existed.
    pub fn del(&mut self, name: &str) -> bool
    {
        let removed = self.timers.remove(name).is_some();
        if removed
        {
            self.dirty = true;
        }
        removed
    }

    /// Returns a metadata snapshot for the timer named `name`, or `None` if not found.
    pub fn info(&self, name: &str) -> Option<TimerInfo>
    {
        self.timers.get(name).map(|e| TimerInfo {
            name: e.name.clone(),
            period_ms: e.period_ms,
            oneshot: e.oneshot,
            fires: e.fires,
        })
    }

    /// Returns a reference to the registry key for `name`'s Lua callback, if present.
    pub fn get_func_key(&self, name: &str) -> Option<&RegistryKey>
    {
        self.timers.get(name).map(|e| &e.func_key)
    }

    /// Returns a sorted list of all active timer names.
    pub fn enum_names(&self) -> Vec<String>
    {
        self.timers.keys().cloned().collect()
    }

    /// Computes the earliest monotonic deadline among all registered timers.
    ///
    /// Clears `dirty` to `false` and returns `None` if the pool is empty.
    pub fn next_deadline_ms(&mut self) -> Option<u64>
    {
        self.dirty = false;
        self.timers.values().map(|e| e.bt_next).min()
    }

    /// Runs all expired timers against `lua`, gracefully handling re-entrancy and errors.
    ///
    /// Returns the monotonic boottime timestamp of the next earliest activation, or `None`.
    pub fn run_expired(pool_rc: &Rc<RefCell<Self>>, lua: &Lua, mut now_ms: u64) -> Option<u64>
    {
        if now_ms == 0
        {
            now_ms = boottime_ms();
        }

        let mut removed_any = false;
        loop
        {
            let next_to_run = {
                let pool = pool_rc.borrow();
                pool.timers
                    .values()
                    .find(|e| now_ms >= e.bt_next)
                    .map(|e| (e.name.clone(), e.seq, e.oneshot, e.period_ms))
            };

            let Some((name, seq, oneshot, period_ms)) = next_to_run
            else
            {
                break;
            };

            let callback_data = {
                let pool = pool_rc.borrow();
                match pool.timers.get(&name)
                {
                    Some(entry) if entry.seq == seq =>
                    {
                        let func: mlua::Result<Function> = lua.registry_value(&entry.func_key);
                        let data: mlua::Result<Value> = match &entry.data_key
                        {
                            Some(k) => lua.registry_value(k),
                            None => Ok(Value::Nil),
                        };
                        match (func, data)
                        {
                            (Ok(f), Ok(d)) => Some((f, d)),
                            _ => None,
                        }
                    }
                    _ => None,
                }
            };

            let Some((func, data)) = callback_data
            else
            {
                let mut pool = pool_rc.borrow_mut();
                removed_any |= pool.timers.remove(&name).is_some();
                continue;
            };

            pool_rc.borrow_mut().dirty = false;

            let call_res = func.call::<()>((name.clone(), data));

            let mut pool = pool_rc.borrow_mut();
            if let Some(entry) = pool.timers.get_mut(&name)
                && entry.seq == seq
            {
                entry.fires = entry.fires.saturating_add(1);
                if call_res.is_err() || oneshot
                {
                    removed_any |= pool.timers.remove(&name).is_some();
                }
                else
                {
                    entry.bt_next = now_ms.saturating_add(period_ms);
                }
            }
        }

        if removed_any
        {
            lua.expire_registry_values();
        }
        pool_rc.borrow_mut().next_deadline_ms()
    }
}
