//! POSIX filesystem `stat` and broken-down calendar time (`localtime`, `gmtime`, `timelocal`, `timegm`) Lua bindings.

/// C string conversion and interior-NUL-safe path construction for `libc` FFI calls.
use std::ffi::{CStr, CString};

/// Embedded LuaJIT types for multi-return values, calendar tables, and variadic arguments.
use mlua::{Lua, MultiValue, Table, Value, Variadic};

/// Shared argument validation and integer/string extractors matching `zapret2`.
use crate::lua::helpers::{check_argc, coerce_i64, coerce_str, require_number_i64};

/// Fixed scratch buffer size passed to thread-safe XSI `libc::strerror_r`.
const STRERROR_BUF_LEN: usize = 256;

/// Resolves an OS `errno` value into its thread-safe locale error message string.
fn strerror_string(errno: i32) -> String {
    let mut buf = [0 as libc::c_char; STRERROR_BUF_LEN];
    // SAFETY: `buf` is valid writable storage of `STRERROR_BUF_LEN` bytes for `strerror_r`.
    let rc = unsafe { libc::strerror_r(errno, buf.as_mut_ptr(), buf.len()) };
    if rc == 0 {
        // SAFETY: XSI `strerror_r` NUL-terminates `buf` upon returning `0`.
        return unsafe { CStr::from_ptr(buf.as_ptr()) }
            .to_string_lossy()
            .into_owned();
    }
    std::io::Error::from_raw_os_error(errno).to_string()
}

/// Maps POSIX `st_mode` file-type bits into `zapret2`'s `stat.type` strings.
const fn stat_file_type(mode: libc::mode_t) -> &'static str {
    match mode & libc::S_IFMT {
        libc::S_IFREG => "file",
        libc::S_IFDIR => "dir",
        libc::S_IFLNK => "symlink",
        libc::S_IFSOCK => "socket",
        libc::S_IFBLK => "blockdev",
        libc::S_IFCHR => "chardev",
        libc::S_IFIFO => "fifo",
        _ => "unknown",
    }
}

/// Converts a populated `libc::tm` struct into a 11-field `zapret2` Lua time table.
fn build_tm_table(lua: &Lua, tm: &libc::tm) -> mlua::Result<Table> {
    let year = tm.tm_year + 1900;
    let zone = if tm.tm_zone.is_null() {
        String::new()
    } else {
        // SAFETY: `localtime_r`/`gmtime_r` populate `tm_zone` with a static NUL-terminated string.
        unsafe { CStr::from_ptr(tm.tm_zone) }
            .to_string_lossy()
            .into_owned()
    };
    let formatted = format!(
        "{:02}.{:02}.{:04} {:02}:{:02}:{:02}",
        tm.tm_mday,
        tm.tm_mon + 1,
        year,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec
    );

    let tbl = lua.create_table_with_capacity(0, 11)?;
    tbl.raw_set("sec", tm.tm_sec)?;
    tbl.raw_set("min", tm.tm_min)?;
    tbl.raw_set("hour", tm.tm_hour)?;
    tbl.raw_set("mday", tm.tm_mday)?;
    tbl.raw_set("mon", tm.tm_mon)?;
    tbl.raw_set("year", year)?;
    tbl.raw_set("wday", tm.tm_wday)?;
    tbl.raw_set("yday", tm.tm_yday)?;
    tbl.raw_set("isdst", tm.tm_isdst)?;
    tbl.raw_set("zone", zone)?;
    tbl.raw_set("str", formatted)?;
    Ok(tbl)
}

/// Extracts one strictly numeric `c_int` field from a Lua `tm` table (`lua.c:3851`).
fn read_tm_int(tbl: &Table, field: &str) -> mlua::Result<libc::c_int> {
    let val: Value = tbl.get(field)?;
    let num = require_number_i64(&val)
        .map_err(|_| mlua::Error::external(format!("invalid tm.{field}")))?;
    libc::c_int::try_from(num).map_err(|_| mlua::Error::external(format!("invalid tm.{field}")))
}

/// Validates and decodes a Lua `tm` table into a zero-initialized `libc::tm`.
fn parse_tm_table(val: &Value) -> mlua::Result<libc::tm> {
    let Value::Table(tbl) = val else {
        return Err(mlua::Error::external("invalid tm structure"));
    };
    // SAFETY: `libc::tm` is a plain C struct where zero-initialization sets pointer fields cleanly.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_sec = read_tm_int(tbl, "sec")?;
    tm.tm_min = read_tm_int(tbl, "min")?;
    tm.tm_hour = read_tm_int(tbl, "hour")?;
    tm.tm_mday = read_tm_int(tbl, "mday")?;
    tm.tm_mon = read_tm_int(tbl, "mon")?;
    tm.tm_year = read_tm_int(tbl, "year")?.wrapping_sub(1900);
    tm.tm_isdst = read_tm_int(tbl, "isdst")?;
    Ok(tm)
}

/// Converts a Unix timestamp into a Lua table via `localtime_r` or `gmtime_r`.
fn run_xtime(
    lua: &Lua,
    val: &Value,
    timefn: unsafe extern "C" fn(*const libc::time_t, *mut libc::tm) -> *mut libc::tm,
) -> mlua::Result<Value> {
    let unixtime = coerce_i64(lua, val)? as libc::time_t;
    // SAFETY: `libc::tm` is completely overwritten by `localtime_r`/`gmtime_r` on non-null return.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: pointers reference valid initialized stack locals.
    let res = unsafe { timefn(&raw const unixtime, &raw mut tm) };
    if res.is_null() {
        return Ok(Value::Nil);
    }
    build_tm_table(lua, &tm).map(Value::Table)
}

/// Converts a Lua `tm` table back into a Unix timestamp (or `nil`) via `mktime` or `timegm`.
fn run_timex(val: &Value, timefn: unsafe extern "C" fn(*mut libc::tm) -> libc::time_t) -> mlua::Result<Option<i64>> {
    let mut tm = parse_tm_table(val)?;
    // SAFETY: `tm` is a valid initialized `libc::tm` with all calendar fields populated.
    let ts = unsafe { timefn(&raw mut tm) };
    if ts == -1 {
        return Ok(None);
    }
    Ok(Some(ts))
}

/// Registers `stat`, `localtime`, `gmtime`, `timelocal`, and `timegm` on `_G`.
pub fn register_fs_time_functions(lua: &Lua) -> mlua::Result<()> {
    let globals = lua.globals();

    globals.set(
        "stat",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("stat", &args, 1)?;
            let path = coerce_str(lua, &args[0])?;
            let Ok(c_path) = CString::new(path) else {
                let err_str = strerror_string(libc::EINVAL);
                return Ok(MultiValue::from_vec(vec![
                    Value::Nil,
                    Value::String(lua.create_string(&err_str)?),
                    Value::Integer(i64::from(libc::EINVAL)),
                ]));
            };

            // SAFETY: `libc::stat` writes into `st` on `0` return and resolves symlinks like C `stat(2)`.
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            // SAFETY: `c_path` is NUL-terminated and `st` is valid writable storage.
            if unsafe { libc::stat(c_path.as_ptr(), &raw mut st) } != 0 {
                let errno = std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(libc::EINVAL);
                let err_str = strerror_string(errno);
                return Ok(MultiValue::from_vec(vec![
                    Value::Nil,
                    Value::String(lua.create_string(&err_str)?),
                    Value::Integer(i64::from(errno)),
                ]));
            }

            let tbl = lua.create_table_with_capacity(0, 5)?;
            tbl.raw_set("dev", st.st_dev as i64)?;
            tbl.raw_set("inode", st.st_ino as i64)?;
            tbl.raw_set("size", st.st_size)?;
            let mtime = (st.st_mtime as f64) + (st.st_mtime_nsec as f64) / 1_000_000_000.0;
            tbl.raw_set("mtime", mtime)?;
            tbl.raw_set("type", stat_file_type(st.st_mode))?;
            Ok(MultiValue::from_vec(vec![Value::Table(tbl)]))
        })?,
    )?;

    globals.set(
        "localtime",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("localtime", &args, 1)?;
            run_xtime(lua, &args[0], libc::localtime_r)
        })?,
    )?;

    globals.set(
        "gmtime",
        lua.create_function(|lua, args: Variadic<Value>| {
            check_argc("gmtime", &args, 1)?;
            run_xtime(lua, &args[0], libc::gmtime_r)
        })?,
    )?;

    globals.set(
        "timelocal",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("timelocal", &args, 1)?;
            run_timex(&args[0], libc::mktime)
        })?,
    )?;

    globals.set(
        "timegm",
        lua.create_function(|_, args: Variadic<Value>| {
            check_argc("timegm", &args, 1)?;
            run_timex(&args[0], libc::timegm)
        })?,
    )?;

    Ok(())
}
