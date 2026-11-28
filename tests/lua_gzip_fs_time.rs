//! Integration tests for Task 4.2: streaming gzip/gunzip, POSIX `stat`/time bindings, and `--writable`.
#![cfg(unix)]

/// Interior mutability and single-thread sharing for passing [`CapturingSender`] into [`LuaRuntime`].
use std::cell::RefCell;
/// Raw OS string helper for testing `TMPDIR` resolution.
use std::ffi::OsStr;
/// Filesystem operations for `stat`, symlinks, and temp dir management.
use std::fs;
/// Symlink creation helper verifying `stat(2)` follows symlinks like `zapret2`.
use std::os::unix::fs::symlink;
/// Canonical path comparisons for temporary writable directories.
use std::path::{Path, PathBuf};
/// Subprocess execution for end-to-end `nfqws2 --writable` tests.
use std::process::Command;
/// Single-thread reference counting for the mock packet sender.
use std::rc::Rc;
/// Atomic sequence counter ensuring unique temporary paths per test.
use std::sync::atomic::{AtomicU64, Ordering};

/// `clap` parser trait for verifying `--writable` CLI flag parsing.
use clap::Parser;
/// Reference `flate2` primitives used to craft full RFC 1952 flag test streams.
use flate2::{Compress, Compression, Crc, FlushCompress, Status};

/// Shared mock `CapturingSender` and unmodified `zapret-lib.lua` path constant.
mod common;

/// Mock raw sender and `zapret-lib.lua` path constant.
use common::{CapturingSender, ZAPRET_LIB_LUA};
/// Config resolution, TOML loader, CLI flags, and `--writable` model enum.
use zapret_rs::config::{AppConfig, CliArgs, WritableDirConfig, resolve_config};
/// Embedded `zapret2`-compatible LuaJIT runtime and configuration.
use zapret_rs::lua::{LuaConfig, LuaRuntime};
/// Runtime `--writable` helpers under test.
use zapret_rs::runtime::{DEFAULT_WRITABLE_SUBDIR, ensure_writable_dir, resolve_default_writable_dir};

/// Path to `zapret2`'s unmodified `zapret-tests.lua`.
const ZAPRET_TESTS_LUA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/lua/zapret-tests.lua");

/// Returns a `zapret-rs daemon` command backed by the compiled unified binary.
fn nfqws2_cmd() -> Command
{
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_zapret-rs"));
    cmd.arg("daemon");
    cmd
}
/// Unique temporary directory sequence counter.
static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// RAII temporary test directory removed cleanly on drop.
struct TempDir(PathBuf);

impl TempDir
{
    /// Creates a unique directory under `std::env::temp_dir()`.
    fn new(prefix: &str) -> Self
    {
        let id = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("{prefix}_{}_{}", std::process::id(), id));
        fs::create_dir_all(&dir).expect("create temp dir");
        Self(dir)
    }

    /// Returns a borrowed reference to the temporary directory path.
    fn path(&self) -> &Path
    {
        &self.0
    }
}

impl Drop for TempDir
{
    /// Removes the temporary directory tree after the test finishes.
    fn drop(&mut self)
    {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Creates a [`LuaRuntime`] preloaded with unmodified `zapret-lib.lua` and `zapret-tests.lua`.
fn runtime_with_zapret_tests() -> LuaRuntime
{
    let sender = Rc::new(RefCell::new(CapturingSender::default()));
    let rt = LuaRuntime::with_sender(LuaConfig::default(), sender).expect("LuaRuntime should initialize");
    rt.exec_file(Path::new(ZAPRET_LIB_LUA)).expect("zapret-lib.lua should load");
    rt.exec_file(Path::new(ZAPRET_TESTS_LUA)).expect("zapret-tests.lua should load");
    rt
}

/// Builds a synthetic RFC 1952 gzip stream enabling `FEXTRA`, `FNAME`, `FCOMMENT`, and `FHCRC`.
fn build_full_rfc1952_gzip(payload: &[u8]) -> Vec<u8>
{
    let mut out = vec![0x1F, 0x8B, 8, 0x1E, 0, 0, 0, 0, 0, 3];
    let extra = b"ZAPRET_EXT";
    out.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    out.extend_from_slice(extra);
    out.extend_from_slice(b"sample.bin\0");
    out.extend_from_slice(b"test header comment\0");
    let mut hcrc = Crc::new();
    hcrc.update(&out);
    out.extend_from_slice(&(hcrc.sum() as u16).to_le_bytes());

    let mut comp = Compress::new(Compression::default(), false);
    let mut deflated = Vec::with_capacity(payload.len() + 64);
    let mut rem = payload;
    loop
    {
        if deflated.capacity() - deflated.len() < 1024
        {
            deflated.reserve(4096);
        }
        let flush = if rem.is_empty() { FlushCompress::Finish } else { FlushCompress::None };
        let before_in = comp.total_in();
        let status = comp.compress_vec(rem, &mut deflated, flush).expect("compress");
        rem = &rem[(comp.total_in() - before_in) as usize..];
        if matches!(status, Status::StreamEnd)
        {
            break;
        }
    }
    out.extend_from_slice(&deflated);

    let mut dcrc = Crc::new();
    dcrc.update(payload);
    out.extend_from_slice(&dcrc.sum().to_le_bytes());
    out.extend_from_slice(&dcrc.amount().to_le_bytes());
    out
}

/// Verifies `zapret2`'s unmodified `test_gzip()` and `test_time()` suites pass end-to-end.
#[test]
fn zapret_tests_gzip_and_time_pass()
{
    let rt = runtime_with_zapret_tests();
    rt.exec_str("test_gzip(); test_time()")
        .expect("unmodified zapret-tests.lua test_gzip and test_time must pass");
}

/// Verifies 1-byte streaming gzip inflate with all RFC 1952 flags and corrupt-stream error handling.
#[test]
fn gzip_byte_by_byte_full_headers_and_corruption_checks()
{
    let rt = runtime_with_zapret_tests();
    let payload: Vec<u8> = (0..18000usize).map(|i| ((i * 29) ^ (i >> 4)) as u8).collect();
    let gz_bytes = build_full_rfc1952_gzip(&payload);
    let g = rt.lua().globals();
    g.set("raw_payload", rt.lua().create_string(&payload).unwrap()).unwrap();
    g.set("full_gz", rt.lua().create_string(&gz_bytes).unwrap()).unwrap();

    rt.exec_str(
        r#"
        -- Auto-detect (default windowBits=47) fed 1 byte at a time across every header/trailer split
        local s = gunzip_init()
        assert(s ~= nil)
        local parts = {}
        local eof = false
        for i = 1, #full_gz do
            assert(not eof, "eof arrived prematurely at byte " .. i)
            local chunk, done = gunzip_inflate(s, string.sub(full_gz, i, i), 32)
            assert(chunk ~= nil, "byte-by-byte inflate failed at byte " .. i)
            parts[#parts + 1] = chunk
            eof = done
        end
        assert(eof, "final byte must trigger EOF")
        assert(table.concat(parts) == raw_payload)
        gunzip_end(s)

        -- Corrupt FHCRC byte, corrupt trailer CRC32, and corrupt ISIZE must return nil, nil
        local bad_hcrc = string.sub(full_gz, 1, 35) .. string.char(bitxor(string.byte(full_gz, 36), 1)) .. string.sub(full_gz, 37)
        local bad_crc = string.sub(full_gz, 1, #full_gz - 6) .. string.char(bitxor(string.byte(full_gz, #full_gz - 5), 1)) .. string.sub(full_gz, #full_gz - 4)
        local bad_size = string.sub(full_gz, 1, #full_gz - 1) .. string.char(bitxor(string.byte(full_gz, #full_gz), 1))
        for _, bad in ipairs({ bad_hcrc, bad_crc, bad_size, "\x1f\x8b\x08\xe0" .. string.rep("\0", 12) }) do
            local st = gunzip_init(31)
            local d, e = gunzip_inflate(st, bad)
            assert(d == nil and e == nil, "corrupt gzip must fail")
            gunzip_end(st)
        end
        "#,
    )
    .expect("RFC 1952 streaming inflate and corruption checks must pass");
}

/// Verifies raw/zlib/gzip framing modes, empty/1-arg finish, `zapret-lib` file helpers, and lifecycle errors.
#[test]
fn gzip_modes_file_helpers_and_lifecycle_errors()
{
    let tmp = TempDir::new("zapret_rs_gzip");
    let plain_path = tmp.path().join("plain.txt");
    let gz_path = tmp.path().join("packed.gz");
    let rt = runtime_with_zapret_tests();
    let g = rt.lua().globals();
    g.set("plain_path", plain_path.to_string_lossy().as_ref()).unwrap();
    g.set("gz_path", gz_path.to_string_lossy().as_ref()).unwrap();

    rt.exec_str(
        r#"
        local sample = string.rep("Hello zapret-rs compression! ", 256)
        for _, mode in ipairs({ { -15, -15 }, { 15, 15 }, { 15, 47 }, { 31, 31 }, { 31, 47 } }) do
            local enc = gzip_init(mode[1], 6, 8)
            assert(enc ~= nil)
            local c1, f1 = gzip_deflate(enc, string.sub(sample, 1, 200))
            assert(c1 ~= nil and not f1)
            local c2, f2 = gzip_deflate(enc, string.sub(sample, 201))
            assert(c2 ~= nil and not f2)
            local c3, f3 = gzip_deflate(enc) -- 1-arg finish
            assert(c3 ~= nil and f3)
            -- Post-finish call fails with nil, nil
            local post, post_eof = gzip_deflate(enc, "extra")
            assert(post == nil and post_eof == nil)
            gzip_end(enc)

            local dec = gunzip_init(mode[2])
            local out, eof = gunzip_inflate(dec, c1 .. c2 .. c3)
            assert(eof and out == sample)
            gunzip_end(dec)
        end

        -- Empty-string finalization (used by zapret-lib.lua gzip_file) + z_readfile round-trip
        local gz2 = gzip_init()
        local p1 = gzip_deflate(gz2, "chunked-")
        local p2, done2 = gzip_deflate(gz2, "")
        assert(done2 and (p1 .. p2):sub(1, 2) == "\x1f\x8b")
        gzip_end(gz2)

        writefile(plain_path, sample)
        assert(not is_gzip_file(plain_path))
        assert(z_readfile(plain_path) == sample)
        gzip_file(gz_path, sample)
        assert(is_gzip_file(gz_path))
        assert(z_readfile(gz_path) == sample)

        -- Invalid init args -> nil
        assert(gunzip_init(7) == nil)
        assert(gzip_init(31, 10, 8) == nil)
        assert(gzip_init(31, 6, 0) == nil)

        -- Role mismatch & closed handle errors
        local d = gunzip_init()
        local g = gzip_init()
        local ok_role1, err_role1 = pcall(gzip_deflate, d, "abc")
        assert(not ok_role1 and tostring(err_role1):find("gzip stream role mismatch", 1, true))
        local ok_role2, err_role2 = pcall(gunzip_inflate, g, "abc")
        assert(not ok_role2 and tostring(err_role2):find("gzip stream role mismatch", 1, true))
        gunzip_end(d)
        gzip_end(g)
        local ok_closed, err_closed = pcall(gunzip_inflate, d, "abc")
        assert(not ok_closed and tostring(err_closed):find("gzip stream is not valid", 1, true))
        "#,
    )
    .expect("gzip mode matrix, file helpers, and error checks must pass");
}

/// Verifies `stat` file/dir/symlink/error semantics and `gmtime`/`localtime`/`timegm` parity.
#[test]
fn stat_and_calendar_time_bindings_match_posix()
{
    let tmp = TempDir::new("zapret_rs_stat");
    let file_path = tmp.path().join("data.bin");
    let link_path = tmp.path().join("data.link");
    let missing_path = tmp.path().join("missing.bin");
    fs::write(&file_path, b"0123456789abcdef").unwrap();
    symlink(&file_path, &link_path).unwrap();

    let rt = LuaRuntime::new(LuaConfig::default()).expect("LuaRuntime should initialize");
    let g = rt.lua().globals();
    g.set("f_path", file_path.to_string_lossy().as_ref()).unwrap();
    g.set("d_path", tmp.path().to_string_lossy().as_ref()).unwrap();
    g.set("l_path", link_path.to_string_lossy().as_ref()).unwrap();
    g.set("m_path", missing_path.to_string_lossy().as_ref()).unwrap();
    g.set("enoent_code", i64::from(libc::ENOENT)).unwrap();

    rt.exec_str(
        r#"
        local st = stat(f_path)
        assert(type(st) == "table" and st.type == "file" and st.size == 16)
        assert(type(st.dev) == "number" and type(st.inode) == "number" and st.mtime > 0)

        local sd = stat(d_path)
        assert(sd.type == "dir")

        -- POSIX stat(2) follows symlinks to target file type/size
        local sl = stat(l_path)
        assert(sl.type == "file" and sl.size == 16 and sl.inode == st.inode)

        local snil, serr, serrn = stat(m_path)
        assert(snil == nil and type(serr) == "string" and #serr > 0 and serrn == enoent_code)

        local epoch = gmtime(0)
        assert(epoch.year == 1970 and epoch.mon == 0 and epoch.mday == 1)
        assert(epoch.hour == 0 and epoch.min == 0 and epoch.sec == 0)
        assert(epoch.wday == 4 and epoch.yday == 0 and epoch.str == "01.01.1970 00:00:00")

        -- 64-bit timestamps beyond 2038 preserve precision in LuaJIT
        local ts64 = 0x120000000
        local tm64 = gmtime(ts64)
        assert(timegm(tm64) == ts64)

        local ok_struct, err_struct = pcall(timegm, "not_a_table")
        assert(not ok_struct and tostring(err_struct):find("invalid tm structure", 1, true))
        local bad_tm = gmtime(1700000000)
        bad_tm.year = "2023"
        local ok_yr, err_yr = pcall(timelocal, bad_tm)
        assert(not ok_yr and tostring(err_yr):find("invalid tm.year", 1, true))
        "#,
    )
    .expect("stat and calendar time parity checks must pass");
}

/// Verifies `--writable` default resolution, file rejection, TOML/CLI config, and `nfqws2` execution.
#[test]
fn writable_dir_config_cli_and_nfqws2_runtime_e2e()
{
    assert_eq!(
        resolve_default_writable_dir(Some(OsStr::new("/var/tmp/custom"))),
        PathBuf::from("/var/tmp/custom").join(DEFAULT_WRITABLE_SUBDIR)
    );
    assert_eq!(resolve_default_writable_dir(Some(OsStr::new(""))), PathBuf::from("/tmp/zapret-rs"));
    assert_eq!(resolve_default_writable_dir(None), PathBuf::from("/tmp/zapret-rs"));

    let tmp = TempDir::new("zapret_rs_writable");
    let blocker = tmp.path().join("not_a_dir");
    fs::write(&blocker, b"file").unwrap();
    let err = ensure_writable_dir(&WritableDirConfig::Custom(blocker), None)
        .expect_err("file blocking writable dir must fail");
    assert!(err.to_string().contains("could not prepare writable dir"));

    let cfg_dir = AppConfig::from_toml_str("writable = \"sub/lua_tmp\"\n", Some(tmp.path()))
        .expect("TOML writable path parses");
    assert_eq!(cfg_dir.writable, Some(WritableDirConfig::Custom(tmp.path().join("sub/lua_tmp"))));
    let cfg_bool = AppConfig::from_toml_str("writable = true\n", None).unwrap();
    assert_eq!(cfg_bool.writable, Some(WritableDirConfig::Default));
    let cfg_off = AppConfig::from_toml_str("writable = false\n", None).unwrap();
    assert_eq!(cfg_off.writable, None);

    let cli_def = CliArgs::try_parse_from(["nfqws2", "--writable"]).unwrap();
    assert_eq!(resolve_config(&cli_def).unwrap().writable, Some(WritableDirConfig::Default));
    let cli_custom = CliArgs::try_parse_from(["nfqws2", "--writable=/tmp/explicit_w"]).unwrap();
    assert_eq!(
        resolve_config(&cli_custom).unwrap().writable,
        Some(WritableDirConfig::Custom(PathBuf::from("/tmp/explicit_w")))
    );

    // End-to-end `nfqws2 --intercept=0 --writable` under custom TMPDIR -> `<TMPDIR>/zapret-rs`
    let tmp_env = tmp.path().join("tmp_root");
    fs::create_dir_all(&tmp_env).unwrap();
    let zapret_lib = Path::new(env!("CARGO_MANIFEST_DIR")).join("lua/zapret-lib.lua");
    let out1 = nfqws2_cmd()
        .env("TMPDIR", &tmp_env)
        .env_remove("WRITABLE")
        .args([
            "--intercept=0",
            "--writable",
            "--lua-init",
            &format!("@{}", zapret_lib.display()),
            "--lua-init",
            r#"
            local w = os.getenv("WRITABLE")
            assert(w and w:sub(-10) == "/zapret-rs", "unexpected WRITABLE: " .. tostring(w))
            local p = writable_file_name("probe.bin")
            writefile(p, "hello-writable")
            local st = stat(p)
            assert(st and st.type == "file" and st.size == 14)
            "#,
        ])
        .output()
        .expect("spawn nfqws2 --writable");
    assert!(
        out1.status.success(),
        "nfqws2 --writable failed: stderr={}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // Explicit `--writable=<path>`
    let explicit = tmp.path().join("explicit_writable");
    let out2 = nfqws2_cmd()
        .env_remove("WRITABLE")
        .args([
            "--intercept=0",
            &format!("--writable={}", explicit.display()),
            "--lua-init",
            r#"assert(os.getenv("WRITABLE") ~= nil)"#,
        ])
        .output()
        .expect("spawn nfqws2 --writable=<explicit>");
    assert!(out2.status.success());
    assert!(explicit.is_dir());
}
