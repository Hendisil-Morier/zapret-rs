# Embedded LuaJIT VM, Timers & Pure-Rust Cryptography

This document details `LuaRuntime` (`src/lua/`), monotonic timer scheduling (`src/timer/`), and the zero-external-C cryptographic layer (`src/crypto/`, `src/protocol/quic_crypto.rs`).

## 1. LuaJIT Security & Initialization (`src/lua/runtime.rs`, `src/lua/constants.rs`)

`LuaRuntime` embeds LuaJIT (`mlua` `0.12.3` with `vendored` + `luajit` features) and applies strict defense-in-depth hardening prior to running any user or bundled script:

- **Privilege stripping (`harden_lua`):** Deletes OS execution, dynamic loading, and low-level introspection primitives (`os.execute`, `io.popen`, `package.loadlib`, `debug`) mirroring `lua_sec_harden` in `zapret2`.
- **Text-only chunk loading (`ChunkMode::Text`):** Every script (`lua_init` file/inline chunks and profile expressions) is compiled via `ChunkMode::Text`, rejecting precompiled LuaJIT bytecode chunks.
- **Global constants (`register_constants`):** Exposes `NFQWS2_VER`, `LUA_COMPAT_VER`, `qnum`, `desync_fwmark`, `b_debug`, `b_daemon`, `b_server`, `b_ipcache_hostname`, `b_ctrack_disable`, protocol numbers (`IPPROTO_*`), TCP flags (`TH_*`), ICMP types, and verdict masks (`VERDICT_PASS`, `VERDICT_MODIFY`, `VERDICT_DROP`, `VERDICT_PRESERVE_NEXT`).
- **O(1) callback caching (`action_funcs`):** On engine creation and live `reload_config`, `LuaRuntime` resolves every profile action function name into `RegistryKey` slots stored in `action_funcs: RefCell<Vec<Vec<RegistryKey>>>` so packet dispatch invokes cached handles without per-packet `_G` string lookups.
- **GC & registry reclamation (`do_gc`):** Periodic garbage collection honors `--lua-gc` (`DEFAULT_LUA_GC_INTERVAL`) and explicitly calls `lua.expire_registry_values()` to reclaim dropped `RegistryKey` slots.

## 2. Host Function Modules (`src/lua/`)

All `zapret2`-compatible Lua APIs are decomposed into single-responsibility registration modules under `src/lua/`:

| Module | Exposed Lua Primitives |
|---|---|
| `bitwise.rs` | Bitwise logic, masks, and shift helpers compatible with LuaJIT `bit.*` usage |
| `bytes.rs` | Big-endian integer packing (`u8`/`u16`/`u24`/`u32`/`u48`), hex encoding, byte slicing, random payloads (`brandom`) |
| `crypto_api.rs` | `hash` (`sha224`/`sha256`), `hmac`, `hkdf`, `aes`, `aes_ctr`, `aes_gcm` backed by `src/crypto/` |
| `gzip_api.rs` | Streaming `gunzip_init`/`gunzip_inflate`/`gunzip_end` & `gzip_*` using `flate2` (`rust_backend`), with strict decompressed output ceilings to defeat gzip bombs |
| `fs_time_api.rs` | `stat` metadata lookup and POSIX calendar conversion (`localtime`, `gmtime`, `timelocal`, `timegm`) |
| `packet_api.rs` | `dissect`, `reconstruct_dissect`, IPv4/IPv6 text conversion, `csum_*` TCP/UDP/IP checksum calculation |
| `protocol_api.rs` | Payload split-marker resolution (`pos`, TLS SNI/extension offsets) and `tls_mod` ClientHello mutation |
| `desync_api.rs` | `DesyncContextState` (`ctx` userdata), `raw_packet`, `execution_plan`, `instance_cutoff`, `conntrack_feed` (`ctrack_encode.rs`) |
| `rawsend_api.rs` | `rawsend`, `rawsend_dissect` delegating into `Rc<RefCell<dyn PacketSender>>` with `desync_fwmark` preservation |
| `timer_api.rs` | `timer_set`, `timer_del`, and timer callback registration into `TimerPool` |
| `system.rs` | Debug logging, OS detection, monotonic `clock_gettime`, interface/source-IP inspection |

### Stateful Context Borrowing (`SessionCtxGuard`)

During packet dispatch, [src/desync/verdict.rs](../../src/desync/verdict.rs) populates `DesyncContextState` behind a scoped RAII `SessionCtxGuard`. Exiting any return path resets borrowed raw-packet slices and temporary action state cleanly so stale packet pointers cannot outlive an interception callback.

## 3. Monotonic Timer Pool & `--intercept=0` Mode (`src/timer/`)

- **`clock.rs`:** Reads monotonic boottime (`boottime_now`, `boottime_ms`, `boottime_secs`) for flow idle timeouts and timer deadlines.
- **`pool.rs`:** `TimerPool` schedules one-shot or repeating Lua callbacks (enforcing `MIN_TIMER_PERIOD_MS`), computing the earliest pending `Duration` (`duration_until`) used as the `poll()` / Win32 wait timeout in the daemon event loop.
- **`runner.rs`:** `run_no_intercept_callbacks` drives timers, Lua GC, `SIGHUP`, and control-socket commands when running headlessly with `--intercept=0` (e.g., pure timer scripts without packet capture).

## 4. Pure-Rust Cryptography (`src/crypto/`, `src/protocol/quic_crypto.rs`)

QUIC Initial packet decryption requires SHA-256, HKDF-Extract/Expand (with protocol-specific v1/v2/draft-22..32 salts), AES-128-ECB header protection mask generation, and AES-128-GCM AEAD decryption:

- [src/crypto/sha2.rs](../../src/crypto/sha2.rs): FIPS 180-4 SHA-224/SHA-256, RFC 2104 HMAC, and RFC 5869 HKDF (`hkdf_sha2`, `hkdf_sha2_extract`, `hkdf_sha2_expand`).
- [src/crypto/aes.rs](../../src/crypto/aes.rs): FIPS-197 AES-128/192/256 single-block cipher (`AesKey`) and AES-CTR (`aes_ctr_crypt`).
- [src/crypto/aes_gcm.rs](../../src/crypto/aes_gcm.rs): NIST SP 800-38D AES-GCM supporting arbitrary IV lengths via GHASH/J0 computation (`aes_gcm_crypt`), keeping zero OpenSSL or runtime C/asm crypto dependencies (`ring` exists only in `[dev-dependencies]` for cross-verification).
