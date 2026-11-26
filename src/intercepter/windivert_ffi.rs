//! Dynamic Win32 `LoadLibraryW` bindings for the WinDivert 2.2 C ABI (`WinDivert.dll`).

/// C string and wide-path encoding for `LoadLibraryW` and `WinDivertOpen`.
use std::ffi::{CString, OsStr, c_char, c_void};
/// Typed OS errors surfaced when `WinDivert.dll` is missing or a WinDivert call fails.
use std::io;
/// Wide UTF-16 path encoding for `LoadLibraryW`.
use std::os::windows::ffi::OsStrExt;
/// Null-safe pointer casting for `GetProcAddress` symbol resolution.
use std::ptr;

/// WinDivert `NETWORK` layer identifier (`WINDIVERT_LAYER_NETWORK`).
pub(crate) const WINDIVERT_LAYER_NETWORK: i32 = 0;
/// WinDivert flag opening a send-only handle (`WINDIVERT_FLAG_SEND_ONLY = 0x0008`; `0x0004` is `RECV_ONLY`).
pub const WINDIVERT_FLAG_SEND_ONLY: u64 = 0x0008;
/// WinDivert `SHUTDOWN_BOTH` mode passed to `WinDivertShutdown`.
pub(crate) const WINDIVERT_SHUTDOWN_BOTH: i32 = 3;
/// Win32 `INVALID_HANDLE_VALUE` sentinel returned by `WinDivertOpen` on error.
const INVALID_HANDLE_VALUE: isize = -1;

/// Raw WinDivert 2.2 `WINDIVERT_ADDRESS` metadata struct (80 bytes, `#[repr(C)]`).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WinDivertAddress {
    /// Capture timestamp in WinDivert ticks.
    pub timestamp: i64,
    /// Packed `Layer` (bits 0..8), `Event` (8..16), `Sniffed`/`Outbound`/`Loopback`/`Impostor`/IP flags.
    pub layer_event_flags: u32,
    /// Reserved alignment padding.
    pub reserved2: u32,
    /// Union payload (`Network.IfIdx` at bytes `0..4`, `Network.SubIfIdx` at bytes `4..8`).
    pub union_bytes: [u8; 64],
}

impl Default for WinDivertAddress {
    /// Returns a zeroed `WinDivertAddress`.
    fn default() -> Self {
        Self {
            timestamp: 0,
            layer_event_flags: 0,
            reserved2: 0,
            union_bytes: [0u8; 64],
        }
    }
}

impl WinDivertAddress {
    /// Constructs an outbound `WINDIVERT_ADDRESS` for raw L3 injection on `(if_idx, sub_if_idx)`.
    pub fn outbound(if_idx: u32, sub_if_idx: u32, is_ipv6: bool) -> Self {
        let mut union_bytes = [0u8; 64];
        union_bytes[0..4].copy_from_slice(&if_idx.to_ne_bytes());
        union_bytes[4..8].copy_from_slice(&sub_if_idx.to_ne_bytes());
        // Bit 17 = Outbound (0x0002_0000), Bit 19 = Impostor (0x0008_0000), Bit 20 = IPv6 (0x0010_0000),
        // Bits 21..23 = IPChecksum | TCPChecksum | UDPChecksum (0x00E0_0000, matching `darkmagic.c`).
        Self {
            layer_event_flags: (1 << 17)
                | (1 << 19)
                | if is_ipv6 { 1 << 20 } else { 0 }
                | (1 << 21)
                | (1 << 22)
                | (1 << 23),
            union_bytes,
            ..Self::default()
        }
    }

    /// Returns `true` when the `Outbound` bit (bit 17) is set in `layer_event_flags`.
    pub(crate) const fn is_outbound(&self) -> bool {
        (self.layer_event_flags & (1 << 17)) != 0
    }

    /// Reads `Network.IfIdx` from the address union.
    pub fn if_idx(&self) -> u32 {
        u32::from_ne_bytes([
            self.union_bytes[0],
            self.union_bytes[1],
            self.union_bytes[2],
            self.union_bytes[3],
        ])
    }
}

/// Win32 `OVERLAPPED` struct passed to `WinDivertRecvEx` for non-blocking timeout waits.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Overlapped {
    /// Internal status (`ULONG_PTR`).
    pub(crate) internal: usize,
    /// Internal transferred count (`ULONG_PTR`).
    pub(crate) internal_high: usize,
    /// Low file offset (unused for WinDivert, must be `0`).
    pub(crate) offset: u32,
    /// High file offset (unused for WinDivert, must be `0`).
    pub(crate) offset_high: u32,
    /// Manual-reset Win32 event handle signaled on completion.
    pub(crate) h_event: isize,
}

/// Function pointer type for `WinDivertOpen`.
type WinDivertOpenFn = unsafe extern "system" fn(*const c_char, i32, i16, u64) -> isize;
/// Function pointer type for `WinDivertRecv`.
type WinDivertRecvFn =
    unsafe extern "system" fn(isize, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
/// Function pointer type for `WinDivertRecvEx`.
type WinDivertRecvExFn = unsafe extern "system" fn(
    isize,
    *mut c_void,
    u32,
    *mut u32,
    u64,
    *mut WinDivertAddress,
    *mut u32,
    *mut Overlapped,
) -> i32;
/// Function pointer type for `WinDivertSend`.
type WinDivertSendFn =
    unsafe extern "system" fn(isize, *const c_void, u32, *mut u32, *const WinDivertAddress) -> i32;
/// Function pointer type for `WinDivertShutdown`.
type WinDivertShutdownFn = unsafe extern "system" fn(isize, i32) -> i32;
/// Function pointer type for `WinDivertClose`.
type WinDivertCloseFn = unsafe extern "system" fn(isize) -> i32;
/// Function pointer type for `WinDivertHelperCalcChecksums`.
type WinDivertCalcChecksumsFn =
    unsafe extern "system" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> i32;

/// Dynamically loaded `WinDivert.dll` function table.
pub(crate) struct WinDivertApi {
    /// Loaded `WinDivert.dll` module handle (`HMODULE`).
    _module: isize,
    /// `WinDivertOpen` entry point.
    open_fn: WinDivertOpenFn,
    /// `WinDivertRecv` entry point.
    recv_fn: WinDivertRecvFn,
    /// `WinDivertRecvEx` entry point.
    recv_ex_fn: WinDivertRecvExFn,
    /// `WinDivertSend` entry point.
    send_fn: WinDivertSendFn,
    /// `WinDivertShutdown` entry point.
    shutdown_fn: WinDivertShutdownFn,
    /// `WinDivertClose` entry point.
    close_fn: WinDivertCloseFn,
    /// `WinDivertHelperCalcChecksums` entry point.
    calc_checksums_fn: WinDivertCalcChecksumsFn,
}

/// Resolves a named symbol from `module` via `GetProcAddress` and transmutes it to `T`.
unsafe fn load_sym<T: Copy>(module: isize, name: &[u8]) -> io::Result<T> {
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetProcAddress(h_module: isize, lp_proc_name: *const c_char) -> *const c_void;
    }
    // SAFETY: `module` is a valid `HMODULE` and `name` is NUL-terminated.
    let ptr = unsafe { GetProcAddress(module, name.as_ptr().cast()) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Caller guarantees `T` matches the WinDivert 2.2 C-ABI signature of `name`.
    Ok(unsafe { std::mem::transmute_copy(&ptr) })
}

impl WinDivertApi {
    /// Loads `WinDivert.dll` via `LoadLibraryW` and resolves the WinDivert 2.2 entry points.
    pub(crate) fn load() -> io::Result<Self> {
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn LoadLibraryW(lp_lib_file_name: *const u16) -> isize;
        }
        let wide: Vec<u16> = OsStr::new("WinDivert.dll")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: `wide` is a NUL-terminated UTF-16 string.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if module == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: Symbol signatures match WinDivert 2.2 (`windivert.h`).
        unsafe {
            Ok(Self {
                _module: module,
                open_fn: load_sym(module, b"WinDivertOpen\0")?,
                recv_fn: load_sym(module, b"WinDivertRecv\0")?,
                recv_ex_fn: load_sym(module, b"WinDivertRecvEx\0")?,
                send_fn: load_sym(module, b"WinDivertSend\0")?,
                shutdown_fn: load_sym(module, b"WinDivertShutdown\0")?,
                close_fn: load_sym(module, b"WinDivertClose\0")?,
                calc_checksums_fn: load_sym(module, b"WinDivertHelperCalcChecksums\0")?,
            })
        }
    }

    /// Opens a WinDivert handle with `filter`, `layer`, `priority`, and `flags`.
    pub(crate) fn open(
        self,
        filter: &str,
        layer: i32,
        priority: i16,
        flags: u64,
    ) -> io::Result<WinDivertHandle> {
        let c_filter = CString::new(filter)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in WinDivert filter"))?;
        // SAFETY: `c_filter` is NUL-terminated and `open_fn` was resolved from `WinDivert.dll`.
        let handle = unsafe { (self.open_fn)(c_filter.as_ptr(), layer, priority, flags) };
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(WinDivertHandle { api: self, handle })
    }
}

/// Owned RAII handle to an open WinDivert session.
pub(crate) struct WinDivertHandle {
    /// Dynamically resolved WinDivert function pointers.
    api: WinDivertApi,
    /// Raw WinDivert kernel handle closed on `Drop`.
    handle: isize,
}

// SAFETY: WinDivert handles are thread-safe kernel handles (`WinDivertShutdown` from another thread).
unsafe impl Send for WinDivertHandle {}
// SAFETY: Concurrent `WinDivertShutdown` with `WinDivertRecv` is thread-safe per WinDivert docs.
unsafe impl Sync for WinDivertHandle {}

impl WinDivertHandle {
    /// Returns the raw Win32 handle for `GetOverlappedResult` / `CancelIoEx`.
    pub(crate) const fn raw_handle(&self) -> isize {
        self.handle
    }

    /// Starts an overlapped receive via `WinDivertRecvEx`, returning `Ok(true)` on immediate
    /// completion or `Ok(false)` when `ERROR_IO_PENDING` (`997`) is returned.
    ///
    /// Callers retrieve the exact byte count via `GetOverlappedResult` so no stack-local
    /// `pRecvLen` pointer is ever handed to asynchronous kernel I/O.
    ///
    /// # Safety
    /// While `Ok(false)` is pending, `buf`, `addr`, `addr_len`, and `overlapped` must remain
    /// pinned/unmoved and untouched until `GetOverlappedResult` (wait=TRUE) completes.
    pub(crate) unsafe fn start_recv_ex(
        &self,
        buf: &mut [u8],
        addr: &mut WinDivertAddress,
        addr_len: &mut u32,
        overlapped: &mut Overlapped,
    ) -> io::Result<bool> {
        /// Win32 `ERROR_IO_PENDING` (`997`).
        const ERROR_IO_PENDING: i32 = 997;
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        *addr_len = u32::try_from(std::mem::size_of::<WinDivertAddress>()).unwrap_or(80);
        // SAFETY: Caller guarantees `buf`, `addr`, `addr_len`, and `overlapped` stay valid until completion.
        let ok = unsafe {
            (self.api.recv_ex_fn)(
                self.handle,
                buf.as_mut_ptr().cast(),
                cap,
                ptr::null_mut(),
                0,
                ptr::from_mut(addr),
                ptr::from_mut(addr_len),
                ptr::from_mut(overlapped),
            )
        };
        if ok != 0 {
            return Ok(true);
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_IO_PENDING) {
            Ok(false)
        } else {
            Err(err)
        }
    }

    /// Receives one packet into `buf` and populates `addr`, returning the byte count read.
    #[allow(dead_code)]
    pub(crate) fn recv(&self, buf: &mut [u8], addr: &mut WinDivertAddress) -> io::Result<usize> {
        let mut read_len = 0u32;
        let cap = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        // SAFETY: `buf` and `addr` point to valid writable memory for `cap` bytes.
        let ok = unsafe {
            (self.api.recv_fn)(
                self.handle,
                buf.as_mut_ptr().cast(),
                cap,
                &raw mut read_len,
                ptr::from_mut(addr),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(read_len as usize)
    }

    /// Sends/reinjects `packet` with `addr` metadata.
    pub(crate) fn send(&self, packet: &[u8], addr: &WinDivertAddress) -> io::Result<usize> {
        let mut send_len = 0u32;
        let len = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        // SAFETY: `packet` and `addr` point to valid readable memory for `len` bytes.
        let ok = unsafe {
            (self.api.send_fn)(
                self.handle,
                packet.as_ptr().cast(),
                len,
                &raw mut send_len,
                ptr::from_ref(addr),
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(send_len as usize)
    }

    /// Recalculates IP/TCP/UDP/ICMP checksums on `packet` via `WinDivertHelperCalcChecksums`.
    pub(crate) fn calc_checksums(&self, packet: &mut [u8], addr: &mut WinDivertAddress) {
        let len = u32::try_from(packet.len()).unwrap_or(u32::MAX);
        // SAFETY: `packet` and `addr` point to valid mutable buffers of `len` bytes.
        let _ = unsafe {
            (self.api.calc_checksums_fn)(packet.as_mut_ptr().cast(), len, ptr::from_mut(addr), 0)
        };
    }

    /// Shuts down both recv and send directions so a blocked `recv()` wakes cleanly.
    pub(crate) fn shutdown(&self) {
        // SAFETY: `handle` is an open WinDivert handle.
        let _ = unsafe { (self.api.shutdown_fn)(self.handle, WINDIVERT_SHUTDOWN_BOTH) };
    }
}

impl Drop for WinDivertHandle {
    /// Closes the underlying WinDivert handle.
    fn drop(&mut self) {
        self.shutdown();
        // SAFETY: `handle` is exclusively owned and closed once on `Drop`.
        let _ = unsafe { (self.api.close_fn)(self.handle) };
    }
}
