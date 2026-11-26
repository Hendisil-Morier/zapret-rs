//! Windows WinDivert packet interception loop implementing [`PacketIntercepter`].

/// Lock-free shutdown polling inside the packet capture loop.
use std::sync::atomic::{AtomicBool, Ordering};
/// Periodic timeout callback duration type required by [`PacketIntercepter`].
use std::time::Duration;

/// Typed interception errors returned when `WinDivert.dll` fails to load or capture.
use crate::intercepter::error::IntercepterError;
/// OS-agnostic [`PacketIntercepter`] trait and packet/verdict DTOs.
use crate::intercepter::types::{Decision, PacketIntercepter, QueuedPacket};
/// Dynamic `WinDivert.dll` FFI handle, overlapped I/O struct, and address metadata.
use crate::intercepter::windivert_ffi::{
    Overlapped, WINDIVERT_LAYER_NETWORK, WinDivertAddress, WinDivertApi, WinDivertHandle,
};

/// Default Win32 event wait timeout when `next_timeout()` returns `None`.
const DEFAULT_WAIT_MS: u32 = 50;
/// Maximum single-packet capture buffer size matching IPv4/IPv6 jumbo limits.
const CAPTURE_BUF_LEN: usize = 65_536;

/// Windows WinDivert packet intercepter implementing [`PacketIntercepter`].
pub struct WinDivertIntercepter {
    /// Open WinDivert network-layer handle capturing matching packets.
    handle: WinDivertHandle,
    /// Reusable packet capture buffer avoiding per-packet heap allocations.
    buf: Vec<u8>,
}

impl WinDivertIntercepter {
    /// Loads `WinDivert.dll` and opens a `NETWORK`-layer capture handle for `filter`.
    pub fn bind(filter: &str) -> Result<Self, IntercepterError> {
        let api = WinDivertApi::load()?;
        let handle = api.open(filter, WINDIVERT_LAYER_NETWORK, 0, 0)?;
        Ok(Self {
            handle,
            buf: vec![0u8; CAPTURE_BUF_LEN],
        })
    }

    /// Signals the underlying WinDivert handle to shut down so a blocked capture loop exits.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }
}

impl PacketIntercepter for WinDivertIntercepter {
    /// Captures and dispatches packets through `on_packet` until `stop` becomes `true`.
    fn run_until<F, T>(
        &mut self,
        stop: &AtomicBool,
        mut next_timeout: T,
        mut on_packet: F,
    ) -> Result<(), IntercepterError>
    where
        F: FnMut(&QueuedPacket<'_>) -> Decision,
        T: FnMut() -> Option<Duration>,
    {
        /// Win32 `WAIT_OBJECT_0` (`0`) and `WAIT_TIMEOUT` (`258`).
        const WAIT_OBJECT_0: u32 = 0;
        const WAIT_TIMEOUT: u32 = 258;

        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn CreateEventW(attrs: *const core::ffi::c_void, manual: i32, initial: i32, name: *const u16) -> isize;
            fn ResetEvent(h_event: isize) -> i32;
            fn WaitForSingleObject(h_handle: isize, ms: u32) -> u32;
            fn GetOverlappedResult(h_file: isize, ov: *const Overlapped, bytes: *mut u32, wait: i32) -> i32;
            fn CancelIoEx(h_file: isize, ov: *const Overlapped) -> i32;
            fn CloseHandle(h_object: isize) -> i32;
        }

        // SAFETY: Creating an unnamed manual-reset event requires no external pointers.
        let h_event = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if h_event == 0 {
            return Err(IntercepterError::Io(std::io::Error::last_os_error()));
        }

        let mut addr = WinDivertAddress::default();
        let mut ov = Overlapped { h_event, ..Overlapped::default() };
        let mut pending = false;
        let mut seq = 0u32;
        let mut result = Ok(());

        while !stop.load(Ordering::Acquire) {
            let timeout = next_timeout();
            if stop.load(Ordering::Acquire) {
                break;
            }
            let read_len = if !pending {
                // SAFETY: `h_event` is valid and `ov` is not in use while `!pending`.
                unsafe {
                    let _ = ResetEvent(h_event);
                    ov = Overlapped { h_event, ..Overlapped::default() };
                }
                // SAFETY: `self.buf`, `addr`, and `ov` outlive any pending overlapped I/O because
                // we cancel and wait for `GetOverlappedResult` before returning from `run_until`.
                match unsafe { self.handle.start_recv_ex(&mut self.buf, &mut addr, &mut ov) } {
                    Ok(Some(n)) => n,
                    Ok(None) => {
                        pending = true;
                        continue;
                    }
                    Err(err) => {
                        if !stop.load(Ordering::Acquire) {
                            result = Err(IntercepterError::Io(err));
                        }
                        break;
                    }
                }
            } else {
                let wait_ms = timeout
                    .map_or(DEFAULT_WAIT_MS, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1));
                // SAFETY: `h_event` is a valid Win32 event handle.
                match unsafe { WaitForSingleObject(h_event, wait_ms) } {
                    WAIT_TIMEOUT => continue,
                    WAIT_OBJECT_0 => {
                        pending = false;
                        let mut xfer = 0u32;
                        // SAFETY: `ov` completed because `h_event` is signaled.
                        let ok = unsafe {
                            GetOverlappedResult(self.handle.raw_handle(), &raw const ov, &raw mut xfer, 1)
                        };
                        if ok == 0 {
                            if !stop.load(Ordering::Acquire) {
                                result = Err(IntercepterError::Io(std::io::Error::last_os_error()));
                            }
                            break;
                        }
                        xfer as usize
                    }
                    _ => {
                        result = Err(IntercepterError::Io(std::io::Error::last_os_error()));
                        break;
                    }
                }
            };

            seq = seq.wrapping_add(1);
            let if_idx_str = addr.if_idx().to_string();
            let if_name = (addr.if_idx() > 0).then_some(if_idx_str.as_str());
            let pkt = QueuedPacket {
                packet_id: seq,
                mark: 0,
                ifin: if addr.is_outbound() { None } else { if_name },
                ifout: if addr.is_outbound() { if_name } else { None },
                payload: &self.buf[..read_len],
            };
            match on_packet(&pkt) {
                Decision::Pass => {
                    if let Err(err) = self.handle.send(&self.buf[..read_len], &addr) {
                        result = Err(IntercepterError::Io(err));
                        break;
                    }
                }
                Decision::Replace(mut modified) => {
                    self.handle.calc_checksums(&mut modified, &mut addr);
                    if let Err(err) = self.handle.send(&modified, &addr) {
                        result = Err(IntercepterError::Io(err));
                        break;
                    }
                }
                Decision::Drop => {}
            }
        }

        if pending {
            let mut xfer = 0u32;
            // SAFETY: Cancel and wait synchronously so the kernel releases `self.buf`/`addr`/`ov` before return.
            unsafe {
                let _ = CancelIoEx(self.handle.raw_handle(), &raw const ov);
                let _ = GetOverlappedResult(self.handle.raw_handle(), &raw const ov, &raw mut xfer, 1);
            }
        }
        // SAFETY: `h_event` was created by `CreateEventW` and is no longer referenced.
        unsafe {
            let _ = CloseHandle(h_event);
        }
        result
    }
}
