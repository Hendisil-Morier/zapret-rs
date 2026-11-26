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
/// Win32 `WAIT_OBJECT_0` (`0`).
const WAIT_OBJECT_0: u32 = 0;
/// Win32 `WAIT_TIMEOUT` (`258`).
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

/// RAII wrapper around a manual-reset Win32 event handle.
struct Win32Event(isize);

impl Win32Event {
    /// Creates an unnamed manual-reset Win32 event handle.
    fn new() -> std::io::Result<Self> {
        // SAFETY: Creating an unnamed manual-reset event requires no external pointers.
        let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if handle == 0 { Err(std::io::Error::last_os_error()) } else { Ok(Self(handle)) }
    }
}

impl Drop for Win32Event {
    /// Closes the underlying Win32 event handle.
    fn drop(&mut self) {
        // SAFETY: `self.0` was created by `CreateEventW`.
        unsafe { let _ = CloseHandle(self.0); }
    }
}

/// Windows WinDivert packet intercepter implementing [`PacketIntercepter`].
pub struct WinDivertIntercepter {
    /// Open WinDivert network-layer handle capturing matching packets.
    handle: WinDivertHandle,
    /// Reusable packet capture buffer avoiding per-packet heap allocations.
    buf: Vec<u8>,
}

/// Maximum single-packet capture buffer size matching IPv4/IPv6 jumbo limits.
const CAPTURE_BUF_LEN: usize = 65_536;

impl WinDivertIntercepter {
    /// Loads `WinDivert.dll` and opens a `NETWORK`-layer capture handle for `filter`.
    pub fn bind(filter: &str) -> Result<Self, IntercepterError> {
        let api = WinDivertApi::load()?;
        let handle = api.open(filter, WINDIVERT_LAYER_NETWORK, 0, 0)?;
        Ok(Self { handle, buf: vec![0u8; CAPTURE_BUF_LEN] })
    }

    /// Signals the underlying WinDivert handle to shut down so a blocked capture loop exits.
    pub fn shutdown(&self) {
        self.handle.shutdown();
    }

    /// Applies `decision` to the captured packet in `self.buf[..read_len]` using `addr`.
    fn apply_decision(
        &self,
        decision: Decision,
        read_len: usize,
        addr: &mut WinDivertAddress,
    ) -> Result<(), IntercepterError> {
        match decision {
            Decision::Pass => {
                self.handle.send(&self.buf[..read_len], addr)?;
            }
            Decision::Replace(mut modified) => {
                self.handle.calc_checksums(&mut modified, addr);
                self.handle.send(&modified, addr)?;
            }
            Decision::Drop => {}
        }
        Ok(())
    }
}

/// Outcome of one overlapped WinDivert receive step.
enum RecvStep {
    /// Packet arrived (`len` bytes in buffer).
    Ready(usize),
    /// Timed out waiting on `h_event`; caller should run `next_timeout()` and wait again.
    TimedOut,
    /// Receive aborted cleanly due to `stop`.
    Stopped,
}

/// Completes a signaled/finished overlapped receive and returns its transferred byte count.
fn finish_overlapped(
    handle: &WinDivertHandle,
    ov: &Overlapped,
    stop: &AtomicBool,
) -> Result<RecvStep, IntercepterError> {
    let mut xfer = 0u32;
    // SAFETY: `ov` has completed (either synchronously or via `WAIT_OBJECT_0`).
    let ok = unsafe { GetOverlappedResult(handle.raw_handle(), &raw const *ov, &raw mut xfer, 1) };
    if ok != 0 {
        return Ok(RecvStep::Ready(xfer as usize));
    }
    if stop.load(Ordering::Acquire) {
        Ok(RecvStep::Stopped)
    } else {
        Err(IntercepterError::Io(std::io::Error::last_os_error()))
    }
}

/// Advances an overlapped `WinDivertRecvEx` state machine by one step (<= `wait_ms`).
#[allow(clippy::too_many_arguments)]
fn poll_recv_ex(
    handle: &WinDivertHandle,
    buf: &mut [u8],
    addr: &mut WinDivertAddress,
    addr_len: &mut u32,
    ov: &mut Overlapped,
    pending: &mut bool,
    wait_ms: u32,
    stop: &AtomicBool,
) -> Result<RecvStep, IntercepterError> {
    if !*pending {
        // SAFETY: `ov.h_event` is valid and `ov` is idle while `!*pending`.
        unsafe {
            let _ = ResetEvent(ov.h_event);
            *ov = Overlapped { h_event: ov.h_event, ..Overlapped::default() };
        }
        // SAFETY: Caller cancels and drains `ov` before `buf`, `addr`, `addr_len`, or `ov` drop.
        match unsafe { handle.start_recv_ex(buf, addr, addr_len, ov) } {
            Ok(true) => return finish_overlapped(handle, ov, stop),
            Ok(false) => {
                *pending = true;
                return Ok(RecvStep::TimedOut);
            }
            Err(err) if stop.load(Ordering::Acquire) => {
                let _ = err;
                return Ok(RecvStep::Stopped);
            }
            Err(err) => return Err(IntercepterError::Io(err)),
        }
    }

    // SAFETY: `ov.h_event` is a valid Win32 event handle.
    let wait_rc = unsafe { WaitForSingleObject(ov.h_event, wait_ms) };
    if wait_rc == WAIT_TIMEOUT {
        return Ok(RecvStep::TimedOut);
    }
    if wait_rc != WAIT_OBJECT_0 {
        return Err(IntercepterError::Io(std::io::Error::last_os_error()));
    }
    *pending = false;
    finish_overlapped(handle, ov, stop)
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
        let event = Win32Event::new()?;
        let mut addr = WinDivertAddress::default();
        let mut addr_len = 0u32;
        let mut ov = Overlapped { h_event: event.0, ..Overlapped::default() };
        let mut pending = false;
        let mut seq = 0u32;
        let mut result = Ok(());

        while !stop.load(Ordering::Acquire) {
            let timeout = next_timeout();
            if stop.load(Ordering::Acquire) {
                break;
            }
            let wait_ms = timeout
                .map_or(DEFAULT_WAIT_MS, |d| u32::try_from(d.as_millis()).unwrap_or(u32::MAX).max(1));
            let step = poll_recv_ex(
                &self.handle,
                &mut self.buf,
                &mut addr,
                &mut addr_len,
                &mut ov,
                &mut pending,
                wait_ms,
                stop,
            );
            let read_len = match step {
                Ok(RecvStep::Ready(n)) => n,
                Ok(RecvStep::TimedOut) => continue,
                Ok(RecvStep::Stopped) => break,
                Err(err) => {
                    result = Err(err);
                    break;
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
            let decision = on_packet(&pkt);
            if let Err(err) = self.apply_decision(decision, read_len, &mut addr) {
                result = Err(err);
                break;
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
        result
    }
}
