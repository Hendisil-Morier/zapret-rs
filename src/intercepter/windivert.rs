//! Windows WinDivert packet interception loop implementing [`PacketIntercepter`].

/// Shared kernel/FFI interior mutability without `&mut` aliasing UB during pending overlapped I/O.
use std::cell::UnsafeCell;
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
/// Maximum single-packet capture buffer size matching IPv4/IPv6 jumbo limits.
const CAPTURE_BUF_LEN: usize = 65_536;

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

impl Win32Event
{
    /// Creates an unnamed manual-reset Win32 event handle.
    fn new() -> std::io::Result<Self>
    {
        // SAFETY: Creating an unnamed manual-reset event requires no external pointers.
        let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
        if handle == 0 { Err(std::io::Error::last_os_error()) } else { Ok(Self(handle)) }
    }
}

impl Drop for Win32Event
{
    /// Closes the underlying Win32 event handle.
    fn drop(&mut self)
    {
        // SAFETY: `self.0` was created by `CreateEventW`.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

/// Windows WinDivert packet intercepter implementing [`PacketIntercepter`].
pub struct WinDivertIntercepter
{
    /// Open WinDivert network-layer handle capturing matching packets.
    handle: WinDivertHandle,
}

impl WinDivertIntercepter
{
    /// Loads `WinDivert.dll` and opens a `NETWORK`-layer capture handle for `filter`.
    pub fn bind(filter: &str) -> Result<Self, IntercepterError>
    {
        let api = WinDivertApi::load()?;
        let handle = api.open(filter, WINDIVERT_LAYER_NETWORK, 0, 0)?;
        Ok(Self { handle })
    }

    /// Signals the underlying WinDivert handle to shut down so a blocked capture loop exits.
    pub fn shutdown(&self)
    {
        self.handle
            .shutdown();
    }

    /// Applies `decision` to `raw_packet` using `addr`.
    fn apply_decision(
        &self,
        decision: Decision,
        raw_packet: &[u8],
        addr: &mut WinDivertAddress,
    ) -> Result<(), IntercepterError>
    {
        match decision
        {
            Decision::Pass =>
            {
                self.handle
                    .send(raw_packet, addr)?;
            }
            Decision::Replace(mut modified) =>
            {
                self.handle
                    .calc_checksums(&mut modified, addr);
                self.handle
                    .send(&modified, addr)?;
            }
            Decision::Drop =>
            {}
        }
        Ok(())
    }
}

/// Outcome of one overlapped WinDivert receive step.
enum RecvStep
{
    /// Packet arrived (`len` bytes available in heap buffer).
    Ready(usize),
    /// Timed out waiting on `h_event`; caller should run `next_timeout()` and wait again.
    TimedOut,
    /// Receive aborted cleanly due to `stop`.
    Stopped,
}

/// Heap-pinned I/O state accessed only through raw pointers while overlapped I/O is pending.
struct PinnedRecvIo
{
    /// Win32 `OVERLAPPED` structure owned exclusively until completion or `CancelIoEx`.
    overlapped: UnsafeCell<Overlapped>,
    /// Captured WinDivert address metadata written asynchronously by the driver.
    addr: UnsafeCell<WinDivertAddress>,
    /// Output address-length word required by `WinDivertRecvEx`.
    addr_len: UnsafeCell<u32>,
    /// Heap-allocated packet buffer whose address stays stable across timeouts.
    buf: UnsafeCell<Box<[u8]>>,
}

/// Drop-safe overlapped receive state machine guaranteeing `CancelIoEx` before freeing heap I/O buffers.
struct OverlappedRecvGuard<'a>
{
    /// Open WinDivert handle issuing overlapped receives.
    handle: &'a WinDivertHandle,
    /// Manual-reset Win32 event referenced by `io.overlapped.h_event`.
    event: Win32Event,
    /// Heap-pinned I/O target memory preserved across both normal exit and panic unwind.
    io: Box<PinnedRecvIo>,
    /// `true` while kernel I/O holds pointers to `self.io`.
    pending: bool,
}

impl<'a> OverlappedRecvGuard<'a>
{
    /// Allocates heap-pinned overlapped capture buffers bound to `handle`.
    fn new(handle: &'a WinDivertHandle) -> std::io::Result<Self>
    {
        let event = Win32Event::new()?;
        let io = Box::new(PinnedRecvIo {
            overlapped: UnsafeCell::new(Overlapped { h_event: event.0, ..Overlapped::default() }),
            addr: UnsafeCell::new(WinDivertAddress::default()),
            addr_len: UnsafeCell::new(0),
            buf: UnsafeCell::new(vec![0u8; CAPTURE_BUF_LEN].into_boxed_slice()),
        });
        Ok(Self { handle, event, io, pending: false })
    }

    /// Completes a signaled/finished overlapped receive and returns its transferred byte count.
    fn finish_overlapped(&self, stop: &AtomicBool) -> Result<RecvStep, IntercepterError>
    {
        let mut xfer = 0u32;
        // SAFETY: `io.overlapped` stays pinned until `GetOverlappedResult` completes synchronously.
        let ok = unsafe {
            GetOverlappedResult(
                self.handle
                    .raw_handle(),
                self.io
                    .overlapped
                    .get(),
                &raw mut xfer,
                1,
            )
        };
        if ok != 0
        {
            return Ok(RecvStep::Ready(xfer as usize));
        }
        if stop.load(Ordering::Acquire)
        {
            Ok(RecvStep::Stopped)
        }
        else
        {
            Err(IntercepterError::Io(std::io::Error::last_os_error()))
        }
    }

    /// Polls or initiates an overlapped `WinDivertRecvEx` wait bounded by `wait_ms`.
    fn poll_step(&mut self, wait_ms: u32, stop: &AtomicBool) -> Result<RecvStep, IntercepterError>
    {
        if !self.pending
        {
            // SAFETY: No kernel I/O is pending (`!self.pending`), so resetting `overlapped` is exclusive.
            unsafe {
                let _ = ResetEvent(
                    self.event
                        .0,
                );
                self.io
                    .overlapped
                    .get()
                    .write(Overlapped {
                        h_event: self
                            .event
                            .0,
                        ..Overlapped::default()
                    });
            }
            // SAFETY: `buf` is heap-allocated and no `&mut` references exist while `pending` can become `true`.
            let (buf_ptr, buf_cap) = unsafe {
                let slice = &mut *self
                    .io
                    .buf
                    .get();
                (slice.as_mut_ptr(), u32::try_from(slice.len()).unwrap_or(u32::MAX))
            };
            // SAFETY: `Drop` guarantees `CancelIoEx` + `GetOverlappedResult` wait before `self.io` frees.
            match unsafe {
                self.handle
                    .start_recv_ex(
                        buf_ptr,
                        buf_cap,
                        self.io
                            .addr
                            .get(),
                        self.io
                            .addr_len
                            .get(),
                        self.io
                            .overlapped
                            .get(),
                    )
            }
            {
                Ok(true) => return self.finish_overlapped(stop),
                Ok(false) =>
                {
                    self.pending = true;
                    return Ok(RecvStep::TimedOut);
                }
                Err(err) if stop.load(Ordering::Acquire) =>
                {
                    let _ = err;
                    return Ok(RecvStep::Stopped);
                }
                Err(err) => return Err(IntercepterError::Io(err)),
            }
        }

        // SAFETY: `self.event.0` stays valid until after `Drop` drains pending I/O.
        let wait_rc = unsafe {
            WaitForSingleObject(
                self.event
                    .0,
                wait_ms,
            )
        };
        if wait_rc == WAIT_TIMEOUT
        {
            return Ok(RecvStep::TimedOut);
        }
        if wait_rc != WAIT_OBJECT_0
        {
            return Err(IntercepterError::Io(std::io::Error::last_os_error()));
        }
        self.pending = false;
        self.finish_overlapped(stop)
    }

    /// Returns an immutable view of the completed packet payload and a copy of `WinDivertAddress`.
    /// Call only immediately after `poll_step` returns `RecvStep::Ready(len)`.
    fn completed_packet(&self, len: usize) -> (&[u8], WinDivertAddress)
    {
        debug_assert!(!self.pending);
        // SAFETY: `pending` is `false`, so no kernel writes are in flight against `io`.
        unsafe {
            let addr = *self
                .io
                .addr
                .get();
            let buf = &(&*self
                .io
                .buf
                .get())[..len];
            (buf, addr)
        }
    }
}

impl Drop for OverlappedRecvGuard<'_>
{
    /// Cancels and synchronously drains any in-flight kernel IRP before `io` and `event` drop.
    fn drop(&mut self)
    {
        if self.pending
        {
            let mut xfer = 0u32;
            // SAFETY: `self.io` and `self.event` stay live until `GetOverlappedResult(..., TRUE)` finishes.
            unsafe {
                let _ = CancelIoEx(
                    self.handle
                        .raw_handle(),
                    self.io
                        .overlapped
                        .get(),
                );
                let _ = GetOverlappedResult(
                    self.handle
                        .raw_handle(),
                    self.io
                        .overlapped
                        .get(),
                    &raw mut xfer,
                    1,
                );
            }
            self.pending = false;
        }
    }
}

impl PacketIntercepter for WinDivertIntercepter
{
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
        let mut guard = OverlappedRecvGuard::new(&self.handle)?;
        let mut seq = 0u32;

        while !stop.load(Ordering::Acquire)
        {
            let timeout = next_timeout();
            if stop.load(Ordering::Acquire)
            {
                break;
            }
            let wait_ms = timeout.map_or(DEFAULT_WAIT_MS, |d| {
                u32::try_from(d.as_millis())
                    .unwrap_or(u32::MAX)
                    .max(1)
            });
            let read_len = match guard.poll_step(wait_ms, stop)?
            {
                RecvStep::Ready(n) => n,
                RecvStep::TimedOut => continue,
                RecvStep::Stopped => break,
            };

            seq = seq.wrapping_add(1);
            let (raw_pkt, mut addr) = guard.completed_packet(read_len);
            let if_idx_str = format!("{}.{}", addr.if_idx(), addr.sub_if_idx());
            let if_name = (addr.if_idx() > 0).then_some(if_idx_str.as_str());
            let pkt = QueuedPacket {
                packet_id: seq,
                mark: 0,
                ifin: if addr.is_outbound() { None } else { if_name },
                ifout: if addr.is_outbound() { if_name } else { None },
                payload: raw_pkt,
            };
            let decision = on_packet(&pkt);
            self.apply_decision(decision, raw_pkt, &mut addr)?;
        }
        Ok(())
    }
}
