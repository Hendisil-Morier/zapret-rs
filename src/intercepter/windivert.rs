//! Windows WinDivert packet interception loop implementing [`PacketIntercepter`].

/// Lock-free shutdown polling inside the packet capture loop.
use std::sync::atomic::{AtomicBool, Ordering};
/// Periodic timeout callback duration type required by [`PacketIntercepter`].
use std::time::Duration;

/// Typed interception errors returned when `WinDivert.dll` fails to load or capture.
use crate::intercepter::error::IntercepterError;
/// OS-agnostic [`PacketIntercepter`] trait and packet/verdict DTOs.
use crate::intercepter::types::{Decision, PacketIntercepter, QueuedPacket};
/// Dynamic `WinDivert.dll` FFI handle and address metadata.
use crate::intercepter::windivert_ffi::{
    WINDIVERT_LAYER_NETWORK, WinDivertAddress, WinDivertApi, WinDivertHandle,
};

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
        let mut seq = 0u32;
        while !stop.load(Ordering::Acquire) {
            let _ = next_timeout();
            let mut addr = WinDivertAddress::default();
            let read_len = match self.handle.recv(&mut self.buf, &mut addr) {
                Ok(n) => n,
                Err(err) => {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    return Err(IntercepterError::Io(err));
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
                    self.handle.send(&self.buf[..read_len], &addr)?;
                }
                Decision::Replace(mut modified) => {
                    self.handle.calc_checksums(&mut modified, &mut addr);
                    self.handle.send(&modified, &addr)?;
                }
                Decision::Drop => {}
            }
        }
        Ok(())
    }
}
