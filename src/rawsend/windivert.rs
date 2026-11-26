//! Windows WinDivert `WINDIVERT_FLAG_SEND_ONLY` raw L3 packet injector.

/// Standard IPv4/IPv6 destination address enum.
use std::net::IpAddr;

/// Dynamic `WinDivert.dll` FFI loader and `SEND_ONLY` handle.
use crate::intercepter::windivert_ffi::{
    WINDIVERT_FLAG_SEND_ONLY, WINDIVERT_LAYER_NETWORK, WinDivertAddress, WinDivertApi,
    WinDivertHandle,
};
/// Typed raw-send error variants.
use crate::rawsend::error::RawSendError;
/// OS-agnostic [`PacketSender`] trait.
use crate::rawsend::types::PacketSender;

/// Windows raw L3 packet injector backed by a lazy `WinDivertOpen("false", SEND_ONLY)` handle.
#[derive(Default)]
pub struct WinDivertSender {
    /// Lazily opened WinDivert send-only handle.
    handle: Option<WinDivertHandle>,
}

impl WinDivertSender {
    /// Creates a new [`WinDivertSender`] that opens `WinDivert.dll` on first send.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the open send-only handle, loading `WinDivert.dll` lazily if needed.
    fn ensure_handle(&mut self) -> Result<&WinDivertHandle, RawSendError> {
        if self.handle.is_none() {
            let api = WinDivertApi::load()?;
            let handle = api.open("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY)?;
            self.handle = Some(handle);
        }
        self.handle
            .as_ref()
            .ok_or_else(|| RawSendError::SocketIo(std::io::Error::other("WinDivert handle missing")))
    }
}

impl PacketSender for WinDivertSender {
    /// Injects one raw IPv4 or IPv6 packet via WinDivert's `SEND_ONLY` handle.
    fn send(
        &mut self,
        dst: IpAddr,
        _fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError> {
        let if_idx = ifout.and_then(|s| s.parse::<u32>().ok()).unwrap_or(0);
        let addr = WinDivertAddress::outbound(if_idx, dst.is_ipv6());
        let handle = self.ensure_handle()?;
        handle.send(packet, &addr)?;
        Ok(())
    }
}
