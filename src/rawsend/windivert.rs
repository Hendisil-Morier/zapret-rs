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

/// Resolves the outbound Windows interface index for `dst` via `GetBestInterfaceEx` when `ifout` is absent.
fn resolve_best_if_idx(dst: IpAddr) -> u32 {
    /// Win32 `AF_INET` address family (`2`).
    const AF_INET: u16 = 2;
    /// Win32 `AF_INET6` address family (`23`).
    const AF_INET6: u16 = 23;

    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetBestInterfaceEx(dest_addr: *const u8, best_if_index: *mut u32) -> u32;
    }

    let mut best_idx = 0u32;
    let rc = match dst {
        IpAddr::V4(v4) => {
            let mut sa = [0u8; 16];
            sa[0..2].copy_from_slice(&AF_INET.to_ne_bytes());
            sa[4..8].copy_from_slice(&v4.octets());
            // SAFETY: `sa` is a 16-byte `SOCKADDR_IN` and `best_idx` is valid writable `DWORD`.
            unsafe { GetBestInterfaceEx(sa.as_ptr(), &raw mut best_idx) }
        }
        IpAddr::V6(v6) => {
            let mut sa = [0u8; 28];
            sa[0..2].copy_from_slice(&AF_INET6.to_ne_bytes());
            sa[8..24].copy_from_slice(&v6.octets());
            // SAFETY: `sa` is a 28-byte `SOCKADDR_IN6` and `best_idx` is valid writable `DWORD`.
            unsafe { GetBestInterfaceEx(sa.as_ptr(), &raw mut best_idx) }
        }
    };
    if rc == 0 { best_idx } else { 0 }
}

/// Parses `"IfIdx"` or `"IfIdx.SubIfIdx"` into `(if_idx, sub_if_idx)` when `if_idx > 0`.
pub fn parse_ifout_indices(ifout: Option<&str>) -> Option<(u32, u32)> {
    let raw = ifout?.trim();
    if let Some((idx_s, sub_s)) = raw.split_once('.') {
        let if_idx = idx_s.parse::<u32>().ok().filter(|&v| v > 0)?;
        let sub_if_idx = sub_s.parse::<u32>().ok()?;
        Some((if_idx, sub_if_idx))
    } else {
        let if_idx = raw.parse::<u32>().ok().filter(|&v| v > 0)?;
        Some((if_idx, 0))
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
        let (if_idx, sub_if_idx) =
            parse_ifout_indices(ifout).unwrap_or_else(|| (resolve_best_if_idx(dst), 0));
        let addr = WinDivertAddress::outbound(if_idx, sub_if_idx, dst.is_ipv6());
        let handle = self.ensure_handle()?;
        handle.send(packet, &addr)?;
        Ok(())
    }
}
