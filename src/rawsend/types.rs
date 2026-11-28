//! OS-agnostic raw L3 packet injection contract.

/// Standard IP address enum for IPv4/IPv6 dispatch.
use std::net::IpAddr;

/// Typed errors returned during raw socket setup or packet injection.
use crate::rawsend::error::RawSendError;

/// Trait abstracting raw L3 packet injection so Lua bindings and desync logic can be tested without `CAP_NET_RAW`.
pub trait PacketSender
{
    /// Sends a single raw IPv4 or IPv6 packet toward `dst` with firewall mark `fwmark` and optional `ifout`.
    fn send(
        &mut self,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>;

    /// Sends `packet` `repeats` consecutive times with identical routing metadata.
    fn send_repeat(
        &mut self,
        repeats: usize,
        dst: IpAddr,
        fwmark: u32,
        ifout: Option<&str>,
        packet: &[u8],
    ) -> Result<(), RawSendError>
    {
        for _ in 0..repeats
        {
            self.send(dst, fwmark, ifout, packet)?;
        }
        Ok(())
    }
}
