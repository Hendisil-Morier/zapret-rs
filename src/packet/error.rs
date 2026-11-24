
#[derive(Debug, thiserror::Error)]
pub enum PacketError
{
    #[error("Packet ended unexpectedly")]
    Truncated,
    
    #[error("Unsupported IP version: {0}")]
    UnsupportedVersion(u8),
    
    #[error("Unsupported protocol number: {0}")]
    UnsupportedProtocol(u8),
    
    #[error("Invalid header length: {0} bytes")]
    InvalidHeaderLen(usize),
}