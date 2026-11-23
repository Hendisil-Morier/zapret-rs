#[derive(Debug, thiserror::Error)]
pub enum IntercepterError
{
    #[error("Linux queue failed: {0}")]
    IoError(#[from] std::io::Error),
    
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError
{
    #[error("Bad {field} '{input}': {source}")]
    InvalidNumber
    {
        field: &'static str,
        input: String,
        source: std::num::ParseIntError,
    },
}

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
