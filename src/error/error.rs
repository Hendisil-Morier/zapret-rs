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