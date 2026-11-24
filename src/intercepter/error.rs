#[derive(Debug, thiserror::Error)]
pub enum IntercepterError
{
    #[error("Linux queue failed: {0}")]
    IoError(#[from] std::io::Error),
}
