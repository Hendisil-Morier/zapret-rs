//! Cross-platform IPC stream transport (`UnixStream` on Unix, loopback `TcpStream` elsewhere).

/// Standard I/O traits and error types for stream reads/writes.
use std::io::{self, Read, Write};
/// Shutdown direction enum shared by `UnixStream` and `TcpStream`.
use std::net::Shutdown;
/// Loopback TCP transport used on non-Unix targets.
#[cfg(not(unix))]
use std::net::TcpStream;
/// Raw FD access on Unix for `SO_PEERCRED`/`getpeereid` and `setsockopt`.
#[cfg(unix)]
use std::os::fd::RawFd;
/// Socket file type check on Unix.
#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;
/// Unix domain socket client stream.
#[cfg(unix)]
use std::os::unix::net::UnixStream;
/// Control socket/rendezvous path type.
use std::path::Path;
/// Socket read/write timeouts.
use std::time::Duration;

/// Connected control IPC stream wrapping `UnixStream` on Unix or loopback `TcpStream` elsewhere.
#[derive(Debug)]
pub struct ControlStream {
    /// Underlying Unix domain stream.
    #[cfg(unix)]
    inner: UnixStream,
    /// Underlying loopback TCP stream on non-Unix targets.
    #[cfg(not(unix))]
    inner: TcpStream,
}

impl ControlStream {
    /// Wraps an accepted `UnixStream` into a [`ControlStream`].
    #[cfg(unix)]
    pub(crate) fn from_unix(inner: UnixStream) -> Self {
        Self { inner }
    }

    /// Wraps an accepted `TcpStream` into a [`ControlStream`].
    #[cfg(not(unix))]
    pub(crate) fn from_tcp(inner: TcpStream) -> Self {
        Self { inner }
    }

    /// Returns the underlying raw file descriptor on Unix.
    #[cfg(unix)]
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        use std::os::fd::AsRawFd;
        self.inner.as_raw_fd()
    }

    /// Connects to an active control endpoint at `path`.
    pub fn connect(path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            UnixStream::connect(path).map(|inner| Self { inner })
        }
        #[cfg(not(unix))]
        {
            let raw = std::fs::read_to_string(path)?;
            let mut lines = raw.lines();
            let port: u16 = lines
                .next()
                .unwrap_or("")
                .trim()
                .parse()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid control port"))?;
            let token = lines.next().unwrap_or("").trim();
            if token.len() != 32 {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid control token"));
            }
            let mut stream = TcpStream::connect(("127.0.0.1", port))?;
            stream.write_all(format!("{token}\n").as_bytes())?;
            Ok(Self { inner: stream })
        }
    }

    /// Clones the underlying socket handle for separate reader/writer threads.
    pub fn try_clone(&self) -> io::Result<Self> {
        self.inner.try_clone().map(|inner| Self { inner })
    }

    /// Sets the socket read timeout.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }

    /// Sets the socket write timeout.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(dur)
    }

    /// Shuts down one or both halves of the underlying socket.
    pub fn shutdown(&self, how: Shutdown) -> io::Result<()> {
        self.inner.shutdown(how)
    }
}

impl Read for ControlStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for ControlStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Returns `true` when `path` is a non-symlink control endpoint accepting connections.
pub fn is_live_control_socket(path: &Path) -> bool {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if meta.file_type().is_symlink() {
        return false;
    }
    #[cfg(unix)]
    if !meta.file_type().is_socket() {
        return false;
    }
    #[cfg(not(unix))]
    if !meta.file_type().is_file() {
        return false;
    }
    ControlStream::connect(path).is_ok()
}

/// Verifies the 32-byte hex session token sent by a connecting loopback TCP client on non-Unix.
#[cfg(not(unix))]
pub(crate) fn verify_loopback_token(stream: &mut ControlStream, expected: &str) -> bool {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
    let mut buf = [0u8; 33];
    let ok = stream.read_exact(&mut buf).is_ok()
        && buf[32] == b'\n'
        && expected.len() == 32
        && buf[..32]
            .iter()
            .zip(expected.as_bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
    let _ = stream.set_read_timeout(None);
    ok
}
