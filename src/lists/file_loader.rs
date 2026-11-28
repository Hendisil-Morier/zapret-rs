//! Plaintext and gzip list-file readers, modification signatures, and append/debug-log writers.

/// Filesystem handles and paths for list loading and autohostlist writes.
use std::fs::{File, OpenOptions};
/// Buffered line reading and file seeking for transparent gzip/plain format detection.
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
/// Unix stat nanosecond mtime extraction matching `zapret2`'s `file_mod_signature`.
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
/// Path reference for list files and debug log outputs.
use std::path::Path;
/// Portable wall-clock fallback when Unix `localtime_r` / `MetadataExt` are unavailable.
#[cfg(not(unix))]
use std::time::{SystemTime, UNIX_EPOCH};

/// Multi-member gzip decoder handling concatenated `.gz` hostlist/ipset files.
use flate2::read::MultiGzDecoder;

/// Gzip magic header bytes (`0x1F 0x8B`) checked before selecting the stream decoder.
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// Snapshot of file modification time and byte size (`file_mod_sig` in `helpers.h`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FileModSig
{
    /// Whole seconds component of `st_mtim`.
    pub mtime_sec: i64,
    /// Nanosecond component of `st_mtim`.
    pub mtime_nsec: i64,
    /// File byte size (`st_size`).
    pub size: u64,
}

impl FileModSig
{
    /// Resets the signature to zeroed unknown state (`FILE_MOD_RESET`).
    pub fn reset(&mut self)
    {
        self.mtime_sec = 0;
        self.mtime_nsec = 0;
        self.size = 0;
    }

    /// Reads the current metadata signature for `path` via `stat` (`file_mod_signature`).
    pub fn read(path: &Path) -> std::io::Result<Self>
    {
        let meta = std::fs::metadata(path)?;
        let (mtime_sec, mtime_nsec) = read_mtime_parts(&meta);
        Ok(Self { mtime_sec, mtime_nsec, size: meta.len() })
    }
}

/// Extracts `(seconds, nanoseconds)` modification time from Unix `stat` metadata.
#[cfg(unix)]
fn read_mtime_parts(meta: &std::fs::Metadata) -> (i64, i64)
{
    (meta.mtime(), meta.mtime_nsec())
}

/// Extracts `(seconds, nanoseconds)` modification time from `std::fs::Metadata::modified` on non-Unix targets.
#[cfg(not(unix))]
fn read_mtime_parts(meta: &std::fs::Metadata) -> (i64, i64)
{
    match meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok())
    {
        Some(dur) => (i64::try_from(dur.as_secs()).unwrap_or(i64::MAX), i64::from(dur.subsec_nanos())),
        None => (0, 0),
    }
}

/// Returns `true` when `path` can currently be opened for reading (`file_open_test(..., O_RDONLY)`).
pub fn file_is_readable(path: &Path) -> bool
{
    File::open(path).is_ok()
}

/// Extracts the leading non-whitespace list token from `line`, skipping empty and `#`/`;`/`/` comment lines.
pub fn parse_list_line_token(line: &str) -> Option<&str>
{
    let trimmed = line.trim_start_matches([' ', '\t']);
    let first = trimmed.as_bytes().first().copied()?;
    if matches!(first, b'#' | b';' | b'/' | b'\r' | b'\n' | b'\0')
    {
        return None;
    }
    let end = trimmed.find([' ', '\t', '\r', '\n', '\0']).unwrap_or(trimmed.len());
    let token = &trimmed[..end];
    (!token.is_empty()).then_some(token)
}

/// Detects whether an open file begins with the gzip magic bytes, rewinding the cursor to offset `0`.
pub fn detect_gzip_and_rewind(file: &mut File) -> std::io::Result<bool>
{
    let mut magic = [0u8; 2];
    let mut read_total = 0usize;
    while read_total < magic.len()
    {
        let n = file.read(&mut magic[read_total..])?;
        if n == 0
        {
            break;
        }
        read_total += n;
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(read_total == 2 && magic == GZIP_MAGIC)
}

/// Streams a plaintext or gzip (including multi-member `.gz`) list file line by line into `on_line`.
pub fn read_list_lines<F>(path: &Path, mut on_line: F) -> std::io::Result<()>
where
    F: FnMut(&str),
{
    let mut file = File::open(path)?;
    let is_gzip = detect_gzip_and_rewind(&mut file)?;
    let mut reader: Box<dyn BufRead> = if is_gzip
    {
        Box::new(BufReader::new(MultiGzDecoder::new(file)))
    }
    else
    {
        Box::new(BufReader::new(file))
    };

    let mut raw_buf = Vec::new();
    loop
    {
        raw_buf.clear();
        let n = reader.read_until(b'\n', &mut raw_buf)?;
        if n == 0
        {
            break;
        }
        let line = String::from_utf8_lossy(&raw_buf);
        on_line(&line);
    }

    Ok(())
}

/// Loads `path` for initial startup validation, resetting `mod_sig` before reading.
pub(crate) fn load_list_initial<T>(
    path: Option<&Path>,
    mod_sig: &mut FileModSig,
    target: &mut T,
    mut load_fn: impl FnMut(&Path) -> std::io::Result<T>,
) -> std::io::Result<()>
{
    mod_sig.reset();
    let Some(file_path) = path
    else
    {
        return Ok(());
    };
    let fsig = FileModSig::read(file_path)?;
    let parsed = load_fn(file_path)?;
    *target = parsed;
    *mod_sig = fsig;
    Ok(())
}

/// Reloads a cached file-backed list if its [`FileModSig`] changed, preserving memory on transient access failure.
pub(crate) fn reload_cached_list<T>(
    path: Option<&Path>,
    mod_sig: &mut FileModSig,
    target: &mut T,
    entity_label: &str,
    mut clear_fn: impl FnMut(&mut T),
    mut load_fn: impl FnMut(&Path) -> std::io::Result<T>,
) -> std::io::Result<bool>
{
    let Some(file_path) = path
    else
    {
        return Ok(false);
    };

    let Ok(fsig) = FileModSig::read(file_path)
    else
    {
        eprintln!(
            "cannot access {entity_label} file '{}'. in-memory content remains unchanged.",
            file_path.display()
        );
        return Ok(false);
    };
    if *mod_sig == fsig
    {
        return Ok(false);
    }
    if !file_is_readable(file_path)
    {
        eprintln!(
            "cannot access {entity_label} file '{}'. in-memory content remains unchanged.",
            file_path.display()
        );
        return Ok(false);
    }

    match load_fn(file_path)
    {
        Ok(loaded) =>
        {
            *target = loaded;
            *mod_sig = fsig;
            Ok(true)
        }
        Err(err) =>
        {
            clear_fn(target);
            mod_sig.reset();
            Err(err)
        }
    }
}

/// Appends one hostname/token line to an autohostlist file (`append_to_list_file` in `helpers.c:157`).
pub fn append_to_list_file(path: &Path, entry: &str) -> std::io::Result<()>
{
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{entry}")
}

/// Formats the current local timestamp on Unix via `localtime_r`.
#[cfg(unix)]
fn format_debug_timestamp() -> String
{
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if !unsafe { libc::localtime_r(&raw const now, &raw mut tm) }.is_null()
    {
        format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec
        )
    }
    else
    {
        now.to_string()
    }
}

/// Formats the current UTC epoch seconds on non-Unix targets.
#[cfg(not(unix))]
fn format_debug_timestamp() -> String
{
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| "0".to_owned(), |dur| dur.as_secs().to_string())
}

/// Appends one local-time stamped debug line to `--hostlist-auto-debug` (`LOG_APPEND` in `params.c:254`).
pub fn append_timestamped_debug_log(path: &Path, message: &str) -> std::io::Result<()>
{
    let ts = format_debug_timestamp();
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{ts} : {message}")
}
