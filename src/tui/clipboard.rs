//! System clipboard and terminal OSC 52 I/O helpers plus single-line paste sanitization.

/// Standard I/O streams and terminal TTY detection for OSC 52 clipboard emission.
use std::io::{self, IsTerminal, Write};
/// Child process spawning for native clipboard read/write utilities (`clip`, `powershell`, `wl-copy`/`wl-paste`, `xclip`, `xsel`, `pbcopy`/`pbpaste`).
use std::process::{Command, Stdio};

/// Encodes arbitrary bytes into standard RFC 4648 base64 for terminal OSC 52 sequences.
fn encode_base64(bytes: &[u8]) -> String
{
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(
        bytes
            .len()
            .div_ceil(3)
            * 4,
    );
    for chunk in bytes.chunks(3)
    {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(
            *chunk
                .get(1)
                .unwrap_or(&0),
        );
        let b2 = u32::from(
            *chunk
                .get(2)
                .unwrap_or(&0),
        );
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
        out.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
    }
    out
}

/// Pipes `text` into an external clipboard write helper and reports exit success.
fn run_clipboard_write(program: &str, args: &[&str], text: &str) -> bool
{
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else
    {
        return false;
    };
    if let Some(mut stdin) = child
        .stdin
        .take()
    {
        let _ = stdin.write_all(text.as_bytes());
    }
    child
        .wait()
        .is_ok_and(|st| st.success())
}

/// Captures UTF-8 text from an external clipboard read helper when exit status succeeds.
fn run_clipboard_read(program: &str, args: &[&str]) -> Option<String>
{
    let out = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Copies `text` via terminal OSC 52 and native OS clipboard utilities.
pub fn copy_to_clipboard(text: &str) -> Result<&'static str, String>
{
    let mut osc52_ok = false;
    if io::stdout().is_terminal()
    {
        let b64 = encode_base64(text.as_bytes());
        let mut out = io::stdout().lock();
        if write!(out, "\x1b]52;c;{b64}\x07").is_ok()
            && out
                .flush()
                .is_ok()
        {
            osc52_ok = true;
        }
    }
    #[cfg(target_os = "macos")]
    let os_ok = run_clipboard_write("pbcopy", &[], text);
    #[cfg(windows)]
    let os_ok = run_clipboard_write("clip", &[], text);
    #[cfg(all(unix, not(target_os = "macos")))]
    let os_ok = (std::env::var_os("WAYLAND_DISPLAY").is_some() && run_clipboard_write("wl-copy", &[], text))
        || run_clipboard_write("xclip", &["-selection", "clipboard"], text)
        || run_clipboard_write("xsel", &["--clipboard", "--input"], text);

    match (os_ok, osc52_ok)
    {
        (true, true) => Ok("clipboard & OSC 52"),
        (true, false) => Ok("clipboard"),
        (false, true) => Ok("terminal OSC 52"),
        (false, false) => Err("no clipboard tool (wl-copy/xclip/xsel) and non-TTY stdout".to_owned()),
    }
}

/// Reads plain text from the active OS clipboard helper (`powershell`, `wl-paste`, `xclip`, `xsel`, `pbpaste`).
pub fn paste_from_clipboard() -> Result<String, String>
{
    #[cfg(target_os = "macos")]
    let text = run_clipboard_read("pbpaste", &[]);
    #[cfg(windows)]
    let text =
        run_clipboard_read("powershell", &["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"]);
    #[cfg(all(unix, not(target_os = "macos")))]
    let text = std::env::var_os("WAYLAND_DISPLAY")
        .and_then(|_| run_clipboard_read("wl-paste", &["--no-newline"]))
        .or_else(|| run_clipboard_read("xclip", &["-o", "-selection", "clipboard"]))
        .or_else(|| run_clipboard_read("xsel", &["--clipboard", "--output"]));

    text.ok_or_else(|| "no clipboard reader available (try terminal bracketed paste)".to_owned())
}

/// Sanitizes pasted text for single-line TUI fields by collapsing whitespace controls cleanly.
pub fn sanitize_paste_text(raw: &str) -> String
{
    raw.trim_matches(['\r', '\n'])
        .chars()
        .map(|c| if matches!(c, '\r' | '\n' | '\t') { ' ' } else { c })
        .filter(|c| !c.is_control())
        .collect()
}
