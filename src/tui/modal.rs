//! Centered floating modal popup for granting Linux capabilities (`setcap`) and `sudo` auth.

/// Standard I/O pipe writing for `sudo -S`.
use std::io::Write as _;
/// Subprocess spawning for silent `sudo -n` and `sudo -S` execution.
use std::process::{Command, Stdio};

/// Keyboard event primitives handled while the modal is open.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// `ratatui` overlay (`Clear`), layout, styling, and widget primitives.
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Non-interactive `sudo` credential probe shared with `nftables` setup.
use crate::tools::sudo_needs_password;

/// Operation awaiting confirmation or `sudo` authentication inside [`AuthModal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalPurpose {
    /// Grant `cap_net_admin,cap_net_raw+ep` to the running binary and restart seamlessly.
    GrantCaps,
    /// Authenticate `sudo` once so temporary `nftables` rules can be installed for a scan.
    SudoForScan,
    /// Authenticate `sudo` once so temporary `nftables` rules can be installed for live `nfqws2`.
    SudoForDaemon,
    /// Confirm stopping the remote `nfqws2` daemon process over the control socket.
    ConfirmStopDaemon,
}

/// Outcome produced by [`AuthModal::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalKeyResult {
    /// Input consumed; keep modal open.
    KeepOpen,
    /// User dismissed the modal (`Esc` or `Ctrl+c`).
    Close,
    /// User pressed `Enter` to execute the privileged operation.
    Submit,
}

/// Overwrites all UTF-8 bytes of `secret` with zeros using volatile writes before clearing.
pub fn zeroize_string(secret: &mut String) {
    // SAFETY: writing `0u8` (valid ASCII/UTF-8) to every byte in `0..len` preserves valid UTF-8.
    unsafe {
        let bytes = secret.as_bytes_mut();
        for b in bytes.iter_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    secret.clear();
}

/// Centered floating popup state for capability grants and password-masked `sudo` elevation.
#[derive(Debug)]
pub struct AuthModal {
    /// Action executed once confirmed/authenticated.
    pub purpose: ModalPurpose,
    /// `true` when `sudo -n true` failed and a password must be entered.
    pub needs_password: bool,
    /// Masked password buffer (zeroized on submit, cancel, and `Drop`).
    password: String,
    /// Command preview displayed inside the popup so the user knows exactly what runs.
    pub command_preview: String,
    /// Optional inline error line shown after a failed authentication attempt.
    pub error: Option<String>,
}

impl AuthModal {
    /// Constructs a floating modal for `purpose`, probing whether `sudo` currently needs a password.
    pub fn open(purpose: ModalPurpose, command_preview: String) -> Self {
        Self::with_password_prompt(purpose, command_preview, sudo_needs_password())
    }

    /// Constructs a floating confirmation dialog that requires no `sudo` password entry.
    pub fn confirm(purpose: ModalPurpose, command_preview: String) -> Self {
        Self::with_password_prompt(purpose, command_preview, false)
    }

    /// Deterministic constructor used by offline tests to control `needs_password`.
    pub fn with_password_prompt(
        purpose: ModalPurpose,
        command_preview: String,
        needs_password: bool,
    ) -> Self {
        Self {
            purpose,
            needs_password,
            password: String::new(),
            command_preview,
            error: None,
        }
    }

    /// Returns the number of password characters currently typed (for masked rendering).
    pub fn password_len(&self) -> usize {
        self.password.chars().count()
    }

    /// Takes ownership of the typed password string and zeroizes the modal's internal buffer.
    pub fn take_password(&mut self) -> String {
        let out = self.password.clone();
        zeroize_string(&mut self.password);
        out
    }

    /// Handles keyboard input while this floating modal has focus.
    pub fn handle_key(&mut self, key: KeyEvent) -> ModalKeyResult {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            zeroize_string(&mut self.password);
            return ModalKeyResult::Close;
        }
        match key.code {
            KeyCode::Esc => {
                zeroize_string(&mut self.password);
                ModalKeyResult::Close
            }
            KeyCode::Enter => ModalKeyResult::Submit,
            KeyCode::Backspace if self.needs_password => {
                self.password.pop();
                self.error = None;
                ModalKeyResult::KeepOpen
            }
            KeyCode::Char(c) if self.needs_password => {
                self.password.push(c);
                self.error = None;
                ModalKeyResult::KeepOpen
            }
            _ => ModalKeyResult::KeepOpen,
        }
    }
}

impl Drop for AuthModal {
    /// Zeroizes any remaining password bytes before freeing memory.
    fn drop(&mut self) {
        zeroize_string(&mut self.password);
    }
}

/// Runs `sudo` without leaving the alternate screen (`sudo -n` if `password` is `None`, or `sudo -S`).
pub fn run_sudo_silent(args: &[&str], password: Option<&str>) -> Result<(), String> {
    let mut cmd = Command::new("sudo");
    if password.is_some() {
        cmd.args(["-S", "-p", ""]).args(args).stdin(Stdio::piped());
    } else {
        cmd.arg("-n").args(args).stdin(Stdio::null());
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn sudo: {err}"))?;

    if let Some(pw) = password
        && let Some(mut stdin) = child.stdin.take()
    {
        let _ = stdin.write_all(pw.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting for sudo: {err}"))?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr.lines().find(|l| !l.trim().is_empty()).unwrap_or("authentication failed");
        Err(first.trim().to_owned())
    }
}

/// Computes a centered popup [`Rect`] of at most `(max_w, max_h)` clamped inside `area`.
fn centered_rect(area: Rect, max_w: u16, max_h: u16) -> Rect {
    let w = max_w.min(area.width.saturating_sub(4)).max(24.min(area.width));
    let h = max_h.min(area.height.saturating_sub(2)).max(9.min(area.height));
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect { x, y, width: w, height: h }
}

/// Renders `modal` as a centered floating overlay on top of the active TUI screen.
pub fn draw_auth_modal(frame: &mut Frame, modal: &AuthModal) {
    let popup = centered_rect(frame.area(), 70, 13);
    frame.render_widget(Clear, popup);

    let (title, summary) = match modal.purpose {
        ModalPurpose::GrantCaps => (
            " Grant Network Capabilities ",
            "zapret-rs needs CAP_NET_ADMIN and CAP_NET_RAW (without running as root).",
        ),
        ModalPurpose::SudoForScan => (
            " Authenticate sudo for nftables ",
            "Enter sudo password once to install the temporary zapret_strat_finder table.",
        ),
        ModalPurpose::SudoForDaemon => (
            " Authenticate sudo for nftables ",
            "Enter sudo password once to install temporary queue rules for live nfqws2.",
        ),
        ModalPurpose::ConfirmStopDaemon => (
            " Confirm Stop Daemon ",
            "Send stop over the control socket? System traffic interception will cease.",
        ),
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .title(Span::styled(title, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(Paragraph::new(summary).wrap(Wrap { trim: true }), rows[0]);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Command: ", Style::default().fg(Color::DarkGray)),
            Span::styled(modal.command_preview.as_str(), Style::default().fg(Color::Cyan)),
        ]))
        .wrap(Wrap { trim: true }),
        rows[1],
    );

    if modal.purpose == ModalPurpose::ConfirmStopDaemon {
        let prompt = Paragraph::new(Line::from(Span::styled(
            " Press Enter to stop the remote nfqws2 daemon, or Esc to keep it running.",
            Style::default().fg(Color::Yellow),
        )))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Yellow)));
        frame.render_widget(prompt, rows[2]);
    } else if modal.needs_password {
        let masked = "*".repeat(modal.password_len());
        let input = Paragraph::new(Line::from(vec![
            Span::raw(masked),
            Span::styled("_", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow))
                .title(" sudo password "),
        );
        frame.render_widget(input, rows[2]);
    } else {
        let cached = Paragraph::new(Line::from(Span::styled(
            " sudo credentials cached — press Enter to run immediately",
            Style::default().fg(Color::Green),
        )))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::Green)));
        frame.render_widget(cached, rows[2]);
    }

    if let Some(err) = &modal.error {
        frame.render_widget(
            Paragraph::new(Span::styled(err.as_str(), Style::default().fg(Color::Red))),
            rows[3],
        );
    }

    let action_hint = match modal.purpose {
        ModalPurpose::GrantCaps => "[Enter] Grant & Restart   [Esc] Dismiss",
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon => "[Enter] Authenticate & Continue   [Esc] Cancel",
        ModalPurpose::ConfirmStopDaemon => "[Enter] Stop Remote Daemon   [Esc] Cancel",
    };
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(action_hint, Style::default().fg(Color::Cyan)))),
        rows[4],
    );
}
