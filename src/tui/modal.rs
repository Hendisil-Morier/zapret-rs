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
/// Shared centered popup clamping and keycap styling helpers.
use crate::tui::theme::{clamped_centered_rect, styled_key_hints};
/// Active configurable color palette.
use crate::tui::theme_config::Theme;

/// Operation awaiting confirmation or `sudo` authentication inside [`AuthModal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalPurpose
{
    /// Grant `cap_net_admin,cap_net_raw+ep` to the running binary and restart seamlessly.
    GrantCaps,
    /// Authenticate `sudo` once so temporary `nftables` rules can be installed for a scan.
    SudoForScan,
    /// Authenticate `sudo` once so temporary `nftables` rules can be installed for live `nfqws2`.
    SudoForDaemon,
    /// Confirm stopping the remote `nfqws2` daemon process over the control socket.
    ConfirmStopDaemon,
    /// Confirm briefly stopping `nfqws2` to measure baseline speed, then restarting and re-testing.
    ConfirmSpeedTest,
    /// Confirm merging newly scanned profiles into existing `nfqws2.toml` rules.
    ConfirmMergeConfig,
    /// Confirm changing OS DNS servers / encrypted DNS (DoH/DoT) to the selected preset.
    ConfirmApplyDns,
}

/// Outcome produced by [`AuthModal::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModalKeyResult
{
    /// Input consumed; keep modal open.
    KeepOpen,
    /// User dismissed the modal (`Esc` or `Ctrl+c`).
    Close,
    /// User pressed `Enter` to execute the privileged operation.
    Submit,
    /// User chose `k` on [`ModalPurpose::ConfirmMergeConfig`] to keep the existing config untouched.
    KeepExisting,
}

/// Overwrites all UTF-8 bytes of `secret` with zeros using volatile writes before clearing.
pub fn zeroize_string(secret: &mut String)
{
    // SAFETY: writing `0u8` (valid ASCII/UTF-8) to every byte in `0..len` preserves valid UTF-8.
    unsafe {
        let bytes = secret.as_bytes_mut();
        for b in bytes.iter_mut()
        {
            std::ptr::write_volatile(b, 0);
        }
    }
    secret.clear();
}

/// Centered floating popup state for capability grants and password-masked `sudo` elevation.
#[derive(Debug)]
pub struct AuthModal
{
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

impl AuthModal
{
    /// Constructs a floating modal for `purpose`, probing whether `sudo` currently needs a password.
    pub fn open(purpose: ModalPurpose, command_preview: String) -> Self
    {
        Self::with_password_prompt(purpose, command_preview, sudo_needs_password())
    }

    /// Constructs a floating confirmation dialog that requires no `sudo` password entry.
    pub fn confirm(purpose: ModalPurpose, command_preview: String) -> Self
    {
        Self::with_password_prompt(purpose, command_preview, false)
    }

    /// Deterministic constructor used by offline tests to control `needs_password`.
    pub fn with_password_prompt(purpose: ModalPurpose, command_preview: String, needs_password: bool)
    -> Self
    {
        Self { purpose, needs_password, password: String::new(), command_preview, error: None }
    }

    /// Returns the number of password characters currently typed (for masked rendering).
    pub fn password_len(&self) -> usize
    {
        self.password
            .chars()
            .count()
    }

    /// Takes ownership of the typed password string and zeroizes the modal's internal buffer.
    pub fn take_password(&mut self) -> String
    {
        let out = self
            .password
            .clone();
        zeroize_string(&mut self.password);
        out
    }

    /// Handles keyboard input while this floating modal has focus.
    pub fn handle_key(&mut self, key: KeyEvent) -> ModalKeyResult
    {
        if key
            .modifiers
            .contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('c')
        {
            zeroize_string(&mut self.password);
            return ModalKeyResult::Close;
        }
        match key.code
        {
            KeyCode::Esc =>
            {
                zeroize_string(&mut self.password);
                ModalKeyResult::Close
            }
            KeyCode::Enter => ModalKeyResult::Submit,
            KeyCode::Char('k' | 'K')
                if !self.needs_password && self.purpose == ModalPurpose::ConfirmMergeConfig =>
            {
                ModalKeyResult::KeepExisting
            }
            KeyCode::Backspace if self.needs_password =>
            {
                self.password
                    .pop();
                self.error = None;
                ModalKeyResult::KeepOpen
            }
            KeyCode::Char(c)
                if self.needs_password
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.password
                    .push(c);
                self.error = None;
                ModalKeyResult::KeepOpen
            }
            _ => ModalKeyResult::KeepOpen,
        }
    }

    /// Appends pasted text into the secret password buffer and clears any stale auth error.
    pub(crate) fn append_password(&mut self, text: &str)
    {
        self.password
            .push_str(text);
        self.error = None;
    }
}

impl Drop for AuthModal
{
    /// Zeroizes any remaining password bytes before freeing memory.
    fn drop(&mut self)
    {
        zeroize_string(&mut self.password);
    }
}

/// Runs trusted `sudo` without leaving the alternate screen (`sudo -n` if `password` is `None`, or `sudo -S`).
pub fn run_sudo_silent(args: &[&str], password: Option<&str>) -> Result<(), String>
{
    let sudo_bin = crate::runtime::resolve_trusted_system_bin("sudo")
        .map_err(|err| format!("failed to locate trusted sudo: {err}"))?;
    let mut cmd = Command::new(sudo_bin);
    if password.is_some()
    {
        cmd.args(["-S", "-p", ""])
            .args(args)
            .stdin(Stdio::piped());
    }
    else
    {
        cmd.arg("-n")
            .args(args)
            .stdin(Stdio::null());
    }
    let mut child = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("failed to spawn sudo: {err}"))?;

    if let Some(pw) = password
        && let Some(mut stdin) = child
            .stdin
            .take()
    {
        let _ = stdin.write_all(pw.as_bytes());
        let _ = stdin.write_all(b"\n");
    }
    let output = child
        .wait_with_output()
        .map_err(|err| format!("failed waiting for sudo: {err}"))?;
    if output
        .status
        .success()
    {
        Ok(())
    }
    else
    {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let first = stderr
            .lines()
            .find(|l| {
                !l.trim()
                    .is_empty()
            })
            .unwrap_or("authentication failed");
        Err(first
            .trim()
            .to_owned())
    }
}

/// Returns `(title, summary, border_color, action_hint)` for each auth/confirmation [`ModalPurpose`].
fn auth_modal_metadata(purpose: ModalPurpose, t: &Theme)
-> (&'static str, &'static str, Color, &'static str)
{
    let (title, summary) = match purpose
    {
        ModalPurpose::GrantCaps if cfg!(windows) => (
            " Administrator Privileges Required ",
            "WinDivert requires Administrator privileges to capture and inject packets.",
        ),
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
        ModalPurpose::ConfirmSpeedTest if cfg!(windows) => (
            " Confirm Before/After Speed Check ",
            "Temporarily stops WinDivert to measure unprotected baseline, then restarts it and re-tests.",
        ),
        ModalPurpose::ConfirmSpeedTest => (
            " Confirm Before/After Speed Check ",
            "Temporarily stops nfqws2 to measure unprotected baseline, then restarts it and re-tests.",
        ),
        ModalPurpose::ConfirmMergeConfig => (
            " Merge Existing nfqws2.toml Profiles? ",
            "Existing profiles are loaded. Merge new strategy results instead of replacing them?",
        ),
        ModalPurpose::ConfirmApplyDns => (
            " Apply OS DNS Preset? ",
            "Update system DNS servers (and DoH/DoT encryption where supported) on active network adapters?",
        ),
    };
    let border_col = match purpose
    {
        ModalPurpose::ConfirmStopDaemon => t.err,
        ModalPurpose::SudoForScan
        | ModalPurpose::SudoForDaemon
        | ModalPurpose::ConfirmSpeedTest
        | ModalPurpose::ConfirmMergeConfig
        | ModalPurpose::ConfirmApplyDns => t.warn,
        ModalPurpose::GrantCaps => t.accent_bright,
    };
    let action_hint = match purpose
    {
        ModalPurpose::GrantCaps if cfg!(windows) => "[Enter/Esc] Dismiss",
        ModalPurpose::GrantCaps => "[Enter] Grant & Restart   [Esc] Dismiss",
        ModalPurpose::SudoForScan | ModalPurpose::SudoForDaemon =>
        {
            "[Enter] Authenticate & Continue   [Esc] Cancel"
        }
        ModalPurpose::ConfirmStopDaemon => "[Enter] Stop Remote Daemon   [Esc] Cancel",
        ModalPurpose::ConfirmSpeedTest => "[Enter] Run Speed Test   [Esc] Cancel",
        ModalPurpose::ConfirmMergeConfig => "[Enter] Merge Profiles   [k] Keep Existing   [Esc] Replace Only",
        ModalPurpose::ConfirmApplyDns => "[Enter] Apply DNS   [Esc] Cancel",
    };
    (title, summary, border_col, action_hint)
}

/// Renders the middle body (confirmation note, Windows admin banner, or password box) inside `rows[2]`.
fn draw_auth_modal_middle(frame: &mut Frame, area: Rect, modal: &AuthModal, is_confirm: bool, t: &Theme)
{
    if is_confirm
    {
        let note = match modal.purpose
        {
            ModalPurpose::ConfirmMergeConfig =>
            {
                "Choose Merge to update matching slots, Keep Existing to leave disk untouched, or Replace Only to discard old profiles."
            }
            ModalPurpose::ConfirmSpeedTest =>
            {
                "Your unprotected baseline connection will be probed briefly before restarting the engine."
            }
            ModalPurpose::ConfirmApplyDns =>
            {
                "DNS changes affect active network interfaces immediately and can be reverted via the Automatic (DHCP) preset."
            }
            _ => "Packet interception will stop until the daemon is started again.",
        };
        frame.render_widget(
            Paragraph::new(Span::styled(note, Style::default().fg(t.muted))).wrap(Wrap { trim: true }),
            area,
        );
    }
    else if cfg!(windows) && modal.purpose == ModalPurpose::GrantCaps
    {
        let notice = Paragraph::new(Line::from(Span::styled(
            " Right-click zapret-rs.exe and select \"Run as administrator\", then retry.",
            Style::default().fg(t.warn_bright),
        )))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.warn)),
        );
        frame.render_widget(notice, area);
    }
    else if modal.needs_password
    {
        let masked = "*".repeat(modal.password_len());
        let input = Paragraph::new(Line::from(vec![
            Span::styled(masked, Style::default().fg(t.text)),
            Span::styled(
                "_",
                Style::default()
                    .fg(t.warn_bright)
                    .add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.warn))
                .title(Span::styled(" sudo password ", Style::default().fg(t.warn_bright))),
        );
        frame.render_widget(input, area);
    }
    else
    {
        let cached = Paragraph::new(Line::from(Span::styled(
            " sudo credentials cached — press Enter to run immediately",
            Style::default().fg(t.ok_bright),
        )))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.ok)),
        );
        frame.render_widget(cached, area);
    }
}

/// Renders `modal` as a centered floating overlay on top of the active TUI screen using `t`.
pub fn draw_auth_modal(frame: &mut Frame, modal: &AuthModal, t: &Theme)
{
    let is_confirm = matches!(
        modal.purpose,
        ModalPurpose::ConfirmStopDaemon
            | ModalPurpose::ConfirmSpeedTest
            | ModalPurpose::ConfirmMergeConfig
            | ModalPurpose::ConfirmApplyDns
    );
    let popup = clamped_centered_rect(frame.area(), 70, 24, if is_confirm { 11 } else { 13 }, 9);
    frame.render_widget(Clear, popup);

    let (title, summary, border_col, action_hint) = auth_modal_metadata(modal.purpose, t);
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(
            Style::default()
                .fg(border_col)
                .add_modifier(Modifier::BOLD),
        )
        .title(Span::styled(
            title,
            Style::default()
                .fg(t.warn_bright)
                .add_modifier(Modifier::BOLD),
        ));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let middle_height = if is_confirm { 2 } else { 3 };
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(middle_height),
            Constraint::Length(1),
            Constraint::Min(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Span::styled(summary, Style::default().fg(t.text))).wrap(Wrap { trim: true }),
        rows[0],
    );
    let preview_label = if is_confirm { "Action : " } else { "Command: " };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(preview_label, Style::default().fg(t.subtle)),
            Span::styled(
                modal
                    .command_preview
                    .as_str(),
                Style::default().fg(t.accent_bright),
            ),
        ]))
        .wrap(Wrap { trim: true }),
        rows[1],
    );

    draw_auth_modal_middle(frame, rows[2], modal, is_confirm, t);

    if let Some(err) = &modal.error
    {
        frame.render_widget(
            Paragraph::new(Span::styled(err.as_str(), Style::default().fg(t.err_bright))),
            rows[3],
        );
    }

    frame.render_widget(Paragraph::new(Line::from(styled_key_hints(action_hint, t))), rows[4]);
}
