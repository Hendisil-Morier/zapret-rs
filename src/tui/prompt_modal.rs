//! Centered floating plain-text prompt modal for Blacklist, Auto Hostlist, and Web UI actions.

/// Keyboard event modifiers and key codes handled while the prompt popup has focus.
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
/// `ratatui` overlay widgets (`Clear`, layout, bordered inputs, styled spans).
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, Paragraph, Wrap},
};

/// Shared centered popup clamping and keycap badge styling helpers.
use crate::tui::theme::{clamped_centered_rect, styled_key_hints};
/// Active configurable TUI color palette.
use crate::tui::theme_config::Theme;
/// Shared inline text buffer editor and outcome signal.
use crate::tui::types::{TextInputOutcome, handle_inline_text_key};

/// Target operation performed when [`PromptModal`] submits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKind
{
    /// Exclude a domain from DPI bypass across all profiles (`hostlist_exclude_domains`).
    BlacklistDomain,
    /// Append a blocked domain to the configured `autohostlist.txt` file.
    AddAutoHostlist,
    /// Choose LAN (`0.0.0.0:8787`) or localhost (`127.0.0.1:8787`) binding to start the Web UI.
    LaunchWebUi,
}

/// Keyboard handling result returned by [`PromptModal::handle_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptKeyResult
{
    /// Input consumed; keep modal open.
    KeepOpen,
    /// Dismissed via `Esc` or `Ctrl+c`.
    Close,
    /// Confirmed via `Enter`.
    Submit,
}

/// Centered plain-text input modal for Tab 3 domain list management.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptModal
{
    /// Target operation selector.
    pub kind: PromptKind,
    /// Plain-text user input buffer (domain hostname).
    pub input: String,
    /// Optional inline validation error displayed below the input field.
    pub error: Option<String>,
}

impl PromptModal
{
    /// Opens a fresh prompt modal for `kind`.
    pub fn open(kind: PromptKind) -> Self
    {
        Self { kind, input: String::new(), error: None }
    }

    /// Consumes and clears keyboard events when this modal is active.
    pub fn handle_key(&mut self, key: KeyEvent) -> PromptKeyResult
    {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c')
        {
            return PromptKeyResult::Close;
        }
        if self.kind == PromptKind::LaunchWebUi
        {
            return match key.code
            {
                KeyCode::Esc => PromptKeyResult::Close,
                KeyCode::Enter | KeyCode::Char('1') =>
                {
                    self.input = "lan".to_owned();
                    PromptKeyResult::Submit
                }
                KeyCode::Char('l' | 'L' | '2') =>
                {
                    self.input = "local".to_owned();
                    PromptKeyResult::Submit
                }
                _ => PromptKeyResult::KeepOpen,
            };
        }
        match handle_inline_text_key(&mut self.input, key)
        {
            TextInputOutcome::Cancelled => PromptKeyResult::Close,
            TextInputOutcome::Submitted => PromptKeyResult::Submit,
            TextInputOutcome::Edited =>
            {
                self.error = None;
                PromptKeyResult::KeepOpen
            }
            TextInputOutcome::Ignored => PromptKeyResult::KeepOpen,
        }
    }
}

/// Renders [`PromptModal`] cleanly centered over the active screen.
pub fn draw_prompt_modal(frame: &mut Frame, modal: &PromptModal, t: &Theme)
{
    let popup = clamped_centered_rect(frame.area(), 76, 24, 12, 9);
    frame.render_widget(Clear, popup);

    let (title, prompt, hint, border_col) = match modal.kind
    {
        PromptKind::BlacklistDomain => (
            " Blacklist Domain (Never Desync) ",
            "Enter domain to exclude via hostlist_exclude_domains (e.g. bank.com):",
            "[Enter] Blacklist Domain   [Esc] Cancel",
            t.warn,
        ),
        PromptKind::AddAutoHostlist => (
            " Add Domain to Auto Hostlist ",
            "Enter blocked domain to append into configured autohostlist.txt:",
            "[Enter] Add Domain   [Esc] Cancel",
            t.accent_bright,
        ),
        PromptKind::LaunchWebUi => (
            " Launch Web Control UI ",
            "Expose mobile/browser UI with a fresh pairing passcode on port 8787:",
            "[Enter] LAN (0.0.0.0:8787)  [l] Localhost (127.0.0.1:8787)  [Esc] Cancel",
            t.info,
        ),
    };

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(border_col).add_modifier(Modifier::BOLD))
        .title(Span::styled(title, Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD)));
    let inner = outer.inner(popup);
    frame.render_widget(outer, popup);

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(2),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(Span::styled(prompt, Style::default().fg(t.text))).wrap(Wrap { trim: true }),
        rows[0],
    );
    let center_widget = if modal.kind == PromptKind::LaunchWebUi
    {
        Paragraph::new(Line::from(vec![
            Span::styled("Mode: ", Style::default().fg(t.muted)),
            Span::styled("[Enter] LAN / Phone ", Style::default().fg(t.ok).add_modifier(Modifier::BOLD)),
            Span::styled("or ", Style::default().fg(t.muted)),
            Span::styled(
                "[l] Localhost only",
                Style::default().fg(t.accent_bright).add_modifier(Modifier::BOLD),
            ),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.accent))
                .title(Span::styled(" Bind Interface ", Style::default().fg(t.info))),
        )
    }
    else
    {
        Paragraph::new(Line::from(vec![
            Span::styled(modal.input.as_str(), Style::default().fg(t.text)),
            Span::styled("_", Style::default().fg(t.warn_bright).add_modifier(Modifier::BOLD)),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.accent))
                .title(Span::styled(" Domain ", Style::default().fg(t.info))),
        )
    };
    frame.render_widget(center_widget, rows[1]);

    if let Some(err) = &modal.error
    {
        frame.render_widget(
            Paragraph::new(Span::styled(err.as_str(), Style::default().fg(t.err_bright))),
            rows[2],
        );
    }
    frame.render_widget(
        Paragraph::new(Line::from(styled_key_hints(hint, t))).wrap(Wrap { trim: true }),
        rows[3],
    );
}
