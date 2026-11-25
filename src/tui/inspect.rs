//! Live packet inspector ring-buffer state and verdict filter helpers for Tab 2.

/// Bounded ring buffer holding recently captured packets for Tab 2 inspection.
use std::collections::VecDeque;

/// Keyboard codes handled by [`PacketInspectorState`].
use crossterm::event::KeyCode;

/// Shared packet record and outcome classification model.
use crate::telemetry::{PacketRecord, PacketVerdict};

/// Maximum recent packets retained in memory for live TUI inspection.
const MAX_INSPECT_PACKETS: usize = 300;

/// Interactive outcome filter cycled via `f` on Tab 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictFilter {
    /// Display all packets.
    All,
    /// Display only `MODIFY` and `DESYNC` packets (actual profile hits).
    DesyncOnly,
    /// Display only `REASM` packets (multi-segment TLS/QUIC reassembly pass-throughs).
    ReasmOnly,
    /// Display only `PASS` packets.
    PassOnly,
}

impl VerdictFilter {
    /// Cycles through `All -> DesyncOnly -> ReasmOnly -> PassOnly -> All`.
    pub const fn next(self) -> Self {
        match self {
            Self::All => Self::DesyncOnly,
            Self::DesyncOnly => Self::ReasmOnly,
            Self::ReasmOnly => Self::PassOnly,
            Self::PassOnly => Self::All,
        }
    }

    /// Returns a short display badge for the table title.
    pub const fn label(self) -> &'static str {
        match self {
            Self::All => "ALL",
            Self::DesyncOnly => "DESYNC+MOD",
            Self::ReasmOnly => "REASM",
            Self::PassOnly => "PASS",
        }
    }

    /// Returns `true` when `verdict` passes this filter.
    pub const fn matches(self, verdict: PacketVerdict) -> bool {
        match self {
            Self::All => true,
            Self::DesyncOnly => matches!(verdict, PacketVerdict::Modify | PacketVerdict::Desync),
            Self::ReasmOnly => matches!(verdict, PacketVerdict::Reasm),
            Self::PassOnly => matches!(verdict, PacketVerdict::Pass),
        }
    }
}

/// Self-contained state for Tab 2's live Packet Inspector table and detail popup.
#[derive(Debug)]
pub struct PacketInspectorState {
    /// Bounded ring buffer of recently captured packets across all outcomes (oldest at front).
    pub packets: VecDeque<PacketRecord>,
    /// Dedicated ring buffer of `MODIFY`/`DESYNC` profile hits so `PASS`/`REASM` never evict them.
    pub desync_packets: VecDeque<PacketRecord>,
    /// Dedicated ring buffer of `REASM` multi-segment pass-through packets.
    pub reasm_packets: VecDeque<PacketRecord>,
    /// Active outcome filter (`ALL`, `DESYNC+MOD`, `REASM`, `PASS`).
    pub filter: VerdictFilter,
    /// When `true`, incoming packets are ignored so the current table stays frozen.
    pub paused: bool,
    /// 0-based selection index into newest-first filtered packets.
    pub selected: usize,
    /// When `true`, renders the centered detail popup for the selected packet.
    pub detail_open: bool,
}

impl Default for PacketInspectorState {
    /// Returns an empty, live (`paused = false`) inspector showing all verdicts.
    fn default() -> Self {
        Self {
            packets: VecDeque::new(),
            desync_packets: VecDeque::new(),
            reasm_packets: VecDeque::new(),
            filter: VerdictFilter::All,
            paused: false,
            selected: 0,
            detail_open: false,
        }
    }
}

impl PacketInspectorState {
    /// Records one packet unless paused, keeping `DESYNC`/`MODIFY` and `REASM` in dedicated buffers.
    pub fn push(&mut self, record: PacketRecord) {
        if self.paused {
            return;
        }
        match record.verdict {
            PacketVerdict::Modify | PacketVerdict::Desync => {
                if self.desync_packets.len() >= MAX_INSPECT_PACKETS {
                    self.desync_packets.pop_front();
                }
                self.desync_packets.push_back(record.clone());
            }
            PacketVerdict::Reasm => {
                if self.reasm_packets.len() >= MAX_INSPECT_PACKETS {
                    self.reasm_packets.pop_front();
                }
                self.reasm_packets.push_back(record.clone());
            }
            PacketVerdict::Pass => {}
        }
        if self.packets.len() >= MAX_INSPECT_PACKETS {
            self.packets.pop_front();
        }
        self.packets.push_back(record);
    }

    /// Clears captured packets and resets selection/detail state.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.desync_packets.clear();
        self.reasm_packets.clear();
        self.selected = 0;
        self.detail_open = false;
    }

    /// Returns filtered packet references in newest-first order using the dedicated ring buffers.
    pub fn visible_packets(&self) -> Vec<&PacketRecord> {
        let source = match self.filter {
            VerdictFilter::DesyncOnly => &self.desync_packets,
            VerdictFilter::ReasmOnly => &self.reasm_packets,
            VerdictFilter::All | VerdictFilter::PassOnly => &self.packets,
        };
        filtered_packets(source, self.filter)
    }

    /// Returns the currently selected packet under the active [`VerdictFilter`], if any.
    pub fn selected_record(&self) -> Option<&PacketRecord> {
        let visible = self.visible_packets();
        if visible.is_empty() {
            return None;
        }
        let idx = self.selected.min(visible.len() - 1);
        visible.get(idx).copied()
    }

    /// Handles inspector navigation/filter/pause/detail keys; returns `Some(status)` when consumed.
    pub fn handle_key(&mut self, code: KeyCode) -> Option<String> {
        if self.detail_open {
            if matches!(code, KeyCode::Esc | KeyCode::Char('d') | KeyCode::Enter) {
                self.detail_open = false;
                return Some("Closed packet detail.".to_owned());
            }
            return Some(String::new());
        }
        let count = self.visible_packets().len();
        match code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Some(String::new())
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if count > 0 {
                    self.selected = (self.selected + 1).min(count - 1);
                }
                Some(String::new())
            }
            KeyCode::Char('f') => {
                self.filter = self.filter.next();
                self.selected = 0;
                Some(format!("Packet filter: {}", self.filter.label()))
            }
            KeyCode::Char('p') => {
                self.paused = !self.paused;
                Some(if self.paused { "Packet inspector paused." } else { "Packet inspector resumed." }.to_owned())
            }
            KeyCode::Char('d') => {
                if self.selected_record().is_some() {
                    self.detail_open = true;
                    Some("Viewing packet detail (press Esc or d to close).".to_owned())
                } else {
                    Some("No packet selected to inspect.".to_owned())
                }
            }
            _ => None,
        }
    }
}

/// Returns filtered packet references in newest-first display order.
pub fn filtered_packets(packets: &VecDeque<PacketRecord>, filter: VerdictFilter) -> Vec<&PacketRecord> {
    packets.iter().rev().filter(|p| filter.matches(p.verdict)).collect()
}
