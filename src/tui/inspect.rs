//! Live packet inspector ring-buffer state and verdict filter helpers for Tab 2.

/// Bounded ring buffer holding recently captured packets for Tab 2 inspection.
use std::collections::VecDeque;

/// Keyboard events and key codes handled by [`PacketInspectorState`].
use crossterm::event::{KeyCode, KeyEvent};

/// Shared packet record and outcome classification model.
use crate::telemetry::{PacketRecord, PacketVerdict};
/// Configurable inspector and navigation keymaps (`[keybinds.inspector]` and `[keybinds.nav]`).
use crate::tui::keybind_schema::Keybinds;

/// Maximum recent packets retained in memory for live TUI inspection.
const MAX_INSPECT_PACKETS: usize = 300;

/// Interactive outcome filter cycled via `f` on Tab 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictFilter
{
    /// Display all packets.
    All,
    /// Display only `MODIFY` and `DESYNC` packets (actual profile hits).
    DesyncOnly,
    /// Display only `REASM` packets (multi-segment TLS/QUIC reassembly pass-throughs).
    ReasmOnly,
    /// Display only `PASS` packets.
    PassOnly,
}

impl VerdictFilter
{
    /// Cycles through `All -> DesyncOnly -> ReasmOnly -> PassOnly -> All`.
    pub const fn next(self) -> Self
    {
        match self
        {
            Self::All => Self::DesyncOnly,
            Self::DesyncOnly => Self::ReasmOnly,
            Self::ReasmOnly => Self::PassOnly,
            Self::PassOnly => Self::All,
        }
    }

    /// Returns a short display badge for the table title.
    pub const fn label(self) -> &'static str
    {
        match self
        {
            Self::All => "ALL",
            Self::DesyncOnly => "DESYNC+MOD",
            Self::ReasmOnly => "REASM",
            Self::PassOnly => "PASS",
        }
    }

    /// Returns `true` when `verdict` passes this filter.
    pub const fn matches(self, verdict: PacketVerdict) -> bool
    {
        match self
        {
            Self::All => true,
            Self::DesyncOnly => matches!(verdict, PacketVerdict::Modify | PacketVerdict::Desync),
            Self::ReasmOnly => matches!(verdict, PacketVerdict::Reasm),
            Self::PassOnly => matches!(verdict, PacketVerdict::Pass),
        }
    }
}

/// Self-contained state for Tab 2's live Packet Inspector table and detail popup.
#[derive(Debug)]
pub struct PacketInspectorState
{
    /// Bounded ring buffer of recently captured packets across all outcomes (oldest at front).
    pub packets: VecDeque<PacketRecord>,
    /// Dedicated ring buffer of `MODIFY`/`DESYNC` profile hits so `PASS`/`REASM` never evict them.
    pub desync_packets: VecDeque<PacketRecord>,
    /// Dedicated ring buffer of `REASM` multi-segment pass-through packets.
    pub reasm_packets: VecDeque<PacketRecord>,
    /// Active outcome filter (`ALL`, `DESYNC+MOD`, `REASM`, `PASS`).
    pub filter: VerdictFilter,
    /// Active text/attribute filter query (`/` search bar) applied on top of [`Self::filter`].
    pub filter_query: String,
    /// When `true`, keystrokes edit [`Self::filter_query`] instead of triggering table/global keys.
    pub filter_editing: bool,
    /// When `true`, incoming packets are ignored so the current table stays frozen.
    pub paused: bool,
    /// 0-based selection index into newest-first filtered packets.
    pub selected: usize,
    /// When `true`, renders the centered detail popup for the selected packet.
    pub detail_open: bool,
}

impl Default for PacketInspectorState
{
    /// Returns an empty, live (`paused = false`) inspector showing all verdicts.
    fn default() -> Self
    {
        Self {
            packets: VecDeque::new(),
            desync_packets: VecDeque::new(),
            reasm_packets: VecDeque::new(),
            filter: VerdictFilter::All,
            filter_query: String::new(),
            filter_editing: false,
            paused: false,
            selected: 0,
            detail_open: false,
        }
    }
}

impl PacketInspectorState
{
    /// Records one packet unless paused, keeping `DESYNC`/`MODIFY` and `REASM` in dedicated buffers.
    pub fn push(&mut self, record: PacketRecord)
    {
        if self.paused
        {
            return;
        }
        match record.verdict
        {
            PacketVerdict::Modify | PacketVerdict::Desync =>
            {
                if self.desync_packets.len() >= MAX_INSPECT_PACKETS
                {
                    self.desync_packets.pop_front();
                }
                self.desync_packets.push_back(record.clone());
            }
            PacketVerdict::Reasm =>
            {
                if self.reasm_packets.len() >= MAX_INSPECT_PACKETS
                {
                    self.reasm_packets.pop_front();
                }
                self.reasm_packets.push_back(record.clone());
            }
            PacketVerdict::Pass =>
            {}
        }
        if self.packets.len() >= MAX_INSPECT_PACKETS
        {
            self.packets.pop_front();
        }
        self.packets.push_back(record);
    }

    /// Clears captured packets and resets selection/detail/filter-edit state.
    pub fn clear(&mut self)
    {
        self.packets.clear();
        self.desync_packets.clear();
        self.reasm_packets.clear();
        self.selected = 0;
        self.detail_open = false;
        self.filter_editing = false;
    }

    /// Returns filtered packet references in newest-first order using the dedicated ring buffers.
    pub fn visible_packets(&self) -> Vec<&PacketRecord>
    {
        let source = match self.filter
        {
            VerdictFilter::DesyncOnly => &self.desync_packets,
            VerdictFilter::ReasmOnly => &self.reasm_packets,
            VerdictFilter::All | VerdictFilter::PassOnly => &self.packets,
        };
        filtered_packets_query(source, self.filter, &self.filter_query)
    }

    /// Returns the currently selected packet under the active [`VerdictFilter`], if any.
    pub fn selected_record(&self) -> Option<&PacketRecord>
    {
        let visible = self.visible_packets();
        if visible.is_empty()
        {
            return None;
        }
        let idx = self.selected.min(visible.len() - 1);
        visible.get(idx).copied()
    }

    /// Handles inspector navigation/filter/pause/detail keys using configurable [`Keybinds`].
    pub fn handle_key_with_binds(&mut self, key: KeyEvent, keybinds: &Keybinds) -> Option<String>
    {
        let insp = &keybinds.inspector;
        let nav = &keybinds.nav;
        if self.detail_open
        {
            if insp.close_detail.contains(key)
            {
                self.detail_open = false;
                return Some("Closed packet detail.".to_owned());
            }
            return Some(String::new());
        }
        if self.filter_editing
        {
            return match key.code
            {
                KeyCode::Esc =>
                {
                    self.filter_editing = false;
                    self.filter_query.clear();
                    self.selected = 0;
                    Some("Packet filter cleared.".to_owned())
                }
                KeyCode::Enter =>
                {
                    self.filter_editing = false;
                    let msg = if self.filter_query.trim().is_empty()
                    {
                        "Packet filter cleared.".to_owned()
                    }
                    else
                    {
                        format!("Filter applied: {}", self.filter_query.trim())
                    };
                    Some(msg)
                }
                KeyCode::Backspace =>
                {
                    self.filter_query.pop();
                    self.selected = 0;
                    Some(String::new())
                }
                KeyCode::Char(c) =>
                {
                    self.filter_query.push(c);
                    self.selected = 0;
                    Some(String::new())
                }
                _ => Some(String::new()),
            };
        }
        let count = self.visible_packets().len();
        if nav.up.contains(key)
        {
            self.selected = self.selected.saturating_sub(1);
            return Some(String::new());
        }
        if nav.down.contains(key)
        {
            if count > 0
            {
                self.selected = (self.selected + 1).min(count - 1);
            }
            return Some(String::new());
        }
        if insp.filter_cycle.contains(key)
        {
            self.filter = self.filter.next();
            self.selected = 0;
            return Some(format!("Packet filter: {}", self.filter.label()));
        }
        if insp.filter_edit.contains(key)
        {
            self.filter_editing = true;
            return Some(
                "Filter (proto: dir: port: verdict: profile: host: !neg): Enter apply, Esc clear".to_owned(),
            );
        }
        if insp.pause.contains(key)
        {
            self.paused = !self.paused;
            return Some(
                if self.paused { "Packet inspector paused." } else { "Packet inspector resumed." }.to_owned(),
            );
        }
        if insp.detail.contains(key)
        {
            if self.selected_record().is_some()
            {
                self.detail_open = true;
                let close_lbl = insp.close_detail.joined_label();
                return Some(format!("Viewing packet detail (press {close_lbl} to close)."));
            }
            return Some("No packet selected to inspect.".to_owned());
        }
        None
    }

    /// Backwards-compatible wrapper handling `code` using default [`Keybinds`].
    pub fn handle_key(&mut self, code: KeyCode) -> Option<String>
    {
        self.handle_key_with_binds(KeyEvent::from(code), &Keybinds::default())
    }
}

/// Returns `true` when `endpoint` (`ip:port` or `[ipv6]:port`) ends with `:port`.
fn endpoint_has_port(endpoint: &str, port: &str) -> bool
{
    !port.is_empty() && endpoint.rsplit_once(':').is_some_and(|(_, p)| p == port)
}

/// Evaluates one lowercased filter term (without leading `!`) against `record`.
fn matches_term(record: &PacketRecord, term: &str) -> bool
{
    let any_field = |needle: &str| {
        record.src.to_ascii_lowercase().contains(needle)
            || record.dst.to_ascii_lowercase().contains(needle)
            || record.proto.to_ascii_lowercase().contains(needle)
            || record.direction.to_ascii_lowercase().contains(needle)
            || record.info.to_ascii_lowercase().contains(needle)
            || record.verdict.label().to_ascii_lowercase().contains(needle)
            || record.profile.as_deref().is_some_and(|p| p.to_ascii_lowercase().contains(needle))
    };
    if let Some((key, val)) = term.split_once(':')
    {
        if val.is_empty()
        {
            return true;
        }
        return match key
        {
            "proto" | "p" => record.proto.to_ascii_lowercase().contains(val),
            "dir" | "d" => record.direction.to_ascii_lowercase().contains(val),
            "port" => endpoint_has_port(&record.src, val) || endpoint_has_port(&record.dst, val),
            "verdict" | "v" => record.verdict.label().to_ascii_lowercase().contains(val),
            "profile" => record.profile.as_deref().is_some_and(|p| p.to_ascii_lowercase().contains(val)),
            "host" | "ip" =>
            {
                record.src.to_ascii_lowercase().contains(val)
                    || record.dst.to_ascii_lowercase().contains(val)
                    || record.info.to_ascii_lowercase().contains(val)
            }
            _ => any_field(term),
        };
    }
    any_field(term)
}

/// Returns `true` when `record` matches every space-separated term in `query`.
///
/// Prefixing a term with `!` negates it; `key:value` targets specific fields.
pub fn matches_query(record: &PacketRecord, query: &str) -> bool
{
    query.split_whitespace().all(|raw| {
        let (negated, term) = match raw.strip_prefix('!')
        {
            Some(rest) if !rest.is_empty() => (true, rest),
            _ => (false, raw),
        };
        let hit = matches_term(record, &term.to_ascii_lowercase());
        if negated { !hit } else { hit }
    })
}

/// Returns filtered packet references in newest-first display order.
pub fn filtered_packets(packets: &VecDeque<PacketRecord>, filter: VerdictFilter) -> Vec<&PacketRecord>
{
    filtered_packets_query(packets, filter, "")
}

/// Returns packet references matching both `filter` and `query` in newest-first display order.
pub fn filtered_packets_query<'a>(
    packets: &'a VecDeque<PacketRecord>,
    filter: VerdictFilter,
    query: &str,
) -> Vec<&'a PacketRecord>
{
    packets.iter().rev().filter(|p| filter.matches(p.verdict) && matches_query(p, query)).collect()
}
