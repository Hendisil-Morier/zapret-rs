//! Tab 4 model: probe targets, per-target before/after samples, run phase, and comparison wording.

/// Domain normalization shared with the Strategy Finder form plus the timed sample types.
use crate::tools::{SpeedSample, SpeedTarget, control_target, domain_target, normalize_domain};

/// Which side of the comparison a sample belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// Measured while the daemon was stopped.
    Before,
    /// Measured after the daemon was started again.
    After,
}

/// Progress of the stop, probe, start, probe sequence shown in the Tab 4 header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpeedPhase {
    /// No comparison is running.
    #[default]
    Idle,
    /// Waiting for the running daemon to exit.
    Stopping,
    /// Measuring targets with the daemon stopped.
    ProbingBefore,
    /// Starting the daemon again.
    Starting,
    /// Waiting for the daemon's firewall rules to settle before measuring.
    Settling,
    /// Measuring targets with the daemon running.
    ProbingAfter,
    /// Both sides finished.
    Done,
}

impl SpeedPhase {
    /// Returns `true` while the sequence is in flight and a new run must not start.
    pub const fn is_running(self) -> bool {
        !matches!(self, Self::Idle | Self::Done)
    }

    /// Returns the short badge text shown in the panel title.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Idle => "IDLE",
            Self::Stopping => "STOPPING DAEMON",
            Self::ProbingBefore => "MEASURING: ZAPRET OFF",
            Self::Starting => "STARTING DAEMON",
            Self::Settling => "SETTLING RULES",
            Self::ProbingAfter => "MEASURING: ZAPRET ON",
            Self::Done => "DONE",
        }
    }
}

/// One table row: a target with its samples from each side once they arrive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpeedRow {
    /// Target label shown in the first column.
    pub label: String,
    /// Sample measured with the daemon stopped.
    pub before: Option<SpeedSample>,
    /// Sample measured with the daemon running.
    pub after: Option<SpeedSample>,
}

/// Mutable Tab 4 state owned by [`crate::tui::AppState`].
#[derive(Debug, Default)]
pub struct SpeedState {
    /// Rows in target order, with the unaffected control target last.
    pub rows: Vec<SpeedRow>,
    /// Current stage of the comparison.
    pub phase: SpeedPhase,
    /// Selected row index.
    pub selected: usize,
}

impl SpeedState {
    /// Resets the table to one empty row per target and marks the run as starting.
    pub fn start(&mut self, targets: &[SpeedTarget]) {
        self.rows = targets
            .iter()
            .map(|t| SpeedRow { label: t.label.clone(), before: None, after: None })
            .collect();
        self.phase = SpeedPhase::Stopping;
        self.selected = 0;
    }

    /// Stores `sample` for row `idx` on `side`; out-of-range indexes are ignored.
    pub fn record(&mut self, side: Side, idx: usize, sample: SpeedSample) {
        if let Some(row) = self.rows.get_mut(idx) {
            match side {
                Side::Before => row.before = Some(sample),
                Side::After => row.after = Some(sample),
            }
        }
    }

    /// Drops all results; ignored while a run is in flight.
    pub fn clear(&mut self) {
        if !self.phase.is_running() {
            self.rows.clear();
            self.phase = SpeedPhase::Idle;
            self.selected = 0;
        }
    }

    /// Moves the row selection by `delta`, clamped to the table.
    pub fn move_selection(&mut self, delta: isize) {
        let last = self.rows.len().saturating_sub(1);
        self.selected = self.selected.saturating_add_signed(delta).min(last);
    }
}

/// Builds the probe list: each distinct Tab 1 domain in order, then the unaffected control target.
pub fn build_targets(domains_input: &str) -> Vec<SpeedTarget> {
    let mut seen: Vec<String> = Vec::new();
    for domain in domains_input
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(normalize_domain)
    {
        if !seen.contains(&domain) {
            seen.push(domain);
        }
    }
    let mut targets: Vec<SpeedTarget> = seen.iter().map(|d| domain_target(d)).collect();
    targets.push(control_target());
    targets
}

/// Formats bytes per second as a decimal `KB/s` or `MB/s` figure.
pub fn format_rate(bytes_per_sec: u64) -> String {
    let b = bytes_per_sec as f64;
    if b >= 1_000_000.0 {
        format!("{:.1} MB/s", b / 1_000_000.0)
    } else if b >= 1_000.0 {
        format!("{:.0} KB/s", b / 1_000.0)
    } else {
        format!("{bytes_per_sec} B/s")
    }
}

/// Describes one sample: first-byte time and speed on success, otherwise the failure class.
pub fn describe_sample(sample: &SpeedSample) -> String {
    if sample.outcome.is_success() {
        format!("{}ms  {}", sample.ttfb_ms, format_rate(sample.bytes_per_sec))
    } else {
        sample.outcome.summary().split(' ').next().unwrap_or("FAILED").to_owned()
    }
}

/// Verdict for one row once both sides are known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Not enough data yet.
    Pending,
    /// Failed without zapret, works with it.
    Fixed,
    /// Worked without zapret, fails with it.
    Broke,
    /// Failed on both sides.
    StillBlocked,
    /// Worked on both sides; carries the first-byte and speed delta text.
    Compared(String),
}

/// Compares the two sides of `row`.
pub fn compare(row: &SpeedRow) -> Change {
    let (Some(before), Some(after)) = (&row.before, &row.after) else {
        return Change::Pending;
    };
    match (before.outcome.is_success(), after.outcome.is_success()) {
        (false, true) => Change::Fixed,
        (true, false) => Change::Broke,
        (false, false) => Change::StillBlocked,
        (true, true) => {
            let ttfb = after.ttfb_ms as i64 - before.ttfb_ms as i64;
            let speed = if before.bytes_per_sec == 0 {
                "n/a".to_owned()
            } else {
                let pct = (after.bytes_per_sec as f64 - before.bytes_per_sec as f64)
                    / before.bytes_per_sec as f64
                    * 100.0;
                format!("{pct:+.0}%")
            };
            Change::Compared(format!("ttfb {ttfb:+}ms  speed {speed}"))
        }
    }
}
