//! Domain-scoped TUI tab state structs decomposed out of [`crate::tui::AppState`].

/// Bounded log buffer container matching `MAX_LOG_LINES`.
use std::collections::VecDeque;
/// Path buffers for config hostlists and daemon control sockets.
use std::path::PathBuf;
/// Lock-free shared packet counters updated by live/attached Tab 2 daemons.
use std::sync::Arc;

/// Default desync fwmark constant used by Strategy Finder scans.
use crate::intercepter::DEFAULT_DESYNC_FWMARK;
/// OS capability and binary identity probes used to initialize [`StatusTabState`].
use crate::runtime::{current_uid_or_zero, has_packet_capture_privileges};
/// Atomic telemetry packet counters shared with background capture loops.
use crate::telemetry::PacketCounters;
/// Strategy catalog, scan parameters, and path defaults for Tab 1.
use crate::tools::{
    CoveredProfile, DEFAULT_STRAT_QNUM, DnsPreset, DomainScope, ScanLevel, TargetScanResult,
    default_output_config_path, detect_lua_dir,
};
/// Attached remote daemon metadata stored on Tab 2.
use crate::tui::remote::RemoteDaemonMeta;
/// Diagnostic component check row struct rendered on Tab 5 (`Status`).
use crate::tui::status_check::ComponentCheck;
/// Live daemon / remote attach status and Strategy Finder enums.
use crate::tui::types::{FinderHoverState, FinderStatus, IpMode, RunStatus};

/// Tab 1 (`Strategy Finder`) form inputs, scan configuration, progress, results, and log state.
#[derive(Debug, Clone)]
pub struct FinderState
{
    /// Selected row index within `FinderField::ALL`.
    pub focus_idx: usize,
    /// `true` while typing into a focused text field.
    pub editing_text: bool,
    /// Byte cursor position within the active text-field buffer (clamped to buffer length on each edit).
    pub text_cursor: usize,
    /// Horizontal character scroll offset for browsing long unfocused/view-mode Tab 1 text fields.
    pub text_scroll: usize,
    /// Comma/space-separated target domains input buffer.
    pub domains_input: String,
    /// Enabled HTTP (TCP 80) protocol checkbox.
    pub proto_http: bool,
    /// Enabled TLS 1.2 (TCP 443) protocol checkbox.
    pub proto_tls12: bool,
    /// Enabled TLS 1.3 (TCP 443) protocol checkbox.
    pub proto_tls13: bool,
    /// Enabled HTTP/3 QUIC (UDP 443) protocol checkbox.
    pub proto_http3: bool,
    /// Selected IP family mode.
    pub ip_mode: IpMode,
    /// Selected scan thoroughness level.
    pub level: ScanLevel,
    /// Stop sweeping a target on first working strategy.
    pub stop_on_first: bool,
    /// Skip automatic `nftables` setup/teardown.
    pub no_nft: bool,
    /// Lua scripts directory input buffer.
    pub lua_dir_input: String,
    /// Destination/loaded `nfqws2.toml` path input buffer.
    pub output_path: String,
    /// Domain scoping mode applied when generating `nfqws2.toml` profiles from a scan.
    pub domain_scope: DomainScope,
    /// NFQUEUE number used during strategy finder scans.
    pub qnum: u16,
    /// Firewall mark used for loop prevention.
    pub fwmark: u32,
    /// Current Finder background task status.
    pub status: FinderStatus,
    /// Current progress numerator within the active target sweep.
    pub progress_done: usize,
    /// Current progress denominator within the active target sweep.
    pub progress_total: usize,
    /// Human-readable status label inside the progress gauge.
    pub progress_label: String,
    /// Per-target completed results shown in the Finder table.
    pub targets: Vec<TargetScanResult>,
    /// Minimal cross-domain profile cover from the latest scan.
    pub cover: Vec<CoveredProfile>,
    /// Recent strategy finder log messages.
    pub logs: VecDeque<String>,
    /// Dwell timer and visibility state for Tab 1's 1-second option explanation tooltip.
    pub hover: FinderHoverState,
}

impl FinderState
{
    /// Initializes Tab 1 state from CLI config/Lua path overrides and `--no-nft`.
    pub fn from_cli(initial_config: Option<PathBuf>, initial_lua_dir: Option<PathBuf>, no_nft: bool) -> Self
    {
        let lua_dir_input = initial_lua_dir
            .or_else(|| detect_lua_dir(None))
            .map_or_else(String::new, |p| p.display().to_string());
        let output_path = initial_config.unwrap_or_else(default_output_config_path).display().to_string();
        Self {
            focus_idx: 0,
            editing_text: false,
            text_cursor: 0,
            text_scroll: 0,
            domains_input: String::new(),
            proto_http: true,
            proto_tls12: true,
            proto_tls13: true,
            proto_http3: true,
            ip_mode: IpMode::V4,
            level: ScanLevel::Quick,
            stop_on_first: true,
            no_nft,
            lua_dir_input,
            output_path,
            domain_scope: DomainScope::default(),
            qnum: DEFAULT_STRAT_QNUM,
            fwmark: DEFAULT_DESYNC_FWMARK,
            status: FinderStatus::Idle,
            progress_done: 0,
            progress_total: 0,
            progress_label: "Idle: enter domain(s) and press 'r' to scan".to_owned(),
            targets: Vec::new(),
            cover: Vec::new(),
            logs: VecDeque::new(),
            hover: FinderHoverState::default(),
        }
    }
}

/// Tab 2 (`Run`) daemon/remote-attach status, packet counters, socket path, and log lines.
#[derive(Debug, Clone)]
pub struct RunState
{
    /// Current live `nfqws2` daemon or remote attach status on Tab 2.
    pub status: RunStatus,
    /// Active remote daemon metadata while `status == RunStatus::Attached`.
    pub remote_meta: Option<RemoteDaemonMeta>,
    /// When `true`, automatically re-attaches if a daemon socket reappears after unexpected loss.
    pub auto_reattach: bool,
    /// Lock-free packet counters shared with local worker or remote subscriber thread.
    pub counters: Arc<PacketCounters>,
    /// Local display baseline subtracted from [`Self::counters`] after pressing `c` while attached.
    pub counter_baseline: (u64, u64, u64, u64, u64),
    /// Recent live `nfqws2` daemon log lines.
    pub logs: VecDeque<String>,
    /// Explicit `--control-socket` override passed into the TUI CLI, if any.
    pub control_socket_override: Option<PathBuf>,
    /// Auto-detected running daemon socket path ready to attach when stopped.
    pub detected_socket: Option<PathBuf>,
}

impl Default for RunState
{
    /// Initializes an idle, auto-reattaching Tab 2 run session with zeroed counters.
    fn default() -> Self
    {
        Self {
            status: RunStatus::Stopped,
            remote_meta: None,
            auto_reattach: true,
            counters: Arc::new(PacketCounters::default()),
            counter_baseline: (0, 0, 0, 0, 0),
            logs: VecDeque::new(),
            control_socket_override: None,
            detected_socket: None,
        }
    }
}

/// Tab 3 (`Config`) active `nfqws2.toml` text, parse state, merge stash, and domain lists.
#[derive(Debug, Clone, Default)]
pub struct ConfigTabState
{
    /// Active TOML text shown in Tab 3 and executed by Tab 2.
    pub active_toml: String,
    /// Parsed profile names summary for the active TOML (`empty` when invalid/empty).
    pub parsed_profiles: Vec<String>,
    /// Parse error message for `active_toml` when non-empty and invalid (`None` when valid/empty).
    pub toml_error: Option<String>,
    /// Vertical scroll offset inside Tab 3's TOML preview pane.
    pub toml_scroll: u16,
    /// Stashed `(previous_toml, scan_toml)` awaiting user merge confirmation after a scan.
    pub pending_merge: Option<(String, String)>,
    /// Unique resolved `hostlist_auto` file paths referenced by `active_toml`.
    pub autohostlist_paths: Vec<PathBuf>,
    /// Learned domain entries currently loaded from `autohostlist_paths`.
    pub autohostlist_entries: Vec<String>,
    /// Excluded (blacklisted) domains configured via `hostlist_exclude` / `hostlist_exclude_domains`.
    pub exclude_entries: Vec<String>,
}

/// Tab 5 operational diagnostics table state, DNS preset selector, and process privilege snapshot.
#[derive(Debug, Clone)]
pub struct StatusTabState
{
    /// Cached operational health checks displayed on Tab 5 (`Status`).
    pub checks: Vec<ComponentCheck>,
    /// Selected row index inside Tab 5's component status table.
    pub selected: usize,
    /// Horizontal scroll offset for the selected Tab 5 `Summary` cell.
    pub hscroll: usize,
    /// Selected OS DNS/DoH preset cycled on Tab 5 (`n`) and applied on confirm (`a`).
    pub dns_preset: DnsPreset,
    /// Effective UID captured at startup for diagnostics.
    pub uid: u32,
    /// Whether `CAP_NET_ADMIN|CAP_NET_RAW` are active in the current process.
    pub has_net_caps: bool,
    /// Current executable path displayed in `setcap` guidance.
    pub exe_path: String,
}

impl Default for StatusTabState
{
    /// Captures current process UID, network capabilities, and executable path with empty checks.
    fn default() -> Self
    {
        let uid = current_uid_or_zero();
        let has_net_caps = has_packet_capture_privileges().unwrap_or(false);
        let exe_path = std::env::current_exe()
            .ok()
            .map_or_else(|| "./target/release/zapret-rs".to_owned(), |p| p.display().to_string());
        Self {
            checks: Vec::new(),
            selected: 0,
            hscroll: 0,
            dns_preset: DnsPreset::Cloudflare,
            uid,
            has_net_caps,
            exe_path,
        }
    }
}
