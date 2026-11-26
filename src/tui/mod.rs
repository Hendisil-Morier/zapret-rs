//! Interactive `ratatui` TUI wrapping `strat_finder`, config preview, and live `nfqws2` execution.

/// Side-effectful action executors bridging Tab 1/2/3 workers, `sudo` modals, and remote attach.
pub mod actions;
/// Detached background `nfqws2` and `systemd` daemon launcher for persistent Tab 2 starts.
pub mod daemon_launch;
/// Unprivileged `$VISUAL`/`$EDITOR` launcher and starter TOML builder for Tab 3.
pub mod editor;
/// Live packet inspector record decoding, state, and verdict filter model.
pub mod inspect;
/// Live packet inspector `ratatui` table, detail popup, and hex dump renderer.
pub mod inspect_ui;
/// Contextual `?` keybindings popup renderer — shows only bindings for the active tab.
pub mod keybinds;
/// Centered floating modal popup for capability grants, `sudo` auth, and confirmations.
pub mod modal;
/// Control socket auto-detection and remote daemon telemetry client for Tab 2 attach mode.
pub mod remote;
/// Pure `ratatui` layout and widget renderer for all three tabs.
pub mod render;
/// Config & Diagnostics Tab 3 panel widgets extracted to keep renderer modules focused.
pub mod render_config;
/// Strategy Finder Tab 1 panel widgets extracted to keep renderer modules focused.
pub mod render_finder;
/// Terminal lifecycle, `sudo`-safe suspend/resume, and worker coordination loop.
pub mod runner;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
pub mod tab2_session;
/// Terminal alternate-screen session RAII guard and unprivileged `$EDITOR` launcher.
pub mod session;
/// Mutable TUI application state and pure keyboard/event transitions.
pub mod state;
/// Strategy Finder form editing, scan config builder, and event handlers for [`AppState`].
pub mod state_finder;
/// Global hotkeys shared by every tab (help, quit, tab switching, panel focus, themes).
pub mod state_global;
/// Tab 2 (Run) and Tab 3 (Config) keyboard handlers for [`AppState`].
pub mod state_tabs;
/// Top-level navigation tab enum shared by state, renderer, and key handling.
pub mod tabs;
/// Theme-driven panel builders, `[key]` badge styling, log tagging, and syntax highlighters.
pub mod theme;
/// Configurable color themes, built-in vivid presets, hex parsing, and `theme.toml` persistence.
pub mod theme_config;
/// Navigation enums, form field descriptors, telemetry counters, and worker events.
pub mod types;
/// Background strategy scan and live `nfqws2` NFQUEUE worker handles.
pub mod workers;

/// Re-exported shared telemetry counters, verdicts, decoded records, and builder.
pub use crate::telemetry::{PacketCounters, PacketRecord, PacketVerdict, build_packet_record};
/// Re-exported live packet inspector state and verdict filter helpers.
pub use inspect::{PacketInspectorState, VerdictFilter, filtered_packets};
/// Re-exported live packet inspector `ratatui` widgets and hex dump formatter.
pub use inspect_ui::{draw_packet_detail_modal, draw_packet_inspector, format_hex_dump};
/// Re-exported contextual keybindings popup renderer.
pub use keybinds::draw_keybinds_modal;
/// Re-exported floating authentication, confirmation, and keybindings modal overlays.
pub use modal::{AuthModal, ModalKeyResult, ModalPurpose, draw_auth_modal};
/// Re-exported remote attach metadata and control socket auto-detection helpers.
pub use remote::{RemoteDaemonMeta, connect_remote_daemon, detect_control_socket};
/// Re-exported top-level frame renderer for headless tests and the event loop.
pub use render::draw_app;
/// Re-exported TUI runner entry point and startup options.
pub use runner::{TuiOptions, run_tui};
/// Re-exported mutable application state container.
pub use state::AppState;
/// Re-exported configurable TUI theme palette and preset/file helpers.
pub use theme_config::Theme;
/// Re-exported navigation, form, and event types.
pub use types::{
    ActiveTab, AppAction, FinderField, FinderStatus, IpMode, RunStatus, ScanUiEvent,
};
