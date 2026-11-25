//! Interactive `ratatui` TUI wrapping `strat_finder`, config preview, and live `nfqws2` execution.

/// Live packet inspector record decoding, state, and verdict filter model.
pub mod inspect;
/// Live packet inspector `ratatui` table, detail popup, and hex dump renderer.
pub mod inspect_ui;
/// Centered floating modal popup for capability grants and `sudo` authentication.
pub mod modal;
/// Pure `ratatui` layout and widget renderer for all three tabs.
pub mod render;
/// Terminal lifecycle, `sudo`-safe suspend/resume, and background scan/daemon workers.
pub mod runner;
/// Mutable TUI application state and pure keyboard/event transitions.
pub mod state;
/// Navigation enums, form field descriptors, telemetry counters, and worker events.
pub mod types;
/// Background strategy scan and live `nfqws2` NFQUEUE worker handles.
pub mod workers;

/// Re-exported live packet inspector types, state, and record decoder.
pub use inspect::{
    PacketInspectorState, PacketRecord, PacketVerdict, VerdictFilter, build_packet_record,
    filtered_packets,
};
/// Re-exported live packet inspector `ratatui` widgets and hex dump formatter.
pub use inspect_ui::{draw_packet_detail_modal, draw_packet_inspector, format_hex_dump};
/// Re-exported floating authentication and capability-grant modal overlay.
pub use modal::{AuthModal, ModalKeyResult, ModalPurpose, draw_auth_modal};
/// Re-exported top-level frame renderer for headless tests and the event loop.
pub use render::draw_app;
/// Re-exported TUI runner entry point and startup options.
pub use runner::{TuiOptions, run_tui};
/// Re-exported mutable application state container.
pub use state::AppState;
/// Re-exported navigation, form, telemetry, and event types.
pub use types::{
    ActiveTab, AppAction, FinderField, FinderStatus, IpMode, PacketCounters, RunStatus, ScanUiEvent,
};
