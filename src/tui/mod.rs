//! Interactive `ratatui` TUI wrapping `strat_finder`, config preview, and live `nfqws2` execution.

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
