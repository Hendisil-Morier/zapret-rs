//! Interactive `ratatui` TUI wrapping `strat_finder`, config preview, and live `nfqws2` execution.

/// Side-effectful action executors bridging Tab 1/2/3 workers, `sudo` modals, and remote attach.
pub mod actions;
/// Centralized `~/.config/zapret-rs/config.toml` loader, writer, and startup option resolver.
pub mod app_config;
/// Recursive `import` / `imports` resolution and TOML table deep-merging for `config.toml`.
pub mod app_config_import;
/// Sparse diff-only `config.toml` serializer and comment-preserving updater.
pub mod app_config_save;
/// System clipboard and terminal OSC 52 I/O helpers.
pub mod clipboard;
/// Context-aware TUI copy selection extraction and active-input paste handlers.
pub mod clipboard_context;
/// Stop-then-start daemon cycle behind the Tab 2 restart key.
pub mod daemon_cycle;
/// Detached background `nfqws2` and `systemd` daemon launcher for persistent Tab 2 starts.
pub mod daemon_launch;
/// Plain-text diagnostic report exporter (`zapret-rs-debug.txt`) bound to `[d]` on Tab 5.
pub mod debug_report;
/// Unprivileged `$VISUAL`/`$EDITOR` launcher and starter TOML builder for Tab 3.
pub mod editor;
/// Tab 6 interactive Auto Hostlist and Blacklist selection, deletion, and transfer handlers.
pub mod hostlist_tab;
/// Live packet inspector record decoding, state, and verdict filter model.
pub mod inspect;
/// Live packet inspector `ratatui` table, detail popup, and hex dump renderer.
pub mod inspect_ui;
/// Complete remappable keymap schema (`[keybinds.*]`) spanning global chrome and every tab.
pub mod keybind_schema;
/// Keybinding primitive parser, matcher, and TOML single/array codec.
pub mod keybind_spec;
/// Contextual `?` keybindings popup renderer — shows only bindings for the active tab.
pub mod keybinds;
/// Centered floating modal popup for capability grants, `sudo` auth, and confirmations.
pub mod modal;
/// Mouse click and scroll wheel hit-testing aligned to the `ratatui` panel layouts.
pub mod mouse;
/// Per-tab mouse click and wheel scroll handlers shared with [`mouse`].
pub(crate) mod mouse_tabs;
/// Centered plain-text input modal for Blacklist, Auto Hostlist, and Web UI actions.
pub mod prompt_modal;
/// Control socket auto-detection and remote daemon telemetry client for Tab 2 attach mode.
pub mod remote;
/// Pure `ratatui` layout and widget renderer for all three tabs.
pub mod render;
/// Config & Diagnostics Tab 3 panel widgets extracted to keep renderer modules focused.
pub mod render_config;
/// Strategy Finder Tab 1 panel widgets extracted to keep renderer modules focused.
pub mod render_finder;
/// Strategy Finder Tab 1 setup-form widgets and horizontal text window helpers.
pub(crate) mod render_finder_form;
/// Auto Hostlist & Blacklist Tab 6 panel renderer.
pub mod render_hostlist;
/// Tab 2 (`Run nfqws2`) controller, metric cards, and shared log list widgets.
pub(crate) mod render_run;
/// Centralized Settings Tab 7 (`config.toml`, theme, keybinds) widget renderer.
pub mod render_settings;
/// Before/after Speed Test Tab 4 table and status card renderer.
pub mod render_speed;
/// Operational component Status Tab 5 table and detail renderer.
pub mod render_status;
/// Terminal lifecycle, `sudo`-safe suspend/resume, and worker coordination loop.
pub mod runner;
/// Terminal alternate-screen session RAII guard and unprivileged `$EDITOR` launcher.
pub mod session;
/// Serializable form and config snapshot preserved across seamless `exec()` restarts.
pub(crate) mod session_reexec;
/// Tab 7 side-effectful `config.toml` save, reload, `$EDITOR`, and mouse helpers.
pub mod settings_actions;
/// Interactive Tab 7 (`Settings`) configuration, theme preset, and keybind remapper.
pub mod settings_tab;
/// Tab 4 model: before/after speed comparison state, targets, and delta helpers.
pub mod speed;
/// Tab 4 speed comparison background runner (`stop -> probe -> start -> settle -> probe`).
pub mod speed_runner;
/// Mutable TUI application state and pure keyboard/event transitions.
pub mod state;
/// Strategy Finder form config, scan events, and hover state methods for [`AppState`].
pub mod state_finder;
/// Strategy Finder form navigation, field activation, text editing, and key handlers.
pub(crate) mod state_finder_keys;
/// Global hotkeys shared by every tab (help, quit, tab switching, panel focus, themes).
pub mod state_global;
/// Tab 2 (Run) and Tab 3 (Config) keyboard handlers for [`AppState`].
pub mod state_tabs;
/// Tab 5 operational health checks for privileges, driver, Lua, `curl`, config, and IPC.
pub mod status_check;
/// Tab 2 daemon session lifecycle: active session type, remote IPC control, and idle socket polling.
pub mod tab2_session;
/// Domain-scoped sub-state structs (`StatusTabState`, etc.) extracted from `AppState`.
pub mod tab_states;
/// Top-level navigation tab enum shared by state, renderer, and key handling.
pub mod tabs;
/// Theme-driven panel builders, `[key]` badge styling, log tagging, and syntax highlighters.
pub mod theme;
/// Configurable color themes, hex parsing, and `theme.toml` persistence.
pub mod theme_config;
/// Built-in TUI `Theme` struct and vivid color palette presets.
pub mod theme_presets;
/// Comment-preserving TOML preamble and section splicing helpers.
pub mod toml_splice;
/// Navigation enums, form field descriptors, telemetry counters, and worker events.
pub mod types;
/// TUI side-effect executors for Blacklist (`hostlist_exclude`), Auto Hostlist, and Web UI actions.
pub mod web_actions;
/// Background strategy scan and live `nfqws2` NFQUEUE worker handles.
pub mod workers;

/// Re-exported shared telemetry counters, verdicts, decoded records, and builder.
pub use crate::telemetry::{PacketCounters, PacketRecord, PacketVerdict, build_packet_record};
/// Re-exported centralized app configuration loader, persistent Finder prefs, and keybind types.
pub use app_config::{FinderPrefs, ResolvedAppConfig};
/// Re-exported Tab 6 interactive Auto Hostlist focus and selection state.
pub use hostlist_tab::{HostlistFocus, HostlistTabState};
/// Re-exported live packet inspector state and verdict filter helpers.
pub use inspect::{PacketInspectorState, VerdictFilter, filtered_packets};
/// Re-exported live packet inspector `ratatui` widgets and hex dump formatter.
pub use inspect_ui::{draw_packet_detail_modal, draw_packet_inspector, format_hex_dump};
pub use keybind_schema::Keybinds;
pub use keybind_spec::{KeyBind, KeyList};
/// Re-exported contextual keybindings popup renderer.
pub use keybinds::draw_keybinds_modal;
/// Re-exported floating authentication, confirmation, and keybindings modal overlays.
pub use modal::{AuthModal, ModalKeyResult, ModalPurpose, draw_auth_modal};
/// Re-exported plain-text prompt modal for Tab 6 domain additions and Web UI launch.
pub use prompt_modal::{PromptKeyResult, PromptKind, PromptModal, draw_prompt_modal};
/// Re-exported remote attach metadata and control socket auto-detection helpers.
pub use remote::{RemoteDaemonMeta, connect_remote_daemon, detect_control_socket};
/// Re-exported top-level frame renderer for headless tests and the event loop.
pub use render::draw_app;
/// Re-exported TUI runner entry point and startup options.
pub use runner::{TuiOptions, run_tui};
/// Re-exported Tab 7 Settings focus, row, and state structs.
pub use settings_tab::{SettingRow, SettingsFocus, SettingsTabState};
/// Re-exported mutable application state container.
pub use state::AppState;
/// Re-exported Tab 1, Tab 2, Tab 3, and Tab 5 domain sub-state structs.
pub use tab_states::{ConfigTabState, FinderState, RunState, StatusTabState};
/// Re-exported configurable TUI theme palette and preset/file helpers.
pub use theme_config::Theme;
/// Re-exported navigation, form, and event types.
pub use types::{ActiveTab, AppAction, FinderField, FinderStatus, IpMode, RunStatus, ScanUiEvent};
