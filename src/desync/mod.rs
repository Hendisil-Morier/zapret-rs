//! Core DPI desync profile routing and Lua action orchestration.

/// Profile filter matching, Lua action execution, and verdict reconstruction engine.
pub mod engine;
/// Verdict aggregation, Lua verdict validation, and baseline L7 payload classification.
pub mod verdict;

/// Re-exported desync execution engine.
pub use engine::DesyncEngine;
/// Re-exported verdict aggregator and baseline L7 payload classifier.
pub use verdict::{aggregate_verdict, classify_baseline_payload};
