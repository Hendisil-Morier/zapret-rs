//! Core DPI desync profile routing and Lua action orchestration.

/// Profile filter matching, Lua action execution, and verdict reconstruction engine.
pub mod engine;

/// Re-exported desync engine, verdict aggregator, and baseline L7 classifier.
pub use engine::{DesyncEngine, aggregate_verdict, classify_baseline_payload};
