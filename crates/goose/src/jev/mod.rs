//! Jev (TypeSafe AI System One) integration: intelligent router & decision assistant.
//!
//! Additive and optional: every consumer is independently toggleable and off by
//! default. Jev advises; existing machinery decides. See
//! `.working_sessions/JEV_INTEGRATION_PLAN.md`.

pub mod client;
pub mod config;
pub mod guard;
pub mod triage;
pub mod types;
