//! UI-agnostic core for tocken.
//!
//! The four module trees here predate the UI-framework pivot
//! (ADR-300) and carry no UI-framework coupling. Both the legacy
//! Tauri binary and the Slint rebuild depend on this crate.

pub mod enroll;
pub mod session;
pub mod store;
pub mod wizard;
