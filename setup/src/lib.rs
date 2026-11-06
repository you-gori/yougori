//! Shared contracts for Yougori templates and setups: the versioned formats, the capability
//! registry, typed resources, conditions, graph planning and the messages the engine, CLI and
//! desktop exchange.
//!
//! Nothing here talks to Tauri, a provider, the network or a terminal. Planning is pure: the same
//! package and answers always give the same plan, and nothing in this crate changes anything
//! outside the values it returns.
/// The compiled distribution policy, shared with the CLI, grid and desktop engine. Included from the
/// repository root so the one source decides whether live research targets exist in this build.
#[path = "../../distribution.rs"]
pub mod distribution;
pub mod capability;
pub mod author;
pub mod condition;
pub mod draft;
pub mod dto;
pub mod format;
pub mod graph;
pub mod limits;
pub mod lock;
pub mod merge;
pub mod pattern;
pub mod placeholder;
pub mod plan;
pub mod resource;
pub mod text;
pub mod unicode;
mod unicode_data;
pub mod v1;
