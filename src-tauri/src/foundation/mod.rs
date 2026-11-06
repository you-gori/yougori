//! Shared infrastructure of the combined GPU memory and VM sandbox plan
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2: CORE-01–CORE-08).
//!
//! Each submodule is one shared contract, built and tested against fakes first (S2).
//! Wiring it into the runners, scheduler and VM backends belongs to the packages that
//! consume it. The single writer of every path here is recorded in
//! docs/combined-plan-agent-rollout.md, section 8.

pub mod catalog;
pub mod catalog_service;
pub mod coordination;
pub(crate) mod elapsed_clock;
pub mod events;
pub mod evidence;
pub mod ids;
pub mod ledger;
pub mod process;
pub mod product;
pub mod report;
#[cfg(test)]
mod scenarios;
pub mod signing;
pub mod strict_serde;
pub mod text;
pub mod transfer;
