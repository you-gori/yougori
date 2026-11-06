//! The engine's conversions into the CORE-07 product contract
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 CORE-07: "Domain packages supply
//! fields and views through one product owner"; leftover task S07).
//!
//! The contract itself, `foundation::product`, depends on the foundation alone. This module
//! sits above it and above the domain packages, and converts each domain's own types into
//! the contract's shapes, one file per source:
//!
//! - [`from_models`]: model readiness, keep-ready preparation, residency, memory fit and
//!   model-memory refusals, from `model_memory`.
//! - [`from_sandbox`]: V17's shown sandbox view with each fact's evidence, the permissions
//!   it lists, V08 policy refusal codes with their help, and V01's migration of an old
//!   isolation tier, from `sandbox_contract` and `sandbox::backend`.
//! - [`from_serving`]: a model's declared agent endpoint, per dialect, from the serving
//!   protocol's capability rows and the conformance runs they were built from.
//! - [`from_setup`]: the setup crate's existing surfaces (a refusal as its `Diagnostic`
//!   with typed next actions, progress as its `OperationEvent`), its capability
//!   permissions, and an old project file's sandbox types.
//!
//! Nothing here decides policy, admits a runtime, checks evidence or plans a migration
//! again: each conversion reads what its source already decided. The golden fixtures of
//! `foundation::product` are what these conversions produce, which the tests here check.

pub mod from_models;
pub mod from_sandbox;
pub mod from_serving;
pub mod from_setup;

#[cfg(test)]
mod tests;
