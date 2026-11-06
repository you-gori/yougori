//! Request state, adapters and dependency-aware eviction: GPU §3.9 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md (lines 630–644), with the KV restore
//! rule of §2.8 (line 461) and the §1.1 rows at lines 304, 307 and 308.
//!
//! - [`graph`]: the dependency graph. Immutable bases, adapters, merged variants and
//!   graph pools are kept apart from mutable session KV (line 632).
//! - [`adapter`]: what an adapter references, and the compatibility check that runs
//!   before admission (line 632).
//! - [`merge`]: merged variants materialized separately from the canonical base and
//!   adapter, and the amortization threshold for merging (line 634).
//! - [`kv`]: KV reuse keys and tenant scope (line 636).
//! - [`placement`]: the choice between KV transfer, exact prefix recomputation and
//!   staying on the current worker (line 636, §2.8).
//! - [`eviction`]: the five eviction rules of lines 640–644 as policy over the graph.
//!
//! Identities are consumed from [`crate::model_memory::identity`] (T07): execution,
//! logical and adapter identities, merged variants through `LogicalModelSpec::with_merged`,
//! the refusal of merge-then-subtract, and the FAST-03 KV scope key. Residency comes from
//! [`crate::model_memory::residency`] (T08): what GPU bytes hold and the copies outside
//! the GPU, its clean-eviction rule for weights and session KV alike (only a verified copy
//! of the exact content in pinned host RAM or local storage spares a copy back), and its
//! retention policies, which choose every victim. Trust scopes and lease ids are the
//! shared [`crate::foundation::ids`] types. The transfer-versus-recompute half of the KV
//! decision is [`crate::model_memory::math::recompute`]; this module adds the third option
//! around it. Everything here is pure, synchronous and deterministic. Bytes are `u64`,
//! durations are `f64` seconds, and invalid numbers are refused with
//! [`crate::model_memory::math::InputError`], never clamped.

pub mod active;
pub mod adapter;
pub mod eviction;
pub mod graph;
pub mod kv;
pub mod merge;
pub mod placement;

#[cfg(test)]
pub(crate) mod fakes;
