//! Model memory planning from the GPU part of the combined plan
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, sections 1–3.2): the cost model,
//! the request state graph, identities and residency policy.
//!
//! Pure library code tested against fakes. Runner integration belongs to GPU-W01
//! onward. The single writer of every path here is recorded in
//! docs/combined-plan-agent-rollout.md, section 8.

/// `From` conversions into one error enum, one variant per source error
/// (`from_error!(ThisError: Source => Variant, ...)`); the readiness, streaming and subgraph
/// errors share it (U05 compactness: each kept a copy).
macro_rules! from_error {
    ($error:ident: $($source:ty => $variant:ident),* $(,)?) => {
        $(
            impl From<$source> for $error {
                fn from(error: $source) -> Self {
                    Self::$variant(error)
                }
            }
        )*
    };
}
pub(crate) use from_error;

pub mod adapters;
pub mod backends;
pub mod bench;
pub mod boundaries;
pub mod bundles;
pub mod executor;
pub mod graph;
pub mod helpers;
pub mod identity;
pub mod manifest;
pub mod math;
pub mod placement;
pub mod profiles;
pub mod progress;
pub mod readiness;
pub mod reclaim;
pub mod representation;
pub mod residency;
pub mod routing;
#[cfg(test)]
mod scenarios;
pub mod streaming;
pub mod subgraph;
pub mod tiers;
pub mod transitions;
pub mod vmm;
