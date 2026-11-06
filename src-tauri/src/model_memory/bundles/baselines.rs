//! The caching baselines of the §4.14 first prototype, taken from
//! [`crate::model_memory::residency`]: LRU and cost-per-byte (the §2.7 starting points),
//! marginal saved latency per retained byte and GreedyDual-Size, both with shared bases
//! charged once (the dependency-aware baselines).
//!
//! A baseline replays the same request history through a
//! [`ResidencyCache`] whose
//! capacity is the horizon's retention budget; its resident set at the end is its X.
//! Reconstruction requirements become the cache's prerequisites, so an object is
//! resident only with them. Weights, layouts and every other immutable kind keep a
//! verified local-storage copy and drop clean; session KV is written back to pinned host
//! memory (line 307).

use std::time::Duration;

use crate::foundation::ids::{ContentKey, ManualClock, MonotonicTime};
use crate::model_memory::graph::node::NodeKind;
use crate::model_memory::residency::eviction::{
    Content, CopyTier, ReconstructibleCopy, Verification,
};
use crate::model_memory::residency::retention::{
    CacheConfig, CacheError, CachedObject, CostPerByte, GreedyDualSize, Lru, MarginalSavedLatency,
    ObjectKind, ResidencyCache, RetentionPolicy,
};

use super::horizon::{Horizon, Selection};
use super::BundleError;

/// One residency policy (GPU §2.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CachePolicy {
    /// Least recently used (§2.7).
    Lru,
    /// Cheapest reload per byte evicted first (§2.7).
    CostPerByte,
    /// Decayed expected uses × reload seconds per byte; shared bases charged once.
    MarginalSavedLatency { half_life_steps: u64 },
    /// Landlord with shared bases charged once; no competitive guarantee is claimed.
    GreedyDualSize,
}

impl CachePolicy {
    /// A short name for reports.
    pub fn label(self) -> &'static str {
        match self {
            Self::Lru => "lru",
            Self::CostPerByte => "cost-per-byte",
            Self::MarginalSavedLatency { .. } => "marginal-saved-latency",
            Self::GreedyDualSize => "greedy-dual-size",
        }
    }

    fn build(self) -> Result<Box<dyn RetentionPolicy>, BundleError> {
        Ok(match self {
            Self::Lru => Box::new(Lru),
            Self::CostPerByte => Box::new(CostPerByte),
            Self::MarginalSavedLatency { half_life_steps } => {
                Box::new(MarginalSavedLatency::new(half_life_steps).map_err(CacheError::Input)?)
            }
            Self::GreedyDualSize => Box::new(GreedyDualSize::new()),
        })
    }
}

/// A baseline's resident set after the history, and what replaying it took.
#[derive(Clone, Debug, PartialEq)]
pub struct CacheOutcome {
    pub selection: Selection,
    /// Accesses the cache refused for lack of room.
    pub refused_accesses: u64,
    pub loaded_bytes: u64,
}

fn cached_object(horizon: &Horizon, at: usize) -> CachedObject {
    let object = horizon.object(at);
    let (kind, content) = match object.kind {
        NodeKind::KvBlock => (
            ObjectKind::SessionKv,
            Content::SessionState(object.identity),
        ),
        NodeKind::Adapter => (
            ObjectKind::Adapter,
            Content::Immutable(ContentKey::from_digest(object.identity)),
        ),
        _ => (
            ObjectKind::BaseWeights,
            Content::Immutable(ContentKey::from_digest(object.identity)),
        ),
    };
    let copies = match content {
        Content::Immutable(_) => vec![ReconstructibleCopy {
            tier: CopyTier::LocalStorage,
            verification: Verification::Verified { content },
        }],
        _ => Vec::new(),
    };
    CachedObject {
        key: object.id.clone(),
        kind,
        bytes: object.bytes,
        reload_seconds: object.load.expected().as_secs_f64(),
        prerequisites: horizon
            .requirements(at)
            .iter()
            .map(|&requirement| horizon.object(requirement).id.clone())
            .collect(),
        content,
        copies,
    }
}

/// Replays `history` (each entry one past request's needs, in order) under `policy` with
/// the horizon's retention budget as capacity, one access per second of a manual clock.
pub fn cache_selection(
    horizon: &Horizon,
    history: &[Vec<String>],
    policy: CachePolicy,
) -> Result<CacheOutcome, BundleError> {
    let config = CacheConfig {
        capacity_bytes: horizon.spec().retention_budget_bytes,
        objects: (0..horizon.objects().len())
            .map(|at| cached_object(horizon, at))
            .collect(),
        write_back_tier: Some(CopyTier::PinnedHost),
    };
    let mut cache = ResidencyCache::new(&config, policy.build()?)?;
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut refused_accesses = 0u64;
    let mut loaded_bytes = 0u64;
    for request in history {
        for need in request {
            if horizon.index_of(need).is_none() {
                return Err(BundleError::Unknown {
                    field: "history",
                    id: need.clone(),
                });
            }
            clock.advance(Duration::from_secs(1));
            match cache.access(need, &clock) {
                Ok(outcome) => loaded_bytes = loaded_bytes.saturating_add(outcome.loaded_bytes),
                Err(CacheError::NoRoom { .. }) => {
                    refused_accesses = refused_accesses.saturating_add(1)
                }
                Err(other) => return Err(other.into()),
            }
        }
    }
    let selection = Selection::from_indices(
        cache
            .resident_objects()
            .into_iter()
            .filter_map(|key| horizon.index_of(key)),
    );
    Ok(CacheOutcome {
        selection,
        refused_accesses,
        loaded_bytes,
    })
}
