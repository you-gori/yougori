//! Model-side reclaimers for the CORE-03 reclamation ladder
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, GPU-W05: "Register model reclamation
//! actions with CORE-03 in this order: cancel speculation, reclaim unused scratch, drop
//! low-value caches, park eligible idle models, then queue/reject"; GPU part §2.7, §2.9,
//! §3.5–§3.9; S2 CORE-03).
//!
//! The host ledger never calls model code: a caller lends it a
//! [`ReclaimLadder`](crate::foundation::ledger::ReclaimLadder) for one foreground
//! admission ([`Ledger::reserve_reclaiming`](crate::foundation::ledger::Ledger)). This
//! module supplies one [`Reclaimer`](crate::foundation::ledger::Reclaimer) per rung, each
//! adapting existing components through their public API:
//!
//! 1. [`CancelSpeculation`] over the transfer executor ([`ExecutorSpeculation`]):
//!    speculative jobs no request waits for yet, least expected value first (§2.9, §3.5).
//! 2. [`ReclaimUnusedScratch`] over idle executor staging ([`ExecutorStaging`]) and idle
//!    pinned staging rings ([`PinnedRings`]) (§3.5 steps 2 and 8; table line 540).
//! 3. [`DropLowValueCaches`] over the representation store and its tiers
//!    ([`TierCaches`]): least measured value per byte first, never an original, a
//!    canonical copy still needed, or leased or pinned state (§2.7, §3.4, §3.9).
//! 4. [`ParkEligibleIdleModels`] over the placement slot ([`SlotParking`]) and the
//!    coordination protocol ([`CoordinatorParking`]): only models no leased request uses
//!    and whose canonical state can rebuild them (§3.6, §3.9).
//!
//! What the GPU tier keeps after its users are gone has a source on each of the last two
//! rungs ([`FinishedSessionKv`] and [`IdleGpuWeights`]): the KV of finished sessions is
//! dropped on rung 3 before any cache of value, and weights no execution, graph or import
//! references are parked clean on rung 4 before any model still activated (§3.4, §3.9).
//!
//! [`register_model_reclaimers`] registers them on a ladder in that order; whatever they
//! cannot free is queued or refused by the ledger with each step's reason.
//!
//! Each step acts for one requester and gives up only reservations that requester filed,
//! still granted or in use, on a resource the request falls short of, and only as many
//! as cover what is missing. Work that is pinned or leased is never given up: a step that
//! gives up nothing says why ([`DeclineReason`](crate::foundation::ledger::DeclineReason)).
//! A granted reservation returns at once; one in use only begins releasing and counts
//! until a source with authority observes the release, which a step never confirms
//! itself. Since nearly all model memory is in use, the steps registered together share
//! what they set releasing in one admission ([`ReleasesUnderWay`]): a later, costlier step
//! stops work in use only for what the releases under way do not cover, and otherwise
//! gives up nothing and lets the request wait for them.
//!
//! Around the admission a step runs in three phases ([`WorkSource`]): it surveys its
//! component before, answers the ledger during, and after stops the work behind every
//! reservation the ledger acted on, reporting in a [`Settlement`] what it stopped and which
//! releases wait to be observed (S10 line 185). Steps keep no borrow of their components
//! between phases, so sources of different steps may borrow the same component in turn,
//! and the ledger is locked only for the admission itself:
//!
//! ```text
//! step.prepare(&mut source)?;                    // each step, outside the ledger lock
//! let mut ladder = ReclaimLadder::new();
//! register_model_reclaimers(&mut ladder, steps);
//! let admission = ledger.lock().reserve_reclaiming(request, &mut ladder);
//! step.settle(&admission.report, &mut source)?;  // each step, outside the ledger lock
//! ```
//!
//! Where a component lacks a listing a step needs (the executor's jobs and delivered
//! regions, a pinned ring's use, the coordinator's models and their canonical state), the
//! caller that owns that work supplies it; nothing here edits another module.

mod caches;
mod gpu;
mod parking;
mod scratch;
mod speculation;
mod steps;
mod work;

#[cfg(test)]
mod tests;

pub use caches::{CacheEntry, TierCaches};
pub use gpu::{
    confirm_freed_allocations, FinishedSessionKv, IdleGpuWeights, IdleWeights, SessionKv,
};
pub use parking::{
    CoordinatedModel, CoordinatorParking, IdleActivation, IdlePlacement, SlotParking,
};
pub use scratch::{ExecutorStaging, ExecutorStagingPools, PinnedRing, PinnedRings, RingUse};
pub use speculation::{ExecutorSpeculation, ExecutorWork, SpeculativeJob};
pub use steps::{
    register_model_reclaimers, CacheSource, CancelSpeculation, DropLowValueCaches, ModelReclaimer,
    ParkEligibleIdleModels, ParkingSource, ReclaimUnusedScratch, ScratchSource, SpeculationSource,
};
pub use work::{
    Candidate, Hold, LeasedBy, PinnedBy, ReclaimError, ReleasesUnderWay, Settlement, StopError,
    StoppedWork, Survey, UnstoppedWork, WorkSource,
};
