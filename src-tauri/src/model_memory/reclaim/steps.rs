//! One [`Reclaimer`] per rung of the GPU-W05 ladder ("cancel speculation, reclaim unused
//! scratch, drop low-value caches, park eligible idle models, then queue/reject"), and the
//! helper that registers them on a [`ReclaimLadder`] in that order.
//!
//! Each step acts for one requester, the owner of the reservations its source's work
//! holds, and takes only sources of its own kind: [`CancelSpeculation`] takes a
//! [`SpeculationSource`], [`ReclaimUnusedScratch`] a [`ScratchSource`],
//! [`DropLowValueCaches`] a [`CacheSource`] and [`ParkEligibleIdleModels`] a
//! [`ParkingSource`]. A step keeps no borrow of its component between phases: it is
//! given the source to prepare and to settle, so the sources of different steps can
//! borrow the same component one after another. Steps registered together share what
//! they set releasing during the admission ([`ReleasesUnderWay`]).

use std::fmt;

use super::work::{
    Candidate, ReclaimError, ReleasesUnderWay, Rung, Settlement, Survey, WorkSource,
};
use crate::foundation::ledger::{
    LadderReport, ReclaimLadder, ReclaimNeed, ReclaimResponse, ReclaimStep, Reclaimer, Requester,
};

/// A source of speculative work no request waits for yet (GPU part §2.9, §3.5).
pub trait SpeculationSource: WorkSource {}

/// A source of scratch reserved and not in use, such as idle staging (§3.5).
pub trait ScratchSource: WorkSource {}

/// A source of caches ranked by value per byte (§2.7, §3.4, §3.9).
pub trait CacheSource: WorkSource {}

/// A source of idle models whose canonical state can rebuild them (§3.6, §3.9).
pub trait ParkingSource: WorkSource {}

/// A model step as the ladder helper registers it: its rung and the requester it acts
/// for.
pub trait ModelReclaimer: Reclaimer {
    /// The rung it implements.
    fn step(&self) -> ReclaimStep;

    /// The requester whose reservations it gives up.
    fn owner(&self) -> Requester;

    /// Counts, for the coming admission, what the steps sharing `releases` set releasing,
    /// and adds what it sets releasing itself.
    fn share_releases(&mut self, releases: &ReleasesUnderWay);
}

macro_rules! model_step {
    ($(#[$doc:meta])* $name:ident, $source:ident, $step:expr) => {
        $(#[$doc])*
        #[derive(Clone, Debug)]
        pub struct $name<W> {
            rung: Rung<W>,
        }

        impl<W: Clone + fmt::Display> $name<W> {
            /// The step acting for `owner`: it gives up only reservations `owner` filed.
            pub fn new(owner: Requester) -> Self {
                Self {
                    rung: Rung::new($step, owner),
                }
            }

            /// The step acting for the owner of `source`'s work.
            pub fn for_source<S: $source<Work = W> + ?Sized>(source: &S) -> Self {
                Self::new(source.owner())
            }

            /// The requester it acts for.
            pub fn owner(&self) -> Requester {
                self.rung.owner()
            }

            /// Phase 1, before the admission and outside the caller's ledger lock:
            /// surveys `source` and keeps what it found until the admission.
            pub fn prepare<S: $source<Work = W> + ?Sized>(
                &mut self,
                source: &mut S,
            ) -> Result<Survey, ReclaimError> {
                self.rung.prepare(source)
            }

            /// Phase 3, after the admission and outside the caller's ledger lock: stops
            /// through `source` the work behind every reservation of this step that the
            /// ledger acted on in `report`.
            pub fn settle<S: $source<Work = W> + ?Sized>(
                &mut self,
                report: &LadderReport,
                source: &mut S,
            ) -> Result<Settlement, ReclaimError> {
                self.rung.settle(report, source)
            }

            /// What the last survey found.
            pub fn candidates(&self) -> &[Candidate<W>] {
                self.rung.candidates()
            }
        }

        impl<W: Clone + fmt::Display> Reclaimer for $name<W> {
            fn reclaim(&mut self, need: &ReclaimNeed<'_>) -> ReclaimResponse {
                self.rung.reclaim(need)
            }
        }

        impl<W: Clone + fmt::Display> ModelReclaimer for $name<W> {
            fn step(&self) -> ReclaimStep {
                self.rung.step()
            }

            fn owner(&self) -> Requester {
                self.rung.owner()
            }

            fn share_releases(&mut self, releases: &ReleasesUnderWay) {
                self.rung.share_releases(releases);
            }
        }
    };
}

model_step!(
    /// Rung 1: cancels speculative jobs no request waits for yet, least expected value
    /// first, and gives up their reservations (GPU part §2.9, §3.5).
    CancelSpeculation,
    SpeculationSource,
    ReclaimStep::CancelSpeculation
);

model_step!(
    /// Rung 2: returns scratch reserved and not in use: idle staging and unused pinned
    /// host space (§3.5 steps 2 and 8; table line 540).
    ReclaimUnusedScratch,
    ScratchSource,
    ReclaimStep::ReclaimUnusedScratch
);

model_step!(
    /// Rung 3: drops caches of least value per byte, never an original, a canonical copy
    /// still needed, or leased or pinned state (§2.7, §3.4, §3.9).
    DropLowValueCaches,
    CacheSource,
    ReclaimStep::DropLowValueCaches
);

model_step!(
    /// Rung 4: parks idle models that no leased request uses and whose canonical state
    /// can rebuild them (§3.6, §3.9; GPU-W05).
    ParkEligibleIdleModels,
    ParkingSource,
    ReclaimStep::ParkEligibleIdleModels
);

/// Registers every model step on `ladder` in the plan's order (GPU-W05: "cancel
/// speculation, reclaim unused scratch, drop low-value caches, park eligible idle models,
/// then queue/reject"), each acting for its owner; several steps of one rung keep the
/// order they were given in. The steps share, for this admission, what each sets
/// releasing ([`ReleasesUnderWay`]). Returns each registration, in the order the ladder
/// runs them.
pub fn register_model_reclaimers<'a>(
    ladder: &mut ReclaimLadder<'a>,
    reclaimers: impl IntoIterator<Item = &'a mut dyn ModelReclaimer>,
) -> Vec<(ReclaimStep, Requester)> {
    let releases = ReleasesUnderWay::new();
    let mut ordered: Vec<&'a mut dyn ModelReclaimer> = reclaimers.into_iter().collect();
    ordered.sort_by_key(|reclaimer| reclaimer.step());
    for reclaimer in ordered {
        reclaimer.share_releases(&releases);
        let (step, owner) = (reclaimer.step(), reclaimer.owner());
        ladder.register(step, owner, reclaimer);
    }
    ladder.registered()
}
