//! Transition peaks (GPU §4.15, line 862: "include transition peaks, so a plan cannot
//! swap through a second full copy that does not fit").
//!
//! Every transition between two stages is checked with residency's §2.7 admission check
//! ([`admit_vram`]) over three pieces of time:
//!
//! 1. [`TransitionSlot::PreviousStage`]: the previous stage runs, with whatever is
//!    prepared for the next stage beside it;
//! 2. [`TransitionSlot::Boundary`]: evicted state is gone, missing state is loaded,
//!    restored, derived or recomputed, and written-back state is still being copied;
//! 3. [`TransitionSlot::NextStage`]: the next stage runs.
//!
//! Shared weights count once per physical allocation, each engine process counts its own
//! context, KV pool and workspace, and transient staging and workspaces count during their
//! piece, exactly as §2.7 counts them. The exact assumptions behind each estimate travel
//! with it ([`Assumption`]).

use serde::Serialize;

use crate::foundation::ids::{MonotonicTime, TrustScope};
use crate::model_memory::residency::vram::{
    admit_vram, ImmutableAllocation, ImmutableKind, KvBound, ProcessVram, TransientDemand,
    TransientKind, VramBreakdown, VramError, VramPlan,
};
use crate::model_memory::residency::{Capacity, Interval};

use super::declaration::CheckedWorkflow;
use super::model::Infeasibility;
use super::TransitionError;

/// One piece of a transition's time (line 862).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum TransitionSlot {
    /// The previous stage runs, and preparation for the next one overlaps it.
    PreviousStage,
    /// Between the stages: evictions done, missing state materialized.
    Boundary,
    /// The next stage runs.
    NextStage,
}

impl TransitionSlot {
    const fn index(self) -> u64 {
        match self {
            Self::PreviousStage => 0,
            Self::Boundary => 1,
            Self::NextStage => 2,
        }
    }

    fn from_start(start: MonotonicTime) -> Self {
        match start.as_nanos() / SLOT_NANOS {
            0 => Self::PreviousStage,
            1 => Self::Boundary,
            _ => Self::NextStage,
        }
    }
}

/// Each slot is one second of the admission check's own time line; only the order of
/// the pieces matters.
const SLOT_NANOS: u64 = 1_000_000_000;

/// The exact assumptions under which a peak estimate is feasible (line 859).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Assumption {
    /// The device budget the CORE-03 ledger granted; telemetry never raises it (S3.2).
    UsableVramFromLedger { bytes: u64 },
    /// Room kept for GPU consumers outside the plan (§3.1).
    SafetyReserve { bytes: u64 },
    /// Evicted state is freed when the previous stage ends, before missing state loads.
    EvictionsAtStageEnd,
    /// Memory for loaded, restored or derived state is allocated when its work starts.
    AllocatedAtLoadStart,
    /// The sources of a derived representation stay resident until it is built, so the
    /// boundary holds both (the "second full copy" of line 862).
    DeriveSourcesHeldUntilBuilt,
    /// One loading process uses this many device staging bytes.
    StagingPerLoadingProcess { bytes: u64 },
    /// A stage's engine reserves its KV pool for its whole life (§2.7: bounded KV).
    KvPoolReserved { stage: String, bytes: u64 },
    /// The session a stage consumes or produces lives inside that stage's KV pool.
    SessionInsideStagePool,
    /// Preparing for the next stage needs an engine context of this size.
    PreparationEngineContext { bytes: u64 },
    /// A session retained between stages is held by a parked engine with this context.
    SessionHolderContext { resource: String, bytes: u64 },
    /// Written-back state stays on the device until its copy completes, and the next
    /// stage starts after every write-back.
    WriteBackBeforeNextStage,
}

/// A peak-memory estimate with the exact assumptions that make it feasible (line 859).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct PeakEstimate {
    /// The left-hand side of the §2.7 inequality at the peak, safety reserve included.
    pub peak_bytes: u64,
    pub usable_vram_bytes: u64,
    pub during: TransitionSlot,
    pub breakdown: VramBreakdown,
    pub assumptions: Vec<Assumption>,
}

/// The allocations and processes of one transition, handed to the §2.7 check.
pub(crate) struct MemoryPlan {
    scope: TrustScope,
    allocations: Vec<ImmutableAllocation>,
    processes: Vec<ProcessVram>,
    assumptions: Vec<Assumption>,
}

/// One process's demand, for [`MemoryPlan::process`].
pub(crate) struct ProcessDemand {
    pub(crate) name: String,
    pub(crate) from: TransitionSlot,
    pub(crate) until: TransitionSlot,
    pub(crate) context_bytes: u64,
    pub(crate) graph_pool_bytes: u64,
    pub(crate) kv_bytes: u64,
    pub(crate) maps: Vec<String>,
    pub(crate) transients: Vec<(TransientKind, u64, TransitionSlot)>,
}

fn span(from: TransitionSlot, until: TransitionSlot) -> Result<Interval, TransitionError> {
    let start = MonotonicTime::from_nanos(from.index() * SLOT_NANOS);
    let end = MonotonicTime::from_nanos((until.index() + 1) * SLOT_NANOS);
    Interval::new(start, end).map_err(|_| TransitionError::Internal {
        what: "a transition span must end after it starts",
    })
}

impl MemoryPlan {
    pub(crate) fn new(scope: TrustScope) -> Self {
        Self {
            scope,
            allocations: Vec::new(),
            processes: Vec::new(),
            assumptions: Vec::new(),
        }
    }

    pub(crate) fn assume(&mut self, assumption: Assumption) {
        if !self.assumptions.contains(&assumption) {
            self.assumptions.push(assumption);
        }
    }

    /// One physical allocation of immutable bytes, resident from the start of `from`
    /// through the end of `until`.
    pub(crate) fn allocation(
        &mut self,
        key: &str,
        kind: ImmutableKind,
        bytes: u64,
        from: TransitionSlot,
        until: TransitionSlot,
    ) -> Result<(), TransitionError> {
        self.allocations.push(ImmutableAllocation {
            key: key.to_string(),
            kind,
            bytes,
            sharing_domain: self.scope,
            resident: span(from, until)?,
        });
        Ok(())
    }

    pub(crate) fn process(&mut self, demand: ProcessDemand) -> Result<(), TransitionError> {
        let transients = demand
            .transients
            .iter()
            .filter(|(_, bytes, _)| *bytes > 0)
            .map(|(kind, bytes, slot)| {
                Ok(TransientDemand {
                    kind: *kind,
                    bytes: *bytes,
                    during: span(*slot, *slot)?,
                })
            })
            .collect::<Result<Vec<_>, TransitionError>>()?;
        self.processes.push(ProcessVram {
            process: demand.name,
            sharing_domain: self.scope,
            lifetime: span(demand.from, demand.until)?,
            maps: demand.maps,
            context_bytes: demand.context_bytes,
            graph_pool_bytes: demand.graph_pool_bytes,
            kv: KvBound::Reserved {
                bytes: demand.kv_bytes,
            },
            transients,
        });
        Ok(())
    }

    /// Admits the plan with residency's §2.7 check: an overcommit on any piece is an
    /// [`Infeasibility::TransitionPeak`], any other refusal an input error.
    pub(crate) fn admit(
        mut self,
        workflow: &CheckedWorkflow,
        usable_vram_bytes: u64,
    ) -> Result<Result<PeakEstimate, Infeasibility>, TransitionError> {
        let safety_reserve_bytes = workflow.budgets.safety_reserve_bytes;
        self.assume(Assumption::UsableVramFromLedger {
            bytes: usable_vram_bytes,
        });
        self.assume(Assumption::SafetyReserve {
            bytes: safety_reserve_bytes,
        });
        let plan = VramPlan {
            device: workflow.budgets.device,
            usable_vram: Capacity::Physical {
                bytes: usable_vram_bytes,
            },
            safety_reserve_bytes,
            allocations: self.allocations,
            processes: self.processes,
        };
        match admit_vram(&plan) {
            Ok(evaluation) => {
                let peak = evaluation.peak().ok_or(TransitionError::Internal {
                    what: "a transition always has a running stage",
                })?;
                Ok(Ok(PeakEstimate {
                    peak_bytes: peak.total_bytes,
                    usable_vram_bytes,
                    during: TransitionSlot::from_start(peak.during.start()),
                    breakdown: peak.demand,
                    assumptions: self.assumptions,
                }))
            }
            Err(VramError::DoesNotFit(overcommit)) => {
                let (term, term_bytes) = overcommit.peak.demand.largest_term();
                Ok(Err(Infeasibility::TransitionPeak {
                    during: TransitionSlot::from_start(overcommit.peak.during.start()),
                    peak_bytes: overcommit.peak.total_bytes,
                    usable_vram_bytes: overcommit.usable_vram_bytes,
                    largest_term: term.to_string(),
                    largest_term_bytes: term_bytes,
                }))
            }
            Err(other) => Err(TransitionError::Admission(other)),
        }
    }
}
