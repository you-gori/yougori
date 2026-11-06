//! Preserve readiness without copying clean weights back (GPU §4.3 lines 681–687; §1.1
//! line 307; §3.6 lines 576–601; §3.8 lines 615–628; GPU-W05 line 1054).
//!
//! Each immutable allocation carries its clean bit and canonical source identity: a
//! residency [`GpuCopy`] of [`Content::Immutable`] content with its other copies. A
//! clean drop is allowed only when every allocation is clean and some copy reconstructs
//! it by the residency rule of clean eviction ([`eviction_action`] gives
//! [`EvictionAction::DropClean`]), each proven by a vmm [`VerifiedCanonicalCopy`]; clean
//! graph pools are dropped for recapture, as residency decides. The backend must also
//! have a way to drop GPU weights while the process lives: a queried sleep level that
//! discards the weights, planned with that copy ([`SleepPlan`]) and only while CORE-01
//! evidence still admits the sleep-weight-discard backend mode on this runtime (no
//! release records that mode today, so the route is closed on every recorded release),
//! or the approved fixed-address arena that keeps virtual reservations. Standard sleep
//! with a CPU copy needs a level that offloads the weights; restart needs nothing.
//!
//! Each option follows placement's lifecycle (§3.6): a sleep or a clean drop parks
//! through draining and wakes back through materialized and activating with its process
//! alive; a restart retires the parked placement and prepares a new one
//! ([`ParkOption::lifecycle`], checked with placement's [`is_allowed`]).
//!
//! [`choose_park`] accounts for both the eviction and the next wake:
//! `park × w_park + p_reuse × wake × w_wake + retained_host × idle × w_host +
//! interrupted × w_interrupt`, so an option that halves eviction time but doubles the
//! next wake can still win for a model unlikely to be reused.
//!
//! The comparison runs on the fake runners. Restart is the full-process-restart mode and
//! standard sleep the version-supported sleep mode. The fake has no per-model clean-drop
//! mode, so the verified-reload mode stands in for it: it releases the weights inside a
//! running process without a device-to-host copy and reloads them, verified, from the
//! host copy. Its single process retains less GPU memory than a parked per-model process
//! would. Reloading from local storage instead is not run: the fake keeps every
//! page-cache copy, and a verified reload of a cold model has no S8 switch label
//! (rollout decision for T12).
//!
//! # Claim record
//!
//! 1. Contribution: park an idle model by dropping its clean, verified-reconstructible
//!    GPU weights instead of copying them back, choosing per model by eviction plus
//!    reuse-weighted next-wake cost.
//! 2. Closest prior work named by the plan: version-supported sleep that copies weights
//!    to the CPU (vLLM sleep mode, GPU §3.8) and the "copy weights back on every sleep"
//!    row it replaces (§1.1 line 307).
//! 3. Difference tested: skipping the device-to-host copy at park time at the price of a
//!    slower verified reload at wake.
//! 4. Assumptions: the canonical copy stays verified and available until the wake; the
//!    reload reproduces exactly the dropped weights; draining interrupts no request.
//!    Smallest counterexample: a local-storage copy deleted or corrupted between park
//!    and wake, so the wake has nothing exact to reload.
//! 5. Baseline: the cheaper of restart and standard sleep with a CPU copy at each reuse
//!    probability.
//! 6. Result: [`ParkingExperiment::claim`]; narrowed to the reuse levels where the clean
//!    drop is not more expensive.

use std::sync::Arc;

use serde::Serialize;

use super::claim::{CellVerdict, ClaimRecord, ClaimText, ComparisonCell, Experiment};
use super::measure::{interval_nanos, measure, Measurement, OutsideRecords};
use super::ReadinessError;
use crate::foundation::evidence::{EvidenceRefusal, Optimization, ProbeRegistry};
use crate::foundation::ids::{Clock, ContentKey, MonotonicTime};
use crate::foundation::report::{
    ArrivalMode, BenchId, EventKind, IntervalKind, Label, LatencyObjective, LoadDescription,
    NoncePlacement, Provenance, RunRecord,
};
use crate::model_memory::backends::{
    BackendRuntime, ExperimentApproval, SleepLevel, SleepPlan, SleepRefusal, Technique,
    TechniqueRefusal, WeightRetention,
};
use crate::model_memory::bench::corpus::{Corpus, NonceSource};
use crate::model_memory::bench::load::RunnerFactory;
use crate::model_memory::bench::profile::RunnerMode;
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::bench::runner::{HostCopy, RequestPlan, RetryPolicy, Script, UserScript};
use crate::model_memory::placement::{is_allowed, IllegalTransition, StateKind};
use crate::model_memory::residency::eviction::{
    eviction_action, Content, CopyTier, EvictionAction, GpuCopy, NotDroppable, ReconstructibleCopy,
    WriteBack,
};
use crate::model_memory::vmm::{CanonicalCopyRefusal, VerifiedCanonicalCopy};

const GENEROUS_NANOS: u64 = 3_600 * 1_000_000_000;

/// The claim record text of this experiment (GPU §4.17).
pub const CLAIM_TEXT: ClaimText = ClaimText {
    contribution: "Park an idle model by dropping its clean, verified-reconstructible GPU \
                   weights instead of copying them back, choosing per model by eviction \
                   plus reuse-weighted next-wake cost",
    closest_prior_work: "Version-supported sleep that copies weights to the CPU (vLLM sleep \
                         mode, GPU §3.8) and the copy-back-on-every-sleep row of §1.1",
    difference_tested: "No device-to-host copy at park time, paid for by a slower verified \
                        reload at wake",
    assumptions: &[
        "the canonical copy stays verified and available until the wake",
        "the reload reproduces exactly the dropped weights",
        "draining interrupts no request",
    ],
    smallest_counterexample: "a local-storage copy deleted or corrupted between park and \
                              wake, so the wake has nothing exact to reload",
    baseline: "the cheaper of restart and standard sleep with a CPU copy at each reuse \
               probability",
};

/// The three ways to park a model that GPU §4.3 compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParkOption {
    Restart,
    SleepWithCpuCopy,
    CleanDrop,
}

impl ParkOption {
    pub const ALL: [Self; 3] = [Self::Restart, Self::SleepWithCpuCopy, Self::CleanDrop];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Restart => "restart",
            Self::SleepWithCpuCopy => "sleep-with-cpu-copy",
            Self::CleanDrop => "clean-drop",
        }
    }

    /// The fake runner mode the option is measured in (see the module docs).
    pub const fn runner_mode(self) -> RunnerMode {
        match self {
            Self::Restart => RunnerMode::FullProcessRestart,
            Self::SleepWithCpuCopy => RunnerMode::VersionSupportedSleep,
            Self::CleanDrop => RunnerMode::VerifiedReload,
        }
    }

    /// The placement states the park and the next wake pass through (§3.6 lines
    /// 580–585). Parking always drains first; a parked process can live with no GPU
    /// weights; a restart retires the parked placement and prepares a new one.
    pub const fn lifecycle(self) -> LifecyclePath {
        use StateKind::*;
        match self {
            Self::Restart => LifecyclePath {
                park: &[Serving, Draining, Parked, Absent],
                wake: &[Absent, Preparing, Materialized, Activating, Serving],
                process_survives: false,
            },
            Self::SleepWithCpuCopy | Self::CleanDrop => LifecyclePath {
                park: &[Serving, Draining, Parked],
                wake: &[Parked, Materialized, Activating, Serving],
                process_survives: true,
            },
        }
    }
}

/// The placement states of one park and the wake after it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LifecyclePath {
    pub park: &'static [StateKind],
    pub wake: &'static [StateKind],
    /// Whether the runtime process stays alive while parked.
    pub process_survives: bool,
}

impl LifecyclePath {
    /// Checks both halves with placement's transition rule.
    pub fn check(&self) -> Result<(), IllegalTransition> {
        check_path(self.park)?;
        check_path(self.wake)
    }
}

/// Refuses the first step of `states` that placement's state diagram does not allow.
pub fn check_path(states: &[StateKind]) -> Result<(), IllegalTransition> {
    for pair in states.windows(2) {
        if let [from, to] = pair {
            if !is_allowed(*from, *to) {
                return Err(IllegalTransition {
                    from: *from,
                    to: *to,
                });
            }
        }
    }
    Ok(())
}

/// One immutable GPU allocation with its clean bit and canonical source identity (GPU
/// §4.3: "Attach a clean/reconstructible bit and canonical source identity to each
/// immutable allocation").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImmutableAllocation {
    pub gpu: GpuCopy,
    /// Every other copy of the allocation's content.
    pub copies: Vec<ReconstructibleCopy>,
}

impl ImmutableAllocation {
    /// The canonical source identity: the content key of immutable bytes. A session
    /// state or a graph pool has none.
    pub fn canonical_source(&self) -> Option<ContentKey> {
        match self.gpu.content {
            Content::Immutable(key) => Some(key),
            Content::SessionState(_) | Content::GraphPool { .. } => None,
        }
    }

    /// How the allocation may be evicted, by the residency rule of clean eviction.
    pub fn eviction(&self) -> EvictionAction {
        eviction_action(&self.gpu, &self.copies, WriteBack::Available)
    }

    /// The clean/reconstructible bit: clean, immutable and rebuilt exactly by a verified
    /// copy in a tier that guarantees availability.
    pub fn clean_and_reconstructible(&self) -> bool {
        self.canonical_source().is_some()
            && matches!(self.eviction(), EvictionAction::DropClean { .. })
    }
}

/// How the backend drops GPU weights while the process lives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "route", rename_all = "snake_case")]
pub enum CleanDropRoute {
    /// A queried sleep level that discards the weights, planned with the copy.
    BackendSleep { plan: SleepPlan },
    /// The approved fixed-address arena on CUDA VMM, which keeps virtual reservations.
    VmmArena,
}

/// An admitted clean-drop park.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CleanDropPlan {
    pub route: CleanDropRoute,
    /// For each immutable allocation, by index: its proof and the fastest tier it
    /// reloads from.
    pub reloads: Vec<(usize, VerifiedCanonicalCopy, CopyTier)>,
    /// Clean graph pools, by index, dropped for recapture over the reloaded weights.
    pub recaptured: Vec<usize>,
    pub keeps_virtual_reservations: bool,
}

/// Why a park option is not available.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ParkRefusal {
    NoAllocations,
    /// The allocation holds session state, which a park never drops.
    NotImmutable {
        index: usize,
    },
    /// The allocation changed since its copies were made.
    Dirty {
        index: usize,
    },
    /// No copy reconstructs the allocation exactly.
    NoVerifiedCopy {
        index: usize,
        refusals: Vec<CanonicalCopyRefusal>,
    },
    /// The backend offers no way to drop GPU weights while the process lives: each
    /// discarding level's refusal, the refused sleep-weight-discard evidence when a
    /// discarding level exists, and the arena's refusal.
    NoBackendRoute {
        sleep: Vec<(SleepLevel, SleepRefusal)>,
        discard_mode: Option<EvidenceRefusal>,
        arena: TechniqueRefusal,
    },
    /// The backend offers no sleep level that offloads the weights to the host.
    NoCpuCopyLevel {
        refusals: Vec<(SleepLevel, SleepRefusal)>,
    },
}

/// Which park options a model may use (GPU §4.3: "for eligible backends").
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ParkEligibility {
    pub sleep_with_cpu_copy: Result<SleepPlan, ParkRefusal>,
    pub clean_drop: Result<CleanDropPlan, ParkRefusal>,
}

impl ParkEligibility {
    /// Restart is always available.
    pub fn allows(&self, option: ParkOption) -> bool {
        match option {
            ParkOption::Restart => true,
            ParkOption::SleepWithCpuCopy => self.sleep_with_cpu_copy.is_ok(),
            ParkOption::CleanDrop => self.clean_drop.is_ok(),
        }
    }
}

/// Immutable allocations reload from their proven copies; clean graph pools are
/// recaptured (the residency rule for graph resources, which no other tier holds).
type CleanAllocations = (Vec<(usize, VerifiedCanonicalCopy, CopyTier)>, Vec<usize>);

fn clean_allocations(allocations: &[ImmutableAllocation]) -> Result<CleanAllocations, ParkRefusal> {
    if allocations.is_empty() {
        return Err(ParkRefusal::NoAllocations);
    }
    let mut reloads = Vec::new();
    let mut recaptured = Vec::new();
    for (index, allocation) in allocations.iter().enumerate() {
        let source = match allocation.eviction() {
            EvictionAction::Recapture => {
                recaptured.push(index);
                continue;
            }
            EvictionAction::WriteBackThenDrop {
                because: NotDroppable::Dirty,
                ..
            }
            | EvictionAction::Retain {
                because: NotDroppable::Dirty,
            } => return Err(ParkRefusal::Dirty { index }),
            EvictionAction::DropClean { source } => Some(source),
            EvictionAction::WriteBackThenDrop { .. } | EvictionAction::Retain { .. } => None,
        };
        let key = allocation
            .canonical_source()
            .ok_or(ParkRefusal::NotImmutable { index })?;
        let mut refusals = Vec::new();
        let proof = allocation.copies.iter().find_map(|copy| {
            VerifiedCanonicalCopy::reconstructing(copy, key)
                .map_err(|refusal| refusals.push(refusal))
                .ok()
        });
        match (proof, source) {
            (Some(proof), Some(source)) => reloads.push((index, proof, source)),
            _ => return Err(ParkRefusal::NoVerifiedCopy { index, refusals }),
        }
    }
    Ok((reloads, recaptured))
}

/// Which park options `allocations` of the model with whole-weights content `weights`
/// may use on `runtime` (GPU §4.3, §3.8). `copy` is the canonical copy a discarding
/// sleep level reloads from; `registry` is the one the runtime's plan was made with.
pub fn park_eligibility<C: Clock>(
    runtime: &BackendRuntime,
    registry: &ProbeRegistry<C>,
    approvals: &[ExperimentApproval],
    weights: ContentKey,
    copy: Option<ReconstructibleCopy>,
    allocations: &[ImmutableAllocation],
) -> ParkEligibility {
    let content = Content::Immutable(weights);
    let levels: Vec<_> = runtime.pinned().levels().collect();
    let plan = |level: SleepLevel, copy| runtime.plan_sleep(level, content, copy, registry);
    let mut offload_refusals = Vec::new();
    let mut sleep_with_cpu_copy = None;
    for (level, semantics) in &levels {
        if semantics.weights == WeightRetention::OffloadedToHost {
            match plan(*level, None) {
                Ok(planned) => {
                    sleep_with_cpu_copy = Some(planned);
                    break;
                }
                Err(refusal) => offload_refusals.push((*level, refusal)),
            }
        }
    }
    let sleep_with_cpu_copy = sleep_with_cpu_copy.ok_or(ParkRefusal::NoCpuCopyLevel {
        refusals: offload_refusals,
    });
    let discard_mode = runtime
        .plan()
        .recheck(Optimization::SleepWeightDiscard, registry)
        .map(|_| ());
    let clean_drop = clean_allocations(allocations).and_then(|(reloads, recaptured)| {
        let mut sleep_refusals = Vec::new();
        let mut discard_refusal = None;
        for (level, semantics) in &levels {
            if semantics.weights == WeightRetention::Discarded {
                if let Err(refusal) = &discard_mode {
                    discard_refusal = Some(refusal.clone());
                    continue;
                }
                match plan(*level, copy) {
                    Ok(planned) => {
                        return Ok(CleanDropPlan {
                            route: CleanDropRoute::BackendSleep { plan: planned },
                            reloads,
                            recaptured,
                            keeps_virtual_reservations: false,
                        })
                    }
                    Err(refusal) => sleep_refusals.push((*level, refusal)),
                }
            }
        }
        match runtime.admit_with_evidence(Technique::FixedAddressArena, approvals, registry) {
            Ok(_) => Ok(CleanDropPlan {
                route: CleanDropRoute::VmmArena,
                reloads,
                recaptured,
                keeps_virtual_reservations: true,
            }),
            Err(arena) => Err(ParkRefusal::NoBackendRoute {
                sleep: sleep_refusals,
                discard_mode: discard_refusal,
                arena,
            }),
        }
    });
    ParkEligibility {
        sleep_with_cpu_copy,
        clean_drop,
    }
}

/// One park option's measured or assumed costs.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ParkCosts {
    pub park_seconds: f64,
    pub next_wake_seconds: f64,
    /// Host memory the parked model keeps guaranteed: process memory and pinned copies.
    pub retained_host_bytes: u64,
    pub interrupted_requests_per_park: f64,
}

/// What a park decision weighs (GPU §4.3: "the policy must account for both").
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct ParkPolicy {
    /// Probability the model is requested again while parked.
    pub reuse_probability: f64,
    /// Expected seconds the model stays parked.
    pub idle_seconds: f64,
    pub weight_per_park_second: f64,
    pub weight_per_wake_second: f64,
    pub weight_per_retained_host_byte_second: f64,
    pub weight_per_interrupted_request: f64,
}

fn finite_non_negative(field: &'static str, value: f64) -> Result<f64, ReadinessError> {
    if value.is_finite() && value >= 0.0 {
        Ok(value)
    } else {
        Err(ReadinessError::InvalidSpec {
            field,
            reason: "a finite number of zero or more",
        })
    }
}

/// The expected lifecycle cost of parking with `costs` under `policy`:
/// `park × w_park + p × wake × w_wake + retained × idle × w_host + interrupted × w_int`.
pub fn lifecycle_cost(costs: &ParkCosts, policy: &ParkPolicy) -> Result<f64, ReadinessError> {
    let p = finite_non_negative("reuse_probability", policy.reuse_probability)?;
    if p > 1.0 {
        return Err(ReadinessError::InvalidSpec {
            field: "reuse_probability",
            reason: "a probability is at most 1",
        });
    }
    Ok(finite_non_negative("park_seconds", costs.park_seconds)?
        * finite_non_negative("weight_per_park_second", policy.weight_per_park_second)?
        + p * finite_non_negative("next_wake_seconds", costs.next_wake_seconds)?
            * finite_non_negative("weight_per_wake_second", policy.weight_per_wake_second)?
        + costs.retained_host_bytes as f64
            * finite_non_negative("idle_seconds", policy.idle_seconds)?
            * finite_non_negative(
                "weight_per_retained_host_byte_second",
                policy.weight_per_retained_host_byte_second,
            )?
        + finite_non_negative(
            "interrupted_requests_per_park",
            costs.interrupted_requests_per_park,
        )? * finite_non_negative(
            "weight_per_interrupted_request",
            policy.weight_per_interrupted_request,
        )?)
}

/// The reuse probability at which `candidate` and `baseline` cost the same, when both
/// costs are linear in it and the lines cross inside [0, 1].
pub fn break_even_reuse(
    candidate: &ParkCosts,
    baseline: &ParkCosts,
    policy: &ParkPolicy,
) -> Result<Option<f64>, ReadinessError> {
    let at = |costs: &ParkCosts, p: f64| {
        lifecycle_cost(
            costs,
            &ParkPolicy {
                reuse_probability: p,
                ..*policy
            },
        )
    };
    let (c0, c1, b0, b1) = (
        at(candidate, 0.0)?,
        at(candidate, 1.0)?,
        at(baseline, 0.0)?,
        at(baseline, 1.0)?,
    );
    let slope = (c1 - c0) - (b1 - b0);
    if slope == 0.0 {
        return Ok(None);
    }
    let p = (b0 - c0) / slope;
    Ok((0.0..=1.0).contains(&p).then_some(p))
}

/// The chosen option and every eligible option's cost.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ParkChoice {
    pub option: ParkOption,
    pub cost: f64,
    pub costs: Vec<(ParkOption, f64)>,
}

/// Chooses the eligible option with the lowest lifecycle cost; ties go to less retained
/// host memory, then to the order of [`ParkOption::ALL`].
pub fn choose_park(
    candidates: &[(ParkOption, ParkCosts)],
    eligibility: &ParkEligibility,
    policy: &ParkPolicy,
) -> Result<ParkChoice, ReadinessError> {
    let mut costs = Vec::new();
    let mut best: Option<(ParkOption, f64, u64)> = None;
    for (option, option_costs) in candidates {
        if !eligibility.allows(*option) {
            continue;
        }
        let cost = lifecycle_cost(option_costs, policy)?;
        costs.push((*option, cost));
        let better = match best {
            None => true,
            Some((best_option, best_cost, best_retained)) => {
                cost < best_cost
                    || (cost == best_cost
                        && (option_costs.retained_host_bytes, *option)
                            < (best_retained, best_option))
            }
        };
        if better {
            best = Some((*option, cost, option_costs.retained_host_bytes));
        }
    }
    let (option, cost, _) = best.ok_or(ReadinessError::InvalidSpec {
        field: "candidates",
        reason: "no eligible park option",
    })?;
    Ok(ParkChoice {
        option,
        cost,
        costs,
    })
}

/// The comparison's parameters.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ParkingSpec {
    /// The model that is parked and woken.
    pub parked: Label,
    /// The model that takes its place meanwhile.
    pub other: Label,
    pub trials: u32,
    pub reuse_probabilities: Vec<f64>,
    /// Its reuse probability is replaced by each of `reuse_probabilities`.
    pub policy: ParkPolicy,
    pub max_output_tokens: u32,
    /// Relative cost difference treated as a tie.
    pub tie_tolerance: f64,
    pub latency_objective: LatencyObjective,
}

/// One option measured on its fake runner mode.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct OptionMeasurement {
    pub option: ParkOption,
    pub mode: RunnerMode,
    pub measurement: Measurement,
    /// Per trial: request dequeued to the demand load or wake starting.
    pub park_seconds: Vec<f64>,
    /// Per trial: the parked model's demand wake or load.
    pub next_wake_seconds: Vec<f64>,
    /// Guaranteed host memory the parked model keeps: its process and pinned copy.
    pub retained_host_bytes: u64,
    /// Page-cache bytes of its weights, which may be reclaimed at any time.
    pub reclaimable_host_bytes: u64,
    /// Failed attempts over every trial.
    pub interrupted_requests: u64,
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

impl OptionMeasurement {
    /// Mean costs per park.
    pub fn costs(&self) -> ParkCosts {
        let parks = self.park_seconds.len().max(1) as f64;
        ParkCosts {
            park_seconds: mean(&self.park_seconds),
            next_wake_seconds: mean(&self.next_wake_seconds),
            retained_host_bytes: self.retained_host_bytes,
            interrupted_requests_per_park: self.interrupted_requests as f64 / parks,
        }
    }
}

/// What happened to one option.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum OptionOutcome {
    Measured {
        measured: Box<OptionMeasurement>,
    },
    NotEligible {
        option: ParkOption,
        refusal: ParkRefusal,
    },
    NotRun {
        label: String,
        reason: String,
    },
}

/// One reuse probability's costs and verdict.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReuseCell {
    pub reuse_probability: f64,
    pub costs: Vec<(ParkOption, f64)>,
    pub verdict: CellVerdict,
}

/// The finished comparison.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ParkingExperiment {
    pub outcomes: Vec<OptionOutcome>,
    pub cells: Vec<ReuseCell>,
    pub claim: ClaimRecord,
}

impl ParkingExperiment {
    pub fn measured(&self, option: ParkOption) -> Option<&OptionMeasurement> {
        self.outcomes.iter().find_map(|outcome| match outcome {
            OptionOutcome::Measured { measured } if measured.option == option => Some(&**measured),
            _ => None,
        })
    }

    /// The GPU §4.17 claim record.
    pub fn claim(&self) -> &ClaimRecord {
        &self.claim
    }
}

fn event_at(record: &RunRecord, matches: impl Fn(&EventKind) -> bool) -> Option<MonotonicTime> {
    record
        .events
        .iter()
        .find(|event| matches(&event.event))
        .map(|event| event.at_nanos)
}

fn plan(
    nonces: &mut NonceSource,
    fixture: &crate::model_memory::bench::corpus::Fixture,
    variant: &str,
    model: &Label,
    switch: bool,
    spec: &ParkingSpec,
) -> Result<RequestPlan, ReadinessError> {
    Ok(RequestPlan {
        variant: Label::new(variant)?,
        model: model.clone(),
        request: nonces.render(fixture)?,
        max_output_tokens: spec.max_output_tokens,
        deadline_nanos: GENEROUS_NANOS,
        timeout_nanos: GENEROUS_NANOS,
        gap_before_nanos: 0,
        switch_from_previous: switch,
        burst: 0,
        check_response: false,
    })
}

fn one_user(start_at: MonotonicTime, requests: Vec<RequestPlan>, burst: u32) -> Script {
    Script {
        bench: BenchId::Bench02,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at,
            requests: requests
                .into_iter()
                .map(|request| RequestPlan { burst, ..request })
                .collect(),
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    }
}

fn measure_option(
    base: &RunnerFactory,
    option: ParkOption,
    spec: &ParkingSpec,
) -> Result<(OptionMeasurement, Vec<RunRecord>), ReadinessError> {
    let mut profile = base.profile.clone();
    profile.mode = option.runner_mode();
    let factory = RunnerFactory {
        profile,
        rules: base.rules.clone(),
        clock: Arc::clone(&base.clock),
        seed: base.seed,
        execution: base.execution.clone(),
    };
    let corpus = Corpus::fast01()?;
    let fixture = corpus.get("fast01-tool-run-tests")?;
    let weights = factory.profile.model(&spec.parked)?.weights_bytes;
    let process_rss = factory.profile.footprint.rss_bytes;
    let mut records = Vec::new();
    let mut park_seconds = Vec::new();
    let mut next_wake_seconds = Vec::new();
    let mut retained_host_bytes = 0u64;
    let mut reclaimable_host_bytes = 0u64;
    let mut interrupted_requests = 0u64;
    for trial in 0..spec.trials {
        let stream = (option as u64) * 10_000 + u64::from(trial);
        let (mut runner, _start) = factory.started(stream, &spec.parked, BenchId::Bench02)?;
        // The other model's first load reuses a verified host copy, as every option may.
        runner.warm_host_copy(&spec.other)?;
        let mut nonces = NonceSource::new(
            SeededRng::new(factory.stream_seed(stream)),
            NoncePlacement::PromptPrefix,
        );
        let park = one_user(
            runner.clock().now(),
            vec![
                plan(
                    &mut nonces,
                    fixture,
                    "park-serving",
                    &spec.parked,
                    false,
                    spec,
                )?,
                plan(&mut nonces, fixture, "park-switch", &spec.other, true, spec)?,
            ],
            trial,
        );
        let parked_out = runner.serve(&park)?;
        let switch = parked_out
            .records
            .iter()
            .find(|record| record.attempt.variant.as_str() == "park-switch");
        if let Some(record) = switch {
            let dequeued = event_at(record, |event| matches!(event, EventKind::RequestDequeued));
            let started = event_at(record, |event| {
                matches!(event, EventKind::LoadStarted | EventKind::WakeStarted)
            });
            if let (Some(dequeued), Some(started)) = (dequeued, started) {
                park_seconds.push(started.saturating_duration_since(dequeued).as_secs_f64());
            }
        }
        let snapshot = runner.snapshot();
        let guaranteed = snapshot
            .rss_bytes
            .saturating_sub(process_rss)
            .saturating_add(snapshot.pinned_host_bytes);
        retained_host_bytes = retained_host_bytes.max(guaranteed);
        if runner.status(&spec.parked)?.host_copy == HostCopy::PageCache {
            reclaimable_host_bytes = reclaimable_host_bytes.max(weights);
        }
        let wake = one_user(
            runner.clock().now(),
            vec![plan(
                &mut nonces,
                fixture,
                "park-wake",
                &spec.parked,
                false,
                spec,
            )?],
            trial,
        );
        let wake_out = runner.serve(&wake)?;
        if let Some(record) = wake_out
            .records
            .iter()
            .find(|record| record.attempt.variant.as_str() == "park-wake")
        {
            let wake_nanos = interval_nanos(record, IntervalKind::DemandWake)
                .or_else(|| interval_nanos(record, IntervalKind::DemandLoad));
            if let Some(nanos) = wake_nanos {
                next_wake_seconds.push(nanos as f64 / 1e9);
            }
        }
        interrupted_requests += parked_out
            .records
            .iter()
            .chain(&wake_out.records)
            .filter(|record| !record.is_success())
            .count() as u64;
        records.extend(parked_out.records);
        records.extend(wake_out.records);
    }
    let measurement = measure(
        records.clone(),
        spec.latency_objective,
        OutsideRecords::default(),
    )?;
    Ok((
        OptionMeasurement {
            option,
            mode: option.runner_mode(),
            measurement,
            park_seconds,
            next_wake_seconds,
            retained_host_bytes,
            reclaimable_host_bytes,
            interrupted_requests,
        },
        records,
    ))
}

/// Measures every eligible option on the fake runners and compares the clean drop with
/// the cheaper baseline at each reuse probability (GPU §4.3).
pub fn run_parking(
    base: &RunnerFactory,
    eligibility: &ParkEligibility,
    spec: &ParkingSpec,
) -> Result<ParkingExperiment, ReadinessError> {
    if spec.trials == 0 {
        return Err(ReadinessError::InvalidSpec {
            field: "trials",
            reason: "at least one trial",
        });
    }
    let mut outcomes = Vec::new();
    let mut all_records = Vec::new();
    for option in ParkOption::ALL {
        option.lifecycle().check()?;
        let refusal = match option {
            ParkOption::Restart => None,
            ParkOption::SleepWithCpuCopy => eligibility.sleep_with_cpu_copy.clone().err(),
            ParkOption::CleanDrop => eligibility.clean_drop.clone().err(),
        };
        match refusal {
            Some(refusal) => outcomes.push(OptionOutcome::NotEligible { option, refusal }),
            None => {
                let (measured, records) = measure_option(base, option, spec)?;
                all_records.extend(records);
                outcomes.push(OptionOutcome::Measured {
                    measured: Box::new(measured),
                });
            }
        }
    }
    outcomes.push(OptionOutcome::NotRun {
        label: "clean-drop-reload-from-local-storage".to_string(),
        reason: "the fake keeps every page-cache copy, and a verified reload of a cold model \
                 has no S8 switch label (rollout decision for T12)"
            .to_string(),
    });
    let costs: Vec<(ParkOption, ParkCosts)> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            OptionOutcome::Measured { measured } => Some((measured.option, measured.costs())),
            _ => None,
        })
        .collect();
    let mut cells = Vec::new();
    let mut claim_cells = Vec::new();
    for &reuse_probability in &spec.reuse_probabilities {
        let policy = ParkPolicy {
            reuse_probability,
            ..spec.policy
        };
        let mut option_costs = Vec::new();
        for (option, option_cost) in &costs {
            option_costs.push((*option, lifecycle_cost(option_cost, &policy)?));
        }
        let candidate = option_costs
            .iter()
            .find(|(option, _)| *option == ParkOption::CleanDrop)
            .map(|(_, cost)| *cost);
        let baseline = option_costs
            .iter()
            .filter(|(option, _)| *option != ParkOption::CleanDrop)
            .map(|(_, cost)| *cost)
            .fold(None, |best: Option<f64>, cost| {
                Some(best.map_or(cost, |best| best.min(cost)))
            });
        let (Some(candidate), Some(baseline)) = (candidate, baseline) else {
            continue;
        };
        let verdict = if candidate < baseline * (1.0 - spec.tie_tolerance) {
            CellVerdict::Better
        } else if candidate <= baseline * (1.0 + spec.tie_tolerance) {
            CellVerdict::Tie
        } else {
            CellVerdict::Worse
        };
        claim_cells.push(ComparisonCell {
            label: format!("reuse-{reuse_probability:.2}"),
            verdict,
        });
        cells.push(ReuseCell {
            reuse_probability,
            costs: option_costs,
            verdict,
        });
    }
    let provenance = Provenance::of_records(&all_records)?;
    let claim = ClaimRecord::new(
        Experiment::CleanDropParking,
        CLAIM_TEXT,
        &provenance,
        claim_cells,
    )?;
    Ok(ParkingExperiment {
        outcomes,
        cells,
        claim,
    })
}

#[cfg(test)]
mod tests;
