//! G05, the library half of GPU-W06: adopt the retention and preparation policies
//! (docs/combined-plan-leftover-tasks.md G05; docs/combined-gpu-memory-and-vm-sandbox-plan.md
//! GPU-W06 at line 1225, §2.9 at line 624, §4.1 at line 824 and §4.5 at line 860).
//!
//! The retention, bundle, transition and readiness contracts were built on declared or
//! fake-runner numbers. This module connects them to real inputs and operations:
//!
//! - [`observed`]: trusted CORE-08 load records become the reload costs and resource
//!   inputs those decisions take, bound to the configuration they were measured under,
//!   with their provenance and freshness. A stale, other-configuration or untrusted
//!   observation falls back to the caller's declared estimate, labelled with why; it is
//!   never a silent measured value.
//! - [`governor`]: a workflow's declared next steps become bounded, cancellable
//!   [`PrepareOperation`](super::intent::PrepareOperation)s whose deadlines, cancellation,
//!   CORE-04 leases and foreground promotion act on CORE-03 reservations and the ledger's
//!   queue fairness. Demand-only is the default and the runtime rollback.
//! - [`shared`]: a prerequisite several preparations share is reserved once and released
//!   only when its last holder finishes or is cancelled.
//!
//! Nothing here restates a committed module. The value of a step is §2.9's
//! [`expected_value`](crate::model_memory::math::prefetch::expected_value); the demand-only
//! signal is [`ModeController`](crate::model_memory::math::calibration::ModeController)'s;
//! deadlines, TTLs, cancellation tokens and lease following are
//! [`intent`](super::intent)'s; percentiles and provenance are `foundation::report`'s;
//! configuration fingerprints are `foundation::evidence`'s; the curve fit is
//! [`LinearServiceFit`](crate::model_memory::math::chunking::LinearServiceFit); admission,
//! budgets, holds and queue fairness are `foundation::ledger`'s. The existing scheduler
//! stays: per-transfer speculative budgets, the foreground reserve and block-boundary
//! cancellation remain the executor's `math::prefetch::PrefetchScheduler`, and the
//! ledger's queue fairness stays arrival order unless the host owner opts in.
//!
//! # Production callers
//!
//! The library half ends here; `model_runner` is not changed. A production caller would:
//!
//! 1. After `measurement::report::adapt` yields a CORE-08 record of a load attempt or of a
//!    request with a demand load, call [`ObservedCosts::ingest`] with that record, the
//!    collector's source class, its clock session and collection time, and
//!    [`LoadAttemptKey::new`] over the runner instance id and the load attempt id (the
//!    attempt's own id, or the demand load's `attempt_id`).
//! 2. Build a [`ReloadConfiguration`] from the trusted run metadata it plans for, take its
//!    [`ReloadConfiguration::fingerprint`], and ask [`ObservedCosts::reload_cost`],
//!    [`ObservedCosts::resources`] and [`ObservedCosts::load_curve`]. Feed
//!    [`Labelled::reload_seconds`] to `residency::retention::CachedObject::reload_seconds`,
//!    the [`ReloadCost`] value to `bundles::ObjectSpec::load`, the curve to
//!    `transitions::MeasuredCurves::host_to_device` with [`Basis::evidence`], and the
//!    cost to [`DeclaredStep::cost`].
//! 3. Hold one [`PreparationGovernor`] per host ledger; call
//!    [`PreparationGovernor::enable_workflow_intent`] only where the operator opts in, and
//!    [`PreparationGovernor::declare`] whenever a workflow's queue changes.
//! 4. Under the ledger lock, call [`PreparationGovernor::poll`] periodically with the
//!    coordinator's lease states; on [`GovernorEvent::Granted`], call
//!    [`PreparationGovernor::begin_work`] and submit the executor job carrying
//!    [`PreparationGovernor::token`]; on completion call [`PreparationGovernor::complete`].
//! 5. At request admission (`gpu_enter`), call [`PreparationGovernor::request_arrived`];
//!    on [`ArrivalReport::Promoted`] also call `TransferExecutor::promote` for the same
//!    operation. Call [`PreparationGovernor::finish`] when the served state is unloaded,
//!    and `Ledger::confirm_release` once the host observes the release.
//! 6. Wire an operator rollback to [`PreparationGovernor::roll_back`] and the §2.9 mode
//!    controller to [`PreparationGovernor::follow`].
//! 7. Submit each preparation's executor job under the preparation's operation, within
//!    its own reservation, and after each poll and every executor or governor restart
//!    call [`StaleStateReconciler::reconcile`] with the `TransferExecutor` and the host's
//!    release observations ([`governor::reconcile`] lists the calls).
//!
//! Every test runs on fakes and manual clocks. Nothing here measures a GPU, and no value
//! from the fake substrate backs a performance claim.

pub mod governor;
pub mod observed;
pub mod prediction;
pub mod shared;

#[cfg(test)]
mod tests;

pub use governor::reconcile::{
    observe_job, ExecutorView, Finding, OrphanWork, PreparationFinding, PreparationView,
    ReconcileReport, ReleaseFinding, ReleaseObservation, StaleStateReconciler, Uncertainty,
    UnownedReservation, WorkLoss, WorkObservation, PREREQUISITE_OPERATION_PREFIX,
};
pub use governor::{
    ArrivalReport, DeclarationReport, DeclaredStep, DeclineReason, GovernorConfig, GovernorError,
    GovernorEvent, PreparationEnd, PreparationGovernor, PreparationMode, PreparationOutcome,
    RollbackCause, StepDecision, StepOutcome, WorkGrant, WorkflowIntent,
};
pub use observed::{
    Basis, CostObservation, CostPolicy, DeclaredEstimate, DeclaredResources, EstimateReason,
    Ingested, Labelled, LoadAttemptKey, ObservationRefusal, ObservedCosts, ReloadConfiguration,
    ReloadCost, ReloadHost, ResourceInputs, UntrustedReason,
};
pub use shared::{
    Acquired, Holding, LedgerRelease, PrerequisiteDemand, PrerequisiteKey, PromotionEffect,
    SharedEvent, SharedPrerequisites, SharedRefusal,
};
